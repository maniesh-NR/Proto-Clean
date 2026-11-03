package app.protoclean.bond

import android.app.Notification
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import app.protoclean.ProtoCleanApp
import app.protoclean.dns.PacketKit
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The Speedify-style bonding VPN.
 *
 * All device traffic enters our tun; TCP flows are forwarded through
 * the [BondEngine] (split across Wi-Fi + cellular, rejoined at the bond
 * server), and DNS is answered over a protected UDP socket so name
 * resolution keeps working while every TCP stream rides both adapters.
 *
 * Member sockets are [VpnService.protect]ed and bound to their specific
 * network, so they never loop back into the tun and both radios stay
 * active at the same time — the whole point of channel bonding.
 *
 * (Android allows one VPN at a time, so this mode is exclusive with the
 * WireGuard tunnel and the DNS-filtering VPN — same as any other VPN
 * app. net-merge lists the same constraint.)
 */
class BondVpnService : VpnService() {

    companion object {
        private const val TAG = "ProtoClean.BondVpn"
        private const val NOTIF_ID = 43
        const val ACTION_STOP = "app.protoclean.BOND_VPN_STOP"

        /** Virtual address of this VPN (also the DNS address). */
        const val VIRTUAL_ADDR = "10.111.222.34"
        private const val DNS_UPSTREAM = "1.1.1.1"

        /** Set by the ViewModel before start(). */
        object Config {
            @Volatile
            var server: String = ""
            @Volatile
            var port: Int = 10820
            @Volatile
            var token: String = ""
            @Volatile
            var mode: String = "bond"        // "bond" | "balance"
            @Volatile
            var upstream: String = "bond"     // "bond" | "samizdat"
        }

        @Volatile
        var running = false
            private set

        fun start(context: android.content.Context) {
            val intent = Intent(context, BondVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: android.content.Context) {
            context.startService(
                Intent(context, BondVpnService::class.java)
                    .setAction(ACTION_STOP))
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var engine: BondEngine? = null
    private lateinit var pool: ExecutorService
    @Volatile
    private var stopping = false
    private val rng = SecureRandom()

    /** One TCP flow through the tun (client app <-> bonded session). */
    private inner class Flow(
        val clientIp: ByteArray,
        val clientPort: Int,
        val dstIp: ByteArray,
        val dstPort: Int,
        val host: String,                    // destination as text
        var ourSeq: Long,                    // our ISN (server side of the flow)
        var clientSeq: Long,                 // next client byte we expect
        var session: UpstreamSession? = null,
        var finSent: Boolean = false,        // we sent FIN toward the client
        var remoteClosed: Boolean = false,
    ) {
        var pendingDown = ByteArray(0)       // downstream bytes the client's
        var clientWindow = 65535             // window could not absorb yet
        var clientAck: Long = 0              // what the client has ACKed of ours

        val key: String get() =
            "${clientIp.joinToString(".")}:$clientPort>" +
                "${dstIp.joinToString(".")}:$dstPort"
    }

    private val flows = ConcurrentHashMap<String, Flow>()

    /** Single-connection session through the local samizdat engine
     *  (SOCKS5 → lantern-box mixed inbound on 127.0.0.1). */
    private inner class LocalSocksSession(
        host: String,
        port: Int,
        onDownstream: (ByteArray) -> Unit,
        onRemoteClose: () -> Unit,
    ) : UpstreamSession {
        private val socket = java.net.Socket()
        @Volatile
        private var closed = false
        private val out by lazy { socket.getOutputStream() }

        init {
            socket.tcpNoDelay = true
            socket.connect(java.net.InetSocketAddress("127.0.0.1",
                SamizdatManager.MIXED_PORT), 8000)
            // SOCKS5: greet (no-auth), CONNECT, expect success
            out.write(byteArrayOf(0x05, 0x01, 0x00))
            out.flush()
            val greet = ByteArray(2)
            java.io.DataInputStream(socket.getInputStream()).readFully(greet)
            require(greet[0] == 0x05.toByte()) { "not a SOCKS5 server" }
            val raw = host.toByteArray(Charsets.US_ASCII)
            require(raw.size in 1..255) { "bad host" }
            out.write(byteArrayOf(0x05, 0x01, 0x00, 0x03, raw.size.toByte()))
            out.write(raw)
            out.write(byteArrayOf(((port shr 8) and 0xFF).toByte(),
                (port and 0xFF).toByte()))
            out.flush()
            val resp = ByteArray(4)
            java.io.DataInputStream(socket.getInputStream()).readFully(resp)
            require(resp[1] == 0.toByte()) { "SOCKS CONNECT refused" }
            // skip the bound address in the reply
            val left = when (resp[3].toInt() and 0xFF) {
                0x01 -> 4 + 2
                0x04 -> 16 + 2
                else -> 1 + (java.io.DataInputStream(
                    socket.getInputStream()).readByte().toInt() and 0xFF) + 2
            }
            val skip = ByteArray(left)
            java.io.DataInputStream(socket.getInputStream()).readFully(skip)
            Thread({
                try {
                    val input = socket.getInputStream()
                    val buf = ByteArray(65536)
                    while (!closed) {
                        val n = input.read(buf)
                        if (n < 0) break
                        if (n > 0) onDownstream(buf.copyOf(n))
                    }
                } catch (e: Exception) {
                    // closed
                } finally {
                    onRemoteClose()
                }
            }, "samizdat-upstream").also { it.isDaemon = true; it.start() }
        }

        override fun sendUp(data: ByteArray) {
            if (closed) return
            try {
                synchronized(out) {
                    out.write(data)
                    out.flush()
                }
            } catch (e: Exception) {
                closed = true
            }
        }

        override fun sendFin() {
            runCatching { socket.shutdownOutput() }
        }

        override fun close() {
            closed = true
            runCatching { socket.close() }
        }
    }

    /** Open a forwarded session per the configured upstream. */
    private fun openUpstream(
        host: String, port: Int,
        onDownstream: (ByteArray) -> Unit,
        onRemoteClose: () -> Unit,
    ): UpstreamSession? =
        if (Config.upstream == "samizdat") {
            runCatching { LocalSocksSession(host, port, onDownstream, onRemoteClose) }
                .getOrNull()
        } else {
            engine?.connect(host, port, onDownstream, onRemoteClose)
        }

    override fun onCreate() {
        super.onCreate()
        running = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        startInForeground()
        if (prepare(this) != null) {
            Log.w(TAG, "VPN consent missing — stopping")
            stopSelf()
            return START_NOT_STICKY
        }
        if (Config.server.isBlank()) {
            Log.w(TAG, "no bond server configured — stopping")
            stopSelf()
            return START_NOT_STICKY
        }
        startTun()
        return START_STICKY
    }

    private fun startInForeground() {
        val notification: Notification =
            androidx.core.app.NotificationCompat.Builder(this, ProtoCleanApp.CHANNEL_DNS)
                .setSmallIcon(app.protoclean.R.drawable.ic_stat_shield)
                .setContentTitle(getText(app.protoclean.R.string.notif_bond_title))
                .setContentText(getText(app.protoclean.R.string.notif_bond_text))
                .setOngoing(true)
                .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    // ------------------------------------------------------------------ tun

    private fun startTun() {
        stopping = false
        pool = Executors.newFixedThreadPool(8)
        val builder = Builder()
            .setSession("Proto Clean link bonding")
            .addAddress(VIRTUAL_ADDR, 32)
            .addDnsServer(VIRTUAL_ADDR)
            .addRoute("0.0.0.0", 0)          // everything enters the tun
            .setBlocking(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        if (Config.upstream == "samizdat") {
            // the lantern-box engine runs as our own uid: exclude the app
            // from the tun so its outbound connection cannot loop back
            runCatching { builder.addDisallowedApplication(packageName) }
            if (!SamizdatManager.start(this)) {
                Log.w(TAG, "samizdat engine failed to start — stopping")
                stopSelf()
                return
            }
        } else {
            engine = BondEngine(this, Config.server, Config.port,
                Config.token, Config.mode).also { it.start() }
        }
        tun = builder.establish() ?: run {
            Log.w(TAG, "establish() failed")
            stopSelf()
            return
        }
        Log.i(TAG, "bonding VPN up (upstream ${Config.upstream}, " +
            "server ${Config.server}:${Config.port}, mode ${Config.mode})")
        reader = Thread({ tunLoop() }, "proto-clean-bond-reader").also {
            it.isDaemon = true
            it.start()
        }
    }

    private fun tunLoop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        while (!stopping) {
            val n = try { input.read(buf) } catch (e: Exception) { break }
            if (n <= 0) continue
            val packet = buf.copyOf(n)
            // TCP -> the bonding engine; UDP/53 -> protected DNS
            val tcpIp = PacketKit.parseIp(packet, n, PacketKit.PROTO_TCP)
            if (tcpIp != null && tcpIp.version == 4) {
                val tcp = PacketKit.parseTcp(packet, tcpIp) ?: continue
                handleTcp(packet, tcpIp, tcp, output)
                continue
            }
            val udpIp = PacketKit.parseIp(packet, n, PacketKit.PROTO_UDP)
            if (udpIp != null) {
                val udp = PacketKit.parseUdp(packet, udpIp) ?: continue
                if (udp.dstPort != 53) continue        // TCP-only bonding
                if (udp.dataLength <= 0) continue
                val query = packet.copyOfRange(
                    udp.dataOffset, udp.dataOffset + udp.dataLength)
                val clientIpAddr = udpIp.src
                val clientPort = udp.srcPort
                val v6 = udpIp.version == 6
                pool.execute {
                    val answer = dnsForward(query) ?: return@execute
                    val reply = if (v6) {
                        PacketKit.buildIp6Udp(
                            PacketKit.ipToBytes(VIRTUAL_ADDR), clientIpAddr,
                            53, clientPort, answer)
                    } else {
                        PacketKit.buildIp4Udp(
                            PacketKit.ipToBytes(VIRTUAL_ADDR), clientIpAddr,
                            53, clientPort, answer)
                    }
                    synchronized(output) {
                        runCatching { output.write(reply) }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------ TCP

    private fun handleTcp(
        packet: ByteArray,
        ip: PacketKit.ParsedIp,
        tcp: PacketKit.ParsedTcp,
        output: FileOutputStream,
    ) {
        val dstText = ip.dst.joinToString(".")
        // our own virtual address is not a real destination
        if (dstText == VIRTUAL_ADDR) return
        val key = "${ip.src.joinToString(".")}:$tcp.srcPort>" +
            "$dstText:$tcp.dstPort"

        // ---- new connection: SYN
        if (tcp.flags and PacketKit.TCP_SYN != 0 &&
            tcp.flags and PacketKit.TCP_ACK == 0
        ) {
            val flow = Flow(
                clientIp = ip.src, clientPort = tcp.srcPort,
                dstIp = ip.dst, dstPort = tcp.dstPort,
                host = dstText,
                ourSeq = (rng.nextLong() and 0xFFFFFFFFL),
                clientSeq = (tcp.seq + 1) and 0xFFFFFFFFL,
            )
            flow.clientWindow = tcp.window
            flows[key] = flow
            // SYN-ACK toward the client app
            writeTcp(output, flow, PacketKit.TCP_SYN or PacketKit.TCP_ACK,
                ByteArray(0))
            flow.ourSeq = (flow.ourSeq + 1) and 0xFFFFFFFFL
            // open the bonded session (may take a moment; data queues
            // inside the member sockets once connected)
            pool.execute {
                val session = openUpstream(
                    flow.host, flow.dstPort,
                    onDownstream = { data -> deliverDownstream(output, flow, data) },
                    onRemoteClose = {
                        flow.remoteClosed = true
                        remoteClose(output, flow)
                    },
                )
                if (session == null) {
                    // no link could reach the bond server: refuse
                    writeTcp(output, flow, PacketKit.TCP_RST or PacketKit.TCP_ACK,
                        ByteArray(0))
                    flows.remove(key)
                } else {
                    flow.session = session
                }
            }
            return
        }

        val flow = flows[key] ?: run {
            // unknown flow (late retransmit after close): reset it
            val fake = Flow(ip.src, tcp.srcPort, ip.dst, tcp.dstPort, dstText,
                0, tcp.seq, null)
            if (tcp.flags and PacketKit.TCP_RST == 0) {
                writeTcp(output, fake, PacketKit.TCP_RST or PacketKit.TCP_ACK,
                    ByteArray(0))
            }
            return
        }

        if (tcp.flags and PacketKit.TCP_RST != 0) {
            flow.session?.close()
            flows.remove(key)
            return
        }

        // ---- client data: ACK it and forward into the bond
        if (tcp.dataLength > 0) {
            val payload = packet.copyOfRange(
                tcp.dataOffsetInPacket,
                tcp.dataOffsetInPacket + tcp.dataLength)
            val seqEnd = (tcp.seq + tcp.dataLength) and 0xFFFFFFFFL
            if (seqEnd == flow.clientSeq || tcp.seq == flow.clientSeq) {
                flow.clientSeq = seqEnd
                flow.session?.sendUp(payload)
            }
            // pure ACK of the data (even for out-of-order: simplified)
            writeTcp(output, flow, PacketKit.TCP_ACK, ByteArray(0))
        } else if (tcp.flags and PacketKit.TCP_ACK != 0) {
            // track what the client absorbed of our downstream data
            flow.clientAck = tcp.ack
            flow.clientWindow = tcp.window
            flushPendingDown(output, flow)
        }

        // ---- client half-close
        if (tcp.flags and PacketKit.TCP_FIN != 0) {
            flow.clientSeq = (flow.clientSeq + 1) and 0xFFFFFFFFL
            writeTcp(output, flow, PacketKit.TCP_ACK, ByteArray(0))
            flow.session?.sendFin()
        }
    }

    /** Downstream bytes from the bond: packetize into the tun, honoring
     *  the client's advertised window (pending bytes wait for ACKs). */
    private fun deliverDownstream(output: FileOutputStream, flow: Flow, data: ByteArray) {
        if (flow.finSent) return
        synchronized(flow) {
            flow.pendingDown += data
        }
        flushPendingDown(output, flow)
    }

    private fun flushPendingDown(output: FileOutputStream, flow: Flow) {
        val tunFd = tun ?: return
        while (true) {
            var chunk: ByteArray
            synchronized(flow) {
                val unacked = ((flow.ourSeq - flow.clientAck +
                    0x100000000L) % 0x100000000L).toInt()
                val room = flow.clientWindow - unacked
                if (room <= 0 || flow.pendingDown.isEmpty()) return
                chunk = flow.pendingDown.copyOfRange(
                    0, minOf(flow.pendingDown.size, room, 1400))
                flow.pendingDown = flow.pendingDown.copyOfRange(
                    chunk.size, flow.pendingDown.size)
            }
            writeTcp(output, flow, PacketKit.TCP_ACK or PacketKit.TCP_PSH, chunk)
            flow.ourSeq = (flow.ourSeq + chunk.size) and 0xFFFFFFFFL
        }
    }

    private fun remoteClose(output: FileOutputStream, flow: Flow) {
        // the bond server's destination closed: FIN toward the client
        if (!flow.finSent) {
            flow.finSent = true
            writeTcp(output, flow, PacketKit.TCP_FIN or PacketKit.TCP_ACK,
                ByteArray(0))
            flow.ourSeq = (flow.ourSeq + 1) and 0xFFFFFFFFL
        }
    }

    /** Write one TCP packet from the flow's "server side" back to the
     *  client app inside the tun. */
    private fun writeTcp(
        output: FileOutputStream,
        flow: Flow,
        flags: Int,
        payload: ByteArray,
    ) {
        val packet = PacketKit.buildIp4Tcp(
            src = flow.dstIp, dst = flow.clientIp,
            sport = flow.dstPort, dport = flow.clientPort,
            seq = flow.ourSeq, ack = flow.clientSeq,
            flags = flags, window = 65535, payload = payload)
        synchronized(output) {
            runCatching { output.write(packet) }
        }
    }

    // ------------------------------------------------------------------ DNS

    /** DNS over a protected UDP socket (bypasses our own tun). */
    private fun dnsForward(query: ByteArray): ByteArray? = runCatching {
        DatagramSocket().use { socket ->
            protect(socket)                    // keep DNS out of the tun
            socket.soTimeout = 4000
            val addr = InetAddress.getByName(DNS_UPSTREAM)
            socket.send(DatagramPacket(query, query.size, addr, 53))
            val buf = ByteArray(4096)
            val packet = DatagramPacket(buf, buf.size)
            socket.receive(packet)
            buf.copyOf(packet.length).takeIf { it.size >= 12 }
        }
    }.getOrNull()

    // ----------------------------------------------------------------- life

    override fun onDestroy() {
        stopping = true
        runCatching { reader?.interrupt() }
        runCatching { pool?.shutdownNow() }
        flows.values.forEach { f -> runCatching { f.session?.close() } }
        flows.clear()
        runCatching { engine?.stop() }
        runCatching { SamizdatManager.stop() }
        runCatching { tun?.close() }
        tun = null
        running = false
        Log.i(TAG, "bonding VPN down")
        super.onDestroy()
    }
}
