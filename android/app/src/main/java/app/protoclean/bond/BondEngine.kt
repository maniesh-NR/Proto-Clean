package app.protoclean.bond

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkRequest
import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** A forwarded stream, whatever carries it: bond members (desktop-
 *  compatible PCB) or the local lantern-box mixed inbound (samizdat). */
interface UpstreamSession {
    fun sendUp(data: ByteArray)
    fun sendFin()
    fun close()
}

/**
 * The bonding engine — the Speedify-style core of the Android client.
 *
 * For every TCP flow the BondVpnService hands it, the engine opens one
 * *member* socket per underlying network (Wi-Fi + cellular), each
 * bound to its network with [Network.bindSocket] and kept OUT of the
 * VPN tun with [android.net.VpnService.protect]. The stream is split
 * into sequenced PCB chunks and spread across the members with a
 * weighted scheduler; the bond server (the desktop app's
 * `python3 -m proto_clean.bondserver`) rejoins them.
 *
 * Both networks stay active simultaneously — that is the point: the
 * stream uses the combined bandwidth, and when one link drops the
 * survivors take over its share seamlessly.
 */
class BondEngine(
    private val vpnService: android.net.VpnService,
    serverHost: String,
    serverPort: Int,
    private val token: String,
    private val mode: String,                 // "bond" | "balance"
) {
    companion object {
        private const val TAG = "ProtoClean.Bond"
        private const val CONNECT_TIMEOUT_MS = 10_000
    }

    private val server = InetSocketAddress(serverHost, serverPort)
    private val cm = vpnService
        .getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val wifiNetwork = AtomicReferenceCompat<Network?>()
    private val cellNetwork = AtomicReferenceCompat<Network?>()
    private val callbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
    private val balanceRr = AtomicLong(0)

    /** Live adapters we can bond over right now. */
    private fun networks(): List<Network?> {
        val out = mutableListOf<Network?>()
        wifiNetwork.get()?.let { out.add(it) }
        cellNetwork.get()?.let { out.add(it) }
        if (out.isEmpty()) out.add(null)      // default-route fallback
        return out
    }

    // ------------------------------------------------------------- lifecycle

    /** Track Wi-Fi and cellular so both stay active at once. Call when
     *  the bonding VPN starts; [stop] releases the callbacks. */
    fun start() {
        try {
            val wifiCb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    wifiNetwork.set(network)
                    Log.i(TAG, "wi-fi network available for bonding")
                }

                override fun onLost(network: Network) {
                    if (wifiNetwork.get() == network) wifiNetwork.set(null)
                }
            }
            val cellCb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    cellNetwork.set(network)
                    Log.i(TAG, "cellular network available for bonding")
                }

                override fun onLost(network: Network) {
                    if (cellNetwork.get() == network) cellNetwork.set(null)
                }
            }
            val wifiReq = NetworkRequest.Builder()
                .addTransportType(android.net.NetworkCapabilities.TRANSPORT_WIFI)
                .build()
            val cellReq = NetworkRequest.Builder()
                .addTransportType(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)
                .build()
            cm.requestNetwork(wifiReq, wifiCb)
            cm.requestNetwork(cellReq, cellCb)
            callbacks.add(wifiCb)
            callbacks.add(cellCb)
        } catch (e: Exception) {
            Log.w(TAG, "network tracking failed: ${e.message}")
        }
    }

    fun stop() {
        callbacks.forEach { runCatching { cm.unregisterNetworkCallback(it) } }
        callbacks.clear()
        wifiNetwork.set(null)
        cellNetwork.set(null)
    }

    // --------------------------------------------------------------- session

    /** One bonded stream: member sockets + scheduler + reassembly. */
    inner class Session(
        val id: ByteArray,
        val onDownstream: (data: ByteArray) -> Unit,
        val onRemoteClose: () -> Unit,
    ) : UpstreamSession {
        val members = mutableListOf<Member>()
        private val upSched = BondProto.WeightedScheduler(intArrayOf(1, 1))
        private val downReasm = BondProto.Reassembler()
        private val upSeq = AtomicLong(0)
        @Volatile
        var closed = false
        @Volatile
        var clientFinSent = false

        val liveMembers: List<Member> get() = members.filter { it.alive }

        fun sendUp(data: ByteArray) {
            if (closed || liveMembers.isEmpty()) return
            for (chunk in BondProto.chunkData(data)) {
                var sent = false
                val live = liveMembers
                for (attempt in live.indices) {
                    val idx = try {
                        upSched.next()
                    } catch (e: BondProto.ProtocolException) {
                        return
                    }
                    if (idx >= members.size) continue
                    val member = members[idx]
                    if (!member.alive) continue
                    if (member.send(BondProto.packFrame(
                            BondProto.FRAME_DATA, upSeq.getAndIncrement(), chunk))
                    ) {
                        sent = true
                        break
                    }
                }
                if (!sent) return      // every link failed
            }
        }

        fun sendFin() {
            clientFinSent = true
            liveMembers.forEach {
                it.send(BondProto.packFrame(BondProto.FRAME_FIN, 0))
            }
        }

        fun close() {
            if (closed) return
            closed = true
            members.forEach { it.shutdown() }
        }

        /** Feed deframed member bytes: reassemble + deliver downstream. */
        internal fun onFrames(frames: List<BondProto.Frame>, from: Member): Boolean {
            for (f in frames) {
                when (f.type) {
                    BondProto.FRAME_DATA -> {
                        for (run in downReasm.feed(f.seq, f.payload)) {
                            from.downBytes.addAndGet(run.size.toLong())
                            onDownstream(run)
                        }
                    }
                    BondProto.FRAME_FIN -> {
                        onRemoteClose()
                        return false
                    }
                    BondProto.FRAME_PING -> {
                        from.send(BondProto.packFrame(
                            BondProto.FRAME_PONG, 0, f.payload))
                    }
                }
            }
            return true
        }
    }

    /** One adapter-bound member socket (labeled "wi-fi"/"cellular"/"default"). */
    inner class Member(
        val index: Int,
        val label: String,
        val socket: Socket,
    ) {
        @Volatile
        var alive = true
        val upBytes = AtomicLong(0)
        val downBytes = AtomicLong(0)
        private val out: OutputStream = socket.getOutputStream()
        private var reader: Thread? = null

        fun send(frame: ByteArray): Boolean {
            if (!alive) return false
            return try {
                synchronized(out) {
                    out.write(frame)
                    out.flush()
                }
                upBytes.addAndGet(frame.size.toLong())
                true
            } catch (e: Exception) {
                alive = false
                false
            }
        }

        fun startReading(session: Session) {
            reader = Thread({
                val input: InputStream = try {
                    socket.getInputStream()
                } catch (e: Exception) {
                    alive = false
                    return@Thread
                }
                val fr = BondProto.FrameReader()
                val buf = ByteArray(65536)
                try {
                    while (alive && !session.closed) {
                        val n = input.read(buf)
                        if (n < 0) break
                        if (n == 0) continue
                        val frames = fr.feed(buf.copyOf(n))
                        if (!session.onFrames(frames, this)) break
                    }
                } catch (e: Exception) {
                    // link loss is a normal event while bonding
                } finally {
                    alive = false
                    runCatching { socket.close() }
                }
            }, "bond-member-$label").also { it.isDaemon = true; it.start() }
        }

        fun shutdown() {
            alive = false
            runCatching { socket.close() }
            runCatching { reader?.interrupt() }
        }
    }

    /**
     * Open a bonded session to *destHost:destPort* across every live
     * network. Returns null when no adapter could reach the bond server.
     */
    fun connect(
        destHost: String,
        destPort: Int,
        onDownstream: (ByteArray) -> Unit,
        onRemoteClose: () -> Unit,
    ): Session? {
        val nets = if (mode == "balance") listOf(networks()[
            (balanceRr.getAndIncrement() % networks().size.toLong()).toInt()])
        else networks()
        val session = Session(BondProto.newSessionId(), onDownstream, onRemoteClose)
        nets.forEachIndexed { index, network ->
            val member = openMember(index, nets.size, network, session,
                destHost, destPort)
            if (member != null) {
                session.members.add(member)
                member.startReading(session)
            }
        }
        if (session.liveMembers().isEmpty()) {
            session.close()
            return null
        }
        Log.i(TAG, "session ${session.id.copyOf(4).joinToString("") {
            "%02x".format(it)
        }} -> $destHost:$destPort over ${session.members.size} link(s)")
        return session
    }

    private fun openMember(
        index: Int, count: Int, network: Network?, session: Session,
        destHost: String, destPort: Int,
    ): Member? {
        return try {
            val socket = Socket()
            // keep the member OUT of our own tun, then pin it to the
            // requested network so Wi-Fi and cellular run in parallel
            vpnService.protect(socket)
            network?.bindSocket(socket)
            socket.tcpNoDelay = true
            socket.connect(server, CONNECT_TIMEOUT_MS)
            val label = when (network) {
                wifiNetwork.get() -> "wi-fi"
                cellNetwork.get() -> "cellular"
                else -> "default"
            }
            val member = Member(index, label, socket)
            member.send(BondProto.packFrame(
                BondProto.FRAME_HANDSHAKE, 0,
                BondProto.packHandshake(
                    token, session.id, index, count, destHost, destPort)))
            member
        } catch (e: Exception) {
            Log.i(TAG, "member $index (${if (network == wifiNetwork.get())
                "wi-fi" else if (network == cellNetwork.get()) "cellular"
                else "default"}) connect failed: ${e.message}")
            null
        }
    }

    /** Per-link stats for the notification / UI (label -> up/down bytes). */
    fun stats(): Map<String, Pair<Long, Long>> {
        val out = HashMap<String, Pair<Long, Long>>()
        // aggregated by label across sessions would need tracking; the
        // service reads member stats through its own flow table instead.
        return out
    }
}

/** Tiny AtomicReference shim (API 21+ has java.util.concurrent.atomic
 *  AtomicReference; this just keeps the imports readable). */
private class AtomicReferenceCompat<T : Any?> {
    @Volatile
    private var value: T? = null
    fun get(): T? = value
    fun set(v: T?) {
        value = v
    }
}
