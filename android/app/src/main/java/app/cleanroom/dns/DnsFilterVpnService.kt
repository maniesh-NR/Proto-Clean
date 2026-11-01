package app.cleanroom.dns

import android.app.Notification
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import app.cleanroom.CleanroomApp
import app.cleanroom.data.DomainFilter
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Standalone DNS-filtering VPN — the Android "ad-blocker" mode.
 *
 * Android allows one VpnService per app, so local blocklist filtering
 * cannot ride along inside the GoBackend WireGuard tunnel (its tun fd is
 * consumed by wireguard-go; there is no packet hook). This service takes
 * the other slot in the architecture: it establishes a DNS-only VPN
 *
 *   * one virtual address (10.111.222.33/32) which is also the DNS server,
 *   * a /32 route for it, so *only* DNS traffic enters the tun,
 *
 * and then answers every UDP/53 query itself: blocked names (suffix match
 * against the configured blocklists) get NXDOMAIN or 0.0.0.0; everything
 * else is forwarded over DNS-over-HTTPS (https://1.1.1.1/dns-query — no
 * bootstrap needed, pinned by IP) with a plain-UDP fallback, and the reply
 * is re-enveloped and written back to the tun.
 *
 * The UI runs this when the WireGuard tunnel is DOWN (mutually exclusive —
 * Android revokes the previous VPN), giving free-plan users NetShield-style
 * blocking on any network. While the tunnel is UP, DNS goes through
 * Proton's in-tunnel resolver (10.2.0.1), which is set by the tunnel
 * config.
 */
class DnsFilterVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    @Volatile
    private var stopping = false
    private lateinit var pool: ExecutorService

    private val http = OkHttpClient.Builder().build()

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
        val filter = DomainFilterHolder.filter
        if (filter == null) {
            Log.w(TAG, "no filter loaded — stopping")
            stopSelf()
            return START_NOT_STICKY
        }
        if (prepare(this) != null) {
            Log.w(TAG, "VPN consent missing — stopping")
            stopSelf()
            return START_NOT_STICKY
        }
        startTun(filter)
        return START_STICKY
    }

    private fun startInForeground() {
        val notification: Notification =
            androidx.core.app.NotificationCompat.Builder(this, CleanroomApp.CHANNEL_DNS)
                .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
                .setContentTitle(getText(app.cleanroom.R.string.notif_dns_title))
                .setContentText(getText(app.cleanroom.R.string.notif_dns_text))
                .setOngoing(true)
                .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID, notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    // ------------------------------------------------------------------ tun

    private fun startTun(filter: DomainFilter) {
        stopping = false
        pool = Executors.newFixedThreadPool(6)
        val builder = Builder()
            .setSession("Cleanroom ad-blocker")
            .addAddress(VIRTUAL_DNS, 32)
            .addDnsServer(VIRTUAL_DNS)
            .addRoute(VIRTUAL_DNS, 32)     // only DNS enters the tun
            .setBlocking(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        tun = builder.establish() ?: run {
            Log.w(TAG, "establish() failed")
            stopSelf()
            return
        }
        Log.i(TAG, "DNS-filter VPN up (${filter.size} blocked domains)")
        reader = Thread({ tunLoop(filter) }, "cleanroom-dns-reader").also {
            it.isDaemon = true
            it.start()
        }
    }

    private fun tunLoop(filter: DomainFilter) {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        while (!stopping) {
            val n = try { input.read(buf) } catch (e: Exception) { break }
            if (n <= 0) continue
            val packet = buf.copyOf(n)
            val ip = PacketKit.parseIp(packet, n) ?: continue
            val udp = PacketKit.parseUdp(packet, ip) ?: continue
            if (udp.dstPort != 53) continue                       // only DNS is routed here
            if (udp.dataLength <= 0) continue
            val query = packet.copyOfRange(udp.dataOffset, udp.dataOffset + udp.dataLength)
            val client = ip.src
            val clientPort = udp.srcPort
            val v6 = ip.version == 6
            pool.execute {
                val answer = answer(query, filter)
                if (answer == null) return@execute
                val reply = if (v6) {
                    PacketKit.buildIp6Udp(
                        PacketKit.ipToBytes(VIRTUAL_DNS), client, 53, clientPort, answer)
                } else {
                    PacketKit.buildIp4Udp(
                        PacketKit.ipToBytes(VIRTUAL_DNS), client, 53, clientPort, answer)
                }
                synchronized(output) {
                    runCatching { output.write(reply) }
                }
            }
        }
    }

    /** Blocked → NXDOMAIN / 0.0.0.0; otherwise forward over DoH (or UDP). */
    private fun answer(query: ByteArray, filter: DomainFilter): ByteArray? {
        val name = PacketKit.parseQname(query)
        if (name != null && filter.blocked(name)) {
            blockedQueries++
            return if (DomainFilterHolder.nxdomain) PacketKit.nxdomain(query)
            else PacketKit.zeroAnswer(query)
        }
        val upstream = doh(query) ?: udp(query)
        return upstream
    }

    // ------------------------------------------------------------- upstream

    private fun doh(query: ByteArray): ByteArray? = runCatching {
        val req = Request.Builder()
            .url("https://$DOH_IP/dns-query")
            .post(query.toRequestBody("application/dns-message".toMediaType()))
            .header("Accept", "application/dns-message")
            .build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return@runCatching null
            resp.body?.bytes()?.takeIf { it.size >= 12 }
        }
    }.getOrNull()

    private fun udp(query: ByteArray): ByteArray? = runCatching {
        DatagramSocket().use { socket ->
            socket.soTimeout = 4000
            val addr = InetAddress.getByName(DOH_IP)
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
        runCatching { tun?.close() }
        tun = null
        running = false
        Log.i(TAG, "DNS-filter VPN down ($blockedQueries blocked so far)")
        super.onDestroy()
    }

    companion object {
        private const val TAG = "Cleanroom.DnsFilter"
        private const val NOTIF_ID = 42
        const val ACTION_STOP = "app.cleanroom.DNS_FILTER_STOP"

        /** Virtual address of the DNS server inside our own VPN. */
        const val VIRTUAL_DNS = "10.111.222.33"

        /** Pinned DoH resolver (IP-pinned: no bootstrap resolution needed). */
        const val DOH_IP = "1.1.1.1"

        @Volatile
        var running = false
            private set

        @Volatile
        var blockedQueries = 0L

        /** Set by the ViewModel before the service starts. */
        object DomainFilterHolder {
            @Volatile
            var filter: DomainFilter? = null

            @Volatile
            var nxdomain: Boolean = true
        }

        fun start(context: android.content.Context) {
            val intent = Intent(context, DnsFilterVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: android.content.Context) {
            context.startService(
                Intent(context, DnsFilterVpnService::class.java)
                    .setAction(ACTION_STOP))
        }
    }
}
