package app.protonclean.vpn

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * NAT-PMP client (RFC 6886) — Kotlin port of the desktop implementation.
 *
 * Talks to the VPN-side gateway (10.2.0.1) on UDP/5351 once the tunnel is
 * up, requests a UDP mapping and keeps the lease alive. Proton grants short
 * leases (~60s), so the keeper refreshes at ~75% of the granted lifetime
 * (45s for a 60s lease) — matching Proton's own manual-setup docs. Paid
 * plans only; free plans get result code 2 (not authorized).
 */
object NatPmp {

    private const val GATEWAY = "10.2.0.1"
    private const val PORT = 5351
    private const val REQUEST_LIFETIME = 7200
    private const val OP_MAP_UDP = 1

    class NatPmpException(message: String) : Exception(message)

    private val RESULT_TEXT = mapOf(
        1 to "unsupported protocol version",
        2 to "not authorized / refused (port forwarding is a paid-plan feature)",
        3 to "network failure",
        4 to "out of resources",
        5 to "unsupported opcode",
    )

    data class Mapping(val internalPort: Int, val externalPort: Int, val lifetimeSec: Int)

    private fun buildMapRequest(internalPort: Int, externalPort: Int = 0): ByteArray =
        ByteBuffer.allocate(12).apply {
            put(0)                       // version
            put(OP_MAP_UDP.toByte())     // opcode
            putShort(0)                  // reserved
            putShort((internalPort and 0xFFFF).toShort())
            putShort((externalPort and 0xFFFF).toShort())
            putInt(REQUEST_LIFETIME)
        }.array()

    private fun parseResponse(data: ByteArray): Mapping {
        if (data.size < 16) throw NatPmpException("short NAT-PMP response")
        val buf = ByteBuffer.wrap(data)
        val ver = buf.get().toInt() and 0xFF
        val op = buf.get().toInt() and 0xFF
        val result = buf.short.toInt() and 0xFFFF
        @Suppress("UNUSED_VARIABLE") val epoch = buf.int
        val internal = buf.short.toInt() and 0xFFFF
        val external = buf.short.toInt() and 0xFFFF
        val lifetime = buf.int
        if (ver != 0 || op != (0x80 or OP_MAP_UDP)) {
            throw NatPmpException("malformed NAT-PMP response")
        }
        if (result != 0) {
            throw NatPmpException(RESULT_TEXT[result] ?: "NAT-PMP result code $result")
        }
        return Mapping(internal, external, lifetime)
    }

    fun mapOnce(internalPort: Int, timeoutMs: Int = 3000): Mapping {
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            val req = buildMapRequest(internalPort)
            socket.send(DatagramPacket(req, req.size, InetAddress.getByName(GATEWAY), PORT))
            val buf = ByteArray(64)
            val packet = DatagramPacket(buf, buf.size)
            socket.receive(packet)
            return parseResponse(buf.copyOf(packet.length))
        }
    }

    /**
     * Keep a mapping alive in a background coroutine; reports the external
     * port (or null) via [onUpdate] and stops on [onError].
     */
    class Forwarder(
        private val internalPort: Int,
        private val onUpdate: (Int?) -> Unit,
        private val onError: (String) -> Unit,
    ) {
        private var job: Job? = null

        fun start(scope: CoroutineScope) {
            if (job?.isActive == true) return
            job = scope.launch(Dispatchers.IO) {
                var first = true
                var internal = internalPort
                while (true) {
                    try {
                        val m = mapOnce(internal)
                        internal = m.internalPort
                        onUpdate(m.externalPort)
                        first = false
                        delay((maxOf(15.0, m.lifetimeSec * 0.75) * 1000).toLong())
                    } catch (e: Exception) {
                        if (first) { onError(e.message ?: "NAT-PMP failed"); return@launch }
                        delay(15_000)
                    }
                }
            }
        }

        fun stop() {
            job?.cancel()
            job = null
            onUpdate(null)
        }
    }
}
