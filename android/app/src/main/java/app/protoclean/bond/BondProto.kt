package app.protoclean.bond

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * The Proto Clean Bond (PCB) wire protocol — Kotlin twin of
 * proto_clean/vpn/bondproto.py. Byte-for-byte compatible: an Android
 * client bonds into a bond server run by the desktop app
 * (`python3 -m proto_clean.bondserver`), and vice versa.
 *
 * Frame layout (14-byte header, big endian):
 *   "PCB" | ver | type | flags | seq:u32 | len:u16 | payload
 */
object BondProto {

    const val VERSION = 1

    const val FRAME_HANDSHAKE = 0x01
    const val FRAME_DATA = 0x02
    const val FRAME_FIN = 0x03
    const val FRAME_PING = 0x04
    const val FRAME_PONG = 0x05
    const val FRAME_MEMBER_DOWN = 0x06

    const val ATYP_IPV4 = 0x01
    const val ATYP_DOMAIN = 0x03
    const val ATYP_IPV6 = 0x04

    const val MAX_CHUNK = 16 * 1024

    private val MAGIC = byteArrayOf(0x50, 0x43, 0x42)   // "PCB"
    private val rng = SecureRandom()

    data class Frame(val type: Int, val seq: Long, val payload: ByteArray)

    class ProtocolException(msg: String) : Exception(msg)

    // ------------------------------------------------------------- framing

    fun packFrame(type: Int, seq: Long, payload: ByteArray = ByteArray(0)): ByteArray {
        require(payload.size <= 0xFFFF) { "payload too large" }
        require(seq in 0..0xFFFFFFFFL) { "seq out of range" }
        val out = ByteArray(14 + payload.size)
        out[0] = MAGIC[0]; out[1] = MAGIC[1]; out[2] = MAGIC[2]
        out[3] = VERSION.toByte()
        out[4] = type.toByte()
        out[5] = 0                                    // flags
        out[6] = ((seq ushr 24) and 0xFF).toByte()
        out[7] = ((seq ushr 16) and 0xFF).toByte()
        out[8] = ((seq ushr 8) and 0xFF).toByte()
        out[9] = (seq and 0xFF).toByte()
        out[10] = ((payload.size shr 8) and 0xFF).toByte()
        out[11] = (payload.size and 0xFF).toByte()
        payload.copyInto(out, 14)
        return out
    }

    /** Incremental frame parser — feed raw socket bytes, receive frames. */
    class FrameReader {
        private var buf = ByteArray(0)

        fun feed(data: ByteArray): MutableList<Frame> {
            buf += data
            val out = mutableListOf<Frame>()
            while (true) {
                if (buf.size < 14) return out
                if (buf[0] != MAGIC[0] || buf[1] != MAGIC[1] || buf[2] != MAGIC[2]) {
                    throw ProtocolException("bad frame magic")
                }
                if ((buf[3].toInt() and 0xFF) != VERSION) {
                    throw ProtocolException("unsupported version ${buf[3]}")
                }
                val type = buf[4].toInt() and 0xFF
                val len = ((buf[10].toInt() and 0xFF) shl 8) or
                        (buf[11].toInt() and 0xFF)
                if (buf.size < 14 + len) return out
                val seq = ((buf[6].toLong() and 0xFF) shl 24) or
                        ((buf[7].toLong() and 0xFF) shl 16) or
                        ((buf[8].toLong() and 0xFF) shl 8) or
                        (buf[9].toLong() and 0xFF)
                val payload = buf.copyOfRange(14, 14 + len)
                buf = buf.copyOfRange(14 + len, buf.size)
                out.add(Frame(type, seq, payload))
            }
        }
    }

    // ------------------------------------------------------------ addresses

    fun packAddress(host: String, port: Int): ByteArray {
        require(port in 1..65535) { "port out of range" }
        // IPv4 literal?
        val parts = host.split(".")
        if (parts.size == 4 && parts.all { (it.toIntOrNull() ?: -1) in 0..255 }) {
            val out = ByteArray(1 + 4 + 2)
            out[0] = ATYP_IPV4.toByte()
            parts.forEachIndexed { i, s -> out[1 + i] = s.toInt().toByte() }
            out[5] = ((port shr 8) and 0xFF).toByte()
            out[6] = (port and 0xFF).toByte()
            return out
        }
        val raw = host.toByteArray(Charsets.US_ASCII)
        require(raw.isNotEmpty() && raw.size <= 255) { "bad host" }
        val out = ByteArray(1 + 1 + raw.size + 2)
        out[0] = ATYP_DOMAIN.toByte()
        out[1] = raw.size.toByte()
        raw.copyInto(out, 2)
        out[2 + raw.size] = ((port shr 8) and 0xFF).toByte()
        out[3 + raw.size] = (port and 0xFF).toByte()
        return out
    }

    // ------------------------------------------------------------ handshake

    fun newSessionId(): ByteArray =
        ByteArray(16).also { rng.nextBytes(it) }

    fun authDigest(token: String, sessionId: ByteArray): ByteArray {
        if (token.isEmpty()) return ByteArray(32)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(token.toByteArray(Charsets.UTF_8))
        md.update(sessionId)
        return md.digest()
    }

    fun packHandshake(
        token: String, sessionId: ByteArray, memberIndex: Int,
        memberCount: Int, destHost: String, destPort: Int,
    ): ByteArray {
        require(sessionId.size == 16) { "session id must be 16 bytes" }
        require(memberIndex in 0 until memberCount) { "bad member index" }
        val addr = packAddress(destHost, destPort)
        val out = ByteArray(32 + 16 + 4 + addr.size)
        authDigest(token, sessionId).copyInto(out, 0)
        sessionId.copyInto(out, 32)
        out[48] = ((memberIndex shr 8) and 0xFF).toByte()
        out[49] = (memberIndex and 0xFF).toByte()
        out[50] = ((memberCount shr 8) and 0xFF).toByte()
        out[51] = (memberCount and 0xFF).toByte()
        addr.copyInto(out, 52)
        return out
    }

    // ------------------------------------------------------------ reassembly

    /** In-order chunk reassembly for one direction (sequence-based, so
     *  re-ordering across adapters is free). */
    class Reassembler {
        private var next = 0L
        private val pending = HashMap<Long, ByteArray>()

        @Synchronized
        fun feed(seq: Long, payload: ByteArray): List<ByteArray> {
            if (seq < next) return emptyList()      // stale duplicate
            if (seq > next && pending.size > 4096) {
                throw ProtocolException("reassembly window exceeded")
            }
            pending[seq] = payload
            val out = mutableListOf<ByteArray>()
            while (pending.containsKey(next)) {
                out.add(pending.remove(next)!!)
                next++
            }
            return out
        }
    }

    // -------------------------------------------------------------- scheduler

    /** Smooth weighted round-robin over live members (nginx-style);
     *  dead members are skipped and their share redistributed. */
    class WeightedScheduler(weights: IntArray) {
        private val w = weights.map { maxOf(1, it) }.toIntArray()
        private val dead = BooleanArray(w.size)
        private val current = IntArray(w.size)

        @Synchronized
        fun markDead(index: Int) {
            if (index in dead.indices) {
                dead[index] = true
                current[index] = 0
            }
        }

        @Synchronized
        fun revive(index: Int) {
            if (index in dead.indices) dead[index] = false
        }

        fun liveIndices(): List<Int> =
            dead.indices.filter { !dead[it] }

        @Synchronized
        fun next(): Int {
            val live = liveIndices()
            if (live.isEmpty()) throw ProtocolException("all links down")
            val total = live.sumOf { w[it] }
            var best = live[0]
            for (i in live) {
                current[i] += w[i]
                if (current[i] > current[best]) best = i
            }
            current[best] -= total
            return best
        }
    }

    fun chunkData(data: ByteArray, maxChunk: Int = MAX_CHUNK): List<ByteArray> {
        if (data.isEmpty()) return emptyList()
        val size = if (maxChunk < 1) MAX_CHUNK else maxChunk
        return (0 until data.size step size).map {
            data.copyOfRange(it, minOf(it + size, data.size))
        }
    }
}
