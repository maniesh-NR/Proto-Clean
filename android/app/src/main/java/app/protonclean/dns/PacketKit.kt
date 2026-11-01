package app.protonclean.dns

import java.net.InetAddress

/**
 * Minimal IPv4/IPv6/UDP packet construction and parsing plus DNS helpers —
 * just enough for a DNS-filtering VpnService: we read DNS queries aimed at
 * our virtual DNS address and inject replies back into the tun.
 *
 * (Network byte order = big endian everywhere.)
 */
object PacketKit {

    const val PROTO_UDP = 17

    data class ParsedIp(
        val version: Int,
        val src: ByteArray,      // 4 or 16 bytes
        val dst: ByteArray,
        val protocol: Int,
        val payloadOffset: Int,
        val payloadLength: Int,
    )

    data class ParsedUdp(
        val srcPort: Int,
        val dstPort: Int,
        val dataOffset: Int,     // offset of the DNS payload inside the packet
        val dataLength: Int,
    )

    // -------------------------------------------------------------- parsing

    fun parseIp(packet: ByteArray, length: Int): ParsedIp? {
        if (length < 28) return null
        return when (packet[0].toInt() ushr 4) {
            4 -> {
                val ihl = (packet[0].toInt() and 0x0F) * 4
                if (ihl < 20 || length < ihl) return null
                val totalLen = ((packet[2].toInt() and 0xFF) shl 8) or
                    (packet[3].toInt() and 0xFF)
                val proto = packet[9].toInt() and 0xFF
                if (proto != PROTO_UDP) return null
                ParsedIp(
                    version = 4,
                    src = packet.copyOfRange(12, 16),
                    dst = packet.copyOfRange(16, 20),
                    protocol = proto,
                    payloadOffset = ihl,
                    payloadLength = minOf(totalLen, length) - ihl,
                )
            }
            6 -> {
                if (length < 48) return null
                val next = packet[6].toInt() and 0xFF
                if (next != PROTO_UDP) return null   // no extension headers expected for DNS
                ParsedIp(
                    version = 6,
                    src = packet.copyOfRange(8, 24),
                    dst = packet.copyOfRange(24, 40),
                    protocol = next,
                    payloadOffset = 40,
                    payloadLength = length - 40,
                )
            }
            else -> null
        }
    }

    fun parseUdp(packet: ByteArray, ip: ParsedIp): ParsedUdp? {
        val off = ip.payloadOffset
        if (ip.payloadLength < 8) return null
        val sport = ((packet[off].toInt() and 0xFF) shl 8) or (packet[off + 1].toInt() and 0xFF)
        val dport = ((packet[off + 2].toInt() and 0xFF) shl 8) or (packet[off + 3].toInt() and 0xFF)
        return ParsedUdp(
            srcPort = sport,
            dstPort = dport,
            dataOffset = off + 8,
            dataLength = ip.payloadLength - 8,
        )
    }

    // ------------------------------------------------------------ building

    /** UDP/IPv4 packet (header checksum computed, UDP checksum 0 = legal). */
    fun buildIp4Udp(src: ByteArray, dst: ByteArray,
                    sport: Int, dport: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val out = ByteArray(total)
        // IPv4 header
        out[0] = 0x45
        out[1] = 0
        out[2] = ((total shr 8) and 0xFF).toByte()
        out[3] = (total and 0xFF).toByte()
        out[4] = 0; out[5] = 0                       // id
        out[6] = 0x40                                // don't fragment
        out[7] = 0
        out[8] = 64                                  // ttl
        out[9] = PROTO_UDP.toByte()
        // checksum filled below
        System.arraycopy(src, 0, out, 12, 4)
        System.arraycopy(dst, 0, out, 16, 4)
        val checksum = headerChecksum(out, 0, 20)
        out[10] = ((checksum shr 8) and 0xFF).toByte()
        out[11] = (checksum and 0xFF).toByte()
        // UDP header
        out[20] = ((sport shr 8) and 0xFF).toByte()
        out[21] = (sport and 0xFF).toByte()
        out[22] = ((dport shr 8) and 0xFF).toByte()
        out[23] = (dport and 0xFF).toByte()
        out[24] = ((udpLen shr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0; out[27] = 0                     // checksum 0 (optional for IPv4)
        System.arraycopy(payload, 0, out, 28, payload.size)
        return out
    }

    /** UDP/IPv6 packet — UDP checksum is mandatory, computed properly. */
    fun buildIp6Udp(src: ByteArray, dst: ByteArray,
                    sport: Int, dport: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val out = ByteArray(40 + udpLen)
        out[0] = 0x60
        out[4] = ((udpLen shr 8) and 0xFF).toByte()
        out[5] = (udpLen and 0xFF).toByte()
        out[6] = PROTO_UDP.toByte()
        out[7] = 64                                  // hop limit
        System.arraycopy(src, 0, out, 8, 16)
        System.arraycopy(dst, 0, out, 24, 16)
        out[40] = ((sport shr 8) and 0xFF).toByte()
        out[41] = (sport and 0xFF).toByte()
        out[42] = ((dport shr 8) and 0xFF).toByte()
        out[43] = (dport and 0xFF).toByte()
        out[44] = ((udpLen shr 8) and 0xFF).toByte()
        out[45] = (udpLen and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 48, payload.size)
        var csum = pseudoHeaderChecksum6(src, dst, udpLen) +
            transportChecksum(out, 40, udpLen)
        csum = (csum and 0xFFFF) + (csum ushr 16)
        csum = (csum and 0xFFFF) + (csum ushr 16)
        val finalSum = (csum.inv()) and 0xFFFF
        val stored = if (finalSum == 0) 0xFFFF else finalSum
        out[46] = ((stored shr 8) and 0xFF).toByte()
        out[47] = (stored and 0xFF).toByte()
        return out
    }

    // ------------------------------------------------------------ checksums

    private fun headerChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        var n = length
        while (n > 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum = (sum and 0xFFFF) + (sum ushr 16)
            i += 2
            n -= 2
        }
        if (n == 1) {
            sum += (buf[i].toInt() and 0xFF) shl 8
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv()) and 0xFFFF
    }

    private fun pseudoHeaderChecksum6(src: ByteArray, dst: ByteArray, length: Int): Int {
        var sum = 0
        fun addWord(b: ByteArray, off: Int) {
            sum += ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        for (i in src.indices step 2) addWord(src, i)
        for (i in dst.indices step 2) addWord(dst, i)
        sum += length
        sum += PROTO_UDP
        sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum
    }

    private fun transportChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        var n = length
        while (n > 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum = (sum and 0xFFFF) + (sum ushr 16)
            i += 2
            n -= 2
        }
        if (n == 1) {
            sum += (buf[i].toInt() and 0xFF) shl 8
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum
    }

    // ----------------------------------------------------------------- DNS

    /** First question's QNAME, lowercase (no DNS library needed). */
    fun parseQname(wire: ByteArray): String? {
        if (wire.size < 12) return null
        var pos = 12
        val labels = ArrayList<String>()
        while (pos < wire.size) {
            val len = wire[pos].toInt() and 0xFF
            if (len == 0) {
                pos++
                break
            }
            if (len and 0xC0 != 0) return null        // compression pointer — give up
            if (pos + 1 + len > wire.size) return null
            labels.add(String(wire, pos + 1, len, Charsets.US_ASCII))
            pos += 1 + len
            if (labels.size > 8) return null
        }
        return if (labels.isEmpty()) null else labels.joinToString(".")
    }

    /** NXDOMAIN (rcode 3) response echoing the question. */
    fun nxdomain(query: ByteArray): ByteArray {
        val qEnd = questionEnd(query) ?: return blockedByDefault(query)
        val header = query.copyOfRange(0, 12)
        header[2] = 0x81.toInt().toByte()            // QR=1, opcode 0, RD=1
        header[3] = 0x83.toInt().toByte()            // RA=1, rcode=3 (NXDOMAIN)
        return header + query.copyOfRange(12, qEnd)
    }

    /** NOERROR response with a single 0.0.0.0 A record (TTL 60). */
    fun zeroAnswer(query: ByteArray): ByteArray {
        val qEnd = questionEnd(query) ?: return blockedByDefault(query)
        val header = query.copyOfRange(0, 12)
        header[2] = 0x81.toByte()
        header[3] = 0x80.toByte()                    // RA=1, rcode 0
        header[6] = 0; header[7] = 1                 // one answer
        val answer = byteArrayOf(
            0xC0.toByte(), 0x0C.toByte(),            // name pointer to question
            0x00, 0x01,                              // type A
            0x00, 0x01,                              // class IN
            0x00, 0x00, 0x00, 60.toByte(),           // ttl 60
            0x00, 0x04,                              // rdlength 4
            0x00, 0x00, 0x00, 0x00,                  // 0.0.0.0
        )
        return header + query.copyOfRange(12, qEnd) + answer
    }

    private fun blockedByDefault(query: ByteArray): ByteArray {
        // cannot locate the question end (malformed) — refuse with NXDOMAIN flags
        return query.copyOf().also {
            if (it.size >= 4) {
                it[2] = 0x81.toByte()
                it[3] = 0x83.toByte()
            }
        }
    }

    /** Offset just past the first question (walks the labels). */
    private fun questionEnd(wire: ByteArray): Int? {
        if (wire.size < 12) return null
        var pos = 12
        while (pos < wire.size) {
            val len = wire[pos].toInt() and 0xFF
            if (len == 0) return pos + 1
            if (len and 0xC0 != 0) return null
            pos += 1 + len
            if (pos > wire.size) return null
        }
        return null
    }

    fun ipToBytes(ip: String): ByteArray = InetAddress.getByName(ip).address
}
