package app.nivyx.android.core

/**
 * Computes the routes sent into the tunnel.
 *
 * Everything except private, link-local, loopback, CGNAT and multicast space is routed into the TUN.
 * Keeping those ranges out means LAN traffic, mDNS/Bonjour and casting never touch Nivyx, which is
 * both faster and avoids breaking local-network features.
 */
object RouteCalculator {
    data class Cidr(val address: String, val prefix: Int)

    const val IPV6_ROUTE = "2000::/3"

    /** Address ranges that stay outside the tunnel (CIDR notation). */
    val excludedV4: List<String> = listOf(
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
    )

    private const val MAX_V4 = 0xFFFF_FFFFL

    fun publicIpv4(): List<Cidr> {
        val excluded = excludedV4.map(::toRange).sortedBy { it.first }
        val out = mutableListOf<Cidr>()
        var cursor = 0L
        for ((start, end) in excluded) {
            if (start > cursor) out += rangeToCidrs(cursor, start - 1)
            cursor = maxOf(cursor, end + 1)
        }
        if (cursor <= MAX_V4) out += rangeToCidrs(cursor, MAX_V4)
        return out
    }

    internal fun toRange(cidr: String): Pair<Long, Long> {
        val (addr, prefixText) = cidr.split('/')
        val prefix = prefixText.toInt()
        val base = addr.split('.').fold(0L) { acc, part -> (acc shl 8) or part.toLong() }
        val size = 1L shl (32 - prefix)
        return base to (base + size - 1)
    }

    internal fun rangeToCidrs(startInput: Long, end: Long): List<Cidr> {
        val out = mutableListOf<Cidr>()
        var start = startInput
        while (start <= end) {
            // Largest aligned block that starts at `start` and does not pass `end`.
            var size = if (start == 0L) 1L shl 32 else start and -start
            while (start + size - 1 > end) size = size shr 1
            val prefix = 32 - java.lang.Long.numberOfTrailingZeros(size)
            out += Cidr(format(start), prefix)
            start += size
        }
        return out
    }

    private fun format(v: Long): String = "${(v shr 24) and 0xFF}.${(v shr 16) and 0xFF}.${(v shr 8) and 0xFF}.${v and 0xFF}"
}
