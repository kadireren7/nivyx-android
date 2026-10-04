package app.nivyx.android.update

/** Semantic version with pre-release ordering (SemVer 2.0 §11). Build metadata is ignored. */
data class Version(val major: Int, val minor: Int, val patch: Int, val pre: List<String> = emptyList()) : Comparable<Version> {
    val isStable: Boolean get() = pre.isEmpty()

    override fun toString(): String = "$major.$minor.$patch" + if (pre.isEmpty()) "" else "-" + pre.joinToString(".")

    override fun compareTo(other: Version): Int {
        compareValuesBy(this, other, { it.major }, { it.minor }, { it.patch }).let { if (it != 0) return it }
        if (pre.isEmpty() && other.pre.isEmpty()) return 0
        if (pre.isEmpty()) return 1 // a release is newer than any of its pre-releases
        if (other.pre.isEmpty()) return -1
        for (i in 0 until minOf(pre.size, other.pre.size)) {
            val a = pre[i]
            val b = other.pre[i]
            val an = a.toLongOrNull()
            val bn = b.toLongOrNull()
            val c = when {
                an != null && bn != null -> an.compareTo(bn)
                an != null -> -1 // numeric identifiers sort before alphanumeric ones
                bn != null -> 1
                else -> a.compareTo(b)
            }
            if (c != 0) return c
        }
        return pre.size.compareTo(other.pre.size)
    }

    companion object {
        private val pattern =
            Regex("""^v?(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$""")

        fun parse(text: String): Version? {
            val m = pattern.matchEntire(text.trim()) ?: return null
            val pre = m.groupValues[4].takeIf { it.isNotEmpty() }?.split('.') ?: emptyList()
            return Version(m.groupValues[1].toInt(), m.groupValues[2].toInt(), m.groupValues[3].toInt(), pre)
        }
    }
}
