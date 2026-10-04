package app.nivyx.android.settings

enum class ResolverChoice(val label: String) {
    AUTO("Automatic (Cloudflare, Google, Quad9)"),
    CLOUDFLARE("Cloudflare"),
    GOOGLE("Google"),
    QUAD9("Quad9"),
    CUSTOM("Custom DoH URL"),
    SYSTEM("System DNS (no encryption)"),
}

enum class Ipv6Setting(val label: String, val wire: String) {
    AUTO("Automatic", "auto"),
    ON("Always", "on"),
    OFF("Never", "off"),
}

data class Settings(
    val autoStartOnLaunch: Boolean = false,
    val startOnBoot: Boolean = false,
    val resolver: ResolverChoice = ResolverChoice.AUTO,
    val customDohUrl: String = "",
    val customBootstrap: String = "",
    val ipv6: Ipv6Setting = Ipv6Setting.AUTO,
    val quicFallback: Boolean = true,
    val tlsRecTcp: Boolean = false,
    val verboseHosts: Boolean = false,
    val debugLogs: Boolean = false,
    val manualRules: String = "",
    val excludedPackages: Set<String> = emptySet(),
    /** The user's last explicit intent. Lets the service resume after the OS restarts the process. */
    val desiredActive: Boolean = false,
)
