package app.nivyx.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import app.nivyx.android.settings.SettingsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/** Starts protection after boot, only if the user enabled it and VPN consent was already given. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val pending = goAsync()
        CoroutineScope(Dispatchers.Default).launch {
            try {
                val settings = SettingsRepository(context).current()
                if (settings.startOnBoot && VpnService.prepare(context) == null) {
                    NivyxVpnService.start(context)
                }
            } catch (e: Exception) {
                Log.w("nivyx", "boot start skipped: ${e.javaClass.simpleName}")
            } finally {
                pending.finish()
            }
        }
    }
}
