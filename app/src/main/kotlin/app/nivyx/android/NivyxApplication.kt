package app.nivyx.android

import android.app.Application
import android.net.VpnService
import android.util.Log

class NivyxApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // A fresh process never owns a TUN interface: the kernel closed any old one when the previous
        // process died, so there is no stale network state to clean up beyond our own in-memory holder.
        Log.i("nivyx", "process start; vpn consent ${if (VpnService.prepare(this) == null) "granted" else "pending"}")
    }
}
