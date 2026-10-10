package app.nivyx.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.PendingIntentCompat
import app.nivyx.android.MainActivity
import app.nivyx.android.R

object Notifications {
    const val CHANNEL_ID = "protection"
    const val NOTIFICATION_ID = 1
    private const val BRAND_COLOR = 0xFF10B981.toInt()

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return // channels do not exist before Android 8
        val nm = androidx.core.content.ContextCompat.getSystemService(context, NotificationManager::class.java)!!
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            val channel = NotificationChannel(CHANNEL_ID, "Protection status", NotificationManager.IMPORTANCE_LOW).apply {
                description = "Shown while Nivyx is active. Android labels it a VPN; no remote server is used."
                setShowBadge(false)
            }
            nm.createNotificationChannel(channel)
        }
    }

    fun build(context: Context, text: String): Notification {
        val open = PendingIntentCompat.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT,
            false,
        )
        val stop = PendingIntentCompat.getService(
            context,
            1,
            Intent(context, NivyxVpnService::class.java).setAction(NivyxVpnService.ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT,
            false,
        )
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_nivyx)
            .setColor(BRAND_COLOR)
            .setContentTitle("Nivyx")
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .build()
    }

    fun update(context: Context, text: String) {
        androidx.core.content.ContextCompat.getSystemService(context, NotificationManager::class.java)!!.notify(NOTIFICATION_ID, build(context, text))
    }
}
