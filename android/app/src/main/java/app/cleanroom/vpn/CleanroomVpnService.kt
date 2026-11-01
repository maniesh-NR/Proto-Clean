package app.cleanroom.vpn

import android.app.Notification
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.util.Log
import app.cleanroom.CleanroomApp
import com.wireguard.android.backend.GoBackend

/**
 * The app's VpnService: a subclass of GoBackend.VpnService so the backend's
 * static future completes with OUR instance before any tunnel goes up
 * (GoBackend only starts its own inner service when none is running yet).
 *
 * GoBackend applies, from the config we build in TunnelManager:
 *   * the tunnel address + AllowedIPs routes,
 *   * DNS = 10.2.0.1 (Proton's in-tunnel resolver),
 *   * excludedApplications → VpnService.addDisallowedApplication (native
 *     per-app split tunneling on Android),
 *   * single-peer default-route configs get safe "block everything not in
 *     the tunnel" behaviour — the platform kill switch.
 */
class CleanroomVpnService : GoBackend.VpnService() {

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "vpn service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startInForeground()
        return super.onStartCommand(intent, flags, startId)
    }

    private fun startInForeground() {
        val notification: Notification =
            androidx.core.app.NotificationCompat.Builder(this, CleanroomApp.CHANNEL_VPN)
                .setSmallIcon(android.R.drawable.stat_sys_vpn_ic_notification)
                .setContentTitle(getText(app.cleanroom.R.string.notif_vpn_title))
                .setContentText("WireGuard tunnel active")
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

    override fun onRevoke() {
        // system revoked the VPN (another VPN started / always-on toggled)
        TunnelManager.onRevoked(this)
        super.onRevoke()
    }

    companion object {
        private const val TAG = "CleanroomVpn"
        private const val NOTIF_ID = 41
    }
}
