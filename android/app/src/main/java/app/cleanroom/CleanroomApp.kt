package app.cleanroom

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import app.cleanroom.data.Blocklists
import app.cleanroom.data.ConfigCache
import app.cleanroom.data.SettingsStore

/**
 * Application singletons: settings (DataStore), blocklist manager, the
 * WireGuard config cache and the backend tunnel handle.
 */
class CleanroomApp : Application() {

    lateinit var settings: SettingsStore
        private set
    lateinit var blocklists: Blocklists
        private set
    lateinit var configCache: ConfigCache
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this
        settings = SettingsStore(this)
        blocklists = Blocklists(this, settings)
        configCache = ConfigCache(this)
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_VPN, getString(R.string.notif_channel_vpn),
                NotificationManager.IMPORTANCE_LOW
            )
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_DNS, getString(R.string.notif_channel_dns),
                NotificationManager.IMPORTANCE_LOW
            )
        )
    }

    companion object {
        lateinit var instance: CleanroomApp
            private set

        const val CHANNEL_VPN = "cleanroom-vpn"
        const val CHANNEL_DNS = "cleanroom-dns"
    }
}
