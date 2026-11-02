package app.protoclean

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import app.protoclean.data.Blocklists
import app.protoclean.data.ConfigCache
import app.protoclean.data.SettingsStore

/**
 * Application singletons: settings (DataStore), blocklist manager, the
 * WireGuard config cache and the backend tunnel handle.
 */
class ProtoCleanApp : Application() {

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
        lateinit var instance: ProtoCleanApp
            private set

        const val CHANNEL_VPN = "proto-clean"
        const val CHANNEL_DNS = "proto-clean-dns"
    }
}
