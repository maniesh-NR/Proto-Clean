package app.protonclean

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import app.protonclean.data.Blocklists
import app.protonclean.data.ConfigCache
import app.protonclean.data.SettingsStore

/**
 * Application singletons: settings (DataStore), blocklist manager, the
 * WireGuard config cache and the backend tunnel handle.
 */
class ProtonCleanApp : Application() {

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
        lateinit var instance: ProtonCleanApp
            private set

        const val CHANNEL_VPN = "proton-clean"
        const val CHANNEL_DNS = "proton-clean-dns"
    }
}
