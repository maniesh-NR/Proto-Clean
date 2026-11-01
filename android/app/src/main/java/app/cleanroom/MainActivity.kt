package app.cleanroom

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import app.cleanroom.ui.BlocklistsScreen
import app.cleanroom.ui.CleanroomTheme
import app.cleanroom.ui.LoginScreen
import app.cleanroom.ui.ServersScreen
import app.cleanroom.ui.SettingsScreen

class MainActivity : ComponentActivity() {

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            // user answered the system VPN consent dialog — nothing else to
            // do here; the next connect() call will pass the prepare() check
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CleanroomTheme {
                CleanroomApp(
                    onNeedConsent = { intent ->
                        intent?.let { vpnConsent.launch(it) }
                    },
                )
            }
        }
    }
}

@Composable
private fun CleanroomApp(onNeedConsent: (android.content.Intent?) -> Unit) {
    val vm: AppViewModel = viewModel()
    val nav = rememberNavController()
    val ui by vm.ui.collectAsState()
    val backStack by nav.currentBackStackEntryAsState()
    val current = backStack?.destination?.route

    // Launch the system VPN-consent dialog when a connect was blocked on it.
    LaunchedEffect(ui.vpnState, ui.detail) {
        if (ui.vpnState == AppViewModel.VpnState.CONNECTING &&
            ui.detail.contains("consent", ignoreCase = true)) {
            onNeedConsent(vm.prepareIntent())
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = current == "servers",
                    onClick = { nav.navigate("servers") { launchSingleTop = true } },
                    icon = { Icon(Icons.Default.Public, contentDescription = null) },
                    label = { Text("Servers") },
                )
                NavigationBarItem(
                    selected = current == "blocklists",
                    onClick = { nav.navigate("blocklists") { launchSingleTop = true } },
                    icon = { Icon(Icons.Default.Block, contentDescription = null) },
                    label = { Text("Blocklists") },
                )
                NavigationBarItem(
                    selected = current == "settings",
                    onClick = { nav.navigate("settings") { launchSingleTop = true } },
                    icon = { Icon(Icons.Default.Settings, contentDescription = null) },
                    label = { Text("Settings") },
                )
            }
        },
    ) { padding ->
        NavHost(
            navController = nav,
            startDestination = if (ui.loggedIn) "servers" else "login",
            modifier = Modifier.padding(padding),
        ) {
            composable("login") {
                LoginScreen(vm, onLoggedIn = {
                    nav.navigate("servers") { popUpTo("login") { inclusive = true } }
                })
            }
            composable("servers") {
                ServersScreen(vm, onNeedLogin = {
                    nav.navigate("login") { launchSingleTop = true }
                })
            }
            composable("blocklists") { BlocklistsScreen(vm) }
            composable("settings") { SettingsScreen(vm) }
        }
    }
}
