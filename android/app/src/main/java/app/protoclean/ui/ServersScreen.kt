package app.protoclean.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.protoclean.AppViewModel
import app.protoclean.proton.LogicalServer

/** Load colour chip: green <50, amber <90, red beyond (Proton's own bands). */
private fun loadColor(load: Float): Color = when {
    load >= 90f -> Color(0xFFE5484D)
    load >= 50f -> Color(0xFFE7A14C)
    else -> Color(0xFF46A758)
}

@Composable
fun ServersScreen(vm: AppViewModel, onNeedLogin: () -> Unit) {
    val ui by vm.ui.collectAsState()
    val servers by vm.servers.collectAsState()
    val settings by vm.settings.settings.collectAsState(initial = app.protoclean.data.AppSettings())

    Column(Modifier.fillMaxSize()) {
        // ---- status banner -------------------------------------------
        Surface(
            color = MaterialTheme.colorScheme.secondaryContainer,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(16.dp)) {
                val stateText = when (ui.vpnState) {
                    AppViewModel.VpnState.CONNECTED ->
                        "Connected · ${ui.currentServer?.name ?: ""}" +
                            (if (ui.viaCache) " · cached config" else "")
                    AppViewModel.VpnState.CONNECTING -> "Connecting… ${ui.detail}"
                    AppViewModel.VpnState.ERROR -> "Error: ${ui.detail}"
                    AppViewModel.VpnState.LOGGED_IN -> "Not connected"
                    AppViewModel.VpnState.LOGGED_OUT -> "Logged out"
                }
                Text(stateText, style = MaterialTheme.typography.titleMedium,
                     fontWeight = FontWeight.SemiBold)
                ui.stats?.let { st ->
                    if (st.up) {
                        Text(
                            "↓ ${fmtBytes(st.rx)}  ↑ ${fmtBytes(st.tx)}" +
                                (st.handshakeAgeSec?.let { "  ·  handshake ${it}s ago" } ?: ""),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                ui.externalPort?.let {
                    Text("NAT-PMP external port: $it",
                         style = MaterialTheme.typography.bodySmall)
                }
                if (ui.message.isNotBlank()) {
                    Text(
                        ui.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = when (ui.messageLevel) {
                            "error" -> MaterialTheme.colorScheme.error
                            "warn" -> Color(0xFFE7A14C)
                            else -> MaterialTheme.colorScheme.onSurface
                        },
                        modifier = Modifier.padding(top = 4.dp),
                    )
                }
                if (ui.lockdown) {
                    Text("System 'Block connections without VPN' is ON — kill switch armed",
                         style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // ---- top controls ---------------------------------------------
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            Text("Auto-connect fastest server", fontWeight = FontWeight.Medium,
                 modifier = Modifier.weight(1f))
            Switch(
                checked = settings.autoconnectFastest,
                onCheckedChange = {
                    vm.updateSettings { s -> s.copy(autoconnectFastest = it) }
                },
            )
        }
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(horizontal = 16.dp),
        ) {
            Button(
                onClick = {
                    if (!ui.loggedIn) onNeedLogin() else if (
                        ui.vpnState == AppViewModel.VpnState.CONNECTED ||
                        ui.vpnState == AppViewModel.VpnState.CONNECTING
                    ) vm.disconnect() else vm.connect()
                },
                modifier = Modifier.weight(1f),
            ) {
                Text(
                    when {
                        !ui.loggedIn -> "Log in to connect"
                        ui.vpnState == AppViewModel.VpnState.CONNECTED -> "Disconnect"
                        ui.vpnState == AppViewModel.VpnState.CONNECTING -> "Connecting…"
                        else -> if (settings.autoconnectFastest) "Connect (fastest free)"
                                else "Connect"
                    }
                )
            }
            OutlinedButton(onClick = { vm.refreshServers() }) { Text("Refresh") }
        }

        // ---- free server list ------------------------------------------
        if (servers.isEmpty()) {
            Column(
                Modifier.fillMaxSize().padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    if (ui.loggedIn) "No servers yet — tap Refresh"
                    else "Log in to see the free server list",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(vertical = 8.dp),
                modifier = Modifier.weight(1f),
            ) {
                items(servers, key = { it.id }) { server ->
                    ServerRow(
                        server = server,
                        selected = ui.currentServer?.id == server.id,
                        onClick = {
                            vm.updateSettings { it.copy(autoconnectFastest = false) }
                            vm.connect(server.id)
                        },
                    )
                    HorizontalDivider()
                }
            }
        }
        Text(
            "Free (tier-0) servers only — paid servers are excluded.",
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(8.dp).align(Alignment.CenterHorizontally),
        )
    }
}

@Composable
private fun ServerRow(server: LogicalServer, selected: Boolean, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 10.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(server.name, fontWeight = FontWeight.Medium)
            Text(
                listOfNotNull(
                    server.city.ifBlank { null },
                    "load ${server.loadLabel}",
                    if (server.isP2p) "P2P" else null,
                    if (server.isTor) "Tor" else null,
                ).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
            )
        }
        if (!server.isOnline) {
            Text("offline", color = MaterialTheme.colorScheme.error,
                 style = MaterialTheme.typography.labelSmall)
        } else {
            Surface(
                color = loadColor(server.load).copy(alpha = 0.18f),
                shape = MaterialTheme.shapes.small,
            ) {
                Text(
                    server.loadLabel,
                    color = loadColor(server.load),
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                )
            }
        }
        if (selected) {
            Text(" ●", color = MaterialTheme.colorScheme.primary,
                 modifier = Modifier.padding(start = 8.dp))
        }
    }
}

private fun fmtBytes(n: Long): String = when {
    n >= 1 shl 20 -> "%.1f MB".format(n / 1048576.0)
    n >= 1 shl 10 -> "%.1f KB".format(n / 1024.0)
    else -> "$n B"
}
