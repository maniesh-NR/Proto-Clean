package app.protoclean.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.protoclean.AppViewModel

/**
 * Settings — protocol selection, advanced connection options (mirrors the
 * desktop Protocol + Advanced tabs), port forwarding, split tunneling
 * (Android's native per-app exclusion), local config cache and the
 * ad-block answer mode.
 *
 * Android notes: the tunnel itself always runs WireGuard (GoBackend), so the
 * OpenVPN choice is shown but disabled; the TAP/TUN network driver and
 * IPv6 leak *blocking* are platform-specific on the desktop — on Android
 * leak protection is the system's "Block connections without VPN" lockdown.
 */
@Composable
fun SettingsScreen(vm: AppViewModel) {
    val settings by vm.settings.settings.collectAsState(initial = app.protoclean.data.AppSettings())

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall,
             fontWeight = FontWeight.Bold)

        Section("Protocol (config downloaded from Proton's page)") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(
                    selected = settings.protocol == "wireguard",
                    onClick = { vm.updateSettings { it.copy(protocol = "wireguard") } },
                )
                Column {
                    Text("WireGuard", fontWeight = FontWeight.SemiBold)
                    Text("Modern protocol — the Android tunnel runs WireGuard",
                         style = MaterialTheme.typography.bodySmall)
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = false, onClick = null, enabled = false)
                Column {
                    Text("OpenVPN", fontWeight = FontWeight.SemiBold)
                    Text(
                        "Not available in the Android build — OpenVPN configs " +
                        "(with the TCP or UDP transport and the TUN/TAP driver) " +
                        "are supported by the desktop app.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            HorizontalDivider()
            ToggleRow("VPN Accelerator (set on the download page)",
                      settings.vpnAccelerator) {
                vm.updateSettings { s -> s.copy(vpnAccelerator = it) }
            }
        }

        Section("Advanced") {
            ToggleRow("Alternative routing — try Proton's mirror API hosts\nwhen the direct ones are blocked",
                      settings.alternativeRouting) {
                vm.updateSettings { s -> s.copy(alternativeRouting = it) }
            }
            ToggleRow("Allow LAN connections — keep local devices\n(printers, speakers) outside the tunnel",
                      settings.allowLan) {
                vm.updateSettings { s -> s.copy(allowLan = it) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    ToggleRow("Custom DNS servers", settings.customDnsEnabled) {
                        vm.updateSettings { s -> s.copy(customDnsEnabled = it) }
                    }
                }
            }
            var dns by remember(settings.customDnsServers) {
                mutableStateOf(settings.customDnsServers.joinToString(", "))
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = dns,
                    onValueChange = { t ->
                        dns = t
                        val servers = t.split(Regex("[,;\\s]+"))
                            .map { it.trim() }
                            .filter { it.isNotEmpty() }
                            .toSet()
                        if (servers != settings.customDnsServers) {
                            vm.updateSettings { it.copy(customDnsServers = servers) }
                        }
                    },
                    label = { Text("e.g. 1.1.1.1, 9.9.9.9") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    enabled = settings.customDnsEnabled,
                )
            }
            ToggleRow("NAT type — Moderate NAT (off = Strict NAT, paid plans)",
                      settings.moderateNat) {
                vm.updateSettings { s -> s.copy(moderateNat = it) }
            }
            ToggleRow("IPv6 support — allow IPv6 traffic through the tunnel",
                      settings.ipv6Support) {
                vm.updateSettings { s -> s.copy(ipv6Support = it) }
            }
            ToggleRow("IPv6 leak protection (default on)", settings.ipv6LeakProtection) {
                vm.updateSettings { s -> s.copy(ipv6LeakProtection = it) }
            }
            Text(
                "IPv6 leak protection notes: when IPv6 support is off, IPv6 " +
                "routes are stripped from the tunnel config; for hard " +
                "blocking of anything that bypasses the VPN, also enable the " +
                "system's Always-on VPN + 'Block connections without VPN' " +
                "(see Kill switch below). The TUN/TAP OpenVPN driver setting " +
                "is desktop-only — Android's VpnService is always TUN.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Section("Port forwarding (NAT-PMP, paid plans)") {
            ToggleRow("Request in generated config", settings.natPmpInConfig) {
                vm.updateSettings { s -> s.copy(natPmpInConfig = it) }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Internal port (0 = generic)", Modifier.weight(1f))
                OutlinedTextField(
                    value = settings.natPmpInternalPort.toString(),
                    onValueChange = { t ->
                        t.filter { it.isDigit() }.take(5).toIntOrNull()?.let {
                            vm.updateSettings { s -> s.copy(natPmpInternalPort = it) }
                        }
                    },
                    modifier = Modifier.width(110.dp),
                    singleLine = true,
                )
            }
        }

        Section("Split tunneling (exclude apps)") {
            ToggleRow("Enable", settings.splitEnabled) {
                vm.updateSettings { s -> s.copy(splitEnabled = it) }
            }
            Text(
                "Excluded apps keep using the normal connection (native " +
                "VpnService exclusion — the Android equivalent of the " +
                "desktop cgroup feature).",
                style = MaterialTheme.typography.bodySmall,
            )
            var newApp by remember { mutableStateOf("") }
            Row {
                OutlinedTextField(
                    value = newApp, onValueChange = { newApp = it },
                    label = { Text("package name, e.g. com.spotify.music") },
                    modifier = Modifier.weight(1f), singleLine = true,
                )
                TextButton(
                    onClick = {
                        val pkg = newApp.trim()
                        if (pkg.isNotEmpty()) {
                            vm.updateSettings {
                                it.copy(excludedApps = it.excludedApps + pkg)
                            }
                            newApp = ""
                        }
                    },
                ) { Text("Add") }
            }
            settings.excludedApps.sorted().forEach { pkg ->
                Row {
                    Text(pkg, Modifier.weight(1f),
                         style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = {
                        vm.updateSettings { it.copy(excludedApps = it.excludedApps - pkg) }
                    }) { Text("Remove") }
                }
            }
        }

        Section("Local config cache") {
            ToggleRow("Cache downloaded configs", settings.cacheConfigs) {
                vm.updateSettings { s -> s.copy(cacheConfigs = it) }
            }
            Text(
                "A server's config is downloaded once and reused; it is " +
                "fetched again only when the saved one fails to connect " +
                "(stale/revoked certificate).",
                style = MaterialTheme.typography.bodySmall,
            )
            Row {
                Text("${vm.configCacheSize()} cached", Modifier.weight(1f))
                OutlinedButton(onClick = { vm.purgeConfigCache() }) { Text("Clear cache") }
            }
        }

        Section("Ad blocking") {
            ToggleRow("Answer blocked domains with NXDOMAIN (else 0.0.0.0)",
                      settings.blockNxdomain) {
                vm.updateSettings { s -> s.copy(blockNxdomain = it) }
            }
            Text(
                "While the VPN is connected, DNS uses Proton's in-tunnel " +
                "resolver (10.2.0.1). The blocklist filter applies in " +
                "Ad-blocker mode (Blocklists tab) — Android allows only one " +
                "VPN per app, so the two modes are mutually exclusive.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Section("Kill switch") {
            Text(
                "The tunnel is always full-route (0.0.0.0/0 + ::/0), so " +
                "traffic cannot bypass it. For blocking even when the tunnel " +
                "drops, enable the system's Always-on VPN + 'Block " +
                "connections without VPN' for Proto Clean in Android's VPN " +
                "settings.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        Section("Account") {
            OutlinedButton(onClick = { vm.logout() }) { Text("Log out & forget") }
        }
    }
}

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title, fontWeight = FontWeight.SemiBold,
             style = MaterialTheme.typography.titleSmall)
        content()
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
