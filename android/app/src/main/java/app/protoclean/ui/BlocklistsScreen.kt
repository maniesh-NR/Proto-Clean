package app.protoclean.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.protoclean.AppViewModel
import app.protoclean.data.BLOCKLIST_PRESETS
import app.protoclean.dns.DnsFilterVpnService

/**
 * Blocklist management — add / remove / update, the same feature set as the
 * desktop menu. The lists feed the standalone DNS-filter (ad-blocker) mode;
 * while the WireGuard tunnel is up, Android runs DNS through Proton's
 * in-tunnel resolver instead (one VPN per app).
 */
@Composable
fun BlocklistsScreen(vm: AppViewModel) {
    val entries by vm.blocklistEntries.collectAsState()
    val settings by vm.settings.settings.collectAsState(initial = app.protoclean.data.AppSettings())
    var showAdd by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { vm.refreshBlocklistEntries() }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("Blocklists", style = MaterialTheme.typography.headlineSmall,
             fontWeight = FontWeight.Bold)
        Text(
            "Ad & malware domains (StevenBlack, HaGeZi, …). Filter matches any " +
            "subdomain of a listed name.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(vertical = 8.dp))

        // ad-blocker mode switch (standalone DNS-filter VPN)
        Card(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(12.dp),
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Ad-blocker mode (DNS filter)", fontWeight = FontWeight.Medium)
                    Text(
                        if (DnsFilterVpnService.running)
                            "Active — DNS filtering system-wide (VPN off)"
                        else
                            "Runs when the VPN is off; Android allows one VPN at a time",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Switch(
                    checked = settings.dnsFilterEnabled,
                    onCheckedChange = { vm.setDnsFilter(it) },
                )
            }
        }

        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.padding(vertical = 4.dp),
        ) {
            Button(onClick = { showAdd = true }) { Text("Add") }
            OutlinedButton(onClick = { vm.updateBlocklists() }) { Text("Update all") }
        }

        LazyColumn(
            contentPadding = PaddingValues(vertical = 8.dp),
            modifier = Modifier.weight(1f),
        ) {
            items(entries, key = { it.url }) { e ->
                BlocklistRow(
                    name = e.name,
                    domains = e.domains,
                    updatedAt = e.updatedAt,
                    enabled = e.enabled,
                    error = e.error,
                    onToggle = { vm.setBlocklistEnabled(e.name, it) },
                    onRemove = { vm.removeBlocklist(e.name) },
                    onUpdate = { vm.updateBlocklists(e.name) },
                )
                HorizontalDivider()
            }
        }
    }

    if (showAdd) {
        AddBlocklistDialog(
            onDismiss = { showAdd = false },
            onAdd = { name, url ->
                vm.addBlocklist(name, url)
                showAdd = false
            },
        )
    }
}

@Composable
private fun BlocklistRow(
    name: String,
    domains: Int,
    updatedAt: String,
    enabled: Boolean,
    error: String,
    onToggle: (Boolean) -> Unit,
    onRemove: () -> Unit,
    onUpdate: () -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(name, fontWeight = FontWeight.Medium)
            Text(
                listOfNotNull(
                    if (domains > 0) "%,d domains".format(domains) else "not downloaded yet",
                    updatedAt.ifBlank { null },
                    error.ifBlank { null },
                ).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = if (error.isBlank()) MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                        else MaterialTheme.colorScheme.error,
            )
        }
        TextButton(onClick = onUpdate) { Text("Update") }
        IconButton(onClick = onRemove) {
            Icon(Icons.Default.Delete, contentDescription = "remove $name")
        }
        Switch(checked = enabled, onCheckedChange = onToggle)
    }
}

@Composable
private fun AddBlocklistDialog(onDismiss: () -> Unit, onAdd: (String, String) -> Unit) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var custom by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add blocklist") },
        text = {
            Column {
                if (!custom) {
                    Text("Presets", fontWeight = FontWeight.Medium)
                    BLOCKLIST_PRESETS.forEach { (presetName, presetUrl) ->
                        TextButton(onClick = { onAdd(presetName, presetUrl) }) {
                            Text(presetName)
                        }
                    }
                    TextButton(onClick = { custom = true }) {
                        Text("Custom URL…")
                    }
                } else {
                    OutlinedTextField(
                        value = name, onValueChange = { name = it },
                        label = { Text("Name (optional)") }, singleLine = true)
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = url, onValueChange = { url = it },
                        label = { Text("https://…/hosts") }, singleLine = true)
                }
            }
        },
        confirmButton = {
            if (custom) {
                TextButton(
                    onClick = { onAdd(name.trim(), url.trim()) },
                    enabled = url.startsWith("http"),
                ) { Text("Add") }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
