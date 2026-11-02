package app.protoclean.ui

import android.webkit.WebView
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import app.protoclean.AppViewModel

/**
 * Login screen: a real, visible WebView on account.protonvpn.com (the
 * CAPTCHA/2FA-friendly path). Stored credentials are auto-filled by
 * ProtonSession's injected script; the user only intervenes for human
 * verification. After login the WebView stays alive (hidden) — it is the
 * backend browser used for the downloads-page automation.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LoginScreen(vm: AppViewModel, onLoggedIn: () -> Unit) {
    var webView by remember { mutableStateOf<WebView?>(null) }
    val ui by vm.ui.collectAsState()

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("Sign in to Proton", style = MaterialTheme.typography.headlineSmall,
             fontWeight = FontWeight.Bold)
        Text(
            "Proto Clean opens the real Proton login page. Saved credentials " +
            "are filled automatically; finish CAPTCHA / 2FA by hand if asked.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(vertical = 8.dp))

        Row(verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            if (ui.loginStatus.isNotBlank()) {
                Text(ui.loginStatus, style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.weight(1f))
            if (ui.loggedIn) {
                Button(onClick = onLoggedIn) { Text("Continue") }
            }
        }

        Box(Modifier.weight(1f).fillMaxWidth()) {
            AndroidView(
                factory = { ctx ->
                    WebView(ctx).also { wv ->
                        webView = wv
                        vm.loginWithWebView(wv)
                    }
                },
                update = { },
                modifier = Modifier.fillMaxSize(),
            )
        }

        // manual credential storage (used for auto-fill next time)
        var user by remember { mutableStateOf(vm.creds.username()) }
        var pass by remember { mutableStateOf("") }
        var totp by remember { mutableStateOf(vm.creds.totpSecret()) }
        OutlinedTextField(
            value = user, onValueChange = { user = it },
            label = { Text("Proton account (optional prefill)") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(
            value = pass, onValueChange = { pass = it },
            label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        OutlinedTextField(
            value = totp, onValueChange = { totp = it },
            label = { Text("2FA secret (optional — auto-answers TOTP)") },
            modifier = Modifier.fillMaxWidth(), singleLine = true)
        Button(
            onClick = { vm.saveCredentials(user.trim(), pass, totp.trim()) },
            enabled = user.isNotBlank() && pass.isNotBlank(),
            modifier = Modifier.padding(top = 8.dp),
        ) { Text("Save credentials") }
        Text(
            "Stored encrypted on this device only.",
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(top = 4.dp))
    }

    LaunchedEffect(ui.loggedIn) {
        if (ui.loggedIn) {
            // keep the WebView alive after leaving this screen
            (webView?.parent as? android.view.ViewGroup)?.removeView(webView)
        }
    }
}
