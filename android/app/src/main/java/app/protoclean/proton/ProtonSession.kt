package app.protoclean.proton

import android.annotation.SuppressLint
import android.content.Context
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import app.protoclean.data.CredentialsStore
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import kotlin.coroutines.resume

/**
 * The Proton account session, driven through a real WebView (the Android
 * analogue of the desktop's backend Chromium browser).
 *
 * Login flow (mirrors the verified desktop selectors):
 *   1. load account.protonvpn.com/login
 *   2. fill #username → submit (two-step form)
 *   3. when #password appears, fill it → submit
 *   4. when a 2FA field appears, answer with the stored TOTP secret
 *   5. CAPTCHA/human-verification: the window is visible — the user
 *      completes it by hand and the flow continues automatically
 *   6. success = AUTH-* cookies for account.protonvpn.com (or landing on
 *      /downloads)
 *
 * The session (cookie jar) is persisted encrypted and restored on next
 * launch, exactly like the desktop storage_state.
 */
class ProtonSession(
    private val context: Context,
    private val creds: CredentialsStore,
) {
    val cookies get() = CookieManager.getInstance()

    @Volatile
    var loggedIn: Boolean = false
        private set

    // ------------------------------------------------------------- session
    fun restoreSession() {
        val saved = creds.sessionCookies()
        if (saved.isBlank()) return
        CookieManager.getInstance().apply {
            setAcceptCookie(true)
            for (pair in saved.split("; ")) {
                if (pair.contains("=")) {
                    setCookie("https://account.protonvpn.com", pair)
                }
            }
        }
    }

    fun persistSession() {
        val jar = cookies.getCookie("https://account.protonvpn.com") ?: ""
        if (jar.contains("AUTH")) {
            creds.saveSessionCookies(jar)
            loggedIn = true
        }
    }

    fun checkLoginFromCookies() {
        val jar = cookies.getCookie("https://account.protonvpn.com") ?: ""
        loggedIn = jar.contains("AUTH")
    }

    fun logout() {
        CookieManager.getInstance().apply {
            removeAllCookies(null)
            flush()
        }
        creds.saveSessionCookies("")
        loggedIn = false
    }

    // ---------------------------------------------------------------- login
    /**
     * Attach to a visible WebView and drive the login. Suspending: resumes
     * with true on success, false with a message on failure/timeout.
     *
     * The WebView must be VISIBLE — this doubles as the CAPTCHA/2FA fallback
     * (same philosophy as the desktop's interactive window).
     */
    @SuppressLint("SetJavaScriptEnabled")
    suspend fun login(
        webView: WebView,
        onStatus: (String) -> Unit,
        timeoutMs: Long = 5 * 60_000,
    ): Pair<Boolean, String> {
        restoreSession()
        val js = JSBridge()
        webView.apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.userAgentString =
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 " +
                "(KHTML, like Gecko) Chrome/124 Mobile Safari/537.36"
            webViewClient = LoginClient(onStatus, js)
            addJavascriptInterface(js, "ProtoClean")
            CookieManager.getInstance().setAcceptCookie(true)
            CookieManager.getInstance().setAcceptThirdPartyCookies(this, true)
        }
        return suspendCancellableCoroutine { cont ->
            js.onDone = { ok, msg -> if (cont.isActive) cont.resume(ok to msg) }
            onStatus("opening account.protonvpn.com…")
            webView.loadUrl(LOGIN_URL)
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                if (cont.isActive) cont.resume(false to "login timed out")
            }, timeoutMs)
            cont.invokeOnCancellation { webView.loadUrl("about:blank") }
        }
    }

    /** Navigate the (logged-in) WebView to the downloads page. */
    fun openDownloads(webView: WebView) {
        webView.loadUrl(DOWNLOADS_URL)
    }

    // --------------------------------------------------------- web client
    private inner class LoginClient(
        private val onStatus: (String) -> Unit,
        private val js: JSBridge,
    ) : WebViewClient() {

        override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest) =
            false

        override fun onPageFinished(view: WebView, url: String) {
            checkLoginFromCookies()
            when {
                loggedIn || url.contains("/downloads") || url.contains("/account") -> {
                    if (loggedIn) {
                        persistSession()
                        js.finish(true, "logged in")
                    }
                    return
                }
                url.contains("/login") -> {
                    onStatus("login page — filling credentials…")
                    view.evaluateJavascript(autoLoginJs(), null)
                }
                else -> onStatus("waiting for $url…")
            }
        }
    }

    /**
     * JS injected on every /login page load: fills the username step, then
     * the password step, then the 2FA step, and reports the outcome through
     * window.ProtoClean.done(). Selectors mirror the desktop implementation.
     */
    private fun autoLoginJs(): String {
        val user = JSONObject.quote(creds.username())
        val pass = JSONObject.quote(creds.password())
        val totp = JSONObject.quote(creds.currentTotp() ?: "")
        return """
            (function () {
              var done = function (ok, msg) {
                try { window.ProtoClean.done(JSON.stringify({ok: ok, msg: msg})); } catch (e) {}
              };
              var q = function (sel) { return document.querySelector(sel); };
              var setValue = function (el, v) {
                if (!el) return false;
                var proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype
                                                      : window.HTMLInputElement.prototype;
                var setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
                setter.call(el, v);
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
                return true;
              };
              var submit = function () {
                var b = q("button[type='submit']") || q("#login_btn");
                if (b) { b.click(); return true; }
                var f = q('form'); if (f) f.submit();
                return !!b || !!f;
              };
              var user = $user, pass = $pass, totp = $totp;
              if (!user) { done(false, 'no stored credentials — type them here'); return; }

              var u = q('#username') || q('#email') || q("input[name='username']");
              if (u) { setValue(u, user); submit(); return; }          // step 1
              var p = q('#password') || q("input[type='password']");
              if (p && pass) { setValue(p, pass); submit(); return; }  // step 2
              var t = q('#totp') || q("input[autocomplete='one-time-code']");
              if (t && totp) { setValue(t, totp); submit(); return; }  // 2FA step
              // captcha / unknown step: the user completes it manually;
              // the next page load re-runs this script if still on /login.
            })();
        """.trimIndent()
    }

    /** JS bridge: the page reports login completion / flow results. */
    class JSBridge {
        @Volatile
        var onDone: ((Boolean, String) -> Unit)? = null

        /** Kotlin-side completion (mirrors window.ProtoClean.done from JS). */
        fun finish(ok: Boolean, msg: String) {
            onDone?.invoke(ok, msg)
        }

        @JavascriptInterface
        fun done(payload: String) {
            runCatching {
                val o = JSONObject(payload)
                onDone?.invoke(o.optBoolean("ok"), o.optString("msg", ""))
            }
        }
    }

    companion object {
        const val LOGIN_URL = "https://account.protonvpn.com/login"
        const val DOWNLOADS_URL = "https://account.protonvpn.com/downloads"

        /** Same cascade as the desktop: same-origin proxy first, then the API host. */
        val LOGICALS_URLS = listOf(
            "https://account.protonvpn.com/api/vpn/v2/logicals",
            "https://api.protonvpn.ch/vpn/logicals",
        )

        /** Alternative routing: Proton mirror API hosts, tried when the
         *  direct ones are blocked (same auth, same payloads). */
        val ALT_LOGICALS_URLS = listOf(
            "https://api.protonvpn.com/vpn/logicals",
            "https://vpn-api.proton.me/vpn/logicals",
        )
    }
}
