package app.protoclean.proton

import android.webkit.WebView
import app.protoclean.data.AppSettings
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import kotlin.coroutines.resume

/**
 * Config-creation options (mirrors the desktop ConfigOptions).
 */
data class ConfigOptions(
    val protocol: String = "wireguard",        // config section on the page
    val openvpnTransport: String = "udp",      // udp | tcp (OpenVPN only)
    val vpnAccelerator: Boolean = true,
    val moderateNat: Boolean = false,
    val natPmpPortForward: Boolean = true,
    val alternativeRouting: Boolean = true,
) {
    companion object {
        fun fromSettings(s: AppSettings) = ConfigOptions(
            protocol = s.protocol,
            openvpnTransport = s.openvpnTransport,
            vpnAccelerator = s.vpnAccelerator,
            moderateNat = s.moderateNat,
            natPmpPortForward = s.natPmpInConfig,
            alternativeRouting = s.alternativeRouting,
        )
    }
}

/**
 * Drives the logged-in downloads page in the WebView with the same DOM
 * automation as the desktop PageBot:
 *
 *  * servers      — in-page fetch of the logicals API (cookies ride along),
 *                   with the rendered "Free server configs" tables as
 *                   fallback (tier-0 only — paid servers never surface);
 *  * createConfig — set the platform radio (#wg-platform-Android), the
 *                   NAT-PMP toggle (#feature-PortForwarding) and the VPN
 *                   Accelerator toggle (#feature-SplitTCP), open the *Free
 *                   server configs* category, search the server, click its
 *                   Create button and read the resulting certificate
 *                   textarea (details[data-certificate-id] blocks render
 *                   every created config — same harvesting path as the
 *                   desktop);
 *  * harvest      — read all existing certificate textareas to warm the
 *                   config cache.
 *
 * All calls must run on the main thread (WebView requirement); they suspend
 * and resume with parsed results.
 */
object ProtonWeb {

    // ---------------------------------------------------------------- helpers

    private suspend fun evaluate(webView: WebView, js: String): String? =
        suspendCancellableCoroutine { cont ->
            webView.evaluateJavascript(js) { result ->
                if (cont.isActive) cont.resume(result)
            }
        }

    /** evaluateJavascript returns a JSON-encoded string (or null). */
    private fun decode(raw: String?): String? {
        if (raw == null || raw == "null" || raw == "undefined") return null
        return runCatching { JSONObject("{\"v\": $raw}").optString("v") }.getOrNull()
    }

    // ---------------------------------------------------------------- servers

    suspend fun scrapeServers(
        webView: WebView,
        alternativeRouting: Boolean = true,
    ): List<LogicalServer> {
        // 1. logicals API via in-page fetch (same session, same origin);
        //    with alternative routing the mirror hosts are tried as well
        val urls = ProtonSession.LOGICALS_URLS +
                (ProtonSession.ALT_LOGICALS_URLS.takeIf { alternativeRouting }
                    ?: emptyList())
        for (url in urls) {
            val raw = withTimeoutOrNull(20_000) {
                evaluate(webView, fetchJs(url))
            }
            val payload = decode(raw)
            if (!payload.isNullOrBlank() && payload.contains("LogicalServers")) {
                val servers = runCatching { LogicalServer.parse(payload) }.getOrDefault(emptyList())
                if (servers.isNotEmpty()) return servers
            }
        }
        // 2. DOM fallback: scrape the rendered free-server table rows
        val rows = decode(withTimeoutOrNull(15_000) {
            evaluate(webView, freeTableJs())
        }) ?: ""
        return rows.lineSequence().mapNotNull { line ->
            val name = Regex("([A-Z]{2}(?:-[A-Z]{2})?-[A-Z0-9]+#\\d+)").find(line)
                ?.groupValues?.get(1) ?: return@mapNotNull null
            val load = Regex("(\\d{1,3})\\s*%").find(line)?.groupValues?.get(1)
                ?.toFloatOrNull() ?: 0f
            LogicalServer(
                id = name, name = name, entryCountry = name.substringBefore('-'),
                exitCountry = name.substringBefore('-'), tier = 0, features = 0,
                city = "", load = load, score = 1e9f, status = 1,
            )
        }.toList()
    }

    private fun fetchJs(url: String): String = """
        (async function () {
          try {
            var r = await fetch("$url", {
              credentials: 'include',
              headers: {'Accept': 'application/json'}
            });
            var text = await r.text();
            return text;
          } catch (e) { return ''; }
        })();
    """.trimIndent()

    private fun freeTableJs(): String = """
        (function () {
          var rows = [];
          document.querySelectorAll(
              '#section-wireguard-configuration tr, table tr').forEach(function (tr) {
            var t = tr.textContent.replace(/\\s+/g, ' ').trim();
            if (/[A-Z]{2}(-[A-Z]{2})?-[A-Z0-9]+#\\d+/.test(t)) rows.push(t);
          });
          return rows.join('\\n');
        })();
    """.trimIndent()

    // ------------------------------------------------------------ create config

    /**
     * Create a WireGuard config for [serverName] on the downloads page and
     * return its text. The page renders created configs as readonly
     * textareas inside details[data-certificate-id] blocks — we read the
     * newest one after clicking Create.
     */
    suspend fun createConfig(
        webView: WebView,
        serverName: String,
        options: ConfigOptions,
        timeoutMs: Long = 60_000,
    ): String? {
        val js = createConfigJs(serverName, options)
        val raw = withTimeoutOrNull(timeoutMs) { evaluate(webView, js) }
        return decode(raw)?.takeIf { it.contains("[Interface]") }
    }

    private fun createConfigJs(server: String, o: ConfigOptions): String = """
        (async function () {
          var WG = '#section-wireguard-configuration ';
          var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
          var waitFor = async function (sel, ms) {
            for (var i = 0; i < ms / 250; i++) {
              var el = document.querySelector(sel);
              if (el) return el;
              await sleep(250);
            }
            return null;
          };
          var click = function (el) {
            if (!el) return false;
            el.scrollIntoView({block: 'center'});
            el.click();
            return true;
          };

          // platform radio: Android
          var androidLabel = Array.prototype.slice.call(
              document.querySelectorAll(WG + 'label')).find(function (l) {
            return /(^|\b)android\b/i.test(l.textContent || '');
          });
          var androidRadio = document.querySelector(WG + '#wg-platform-Android');
          if (!click(androidRadio)) click(androidLabel);

          // option toggles (checkbox inputs inside labeled wrappers)
          var setToggle = function (id, on) {
            var box = document.querySelector(WG + '#' + id)
                      || document.querySelector('#' + id);
            if (box && typeof box.checked === 'boolean' && box.checked !== on) box.click();
          };
          setToggle('feature-PortForwarding', ${o.natPmpPortForward});
          setToggle('feature-SplitTCP', ${o.vpnAccelerator});
          setToggle('feature-ModerateNAT', ${o.moderateNat});
          await sleep(500);

          // free-server category (paid servers excluded from the picker)
          var free = document.querySelector(WG + "label[class*='category']")
            || Array.prototype.slice.call(
                  document.querySelectorAll(WG + 'label')).find(function (l) {
                return /free server configs/i.test(l.textContent || '');
              });
          click(free);
          await sleep(800);

          // device name for the certificate
          var name = document.querySelector(WG + '#certificate-device-name');
          if (name) {
            var setter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value').set;
            setter.call(name, 'ProtoClean-Android');
            name.dispatchEvent(new Event('input', {bubbles: true}));
          }

          // search the server
          var lookup = document.querySelector(WG + '#server-lookup');
          if (lookup) {
            var ls = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value').set;
            ls.call(lookup, ${JSONObject.quote(server)});
            lookup.dispatchEvent(new Event('input', {bubbles: true}));
            await sleep(600);
            var searchBtn = Array.prototype.slice.call(
                document.querySelectorAll(WG + 'button')).find(function (b) {
              return /search/i.test(b.textContent || '');
            });
            click(searchBtn);
            await sleep(1200);
          }

          // click Create on the row that mentions our server
          var createBtn = null;
          for (var attempt = 0; attempt < 20 && !createBtn; attempt++) {
            var trs = document.querySelectorAll(WG + 'tr');
            for (var i = 0; i < trs.length; i++) {
              if (trs[i].textContent.indexOf(${JSONObject.quote(server)}) >= 0) {
                var btn = trs[i].querySelector('button');
                if (btn) { createBtn = btn; break; }
              }
            }
            if (!createBtn) {
              createBtn = document.querySelector(WG + "button[type='submit']");
            }
            if (!createBtn) await sleep(500);
          }
          if (!click(createBtn)) return '';

          // wait for the certificate block and read the textarea
          for (var w = 0; w < 120; w++) {
            await sleep(1000);
            var blocks = document.querySelectorAll(
                WG + "details[data-certificate-id] textarea");
            if (blocks.length) {
              var newest = blocks[blocks.length - 1].value || blocks[blocks.length - 1].textContent;
              if (newest && newest.indexOf('[Interface]') >= 0) return newest;
            }
          }
          return '';
        })();
    """.trimIndent()

    // ----------------------------------------------------------------- harvest

    /** Read every existing certificate textarea: {serverName: configText}. */
    suspend fun harvestConfigs(webView: WebView): Map<String, String> {
        val raw = withTimeoutOrNull(15_000) {
            evaluate(webView, harvestJs())
        } ?: return emptyMap()
        val payload = decode(raw) ?: return emptyMap()
        return runCatching {
            val obj = JSONObject(payload)
            obj.keys().asSequence().associateWith { key ->
                obj.optString(key)
            }.filterValues { it.contains("[Interface]") }
        }.getOrDefault(emptyMap())
    }

    private fun harvestJs(): String = """
        (function () {
          var out = {};
          document.querySelectorAll(
              '#section-wireguard-configuration details[data-certificate-id]'
          ).forEach(function (d) {
            var ta = d.querySelector('textarea');
            var text = ta ? (ta.value || ta.textContent || '') : '';
            var m = text.match(/^\s*#\s*([A-Z]{2}(-[A-Z]{2})?-[A-Z0-9]+#\d+)\s*$/m);
            if (m && text.indexOf('[Interface]') >= 0) out[m[1]] = text;
          });
          return JSON.stringify(out);
        })();
    """.trimIndent()
}
