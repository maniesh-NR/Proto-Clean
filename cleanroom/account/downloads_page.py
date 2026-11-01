"""The Downloads page (account.protonvpn.com/downloads) in the backend
browser: scrape the *free* server list + live loads, set the config options
(VPN Accelerator, NAT-PMP port forwarding, Moderate NAT), pick a server
and capture the generated config — for **WireGuard or OpenVPN**, depending
on the selected protocol (Settings → Protocol).

Selector facts verified against the live page DOM (2025):

* everything WireGuard-related lives in ``#section-wireguard-configuration``;
  the OpenVPN section below re-uses similar markup with different ids
  (``#section-openvpn-configuration``) — Cleanroom carries layered selector
  candidates for both because the OpenVPN ids are not stable
* the config name input is ``#certificate-device-name``
* platforms are radios: ``#wg-platform-Android|iOS|Windows|macOS|Linux|Router``
  (label text "GNU/Linux"); the OpenVPN section has its own equivalents
* the OpenVPN transport (TCP or UDP) is a pair of radios in the OpenVPN
  section (``label:has-text('UDP')`` / ``label:has-text('TCP')``)
* VPN options are inline toggles: ``#feature-PortForwarding`` (NAT-PMP) and
  ``#feature-SplitTCP`` (VPN Accelerator); Moderate NAT only renders on paid
  plans
* server categories are radios ``name="category-list"``: "Standard server
  configs" / **"Free server configs"** / "Secure Core configs" — we click
  *Free* so only free servers are ever visible/selectable (paid excluded)
* each country is a ``<details>`` block with a table of rows:
  ``<td>CA-FREE#1</td><td>…64%…</td><td><button>Create</button></td>``
* extra servers are reachable via the ``#server-lookup`` search field
* previously created configs render as ``details[data-certificate-id]``
  blocks with a readonly ``<textarea>`` holding the full config — Cleanroom
  harvests these (both sections) to warm its local config cache

Server data strategy (most → least preferred):
  1. capture the page's own XHR payloads (logicals JSON with Load/Score/Tier)
  2. ask the logged-in page to fetch the endpoint for us — with
     *alternative routing* enabled, Proton's mirror API hosts are tried too
     (api.protonvpn.com / vpn-api.proton.me) so a blocked direct API does
     not break the server list
  3. scrape the rendered "Free server configs" country tables

Config capture (both protocols): XHR body → new certificate textarea → the
Download button's file.

Every step is resilient: multiple selector candidates, generous waits, a
debug screenshot on failure (~/.cache/cleanroom/screenshots).
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..log import get
from .browser import settle
from ..paths import DOWNLOADS_DIR
from ..servers.models import LogicalServer, parse_logical_servers

log = get("downloads")

DOWNLOADS_URL = "https://account.protonvpn.com/downloads"

WG = "#section-wireguard-configuration"
OVPN = "#section-openvpn-configuration"

WIREGUARD_LINK_SELECTORS = [WG, "a:has-text('WireGuard')", "button:has-text('WireGuard')",
                            "[data-testid*='wireguard']", "text=/WireGuard configuration/i"]
OPENVPN_LINK_SELECTORS = [OVPN, "a:has-text('OpenVPN')", "button:has-text('OpenVPN')",
                          "[data-testid*='openvpn']", "text=/OpenVPN configuration/i"]

CONFIG_NAME_SELECTORS = [
    "#certificate-device-name",
    "input[placeholder*='name' i]",
    "input[placeholder*='certificate' i]",
    "input[data-testid*='name']",
    "input[name='name']",
]
OVPN_CONFIG_NAME_SELECTORS = [
    f"{OVPN} #certificate-device-name",
    f"{OVPN} #ovpn-certificate-device-name",
    f"{OVPN} #openvpn-certificate-device-name",
    f"{OVPN} input[placeholder*='name' i]",
    f"{OVPN} input[placeholder*='certificate' i]",
    f"{OVPN} input[data-testid*='name']",
]

PLATFORM_RADIO_SELECTORS = [
    "#wg-platform-Linux",
    f"{WG} label:has-text('GNU/Linux')",
    f"{WG} label:has-text('Linux')",
]
OVPN_PLATFORM_RADIO_SELECTORS = [
    f"{OVPN} #ovpn-platform-Linux",
    f"{OVPN} #platform-Linux",
    f"{OVPN} label:has-text('GNU/Linux')",
    f"{OVPN} label:has-text('Linux')",
]

# OpenVPN transport: TCP or UDP radios in the OpenVPN section
OVPN_UDP_SELECTORS = [
    f"{OVPN} #ovpn-protocol-UDP",
    f"{OVPN} #protocol-UDP",
    f"{OVPN} input[value='udp']",
    f"{OVPN} label:has-text('UDP')",
]
OVPN_TCP_SELECTORS = [
    f"{OVPN} #ovpn-protocol-TCP",
    f"{OVPN} #protocol-TCP",
    f"{OVPN} input[value='tcp']",
    f"{OVPN} label:has-text('TCP')",
]

# radio category that shows only free servers (paid excluded)
FREE_CATEGORY_SELECTORS = [
    f"{WG} label:has-text('Free server configs')",
    f"{WG} label:has-text('Free')",
]
OVPN_FREE_CATEGORY_SELECTORS = [
    f"{OVPN} label:has-text('Free server configs')",
    f"{OVPN} label:has-text('Free')",
]

SERVER_LOOKUP_SELECTORS = [f"{WG} #server-lookup", "#server-lookup",
                           "input[placeholder*='AT#' i]"]
SEARCH_BUTTON_SELECTORS = [f"{WG} button:has-text('Search')", "button:has-text('Search')"]

SUBMIT_CREATE_SELECTORS = [f"{WG} button[type='submit']",
                           f"{WG} button:has-text('Create')"]

CERTIFICATE_BLOCKS = "details[data-certificate-id]"
CERT_TEXTAREA = "textarea"

LOGICALS_URL_PATTERNS = ("logicals", "/logical", "vpn/servers")
LOGICALS_FETCH_URLS = [
    "https://api.protonvpn.ch/vpn/logicals",
    "https://api.protonvpn.ch/vpn/v1/logicals",
]
# Alternative routing: Proton's mirror API hosts, tried when the direct
# ones are blocked or unreachable (same auth, same payloads).
LOGICALS_ALT_FETCH_URLS = [
    "https://api.protonvpn.com/vpn/logicals",
    "https://vpn-api.proton.me/vpn/logicals",
]

LOAD_FROM_TEXT = re.compile(r"(\d{1,3})\s*%")
SERVER_NAME_RE = re.compile(r"^([A-Z]{2}(?:-[A-Z]{2})?-[A-Z0-9]+#\d+)\s*$")


def parse_server_row(text: str) -> Optional[tuple]:
    """(name, load) from a rendered table row — tolerant of newline- or
    tab-separated cells (both occur depending on rendering)."""
    name = None
    for tok in re.split(r"\s+", (text or "").strip()):
        m = SERVER_NAME_RE.match(tok)
        if m:
            name = m.group(1)
            break
    if not name:
        return None
    load_m = LOAD_FROM_TEXT.search(text)
    return name, (float(load_m.group(1)) if load_m else 0.0)


def looks_like_wireguard(text: str) -> bool:
    return "[Interface]" in text and "PrivateKey" in text


def looks_like_openvpn(text: str) -> bool:
    """Heuristic for a captured .ovpn config body (a 'remote' line is the
    one directive every usable OpenVPN config has)."""
    lines = [ln.strip() for ln in (text or "").splitlines()]
    has_remote = any(ln.startswith("remote ") for ln in lines)
    if not has_remote:
        return False
    has_client = any(ln == "client" for ln in lines)
    has_marker = "<ca>" in text or re.search(r"(?m)^proto\s+(udp|tcp)", text)
    return has_client or bool(has_marker)


@dataclass
class ConfigOptions:
    protocol: str = "wireguard"          # "wireguard" | "openvpn"
    vpn_accelerator: bool = True
    moderate_nat: bool = False
    nat_pmp_port_forward: bool = True     # toggle on the download page
    netshield_level: int = 0              # free plans: unavailable
    openvpn_transport: str = "udp"        # "udp" | "tcp" (OpenVPN only)
    alternative_routing: bool = True      # mirror API hosts + load retries


@dataclass
class ScrapeResult:
    config_text: str
    server: Optional[LogicalServer] = None
    used_recommended: bool = False
    from_cache_warm: bool = False         # True when read from an existing cert
    protocol: str = "wireguard"           # config actually captured


class ScrapeError(RuntimeError):
    pass


class PageBot:
    """Resilient selector helpers on top of a Playwright page."""

    def __init__(self, page, shots_dir=DOWNLOADS_DIR.parent / "screenshots") -> None:
        self.page = page
        self.shots_dir = shots_dir

    def screenshot(self, tag: str) -> None:
        try:
            self.shots_dir.mkdir(parents=True, exist_ok=True)
            path = self.shots_dir / f"{tag}-{int(time.time())}.png"
            self.page.screenshot(path=str(path), full_page=True)
            log.info("debug screenshot saved: %s", path)
        except Exception:  # noqa: BLE001
            pass

    def goto(self, url: str, *, alternative_routing: bool = True,
             timeout: int = 60000) -> None:
        """Load a page; with alternative routing, retry once on failure."""
        try:
            self.page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        except Exception as e:  # noqa: BLE001
            if not alternative_routing:
                raise
            log.warning("page load failed (%s) — retrying (alternative routing)", e)
            time.sleep(2.0)
            self.page.goto(url, wait_until="domcontentloaded", timeout=timeout)

    def click_any(self, selectors: List[str], timeout: float = 12000) -> bool:
        for sel in selectors:
            try:
                loc = self.page.locator(sel).first
                loc.wait_for(state="visible", timeout=timeout)
                loc.click()
                return True
            except Exception:  # noqa: BLE001
                continue
        return False

    def click_button_with_text(self, texts: List[str]) -> bool:
        for text in texts:
            try:
                btn = self.page.get_by_role("button", name=text, exact=False).first
                btn.wait_for(state="visible", timeout=8000)
                btn.click()
                return True
            except Exception:  # noqa: BLE001
                continue
        for text in texts:
            if self.click_any([f"button:has-text('{text}')"]):
                return True
        return False

    def fill_any(self, selectors: List[str], value: str) -> bool:
        for sel in selectors:
            try:
                loc = self.page.locator(sel).first
                loc.wait_for(state="visible", timeout=8000)
                loc.fill(value)
                return True
            except Exception:  # noqa: BLE001
                continue
        return False

    def set_toggle(self, selectors: List[str], checked: bool) -> Optional[bool]:
        """Set an on/off toggle. Returns the state, None when absent.

        Tries the checkbox input first (real ids such as #feature-SplitTCP),
        then the label text (plan-gated options have no stable id).
        """
        page = self.page
        # direct checkbox input
        for sel in selectors:
            try:
                cb = page.locator(f"{sel} input[type='checkbox']").first
                if not cb.count():
                    cb = page.locator(sel).first if sel.startswith("#") \
                        else page.locator(sel).first
                    if not cb.count():
                        continue
                    # sel may BE the input
                    if cb.get_attribute("type") != "checkbox":
                        continue
                if cb.is_checked() != checked:
                    cb.click(force=True)
                return checked
            except Exception:  # noqa: BLE001
                continue
        # label-text fallback (clicking the label toggles the input)
        for sel in selectors:
            if "has-text" not in sel:
                continue
            try:
                label = page.locator(sel).first
                label.wait_for(state="visible", timeout=4000)
                row = label.locator(
                    "xpath=ancestor::div[.//input[@type='checkbox']][1]")
                if row.count():
                    cb = row.locator("input[type='checkbox']").first
                    if cb.is_checked() != checked:
                        label.click()
                    return checked
            except Exception:  # noqa: BLE001
                continue
        return None

    # kept for compatibility with older call sites
    def set_checkbox_for_label(self, label_text: str, checked: bool) -> Optional[bool]:
        return self.set_toggle([f"label:has-text('{label_text}')",
                                f"text={label_text}"], checked)

    def click_dropdown_item(self, texts: List[str], option_text: str,
                            timeout: float = 15000) -> bool:
        """Legacy helper: custom dropdown by label text."""
        if not self.click_any([f"text={t}" for t in texts], timeout=timeout):
            return False
        time.sleep(0.4)
        candidates = [
            f"[role='option']:has-text('{option_text}')",
            f"li:has-text('{option_text}')",
            f"button:has-text('{option_text}')",
            f"div[role='menuitem']:has-text('{option_text}')",
            f"text='{option_text}'",
        ]
        return self.click_any(candidates, timeout=timeout)


def _section_for(protocol: str) -> str:
    return OVPN if protocol == "openvpn" else WG


def _link_selectors_for(protocol: str) -> List[str]:
    return OPENVPN_LINK_SELECTORS if protocol == "openvpn" else WIREGUARD_LINK_SELECTORS


def _name_selectors_for(protocol: str) -> List[str]:
    return (OVPN_CONFIG_NAME_SELECTORS + CONFIG_NAME_SELECTORS
            if protocol == "openvpn" else CONFIG_NAME_SELECTORS)


def _platform_selectors_for(protocol: str) -> List[str]:
    return (OVPN_PLATFORM_RADIO_SELECTORS if protocol == "openvpn"
            else PLATFORM_RADIO_SELECTORS)


def _free_category_selectors_for(protocol: str) -> List[str]:
    return (OVPN_FREE_CATEGORY_SELECTORS if protocol == "openvpn"
            else FREE_CATEGORY_SELECTORS)


def _config_matches(protocol: str, text: str) -> bool:
    if protocol == "openvpn":
        return looks_like_openvpn(text) and not looks_like_wireguard(text)
    return looks_like_wireguard(text)


class DownloadsPage:
    """Drives the logged-in Downloads page (WireGuard + OpenVPN)."""

    def __init__(self, worker, session) -> None:
        self.worker = worker
        self.session = session

    # ------------------------------------------------------------ server data
    def scrape_servers(self, alternative_routing: bool = True) -> List[LogicalServer]:
        """Refresh the server list (+ loads) from the logged-in page."""
        return self.worker.submit(
            lambda pw: self._scrape_servers_job(pw, alternative_routing),
            timeout=180)

    def _scrape_servers_job(self, pw, alternative_routing: bool = True
                            ) -> List[LogicalServer]:
        captured: List[Any] = []

        def on_response(resp):
            try:
                url = resp.url
                if any(p in url for p in LOGICALS_URL_PATTERNS):
                    body = resp.text()
                    data = json.loads(body)
                    captured.append(data)
            except Exception:  # noqa: BLE001
                pass

        browser, ctx = self.session._launch(pw, headless=True)
        try:
            page = ctx.new_page()
            page.on("response", on_response)
            bot = PageBot(page)
            bot.goto(DOWNLOADS_URL, alternative_routing=alternative_routing)
            settle(page)
            bot.click_any(WIREGUARD_LINK_SELECTORS, timeout=20000)
            time.sleep(2.0)

            servers: List[LogicalServer] = []
            for payload in captured:
                parsed = parse_logical_servers(payload)
                if parsed:
                    servers = parsed
                    log.info("captured logicals XHR: %d servers", len(servers))
                    break

            if not servers:
                servers = self._fetch_via_page(page,
                                               alternative=alternative_routing)
            if not servers:
                servers = self._scrape_tables(page)
            if not servers:
                bot.screenshot("servers-not-found")
                raise ScrapeError(
                    "could not obtain the server list — Proton may have changed "
                    "the page; see the debug screenshot in ~/.cache/cleanroom/"
                    "screenshots")
            return servers
        finally:
            browser.close()

    def _fetch_via_page(self, page, alternative: bool = True) -> List[LogicalServer]:
        """Ask the logged-in page context to fetch the logicals endpoint.

        With alternative routing the mirror API hosts (api.protonvpn.com,
        vpn-api.proton.me) are tried after the direct ones.
        """
        urls = list(LOGICALS_FETCH_URLS)
        if alternative:
            urls += LOGICALS_ALT_FETCH_URLS
        for url in urls:
            try:
                body = page.evaluate(
                    """async (u) => {
                        const r = await fetch(u, {credentials: 'include'});
                        return await r.text();
                    }""", url)
                data = json.loads(body)
                servers = parse_logical_servers(data)
                if servers:
                    log.info("page-fetched %s: %d servers", url, len(servers))
                    return servers
            except Exception as e:  # noqa: BLE001
                log.debug("page fetch %s failed: %s", url, e)
        return []

    def _scrape_tables(self, page) -> List[LogicalServer]:
        """Fallback: read the rendered 'Free server configs' country tables.

        Clicks the Free category first, so the tables contain free servers
        only — paid servers never even render for us.
        """
        bot = PageBot(page)
        bot.click_any(FREE_CATEGORY_SELECTORS, timeout=8000)
        time.sleep(0.6)
        self._open_all_countries(page, WG)
        servers: List[LogicalServer] = []
        try:
            rows = page.locator(f"{WG} tbody tr")
            count = min(rows.count(), 600)
            for i in range(count):
                try:
                    txt = (rows.nth(i).inner_text() or "").strip()
                except Exception:  # noqa: BLE001
                    continue
                if not txt:
                    continue
                parsed = parse_server_row(txt)
                if not parsed:
                    continue
                name, load = parsed
                servers.append(LogicalServer(
                    id=name, name=name,
                    entry_country=name.split("-")[0], exit_country=name.split("-")[0],
                    domain="", tier=0, features=0,
                    load=load,
                    score=1e9,
                ))
        except Exception as e:  # noqa: BLE001
            log.debug("table scrape failed: %s", e)
        if servers:
            log.info("DOM-scraped %d free servers from the country tables",
                     len(servers))
        return servers

    def _open_all_countries(self, page, section: str = WG) -> None:
        """Expand every country <details> in a section's server list."""
        try:
            details = page.locator(f"{section} details")
            for i in range(min(details.count(), 60)):
                d = details.nth(i)
                try:
                    # NB: attribute "open" is "" when present — use el.open
                    if not d.evaluate("el => el.open"):
                        d.locator("summary").first.click(timeout=2000)
                        time.sleep(0.1)
                except Exception:  # noqa: BLE001
                    continue
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------- config
    def create_config(self, server: Optional[LogicalServer],
                      options: ConfigOptions, config_name: str = "Cleanroom",
                      fastest: bool = False) -> ScrapeResult:
        """Generate + capture a config for the chosen server.

        ``options.protocol`` selects the section used on the Downloads page:
        WireGuard or OpenVPN (with its TCP/UDP transport).
        """
        job = lambda pw: self._create_config_job(pw, server,  # noqa: E731
                                                 options, config_name, fastest)
        return self.worker.submit(job, timeout=300)

    def _create_config_job(self, pw, server, options: ConfigOptions,
                           config_name, fastest) -> ScrapeResult:
        protocol = options.protocol if options.protocol == "openvpn" else "wireguard"
        section = _section_for(protocol)
        browser, ctx = self.session._launch(pw, headless=True)
        try:
            page = ctx.new_page()
            bot = PageBot(page)
            bot.goto(DOWNLOADS_URL,
                     alternative_routing=options.alternative_routing)
            settle(page)

            if not bot.click_any(_link_selectors_for(protocol), timeout=25000):
                bot.screenshot("section-not-found")
                raise ScrapeError(
                    f"{protocol.capitalize()} section not found on the "
                    "Downloads page")
            time.sleep(1.0)

            # existing certificates (used to detect the NEW one after Create,
            # and to reuse a matching config instead of generating another)
            existing = self._read_certificates(page, section)

            # 1. name the configuration
            bot.fill_any(_name_selectors_for(protocol), config_name)

            # 2. platform: GNU/Linux radio
            if not bot.click_any(_platform_selectors_for(protocol), timeout=8000):
                log.warning("could not select the Linux platform radio (continuing)")

            # 3. OpenVPN transport: TCP or UDP radio
            if protocol == "openvpn":
                self._set_transport(bot, options.openvpn_transport)

            # 4. VPN options: VPN Accelerator / NAT-PMP / Moderate NAT toggles
            self._set_vpn_options(bot, options)

            # 5. free servers only: click the "Free server configs" category
            bot.click_any(_free_category_selectors_for(protocol), timeout=8000)
            time.sleep(0.4)

            # 6. server selection (our own pick, so the config matches `server`)
            used_recommended = False
            if server is None:
                used_recommended = True   # leave Proton's recommended server
                log.info("no server given — leaving the page's recommended one")
            else:
                self._select_server(bot, page, server.name, section)

            # 7. capture the generated config: XHR body, new certificate
            #    textarea, or the Download button's file — in that order.
            captured_text: List[str] = []

            def on_response(resp):
                try:
                    if any(k in resp.url for k in ("config", "wireguard",
                                                   "certificate", "wg",
                                                   "openvpn", "ovpn")):
                        body = resp.text()
                        if _config_matches(protocol, body):
                            captured_text.append(body)
                except Exception:  # noqa: BLE001
                    pass

            page.on("response", on_response)

            if not bot.click_button_with_text(["Create"]):
                bot.screenshot("create-button-not-found")
                raise ScrapeError("'Create' button not found")

            text = self._await_capture(page, captured_text, existing,
                                       server.name if server else None,
                                       protocol=protocol, section=section,
                                       timeout=25.0)

            if not text:
                # docs flow: Create → wait → per-certificate Download button
                for _ in range(15):
                    if bot.click_button_with_text(["Download"]):
                        try:
                            with page.expect_download(timeout=45000) as dl_info:
                                bot.click_button_with_text(["Download"])
                            dl = dl_info.value
                            text = open(dl.path(), encoding="utf-8").read()
                            if _config_matches(protocol, text):
                                break
                        except Exception:  # noqa: BLE001
                            pass
                    time.sleep(1.0)

            if not text or not _config_matches(protocol, text):
                bot.screenshot("config-not-captured")
                raise ScrapeError(
                    f"{protocol.capitalize()} config was not captured — see "
                    "debug screenshot")

            DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
            ext = "ovpn" if protocol == "openvpn" else "conf"
            fname = DOWNLOADS_DIR / f"{(server.name if server else 'recommended')}.{ext}"
            fname.write_text(text, encoding="utf-8")
            return ScrapeResult(config_text=text, server=server,
                                used_recommended=used_recommended,
                                protocol=protocol)
        finally:
            browser.close()

    def _set_transport(self, bot: PageBot, transport: str) -> None:
        """Select the OpenVPN transport (UDP or TCP) radio on the page."""
        want_udp = str(transport).lower() != "tcp"
        selectors = OVPN_UDP_SELECTORS if want_udp else OVPN_TCP_SELECTORS
        if bot.click_any(selectors, timeout=8000):
            log.info("OpenVPN transport selected: %s", "udp" if want_udp else "tcp")
        else:
            log.warning("could not select the OpenVPN %s radio (continuing "
                        "with the page default)", transport)

    def _await_capture(self, page, captured_text: List[str],
                       existing: Dict[str, tuple], server_name: Optional[str],
                       *, protocol: str = "wireguard", section: str = WG,
                       timeout: float = 25.0) -> Optional[str]:
        """Wait for the generated config to appear via any capture path."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if captured_text:
                return captured_text[0]
            certs = self._read_certificates(page, section)
            for cert_id, (name, text) in certs.items():
                if cert_id in existing:
                    continue                      # old certificate
                if not _config_matches(protocol, text):
                    continue
                if server_name and name and name != server_name:
                    continue                      # someone else's new cert
                log.info("captured config from new certificate block %s (%s)",
                         cert_id[:24], name)
                return text
            time.sleep(0.8)
        # last resort: an existing certificate for this exact server
        if server_name:
            for cert_id, (name, text) in self._read_certificates(
                    page, section).items():
                if name == server_name and _config_matches(protocol, text):
                    log.info("re-using existing certificate for %s", server_name)
                    return text
        return captured_text[0] if captured_text else None

    # -------------------------------------------------------------- harvest
    def harvest_configs(self) -> List[Tuple[str, str]]:
        """Read every existing certificate's config from the page (both the
        WireGuard and the OpenVPN section).

        Returns [(server_name, config_text)] — used to warm the local config
        cache so connections work without downloading anything. The protocol
        is recovered from each config's text by the cache layer.
        """
        return self.worker.submit(lambda pw: self._harvest_job(pw), timeout=180)

    def _harvest_job(self, pw) -> List[Tuple[str, str]]:
        browser, ctx = self.session._launch(pw, headless=True)
        try:
            page = ctx.new_page()
            bot = PageBot(page)
            bot.goto(DOWNLOADS_URL)
            settle(page)
            out: List[Tuple[str, str]] = []
            seen: set = set()
            for section, proto_name in ((WG, "WireGuard"), (OVPN, "OpenVPN")):
                try:
                    if section == OVPN:
                        # the WG section is the default view; OpenVPN needs
                        # its tab clicked before its certificates render
                        bot.click_any(OPENVPN_LINK_SELECTORS, timeout=15000)
                        time.sleep(1.0)
                    certs = self._read_certificates(page, section)
                except Exception as e:  # noqa: BLE001
                    log.debug("%s certificate harvest skipped: %s", proto_name, e)
                    continue
                for _cert_id, (name, text) in certs.items():
                    if name and (looks_like_wireguard(text)
                                 or looks_like_openvpn(text)) and (name, section) not in seen:
                        seen.add((name, section))
                        out.append((name, text))
                log.info("harvested %d existing %s configs from the Downloads page",
                         len(certs), proto_name)
            return out
        finally:
            browser.close()

    def _read_certificates(self, page, section: str = WG) -> Dict[str, tuple]:
        """{certificate-id: (server_name, config_text)} rendered in a section."""
        certs: Dict[str, tuple] = {}
        try:
            blocks = page.locator(f"{section} {CERTIFICATE_BLOCKS}")
            for i in range(min(blocks.count(), 50)):
                try:
                    block = blocks.nth(i)
                    cert_id = block.get_attribute("data-certificate-id") or str(i)
                    ta = block.locator(CERT_TEXTAREA).first
                    if not ta.count():
                        continue
                    text = ta.input_value() or ta.inner_text() or ""
                    if not (looks_like_wireguard(text) or looks_like_openvpn(text)):
                        continue
                    # "Config to connect to CA-FREE#1"
                    name = ""
                    try:
                        label_txt = block.locator("label").first.inner_text() or ""
                        m = re.search(r"connect to\s+([A-Z0-9-]+#\d+)", label_txt)
                        if m:
                            name = m.group(1)
                    except Exception:  # noqa: BLE001
                        pass
                    if not name:
                        from ..vpn.config_cache import parse_config_meta
                        name = parse_config_meta(text).get("server") or ""
                    certs[cert_id] = (name, text)
                except Exception:  # noqa: BLE001
                    continue
        except Exception as e:  # noqa: BLE001
            log.debug("certificate scan failed: %s", e)
        return certs

    # ------------------------------------------------------------- helpers
    def _set_vpn_options(self, bot: PageBot, options: ConfigOptions) -> None:
        """Flip the inline option toggles (verified ids on the real page)."""
        toggles = (
            (["#feature-SplitTCP", "label:has-text('VPN Accelerator')",
              "text=VPN Accelerator"], options.vpn_accelerator, "VPN Accelerator"),
            (["#feature-PortForwarding", "label:has-text('NAT-PMP')",
              "label:has-text('Port Forwarding')", "text=NAT-PMP"],
             options.nat_pmp_port_forward, "NAT-PMP"),
            (["label:has-text('Moderate NAT')", "text=Moderate NAT"],
             options.moderate_nat, "Moderate NAT"),
        )
        for selectors, want, label in toggles:
            got = bot.set_toggle(selectors, want)
            if got is None:
                log.debug("option %r not present on this plan", label)

    def _select_server(self, bot: PageBot, page, server_name: str,
                       section: str = WG) -> None:
        """Click the row-Create button for one specific free server."""
        row_sel = f'{section} tr:has(td:text-is("{server_name}"))'
        create_in_row = f'{row_sel} button:has-text("Create")'

        # 1. row already rendered?
        if bot.click_any([create_in_row], timeout=6000):
            return
        # 2. expand every country and retry
        self._open_all_countries(page, section)
        if bot.click_any([create_in_row], timeout=6000):
            return
        # 3. server-lookup search ("e.g., AT#62")
        if bot.fill_any(SERVER_LOOKUP_SELECTORS, server_name):
            time.sleep(0.4)
            bot.click_any(SEARCH_BUTTON_SELECTORS, timeout=5000)
            time.sleep(1.2)
            if bot.click_any([create_in_row], timeout=8000):
                return
            # search results may render rows outside the section scoping
            if bot.click_any([
                f'tr:has(td:text-is("{server_name}")) button:has-text("Create")',
            ], timeout=5000):
                return
        bot.screenshot("server-row-not-found")
        raise ScrapeError(f"server {server_name!r} not selectable")
