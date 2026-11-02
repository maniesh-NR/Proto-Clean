"""Controller: the app state machine tying account session, server store,
tunnel, DNS blocker and port forwarding together. UI-agnostic (callbacks),
so it can be driven headless (tests) or from Qt."""

from __future__ import annotations

import os
import threading
import time
from enum import Enum
from typing import Callable, List, Optional

from . import credentials as creds
from .account.browser import AccountSession, LoginOutcome
from .account.downloads_page import ConfigOptions, DownloadsPage
from .log import get
from .netshield.blocklists import BlocklistManager
from .netshield.dns_server import DnsBlocker, DnsUpstream
from .paths import DNS_BLOCKER_PORT, ensure_dirs
from .servers.models import LogicalServer
from .servers.selection import fastest_server
from .servers.store import ServerStore
from .settings import (Settings, BlocklistSource, load_settings, update)
from .vpn.config_cache import ConfigCache
from .vpn.helper import Helper, HelperError, helper_installed
from .vpn.monitor import TunnelMonitor
from .vpn.portforward import PortForwarder
from .vpn.tunnel import TunnelManager

log = get("controller")


class State(str, Enum):
    LOGGED_OUT = "logged_out"
    LOGGED_IN = "logged_in"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"


class Controller:
    """Long-running orchestrator. Long operations run in worker threads."""

    def __init__(self) -> None:
        ensure_dirs()
        self.settings: Settings = load_settings()
        self.state: State = State.LOGGED_OUT
        self.state_detail: str = ""
        self.session = AccountSession()
        self.downloads = DownloadsPage(self.session.worker, self.session)
        self.store = ServerStore()
        self.blocklists = BlocklistManager(self.settings.netshield.blocklists)
        self.config_cache = ConfigCache()
        self.dns: Optional[DnsBlocker] = None
        self.dns_thread_lock = threading.Lock()
        self._blocklist_lock = threading.Lock()

        self._op_lock = threading.Lock()
        self._threads: List[threading.Thread] = []

        self.on_state: Callable = lambda state, detail: None
        self.on_servers: Callable = lambda servers: None
        self.on_stats: Callable = lambda stats: None
        self.on_port: Callable = lambda port: None
        self.on_message: Callable = lambda text, level: None
        self.on_blocklists: Callable = lambda entries: None
        self.on_login_event: Callable = lambda kind, detail: None
        self.totp_provider: Callable[[], Optional[str]] = lambda: None

        # pending login request: {mode: stored|once|interactive, username,
        # password, totp_secret, remember} — consumed by the login worker
        self._login_request: Optional[dict] = None
        self.session.on_event = self._on_session_event

        self.tunnel: Optional[TunnelManager] = None
        self.monitor: Optional[TunnelMonitor] = None
        self.port_forwarder: Optional[PortForwarder] = None
        self.current_server: Optional[LogicalServer] = None
        self.connected_via: dict = {}

    # ------------------------------------------------------------- plumbing
    def _set_state(self, state: State, detail: str = "") -> None:
        self.state = state
        self.state_detail = detail
        log.info("state -> %s (%s)", state, detail)
        self.on_state(state, detail)

    def _spawn(self, fn, name: str) -> threading.Thread:
        t = threading.Thread(target=fn, daemon=True, name=name)
        t.start()
        return t

    def helper_ready(self) -> bool:
        return helper_installed()

    # ------------------------------------------------------------- account
    def login_async(self) -> None:
        """Auto-login with the stored credentials (and cached session)."""
        self._login_request = {"mode": "stored"}
        self._spawn(self._login_worker, "proto_clean-login")

    def login_once_async(self, username: str, password: str,
                         totp_secret: str = "", remember: bool = True) -> None:
        """Log in with credentials typed in the UI.

        With ``remember`` the credentials (+ optional TOTP secret) are saved
        so future launches auto-login; without it they are used once and
        kept only in memory for this attempt.
        """
        if remember:
            creds.store_credentials(username, password)
            if totp_secret:
                creds.store_totp_secret(totp_secret)
        self._login_request = {
            "mode": "once", "username": username, "password": password,
            "totp_secret": totp_secret or None,
        }
        self._spawn(self._login_worker, "proto_clean-login")

    def login_interactive_async(self, username: str = "",
                                password: str = "") -> None:
        """Open a visible browser window and let the user log in by hand
        (CAPTCHA-friendly; the session is captured automatically)."""
        self._login_request = {
            "mode": "interactive", "username": username, "password": password,
        }
        self._spawn(self._login_worker, "proto_clean-login")

    def _on_session_event(self, kind: str, detail: str) -> None:
        """Relay login progress from the backend browser to the UI."""
        user_visible = {
            "captcha": ("Proton requires human verification — a browser "
                        "window opened; please complete it there so login "
                        "can continue", "warn"),
            "interactive_open": ("Waiting for you in the browser window — "
                                 "finish logging in there", "warn"),
            "interactive_done": ("Verification completed — logging in…", "info"),
            "interactive_timeout": ("the browser login window timed out", "warn"),
            "totp_needed": ("two-factor code requested", "info"),
            "session_restored": ("cached Proton session still valid", "info"),
        }
        entry = user_visible.get(kind)
        if entry:
            text, level = entry
            self.on_message(f"{text}" if kind != "interactive_timeout"
                            else f"Login: {detail}", level)
        # keep the status line fresh without touching the state machine
        if detail:
            try:
                self.on_state(self.state, detail)
            except Exception:  # noqa: BLE001
                pass
        self.on_login_event(kind, detail)

    def _login_worker(self) -> None:
        if not self._op_lock.acquire(blocking=False):
            self.on_message("another account operation is running", "warn")
            return
        request = self._login_request or {"mode": "stored"}
        self._login_request = None
        try:
            mode = request.get("mode", "stored")

            if mode == "interactive":
                self._set_state(State.LOGGED_OUT,
                                "interactive login — use the browser window")
                result = self.session.login_interactive(
                    request.get("username") or "",
                    request.get("password") or "")
                if result.outcome is LoginOutcome.SUCCESS:
                    self._after_login(fresh=True)
                else:
                    self._set_state(State.LOGGED_OUT, result.message)
                    self.on_message(f"Login failed: {result.message}", "error")
                return

            # stored / once modes: try the cached session first, unless the
            # user just typed fresh credentials (they may be a different
            # account than the cached session)
            if mode == "stored" and self.session.try_session():
                self._after_login()
                return

            username = request.get("username")
            password = request.get("password")
            if not (username and password):
                username, password = creds.load_credentials()
            if not username or not password:
                self._set_state(State.LOGGED_OUT, "no stored credentials")
                self.on_login_event(
                    "credentials_needed",
                    "no stored credentials — log in to enable auto-login")
                self.on_message(
                    "No stored credentials — use Log in… to add them", "warn")
                return

            totp_secret = request.get("totp_secret") or creds.load_totp_secret()

            def provider():
                ui_code = self.totp_provider()
                if ui_code:
                    return ui_code
                if totp_secret:
                    try:
                        from .totp import code_from
                        return code_from(totp_secret)
                    except Exception as e:  # noqa: BLE001
                        log.warning("TOTP generation failed: %s", e)
                return None

            self._set_state(State.LOGGED_OUT, "logging in…")
            result = self.session.login(username, password,
                                        totp_code_provider=provider)
            if result.outcome is LoginOutcome.SUCCESS:
                self._after_login(fresh=True)
            elif result.outcome is LoginOutcome.NEEDS_INTERACTION:
                self._after_login(fresh=True)
            elif result.outcome is LoginOutcome.BAD_CREDENTIALS:
                self._set_state(State.LOGGED_OUT, "wrong credentials")
                self.on_login_event("bad_credentials",
                                    "wrong username/password")
                self.on_message("Login failed: wrong username/password", "error")
            else:
                self._set_state(State.LOGGED_OUT, result.message)
                self.on_message(f"Login failed: {result.message}", "error")
        except Exception as e:  # noqa: BLE001
            log.exception("login crashed")
            self._set_state(State.LOGGED_OUT, str(e))
            self.on_message(f"Login error: {e}", "error")
        finally:
            self._op_lock.release()

    def _after_login(self, fresh: bool = False) -> None:
        self._set_state(State.LOGGED_IN, "logged in")
        self.refresh_servers_async()
        if fresh:
            self._spawn(self._harvest_configs_worker, "proto_clean-harvest")
        if self.settings.netshield.enabled:
            self.update_blocklists_async()

    def logout(self) -> None:
        self.disconnect_async()
        creds.clear_credentials()
        self.session.logout()
        self._set_state(State.LOGGED_OUT, "logged out")

    # ------------------------------------------------------------- servers
    def refresh_servers_async(self) -> None:
        self._spawn(self._refresh_servers_worker, "proto_clean-servers")

    def _emit_servers(self) -> None:
        """Push the *free-only* server list to the UI (paid excluded)."""
        self.on_servers(self.store.free_servers())

    def _refresh_servers_worker(self) -> None:
        try:
            servers = self.downloads.scrape_servers(
                alternative_routing=self.settings.advanced.alternative_routing)
            self.store.replace(servers)
            self._emit_servers()
        except Exception as e:  # noqa: BLE001
            log.exception("server refresh failed")
            if not self.store.servers:
                self.on_message(f"Could not refresh servers: {e}", "error")
            else:
                self.on_message(
                    f"Server refresh failed (using cached {len(self.store.free_servers())} free): {e}",
                    "warn")

    def select_server(self, server_id: Optional[str]) -> Optional[LogicalServer]:
        """Fastest when the toggle is on, otherwise the chosen server.

        Only free (tier 0) servers are ever eligible — paid servers are
        excluded from the list and from selection; requesting one falls
        back to the fastest free server with a warning.
        """
        free = self.store.free_servers()
        if self.settings.autoconnect_fastest or server_id is None:
            pick = fastest_server(free, max_tier=0)
            if pick:
                return pick
        if server_id:
            server = self.store.by_id(server_id)
            if server and server.is_free:
                return server
            if server:
                self.on_message(
                    f"{server.name} is a paid server — excluded; "
                    "using the fastest free server", "warn")
            pick = fastest_server(free, max_tier=0)
            if pick:
                return pick
        return None

    # ------------------------------------------------------------ connect
    def connect_async(self, server_id: Optional[str] = None) -> None:
        self._spawn(lambda: self._connect_worker(server_id), "proto_clean-connect")

    def _config_options(self) -> ConfigOptions:
        """Snapshot of every setting that shapes the downloaded config."""
        p = self.settings.protocol.normalized()
        return ConfigOptions(
            protocol=p.protocol,
            vpn_accelerator=self.settings.vpn_options.vpn_accelerator,
            moderate_nat=self.settings.vpn_options.moderate_nat,
            nat_pmp_port_forward=self.settings.port_forward.request_in_config,
            netshield_level=self.settings.vpn_options.proton_netshield_level,
            openvpn_transport=p.openvpn_transport,
            alternative_routing=self.settings.advanced.alternative_routing,
        )

    def _connect_worker(self, server_id: Optional[str]) -> None:
        if not self.helper_ready():
            self.on_message(
                "privileged helper missing — run scripts/install.sh first", "error")
            self._set_state(State.ERROR, "helper not installed")
            return
        if not self._op_lock.acquire(blocking=False):
            self.on_message("busy — try again in a moment", "warn")
            return
        try:
            self._set_state(State.CONNECTING, "choosing server…")
            if not self.session.logged_in:
                username, password = creds.load_credentials()
                if username and password:
                    if not self.session.try_session():
                        result = self.session.login(username, password,
                                                    totp_code_provider=self.totp_provider)
                        if result.outcome not in (LoginOutcome.SUCCESS,
                                                  LoginOutcome.NEEDS_INTERACTION):
                            self._set_state(State.LOGGED_OUT, result.message)
                            self.on_message(f"Login failed: {result.message}", "error")
                            return
                else:
                    self.on_message("add your Proton credentials in Settings", "warn")
                    self._set_state(State.LOGGED_OUT, "no credentials")
                    return

            if not self.store.servers:
                self._set_state(State.CONNECTING, "fetching servers…")
                self.store.replace(self.downloads.scrape_servers(
                    alternative_routing=self.settings.advanced.alternative_routing))
                self._emit_servers()

            server = self.select_server(server_id)
            if not server:
                self.on_message("no usable server found", "error")
                self._set_state(State.LOGGED_IN, "no servers")
                return

            options = self._config_options()
            self.current_server = server

            # ---- 1. try the locally cached config first (no download) -------
            cached = None
            if self.settings.cache_configs:
                cached = self.config_cache.get(server.name, options)
            if cached is not None:
                proto_label = ("OpenVPN" if cached.protocol == "openvpn"
                               else "WireGuard")
                self._set_state(
                    State.CONNECTING,
                    f"connecting to {server.name} (cached {proto_label} config"
                    + ("" if cached.exact else ", other options") + ")…")
                log.info("using cached config for %s (%s, %s, %s)", server.name,
                         cached.fingerprint, cached.protocol, cached.source)
                try:
                    self._bring_up(cached.text, server)
                    self.config_cache.mark_verified(server.name, cached.fingerprint)
                    self._set_connected(server, server_id,
                                        via_cache=True, exact=cached.exact)
                    return
                except Exception as e:  # noqa: BLE001
                    log.warning("cached config failed (%s) — re-downloading", e)
                    self.config_cache.note_failure(server.name, cached.fingerprint)
                    self._teardown_partial()
                    self.config_cache.invalidate(server.name)
                    self.on_message(
                        "saved config failed — downloading a fresh one…", "warn")

            # ---- 2. fresh download path -------------------------------------
            self._set_state(
                State.CONNECTING,
                f"generating {options.protocol} config for {server.name}…")
            result = self.downloads.create_config(server, options,
                                                  fastest=(server_id is None
                                                           and self.settings.autoconnect_fastest))
            if self.settings.cache_configs:
                self.config_cache.put(server.name, result.config_text, options)

            self._set_state(State.CONNECTING, "bringing the tunnel up…")
            self._bring_up(result.config_text, server)
            if self.settings.cache_configs:
                self.config_cache.mark_verified(server.name,
                                                options=options)
            self._set_connected(server, server_id, via_cache=False)
        except Exception as e:  # noqa: BLE001
            log.exception("connect failed")
            self._teardown_partial()
            self._set_state(State.ERROR, str(e))
            self.on_message(f"Connection failed: {e}", "error")
        finally:
            self._op_lock.release()

    def _bring_up(self, config_text: str, server: LogicalServer) -> dict:
        """Tunnel up (DNS blocker, kill switch, split tunnel) + liveness check."""
        from . import paths as _paths
        from .platforms import capabilities

        self._start_dns_blocker()

        caps = capabilities()
        proto = self.settings.protocol.normalized().protocol
        # a cached config of the other protocol wins over the setting
        if config_text.lstrip().startswith("["):
            proto = "wireguard"          # wg-quick config → WireGuard
        elif "remote " in config_text and "[Interface]" not in config_text:
            proto = "openvpn"            # .ovpn → OpenVPN
        netshield_on = self.settings.netshield.enabled
        custom_dns_on = (self.settings.advanced.custom_dns_enabled
                         and self.settings.advanced.custom_dns_list())
        dns_active = netshield_on or custom_dns_on
        self.tunnel = TunnelManager()
        up_info = self.tunnel.up(
            config_text,
            protocol=proto,
            openvpn_driver=self.settings.protocol.openvpn_driver,
            kill_switch=self.settings.kill_switch.enabled,
            allow_lan=self.settings.kill_switch.allow_lan,
            split_enabled=self.settings.split_tunnel.enabled,
            excluded_cidrs=(self.settings.split_tunnel.excluded_cidrs
                            if self.settings.split_tunnel.enabled else None),
            ipv6=self.settings.advanced.ipv6_support,
            ipv6_leak_protection=self.settings.advanced.ipv6_leak_protection,
            # Linux/macOS: the helper redirects/relays port 53 to the blocker
            # (uid-exempt so our own upstream queries do not loop).
            dns_blocker_uid=(os.getuid() if dns_active and not _paths.IS_WINDOWS
                             else None),
            # Windows: no firewall redirect needed — the blocker binds
            # 127.0.0.1:53 itself and the config's DNS points at it.
            dns_loopback=("127.0.0.1" if dns_active
                          and caps.dns_loopback_in_config else None),
        )
        self.connected_via = up_info

        self.monitor = TunnelMonitor(
            self.tunnel.helper, on_stats=lambda s: self.on_stats(s.as_dict()))
        self.monitor.start()

        # verify the tunnel actually works (catches stale/revoked configs)
        if not self.tunnel.wait_handshake(
                timeout=max(5, self.settings.config_verify_timeout)):
            what = ("OpenVPN daemon did not come up" if proto == "openvpn"
                    else "WireGuard handshake never completed")
            raise RuntimeError(
                f"tunnel is up but the {what} "
                "(stale or revoked config?)")

        # NAT-PMP speaks to the tunnel gateway (10.2.0.1) — works for both
        # protocols when the config was generated with port forwarding on
        if self.settings.port_forward.request_in_config:
            self.port_forwarder = PortForwarder(
                internal_port=self.settings.port_forward.internal_port,
                on_update=lambda port: self.on_port(port),
                on_error=lambda msg: self.on_message(f"Port forwarding: {msg}",
                                                     "warn"),
            )
            self.port_forwarder.start()
        return up_info

    def _set_connected(self, server: LogicalServer, server_id: Optional[str],
                       via_cache: bool, exact: bool = True) -> None:
        self._set_state(State.CONNECTED, server.name)
        proto = (getattr(self.tunnel, "protocol", None)
                 or self.settings.protocol.protocol)
        suffix = [proto.capitalize()]
        if via_cache:
            suffix.append("cached config")
            if not exact:
                suffix.append("different options")
        if server_id is None:
            suffix.append("fastest available")
        self.on_message(
            f"Connected to {server.name} ({server.load_label} load, "
            + ", ".join(suffix) + ")", "info")

    def _harvest_configs_worker(self) -> None:
        """Warm the config cache from the certificates already on the page.

        Proton renders every previously-created config (WireGuard and
        OpenVPN sections alike) in a readonly textarea — reading them means
        future connects need no download.
        """
        if not self.settings.cache_configs:
            return
        try:
            configs = self.downloads.harvest_configs()
            added = 0
            for name, text in configs:
                current = self.config_cache.get(name)
                if current is not None and current.verified_at:
                    continue          # keep the entry we already verified
                self.config_cache.put(name, text, options=None, source="harvested")
                added += 1
            if added:
                log.info("config cache warmed with %d harvested configs", added)
                self.on_message(
                    f"cached {added} existing config(s) from your account", "info")
        except Exception as e:  # noqa: BLE001
            log.debug("config harvest skipped: %s", e)

    def disconnect_async(self) -> None:
        self._spawn(self._disconnect_worker, "proto_clean-disconnect")

    def _disconnect_worker(self) -> None:
        if not self._op_lock.acquire(blocking=False):
            self.on_message("busy — try again in a moment", "warn")
            return
        try:
            self._set_state(State.DISCONNECTING, "disconnecting…")
            self._teardown_partial()
            self._set_state(State.LOGGED_IN if self.session.logged_in
                            else State.LOGGED_OUT, "disconnected")
        finally:
            self._op_lock.release()

    def _teardown_partial(self) -> None:
        if self.port_forwarder:
            self.port_forwarder.stop()
            self.port_forwarder = None
            self.on_port(None)
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
        if self.tunnel:
            try:
                self.tunnel.down(dns_blocker=self.settings.netshield.enabled)
            except HelperError as e:
                log.warning("tunnel down: %s", e)
            self.tunnel = None
        self._stop_dns_blocker()

    # ------------------------------------------------------------ netshield
    def _start_dns_blocker(self) -> None:
        """Start the embedded DNS resolver when it has a job to do.

        * ad blocking on  → blocklist filter active;
        * custom DNS on   → the blocker forwards to the user's servers (an
          empty filter is used when ad blocking is off) — this is how custom
          DNS works for BOTH protocols on every platform;
        * both off        → no local resolver at all.
        """
        from .netshield.blocklists import DomainFilter

        netshield_on = self.settings.netshield.enabled
        custom = (self.settings.advanced.custom_dns_list()
                  if self.settings.advanced.custom_dns_enabled else [])
        if not netshield_on and not custom:
            return
        with self.dns_thread_lock:
            if self.dns and self.dns.running:
                return
            flt = self.blocklists.filter
            if netshield_on:
                n = self.blocklists.load_cached()
                if not n:
                    self.blocklists.rebuild()
                    n = len(self.blocklists.filter)
                if not n:
                    result = self.blocklists.update_all()
                    if not result.ok:
                        log.warning("blocklist update failed: %s", result.error)
                flt = self.blocklists.filter
            else:
                flt = DomainFilter([])   # custom DNS only: no filtering
            self.dns = DnsBlocker(
                flt,
                upstream=DnsUpstream(
                    use_doh=self._doh_preferred(custom),
                    udp_resolvers=custom or ["10.2.0.1"],
                ),
                nxdomain_for_blocked=self.settings.netshield.block_nxdomain,
                port=DNS_BLOCKER_PORT,
            )
            self.dns.start()

    def _doh_preferred(self, custom: Optional[list] = None) -> bool:
        """Custom DNS servers are queried directly; without them DoH via
        the tunnel is preferred (plain-UDP fallback is automatic)."""
        return not custom

    def _stop_dns_blocker(self) -> None:
        with self.dns_thread_lock:
            if self.dns:
                self.dns.stop()
                self.dns = None

    # -------------------------------------------------- blocklist management
    def _notify_blocklists(self) -> None:
        try:
            self.on_blocklists(self.blocklists.entries())
        except Exception:  # noqa: BLE001
            log.exception("on_blocklists callback failed")

    def _persist_blocklists(self) -> None:
        """Save the current source list to settings.json and refresh self.settings."""
        update(**{"netshield.blocklists": [b.to_json()
                                           for b in self.blocklists.sources]})
        self.settings = load_settings()

    def _apply_live_filter(self, total: Optional[int] = None) -> None:
        """Push the rebuilt filter into the running DNS blocker (if any)."""
        if total is None:
            total = len(self.blocklists.filter)
        update(**{
            "netshield.domain_count": total,
            "netshield.last_update": time.strftime("%Y-%m-%d %H:%M"),
        })
        self.settings = load_settings()
        with self.dns_thread_lock:
            if self.dns and self.dns.running:
                self.dns.reload_filter(self.blocklists.filter)
        self._notify_blocklists()

    def add_blocklist_async(self, name: str, url: str) -> None:
        self._spawn(lambda: self._add_blocklist_worker(name, url),
                    "proto_clean-blocklist-add")

    def _add_blocklist_worker(self, name: str, url: str) -> None:
        url = url.strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            self.on_message("blocklist URL must start with http(s)://", "error")
            return
        with self._blocklist_lock:
            if any(b.url == url for b in self.blocklists.sources):
                self.on_message("that blocklist URL is already configured", "warn")
                return
            name = (name or "").strip() or BlocklistSource.from_json({"url": url}).name
            if any(b.name == name for b in self.blocklists.sources):
                name = f"{name} (2)"
            self.blocklists.sources.append(BlocklistSource(name=name, url=url))
            self._persist_blocklists()
        self.on_message(f"added blocklist {name!r} — downloading…", "info")
        result = self.blocklists.update_one(name)
        if result.ok:
            self._apply_live_filter(result.total_domains)
            self.on_message(
                f"Blocklist {name!r} updated — {result.total_domains:,} domains total",
                "info")
        else:
            self.on_message(f"Blocklist download failed: {result.error}", "error")
        self._notify_blocklists()

    def remove_blocklist_async(self, name: str) -> None:
        self._spawn(lambda: self._remove_blocklist_worker(name),
                    "proto_clean-blocklist-remove")

    def _remove_blocklist_worker(self, name: str) -> None:
        with self._blocklist_lock:
            src = self.blocklists.by_name(name)
            if not src:
                self.on_message(f"no blocklist named {name!r}", "warn")
                return
            self.blocklists.sources = [b for b in self.blocklists.sources
                                       if b.name != name]
            self.blocklists.remove_cached(src.url)
            self._persist_blocklists()
        self._apply_live_filter()
        self.on_message(f"removed blocklist {name!r}", "info")

    def set_blocklist_enabled_async(self, name: str, enabled: bool) -> None:
        self._spawn(lambda: self._set_enabled_worker(name, enabled),
                    "proto_clean-blocklist-toggle")

    def _set_enabled_worker(self, name: str, enabled: bool) -> None:
        with self._blocklist_lock:
            src = self.blocklists.by_name(name)
            if not src:
                return
            src.enabled = enabled
            self._persist_blocklists()
            self.blocklists.rebuild()
        self._apply_live_filter()
        self.on_message(
            f"blocklist {name!r} {'enabled' if enabled else 'disabled'}", "info")

    def update_blocklists_async(self, name: Optional[str] = None) -> None:
        """Update one list by name, or all of them when name is None."""
        self._spawn(lambda: self._update_blocklists(name),
                    "proto_clean-blocklists-refresh")

    def _update_blocklists(self, name: Optional[str] = None) -> None:
        result = (self.blocklists.update_one(name) if name
                  else self.blocklists.update_all())
        if result.ok:
            self._apply_live_filter(result.total_domains)
            what = name if name else "all blocklists"
            self.on_message(
                f"{what} updated — {result.total_domains:,} domains", "info")
        else:
            self.on_message(f"Blocklist update failed: {result.error}", "warn")
        self._notify_blocklists()

    def blocklist_entries(self):
        """Synchronous snapshot for UI menus."""
        return self.blocklists.entries()

    def reload_settings(self) -> None:
        self.settings = load_settings()
        self.blocklists.set_sources(self.settings.netshield.blocklists)

    # ----------------------------------------------------------- split apps
    def move_pid_to_split(self, pid: int) -> bool:
        if not self.tunnel or not self.tunnel.split.active:
            self.on_message("connect with split tunneling enabled first", "warn")
            return False
        try:
            self.tunnel.split.move_pid(pid)
            self.on_message(f"PID {pid} now bypasses the tunnel", "info")
            return True
        except HelperError as e:
            self.on_message(f"could not move PID: {e}", "error")
            return False

    def launch_excluded(self, executable: str) -> bool:
        if not self.tunnel or not self.tunnel.split.active:
            self.on_message("connect with split tunneling enabled first", "warn")
            return False
        try:
            pid = self.tunnel.split.launch_excluded(executable)
            self.on_message(f"launched {executable} (pid {pid}) outside the tunnel",
                            "info")
            return True
        except HelperError as e:
            self.on_message(f"could not launch: {e}", "error")
            return False

    def shutdown(self) -> None:
        try:
            self._teardown_partial()
        finally:
            self.session.worker.stop()
