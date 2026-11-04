"""Controller: the app state machine tying account session, server store,
tunnel, DNS blocker and port forwarding together. UI-agnostic (callbacks),
so it can be driven headless (tests) or from Qt."""

from __future__ import annotations

import asyncio
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
from .proton.guest import (
    GuestAuth,
    GuestAuthError,
    GuestSession,
    build_wg_quick_config,
    gen_x25519_keypair,
)
from .servers.models import LogicalServer
from .servers.selection import fastest_server
from .servers.store import ServerStore
from .settings import (Settings, BlocklistSource, load_settings, update)
from .vpn.config_cache import ConfigCache
from .vpn.helper import Helper, HelperError, helper_installed
from .vpn.monitor import TunnelMonitor
from .vpn.portforward import PortForwarder
from .vpn.tunnel import TunnelManager
from .vpn.xray import PROXY_ERROR, PROXY_OFF, PROXY_ON, PROXY_STARTING, XrayError, XrayManager
from .vpn.xrayconf import XrayProfile, XrayConfigError
from .vpn.samizdat import SamizdatManager
from .vpn.samizdatconf import SamizdatProfile, SamizdatConfigError
from .vpn.bond import BondManager

log = get("controller")


def _proxy_server_dict(raw: str) -> Optional[dict]:
    """Normalize a user-entered proxy ("127.0.0.1:8787",
    "socks5://host:1080", "http://host:3128") into a Playwright proxy
    dict; None when unusable."""
    s = (raw or "").strip()
    if not s:
        return None
    if "://" not in s:
        s = "http://" + s
    scheme, _, rest = s.partition("://")
    if scheme not in ("http", "https", "socks4", "socks5") or not rest \
            or ":" not in rest:
        return None
    return {"server": s}


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
        self._proxy_listeners: List[Callable] = []
        self.totp_provider: Callable[[], Optional[str]] = lambda: None

        # pending login request: {mode: stored|once|interactive|guest,
        # username, password, totp_secret, remember} — consumed by the login
        # worker
        self._login_request: Optional[dict] = None
        self.session.on_event = self._on_session_event

        self.tunnel: Optional[TunnelManager] = None
        self.monitor: Optional[TunnelMonitor] = None
        self.port_forwarder: Optional[PortForwarder] = None
        self.current_server: Optional[LogicalServer] = None
        self.connected_via: dict = {}

        # Xray / v2ray proxy (VLESS REALITY / Trojan) + samizdat (Lantern)
        # + link bonding (multi-adapter)
        self.xray = XrayManager()
        self._protocol_engine = None          # generic protocol layer
        self.samizdat = SamizdatManager()
        self.bond = BondManager()
        self.proxy_state: str = PROXY_OFF
        self._proxy_lock = threading.Lock()
        self.bond_state: str = PROXY_OFF
        self._bond_listeners: List[Callable] = []
        self._bond_lock = threading.Lock()

        # Guest-mode (credentialless) state. When ``guest_session`` is set
        # the controller uses the Proton API directly (GuestAuth) instead of
        # the backend browser session — no Playwright, no CAPTCHA, no
        # account. Free-tier (Tier=0) servers only; max one connection.
        self.guest_session: Optional["GuestSession"] = None
        self.guest_auth: Optional["GuestAuth"] = None
        self._guest_loop: Optional[asyncio.AbstractEventLoop] = None

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

    def login_guest_async(self) -> None:
        """Continue as guest — credentialless Proton API flow.

        Spawns a worker that calls the Proton API directly (no browser,
        no account, no CAPTCHA) to obtain a Tier=0 session bound to a
        client-generated Ed25519 keypair. The session is persisted so
        subsequent launches auto-resume as guest until the user explicitly
        logs out. Free servers only; one concurrent connection.
        """
        self._login_request = {"mode": "guest"}
        self._spawn(self._login_worker, "proto_clean-guest-login")

    def is_guest(self) -> bool:
        """True when the controller is running a credentialless guest
        session (no Proton account)."""
        return self.guest_session is not None

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
        self._apply_browser_proxy()      # maybe log in through the proxy
        request = self._login_request or {"mode": "stored"}
        self._login_request = None
        try:
            mode = request.get("mode", "stored")

            if mode == "guest":
                self._login_guest_worker()
                return

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
        # Tear down any guest session first so a subsequent "Log in…"
        # properly resets to account-mode.
        if self.guest_session is not None:
            self._stop_guest_loop()
            self.guest_session = None
            self.guest_auth = None
        creds.clear_guest_session()
        creds.clear_credentials()
        self.session.logout()
        self._set_state(State.LOGGED_OUT, "logged out")

    # ----------------------------------------------------------- guest mode
    def _login_guest_worker(self) -> None:
        """Guest-mode login worker — runs inside ``_login_worker`` (the
        op lock is already held). Calls the Proton API directly to obtain
        a credentialless Tier=0 session, persists it, then refreshes
        servers via the same API (no browser session needed)."""
        self._set_state(State.LOGGED_OUT, "guest login — contacting Proton API…")
        try:
            stored = creds.load_guest_session()
            if stored:
                try:
                    session = GuestSession.from_storage_dict(stored)
                except Exception as e:  # noqa: BLE001
                    log.warning("stored guest session unreadable: %s", e)
                    session = None
                if session and session.refresh_expires_at > time.time():
                    # Stored session still within refresh window — reuse it.
                    self.guest_session = session
                    self.guest_auth = GuestAuth()
                    self._spawn_guest_loop()
                    self._after_guest_login(fresh=False)
                    return
                # Stored session expired — clear it and do a fresh login.
                creds.clear_guest_session()

            # Fresh guest login: spin up a GuestAuth (owns an httpx client)
            # and run the async login coroutine on a dedicated event loop
            # so we don't collide with Qt's loop.
            auth = GuestAuth()
            loop = asyncio.new_event_loop()
            try:
                session = loop.run_until_complete(auth.login())
            finally:
                # Keep the loop alive for follow-up calls (fetch_logicals,
                # fetch_certificate) — park it on a background thread.
                self.guest_auth = auth
                self._guest_loop = loop
                self._spawn_guest_loop_with_loop(loop)
            self.guest_session = session
            creds.store_guest_session(session.to_storage_dict())
            self._after_guest_login(fresh=True)
        except GuestAuthError as e:
            log.warning("guest login failed: %s", e)
            self._set_state(State.LOGGED_OUT, str(e))
            self.on_message(f"Guest login failed: {e}", "error")
            self.on_login_event("guest_login_failed", str(e))
        except Exception as e:  # noqa: BLE001
            log.exception("guest login crashed")
            self._set_state(State.LOGGED_OUT, str(e))
            self.on_message(f"Guest login error: {e}", "error")
            self.on_login_event("guest_login_failed", str(e))

    def _spawn_guest_loop(self) -> None:
        """Park ``self._guest_loop`` on a background thread if not already."""
        if self._guest_loop is None and self.guest_auth is not None:
            loop = asyncio.new_event_loop()
            self._guest_loop = loop
            self._spawn_guest_loop_with_loop(loop)

    def _spawn_guest_loop_with_loop(self, loop) -> None:
        """Run ``loop`` forever on a daemon thread."""
        def _runner():
            asyncio.set_event_loop(loop)
            loop.run_forever()
        t = threading.Thread(target=_runner, daemon=True,
                             name="proto_clean-guest-loop")
        t.start()

    def _stop_guest_loop(self) -> None:
        """Stop the guest event loop and close the httpx client."""
        loop = self._guest_loop
        auth = self.guest_auth
        if loop is not None and auth is not None:
            try:
                fut = asyncio.run_coroutine_threadsafe(auth.close(), loop)
                fut.result(timeout=5)
            except Exception:  # noqa: BLE001
                pass
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:  # noqa: BLE001
                pass
        self._guest_loop = None

    def _after_guest_login(self, fresh: bool) -> None:
        """Mirror of ``_after_login`` for guest mode: marks the session
        as logged in and kicks off the guest-specific server refresh."""
        self.session.logged_in = True
        self.session.user_plan_hint = "guest"
        self._set_state(State.LOGGED_IN, "guest mode — free servers only")
        self.on_message("Guest login successful — free-tier servers only",
                        "info")
        self._spawn(self._refresh_guest_servers_worker,
                    "proto_clean-guest-servers")
        if self.settings.netshield.enabled:
            self.update_blocklists_async()

    def _refresh_guest_servers_worker(self) -> None:
        """Fetch the free-tier server list via the Proton API (guest mode)."""
        if self.guest_session is None or self.guest_auth is None \
                or self._guest_loop is None:
            self.on_message(
                "guest server refresh requested without a guest session",
                "warn")
            return
        try:
            coro = self.guest_auth.fetch_logicals(self.guest_session)
            fut = asyncio.run_coroutine_threadsafe(coro, self._guest_loop)
            guest_servers = fut.result(timeout=60)
            logicals = [s.to_logical_server() for s in guest_servers]
            self.store.replace(logicals)
            self._emit_servers()
            log.info("guest server refresh: %d free servers", len(logicals))
        except GuestAuthError as e:
            log.warning("guest server refresh failed: %s", e)
            self.on_message(f"Guest server refresh failed: {e}", "warn")
            if "token" in str(e).lower() or "auth" in str(e).lower():
                # Token expired — try a refresh, then retry once.
                self._refresh_guest_token_and_retry()
        except Exception as e:  # noqa: BLE001
            log.exception("guest server refresh crashed")
            self.on_message(f"Guest server refresh error: {e}", "warn")

    def _refresh_guest_token_and_retry(self) -> None:
        if self.guest_session is None or self.guest_auth is None \
                or self._guest_loop is None:
            return
        try:
            coro = self.guest_auth.refresh(self.guest_session)
            fut = asyncio.run_coroutine_threadsafe(coro, self._guest_loop)
            refreshed = fut.result(timeout=30)
            # Build a new GuestSession with the refreshed tokens (preserving
            # the device keypair + plan info).
            new_session = GuestSession(
                access_token=refreshed.get("access_token", ""),
                refresh_token=refreshed.get("refresh_token", ""),
                uid=refreshed.get("uid", self.guest_session.uid),
                expires_at=refreshed.get("expires_at", time.time() + 3600),
                refresh_expires_at=refreshed.get(
                    "refresh_expires_at",
                    self.guest_session.refresh_expires_at),
                scope=refreshed.get("scope", self.guest_session.scope),
                device_ed25519_pub_b64=self.guest_session.device_ed25519_pub_b64,
                device_ed25519_priv=self.guest_session.device_ed25519_priv,
                max_tier=0, max_connect=1, plan_name="guest",
            )
            self.guest_session = new_session
            creds.store_guest_session(new_session.to_storage_dict())
            log.info("guest token refreshed — retrying server fetch")
            self._spawn(self._refresh_guest_servers_worker,
                        "proto_clean-guest-servers-retry")
        except Exception as e:  # noqa: BLE001
            log.warning("guest token refresh failed: %s", e)
            self.on_message(
                "Guest session expired — log in as guest again", "warn")
            self.guest_session = None
            self._set_state(State.LOGGED_OUT, "guest session expired")

    def _connect_guest_worker(self, server: LogicalServer) -> None:
        """Guest-mode connect path: build a wg-quick config from the API
        certificate + server's X25519 public key, then bring up the tunnel.
        Bypasses the browser downloads-page flow entirely."""
        if self.guest_session is None or self.guest_auth is None \
                or self._guest_loop is None:
            self.on_message(
                "guest connect requested without a guest session", "error")
            self._set_state(State.ERROR, "no guest session")
            return
        try:
            self._set_state(State.CONNECTING,
                            f"generating WireGuard cert for {server.name}…")
            # Generate a fresh X25519 keypair for this connection (the
            # public key is sent to Proton; the private key goes into the
            # wg-quick [Interface] block).
            client_pub_b64, client_priv_b64 = gen_x25519_keypair()
            coro = self.guest_auth.fetch_certificate(
                self.guest_session, client_pub_b64, persistent=True)
            fut = asyncio.run_coroutine_threadsafe(coro, self._guest_loop)
            cert = fut.result(timeout=60)

            # DNS override: Proto Clean's DNS blocker redirects 127.0.0.1
            # on Linux/macOS via the firewall; Windows uses the
            # ``dns_loopback`` config knob. Match the regular path.
            from . import paths as _paths
            from .platforms import capabilities
            caps = capabilities()
            netshield_on = self.settings.netshield.enabled
            custom_dns_on = (self.settings.advanced.custom_dns_enabled
                             and self.settings.advanced.custom_dns_list())
            dns_active = netshield_on or custom_dns_on
            dns_server = None
            if dns_active:
                dns_server = ("127.0.0.1" if not _paths.IS_WINDOWS
                              else ("127.0.0.1" if caps.dns_loopback_in_config
                                    else None))

            # Build the wg-quick config text.
            # The GuestLogicalServer.to_logical_server() conversion stored
            # the server's X25519 pubkey + entry IP in physical[0]; reuse
            # the same fields directly from the stored LogicalServer.
            phys = server.physical[0] if server.physical else None
            if phys is None or not phys.x25519_pk or not phys.entry_ip:
                self.on_message(
                    f"{server.name} has no usable WireGuard endpoint "
                    "(missing X25519 key or entry IP)", "error")
                self._set_state(State.ERROR, "no WG endpoint")
                return

            # Build a tiny ad-hoc server object quacking like
            # GuestLogicalServer for build_wg_quick_config() (it only
            # reads entry_ip + x25519_public_key).
            server_view = type("_S", (), {
                "entry_ip": phys.entry_ip,
                "x25519_public_key": phys.x25519_pk,
            })()
            config_text = build_wg_quick_config(
                server_view, cert, client_priv_b64,
                dns_server=dns_server,
                ipv6=self.settings.advanced.ipv6_support,
            )

            self._set_state(State.CONNECTING, "bringing the tunnel up…")
            self._bring_up(config_text, server)
            self._set_connected(server, server.id, via_cache=False,
                                exact=True)
        except GuestAuthError as e:
            log.warning("guest connect failed: %s", e)
            self._teardown_partial()
            self._set_state(State.ERROR, str(e))
            self.on_message(f"Guest connect failed: {e}", "error")
        except Exception as e:  # noqa: BLE001
            log.exception("guest connect crashed")
            self._teardown_partial()
            self._set_state(State.ERROR, str(e))
            self.on_message(f"Guest connect error: {e}", "error")

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
        # Guest-mode dispatch: bypass the browser/downloads flow entirely
        # and use the Proton API directly (no Playwright, no CAPTCHA).
        if self.is_guest():
            try:
                self._set_state(State.CONNECTING, "choosing server…")
                if not self.store.servers:
                    self._set_state(State.CONNECTING, "fetching servers…")
                    self._refresh_guest_servers_worker()
                server = self.select_server(server_id)
                if not server:
                    self.on_message("no usable free server found", "error")
                    self._set_state(State.LOGGED_IN, "no servers")
                    return
                self.current_server = server
                self._connect_guest_worker(server)
            except Exception as e:  # noqa: BLE001
                log.exception("guest connect dispatch failed")
                self._teardown_partial()
                self._set_state(State.ERROR, str(e))
                self.on_message(f"Guest connect error: {e}", "error")
            finally:
                self._op_lock.release()
            return
        self._apply_browser_proxy()      # downloads may need the proxy
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
        self._apply_browser_proxy()      # blocklist fallback via proxy
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

    # --------------------------------------------------- Xray / v2ray proxy
    def _set_proxy(self, state: str, detail: str = "") -> None:
        self.proxy_state = state
        log.info("proxy -> %s (%s)", state, detail)
        for fn in list(self._proxy_listeners):
            try:
                fn(state, detail)
            except Exception:  # noqa: BLE001
                pass

    def add_proxy_listener(self, fn: Callable) -> None:
        """Subscribe to proxy state changes (multiple listeners allowed)."""
        if fn not in self._proxy_listeners:
            self._proxy_listeners.append(fn)

    def save_xray_settings(self, xray) -> None:
        """Persist an XraySettings (already normalized by the caller)."""
        from .settings import update
        update(**{"xray": xray})
        self.settings = load_settings()

    def save_samizdat_settings(self, sam) -> None:
        """Persist a SamizdatSettings (already normalized by the caller)."""
        from .settings import update
        update(**{"samizdat": sam})
        self.settings = load_settings()

    def _proxy_provider(self) -> str:
        p = self.settings.xray.provider
        return p if p in ("xray", "samizdat") else "xray"

    def _active_proxy_manager(self):
        """The manager the Start button drives (per settings.xray.provider)."""
        return self.samizdat if self._proxy_provider() == "samizdat" \
            else self.xray

    # ------------------------------------------------- browser / fetch proxy
    def browser_proxy(self) -> Optional[dict]:
        """Upstream proxy for the backend browser (and blocklist downloads),
        honoring advanced.browser_proxy_mode:

        * direct — None
        * auto   — the running proxy's local inbound (samizdat mixed port
          or the Xray SOCKS inbound)
        * custom — any host:port, e.g. Lantern on 127.0.0.1:8787
        """
        adv = getattr(getattr(self, "settings", None), "advanced", None)
        mode = getattr(adv, "browser_proxy_mode", "direct")
        if mode == "custom":
            return _proxy_server_dict(
                getattr(adv, "browser_proxy_custom",
                        "http://127.0.0.1:8787"))
        if mode == "auto":
            for mgr in (self.samizdat, self.xray):
                if mgr.running:
                    return {"server": f"socks5://127.0.0.1:{mgr.socks_port}"}
            if self.bond.running:      # nothing else up: ride the bond
                return {"server": f"socks5://127.0.0.1:{self.bond.socks_port}"}
        return None

    def _apply_browser_proxy(self) -> None:
        """Push the resolved browser proxy into the backend browser and
        the blocklist downloader (called before network operations)."""
        p = self.browser_proxy()
        try:
            self.session.proxy = p
        except Exception:  # noqa: BLE001
            pass
        try:
            self.blocklists.proxy = p["server"] if p else None
        except Exception:  # noqa: BLE001
            pass
        if p:
            log.info("browser/downloads routed through %s", p["server"])

    def start_proxy_async(self) -> None:
        """Start the selected proxy (Xray or samizdat) with its profile."""
        self._spawn(self._proxy_start_worker, "proto_clean-proxy")

    def stop_proxy_async(self) -> None:
        self._spawn(self._proxy_stop_worker, "proto_clean-proxy")

    def _profile_from_settings(self) -> XrayProfile:
        x = self.settings.xray.normalized()
        return XrayProfile(
            protocol=x.protocol, address=x.address, port=x.port, name=x.name,
            uuid=x.uuid, public_key=x.public_key, short_id=x.short_id,
            flow=x.flow, password=x.password, sni=x.sni,
            fingerprint=x.fingerprint, allow_insecure=x.allow_insecure,
            spider_x=x.spider_x,
        )

    def _samizdat_profile_from_settings(self) -> SamizdatProfile:
        s = self.settings.samizdat.normalized()
        return SamizdatProfile(
            address=s.address, port=s.port, name=s.name,
            public_key=s.public_key, short_id=s.short_id,
            server_name=s.server_name, fingerprint=s.fingerprint,
            padding_profile=s.padding_profile, max_jitter_ms=s.max_jitter_ms,
            max_streams_per_conn=s.max_streams_per_conn,
            data_threshold=s.data_threshold,
            disable_padding=s.disable_padding,
            disable_jitter=s.disable_jitter,
            disable_tcp_fragmentation=s.disable_tcp_fragmentation,
            disable_record_fragmentation=s.disable_record_fragmentation,
            idle_timeout=s.idle_timeout, connect_timeout=s.connect_timeout,
        )

    def _proxy_start_worker(self) -> None:
        if not self._proxy_lock.acquire(blocking=False):
            self.on_message("a proxy operation is already running", "warn")
            return
        try:
            mgr = self._active_proxy_manager()
            provider = self._proxy_provider()
            if mgr.running:
                self.on_message(f"the {provider} proxy is already running",
                                "warn")
                return
            self._set_proxy(PROXY_STARTING)
            # interop: when the bond is up and the engine's ride_bond
            # toggle is on, the proxy outbound dials through the bond's
            # local SOCKS — the tunnel rides every selected adapter
            upstream = 0
            if self.bond.running:
                ride = getattr(
                    self.settings.xray if provider != "samizdat"
                    else self.settings.samizdat, "ride_bond", True)
                if ride:
                    upstream = self.bond.socks_port
            if provider == "samizdat":
                s = self.settings.samizdat.normalized()
                try:
                    profile = self._samizdat_profile_from_settings()
                    mgr.upstream_socks_port = upstream
                    mgr.start(profile, socks_port=s.mixed_port)
                except (XrayError, SamizdatConfigError) as e:
                    self._set_proxy(PROXY_ERROR, str(e))
                    self.on_message(f"samizdat proxy: {e}", "error")
                    return
                mode, port, label = s.mode, s.mixed_port, (
                    s.server_name or s.address)
                kind = "samizdat"
            else:
                x = self.settings.xray.normalized()
                try:
                    profile = self._profile_from_settings()
                    self.xray.upstream_socks_port = upstream
                    self.xray.start(profile, socks_port=x.socks_port,
                                    http_port=x.http_port)
                except (XrayError, XrayConfigError) as e:
                    self._set_proxy(PROXY_ERROR, str(e))
                    self.on_message(f"Xray proxy: {e}", "error")
                    return
                mgr, mode, port = self.xray, x.mode, x.socks_port
                label = x.sni or x.address
                kind = profile.protocol
            if mode == "system":
                try:
                    mgr.apply_system_proxy()
                except Exception as e:  # noqa: BLE001
                    # proxy process is up; only the system switch failed
                    self.on_message(
                        f"The proxy is running but the system proxy could "
                        f"not be set ({e}). Manual: SOCKS 127.0.0.1:{port}",
                        "warn")
            self._set_proxy(PROXY_ON, f"{kind} → {label}")
            self.on_message(
                f"Proxy on ({kind}, masquerade {label}) — "
                f"SOCKS 127.0.0.1:{port}", "info")
            # a proxy just came up: re-route browser/downloads if asked to
            self._apply_browser_proxy()
        finally:
            self._proxy_lock.release()

    def _proxy_stop_worker(self) -> None:
        if not self._proxy_lock.acquire(blocking=False):
            self.on_message("a proxy operation is already running", "warn")
            return
        try:
            if not self.xray.running and not self.samizdat.running \
                    and not self.xray._proxy_applied \
                    and not self.samizdat._proxy_applied:
                self._set_proxy(PROXY_OFF)
                return
            try:
                self.xray.stop()
            except Exception as e:  # noqa: BLE001
                self.on_message(f"Xray stop failed: {e}", "warn")
            try:
                self.samizdat.stop()
            except Exception as e:  # noqa: BLE001
                self.on_message(f"samizdat stop failed: {e}", "warn")
            self._set_proxy(PROXY_OFF)
            self.on_message("Proxy off", "info")
            self._apply_browser_proxy()
        finally:
            self._proxy_lock.release()

    def proxy_status(self) -> dict:
        """Synchronous snapshot for UI (tray / settings)."""
        st = self.xray.status()
        st.update(self.samizdat.status())
        st["provider"] = self._proxy_provider()
        return st

    # ---------------------------------------------------- protocol engines
    # the generic multi-protocol layer (imported profiles, chains, WARP):
    # any engine from proto_clean.vpn.protocols can run behind the same
    # start/stop/status lifecycle, sharing the system-proxy switch.
    def start_profile_async(self, entry_id: str) -> None:
        """Start a saved profile from the protocols store (async)."""
        self._spawn(lambda: self._profile_start_worker(entry_id),
                    "proto_clean-protocol")

    def _profile_start_worker(self, entry_id: str) -> None:
        if not self._proxy_lock.acquire(blocking=False):
            self.on_message("a proxy operation is already running", "warn")
            return
        try:
            from .vpn.protocols import chain as chain_mod
            from .vpn.protocols import make_engine
            from .vpn.protocols.profiles import ProfileStore
            store = ProfileStore()
            entry = store.get(entry_id)
            if entry is None:
                self.on_message("profile not found", "error")
                return
            profile = entry.profile()
            if profile is None:
                self.on_message(f"cannot restore {entry.name}", "error")
                return
            self._set_proxy(PROXY_STARTING)
            # stop anything else first — one proxy engine at a time
            for mgr in (self.xray, self.samizdat):
                try:
                    mgr.stop()
                except Exception:  # noqa: BLE001
                    pass
            if getattr(self, "_protocol_engine", None) is not None:
                try:
                    self._protocol_engine.stop()
                except Exception:  # noqa: BLE001
                    pass
                self._protocol_engine = None
            try:
                if entry.kind == "chain":
                    eng = chain_mod.engine(profile)
                    eng.start(profile)
                elif entry.kind == "warp":
                    from .vpn.protocols import warp as warp_mod
                    warp_mod.register(profile)
                    from .vpn.protocols import boxproto
                    eng = boxproto.engine("warp", profile,
                                          socks_port=10800)
                    eng.start(profile, socks_port=eng.socks_port or 10800)
                elif entry.kind == "clash" or entry.kind == "boxraw":
                    from .vpn.protocols import boxproto
                    kind = "boxraw" if entry.kind == "boxraw" else \
                        profile.kind
                    # clash entries expand on import; a stored clash doc
                    # means the user kept the whole config — run raw
                    if entry.kind == "clash":
                        from .vpn.protocols.convert import parse_clash_yaml
                        subs = parse_clash_yaml(profile.yaml_text)
                        if len(subs) == 1:
                            profile = subs[0]
                            kind = subs[0].kind
                    eng = boxproto.engine(kind, profile)
                    eng.start(profile, socks_port=eng.socks_port or 10800)
                else:
                    eng = make_engine(entry.kind, profile,
                                      socks_port=10800)
                    eng.start(profile, socks_port=eng.socks_port or 10800)
            except Exception as e:  # noqa: BLE001
                self._set_proxy(PROXY_ERROR, str(e))
                self.on_message(f"{entry.kind}: {e}", "error")
                return
            self._protocol_engine = eng
            self._set_proxy(PROXY_ON, entry.kind)
            # share the system-proxy switch with the xray family
            try:
                if hasattr(eng, "apply_system_proxy"):
                    eng.apply_system_proxy()
            except Exception as e:  # noqa: BLE001
                self.on_message(f"running; system proxy switch failed: {e}",
                                "warn")
            self.on_message(f"{entry.name} is running", "info")
            self._apply_browser_proxy()
        finally:
            self._proxy_lock.release()

    def stop_protocol_async(self) -> None:
        """Stop the running protocol engine (shares the proxy lock)."""
        self._spawn(self._protocol_stop_worker, "proto_clean-protocol")

    def _protocol_stop_worker(self) -> None:
        if not self._proxy_lock.acquire(blocking=False):
            self.on_message("a proxy operation is already running", "warn")
            return
        try:
            eng = getattr(self, "_protocol_engine", None)
            if eng is not None:
                try:
                    eng.stop()
                except Exception as e:  # noqa: BLE001
                    self.on_message(f"stop failed: {e}", "warn")
                self._protocol_engine = None
                self._set_proxy(PROXY_OFF)
                self.on_message("Protocol engine stopped", "info")
                self._apply_browser_proxy()
                return
            # fall through to the classic proxy stop
            self._proxy_stop_worker()
        finally:
            self._proxy_lock.release()

    def protocol_engine_status(self) -> dict:
        eng = getattr(self, "_protocol_engine", None)
        if eng is None:
            return {"running": False, "kind": ""}
        try:
            st = eng.status()
        except Exception:  # noqa: BLE001
            st = {"running": False, "kind": getattr(eng, "proxy_kind", "")}
        return st

    def protocol_store(self):
        """The profiles store (imported servers) for the UI."""
        from .vpn.protocols.profiles import ProfileStore
        return ProfileStore()

    def import_center(self):
        from .vpn.protocols.importers import ImportCenter
        return ImportCenter(self.protocol_store())

    # ------------------------------------------------------- link bonding
    def _set_bond(self, state: str, detail: str = "") -> None:
        self.bond_state = state
        log.info("bond -> %s (%s)", state, detail)
        for fn in list(self._bond_listeners):
            try:
                fn(state, detail)
            except Exception:  # noqa: BLE001
                pass

    def add_bond_listener(self, fn: Callable) -> None:
        """Subscribe to bond state changes (multiple listeners allowed)."""
        if fn not in self._bond_listeners:
            self._bond_listeners.append(fn)

    def save_bond_settings(self, bond) -> None:
        """Persist a BondSettings (already normalized by the caller)."""
        from .settings import update
        update(**{"bond": bond})
        self.settings = load_settings()

    def start_bond_async(self) -> None:
        """Start link bonding with the saved settings."""
        self._spawn(self._bond_start_worker, "proto_clean-bond")

    def stop_bond_async(self) -> None:
        self._spawn(self._bond_stop_worker, "proto_clean-bond")

    def _bond_start_worker(self) -> None:
        if not self._bond_lock.acquire(blocking=False):
            self.on_message("a bonding operation is already running", "warn")
            return
        try:
            if self.bond.running:
                self.on_message("link bonding is already running", "warn")
                return
            s = self.settings.bond.normalized()
            if not s.server:
                self._set_bond(PROXY_ERROR, "no server")
                self.on_message(
                    "Link bonding needs a bond server — run "
                    "`python3 -m proto_clean.bondserver` on a VPS and "
                    "enter its address in Settings → Link bonding", "error")
                return
            self._set_bond(PROXY_STARTING)
            try:
                self.bond.start(s)
            except XrayError as e:
                self._set_bond(PROXY_ERROR, str(e))
                self.on_message(f"link bonding: {e}", "error")
                return
            if s.mode_proxy == "system":
                try:
                    self.bond.apply_system_proxy()
                except Exception as e:  # noqa: BLE001
                    self.on_message(
                        f"Bonding is running but the system proxy could not "
                        f"be set ({e}). Manual: SOCKS 127.0.0.1:"
                        f"{self.bond.socks_port}", "warn")
            n = len(self.bond.settings_snapshot.get("bind_ips", []))
            self._set_bond(PROXY_ON, f"{s.mode} → {s.server}:{s.port}")
            self.on_message(
                f"Link bonding on ({s.mode}, {n or 1} adapter(s), server "
                f"{s.server}:{s.port}) — SOCKS 127.0.0.1:{self.bond.socks_port}",
                "info")
            self._apply_browser_proxy()
        finally:
            self._bond_lock.release()

    def _bond_stop_worker(self) -> None:
        if not self._bond_lock.acquire(blocking=False):
            self.on_message("a bonding operation is already running", "warn")
            return
        try:
            if not self.bond.running and not self.bond._proxy_applied:
                self._set_bond(PROXY_OFF)
                return
            try:
                self.bond.stop()
            except Exception as e:  # noqa: BLE001
                self.on_message(f"bond stop failed: {e}", "warn")
            self._set_bond(PROXY_OFF)
            self.on_message("Link bonding off", "info")
            self._apply_browser_proxy()
        finally:
            self._bond_lock.release()

    def bond_status(self) -> dict:
        """Synchronous bond snapshot for UI (tray / settings)."""
        return self.bond.status()

    def bond_upstream(self) -> int:
        """The bond's local SOCKS port when it is running (else 0)."""
        return self.bond.socks_port if self.bond.running else 0

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
            try:
                self.xray.stop()
            except Exception:  # noqa: BLE001
                pass
            try:
                self.samizdat.stop()
            except Exception:  # noqa: BLE001
                pass
            try:
                self.bond.stop()
            except Exception:  # noqa: BLE001
                pass
            self._teardown_partial()
        finally:
            self.session.worker.stop()
