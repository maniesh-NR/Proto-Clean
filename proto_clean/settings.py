"""Application settings, persisted to ~/.config/proto-clean/settings.json."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field, replace
from typing import List, Optional

from .paths import SETTINGS_FILE, ensure_dirs

_lock = threading.RLock()


@dataclass
class BlocklistSource:
    """One user-manageable blocklist source (hosts or domains format)."""
    name: str
    url: str
    enabled: bool = True

    @classmethod
    def from_json(cls, d: dict) -> "BlocklistSource":
        if isinstance(d, str):  # legacy plain-URL entry
            d = {"url": d}
        url = str(d.get("url", "")).strip()
        name = str(d.get("name", "")).strip() or _name_from_url(url)
        return cls(name=name, url=url, enabled=bool(d.get("enabled", True)))

    def to_json(self) -> dict:
        return {"name": self.name, "url": self.url, "enabled": self.enabled}


def _name_from_url(url: str) -> str:
    """Human-friendly name derived from a blocklist URL."""
    import re

    tail = url.rstrip("/").split("/")[-1] or url
    tail = re.sub(r"\.(txt|hosts|json|conf)$", "", tail, flags=re.I)
    host = url.split("//", 1)[-1].split("/", 1)[0] if "//" in url else ""
    base = host.split(".", 1)[0] if host else "blocklist"
    return f"{base} · {tail}" if tail else base


# The blocklists enabled by default — kept identical to the filter lists
# uBlock Origin enables out of the box (gorhill/uBlock assets.json, the
# entries without "off": true). uBO auto-enables extra *regional* lists
# based on the browser locale; a VPN DNS filter has no browser locale, so
# those are not part of our defaults (they remain one click away).
UBLOCK_ORIGIN_DEFAULT_LISTS: List = [
    # Built-in "uBlock filters" group (group: "default" in assets.json)
    ("uBlock filters – Ads",
     "https://ublockorigin.github.io/uAssets/filters/filters.txt"),
    ("uBlock filters – Badware risks",
     "https://ublockorigin.github.io/uAssets/filters/badware.txt"),
    ("uBlock filters – Privacy",
     "https://ublockorigin.github.io/uAssets/filters/privacy.txt"),
    ("uBlock filters – Unbreak",
     "https://ublockorigin.github.io/uAssets/filters/unbreak.txt"),
    ("uBlock filters – Quick fixes",
     "https://ublockorigin.github.io/uAssets/filters/quick-fixes.txt"),
    # Ads / Privacy / Malware / Multipurpose defaults
    ("EasyList",
     "https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt"),
    ("EasyPrivacy",
     "https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt"),
    ("Online Malicious URL Blocklist",
     "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-vivaldi-online.txt"),
    ("Peter Lowe's Ad and tracking server list",
     "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
]

# The single default list shipped before the uBlock Origin parity release.
# Settings that still hold exactly this set are migrated to the new
# defaults on load (users who customized their lists keep them).
LEGACY_DEFAULT_BLOCKLIST = BlocklistSource(
    name="StevenBlack unified (ads + malware)",
    url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
)
LEGACY_DEFAULT_BLOCKLIST_URL = LEGACY_DEFAULT_BLOCKLIST.url


def default_blocklists() -> List[BlocklistSource]:
    return [BlocklistSource(name=name, url=url)
            for name, url in UBLOCK_ORIGIN_DEFAULT_LISTS]


def _is_legacy_default(lists: List[BlocklistSource]) -> bool:
    """True when the saved set is exactly the pre-parity default."""
    return (len(lists) == 1 and lists[0].enabled
            and lists[0].name == LEGACY_DEFAULT_BLOCKLIST.name
            and lists[0].url == LEGACY_DEFAULT_BLOCKLIST.url)


# Well-known lists offered as presets in the "Add blocklist" dialog:
# the uBlock Origin defaults first (so a removed default can be re-added),
# then popular aggregated hosts lists.
BLOCKLIST_PRESETS = list(UBLOCK_ORIGIN_DEFAULT_LISTS) + [
    ("StevenBlack unified (ads + malware)",
     "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    ("HaGeZi Pro — ads, tracking, malware",
     "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt"),
    ("HaGeZi Multi PRO++ — heavier",
     "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multipro.txt"),
    ("OISD Big — aggregated ads/tracking",
     "https://hosts.oisd.nl/big"),
    ("1Hosts Lite",
     "https://badmojr.github.io/1hosts/Lite/hosts"),
]



@dataclass
class NetShieldSettings:
    enabled: bool = True
    # User-managed blocklist sources (add / remove / update via the menu).
    blocklists: List[BlocklistSource] = field(default_factory=default_blocklists)
    update_interval_hours: int = 24
    block_nxdomain: bool = True   # answer blocked names with NXDOMAIN (else 0.0.0.0)
    last_update: Optional[str] = None  # ISO timestamp of last successful refresh
    domain_count: int = 0

    def urls(self) -> List[str]:
        return [b.url for b in self.blocklists]

    def enabled_lists(self) -> List[BlocklistSource]:
        return [b for b in self.blocklists if b.enabled]


@dataclass
class SplitTunnelSettings:
    enabled: bool = False
    # Executables whose traffic should bypass the tunnel (exclude-apps mode).
    # Full per-app routing is implemented with cgroups on Linux and with the
    # VPN service's excludedApplications on Android; on Windows/macOS apps
    # cannot be policy-routed without kernel drivers, so only excluded_cidrs
    # apply there (the UI explains this).
    excluded_apps: List[str] = field(default_factory=list)  # absolute paths
    # Destinations that bypass the tunnel — portable on every platform:
    # these CIDRs are subtracted from the tunnel's AllowedIPs so they keep
    # using the original default route.
    excluded_cidrs: List[str] = field(default_factory=list)  # e.g. 192.168.1.0/24


@dataclass
class PortForwardSettings:
    # Ask the Downloads page to enable NAT-PMP on the generated config (paid plans).
    # Surfaced as the "NAT-PMP (Port Forwarding)" toggle in the Protocol tab
    # when WireGuard is the selected protocol (the same checkbox exists for
    # OpenVPN configs and is driven by this same setting).
    request_in_config: bool = True
    # Local (internal) port to map; packets arrive at 10.2.0.2:<internal port>.
    internal_port: int = 0          # 0 = map a generic port / just show the external one
    keep_alive: bool = True


PROTOCOLS = ("wireguard", "openvpn")
OPENVPN_TRANSPORTS = ("udp", "tcp")
OPENVPN_DRIVERS = ("tun", "tap")

# Xray / v2ray proxy protocols (see vpn/xrayconf.py).
XRAY_PROTOCOLS = ("vless-reality", "trojan")
# Which proxy engine the Start button drives (see controller.py):
# "xray" (VLESS REALITY / Trojan) or "samizdat" (Lantern's protocol).
PROXY_PROVIDERS = ("xray", "samizdat")
# How the backend browser (and blocklist downloads) reach the internet.
BROWSER_PROXY_MODES = ("direct", "auto", "custom")

# UI themes: "system" follows the desktop color scheme (and live-switches
# when the desktop changes), "light" and "dark" force a fixed look.
THEMES = ("system", "light", "dark")


@dataclass
class ProtocolSettings:
    """Which config type Proto Clean downloads from the Proton Downloads page.

    * wireguard (default) — a WireGuard config; NAT-PMP (port forwarding) and
    VPN Accelerator are set with the toggles in the Protocol tab
    (vpn_options.vpn_accelerator / port_forward.request_in_config).
    * openvpn — an OpenVPN .ovpn config; the transport (TCP or UDP) is chosen
    on the page, and the network driver (TUN or TAP) is a local choice
    applied when the tunnel is started.
    """
    protocol: str = "wireguard"          # "wireguard" | "openvpn"
    openvpn_transport: str = "udp"       # "udp" | "tcp" (OpenVPN only)
    openvpn_driver: str = "tun"          # "tun" | "tap" (OpenVPN only)

    def normalized(self) -> "ProtocolSettings":
        p = self.protocol if self.protocol in PROTOCOLS else "wireguard"
        t = self.openvpn_transport if self.openvpn_transport in OPENVPN_TRANSPORTS else "udp"
        d = self.openvpn_driver if self.openvpn_driver in OPENVPN_DRIVERS else "tun"
        return ProtocolSettings(protocol=p, openvpn_transport=t, openvpn_driver=d)


@dataclass
class AdvancedSettings:
    """Advanced connection options (mirrors Proton's Advanced settings page).

    * allow LAN lives on KillSwitchSettings (it is a kill-switch rule) but is
      toggled from the Advanced tab;
    * "NAT type" maps to vpn_options.moderate_nat (on = Moderate NAT);
    * custom DNS replaces Proton's resolver: queries are answered by the
      embedded DNS blocker forwarding to these servers;
    * alternative routing retries Proton through mirror API hosts when the
      direct ones are blocked;
    * IPv6 support routes IPv6 through the tunnel; IPv6 leak protection
      blocks IPv6 that would bypass the tunnel.
    """
    alternative_routing: bool = True
    custom_dns_enabled: bool = False
    custom_dns_servers: List[str] = field(default_factory=list)  # e.g. ["1.1.1.1"]
    ipv6_support: bool = False          # allow IPv6 through the tunnel
    ipv6_leak_protection: bool = True   # block IPv6 outside the tunnel
    # How the backend browser + blocklist downloads reach the internet.
    # "auto" rides the running proxy (Xray or samizdat); "custom" points
    # at any local proxy — e.g. Lantern (lantern-headless-client) on
    # 127.0.0.1:8787 — so Proton access works even where it is censored.
    browser_proxy_mode: str = "direct"  # "direct" | "auto" | "custom"
    browser_proxy_custom: str = "http://127.0.0.1:8787"

    def custom_dns_list(self) -> List[str]:
        """Validated custom DNS servers (IPv4/IPv6 addresses, deduplicated)."""
        import ipaddress

        out: List[str] = []
        for raw in self.custom_dns_servers or []:
            tok = str(raw).strip()
            if not tok:
                continue
            try:
                ipaddress.ip_address(tok)
            except ValueError:
                continue
            if tok not in out:
                out.append(tok)
        return out


@dataclass
class VpnOptions:
    """Options applied in the backend browser on the config-download page."""
    vpn_accelerator: bool = True
    moderate_nat: bool = False
    # NetShield level on the page itself (0=off). Free plans cannot enable it —
    # local blocklist filtering is the Proto Clean alternative.
    proton_netshield_level: int = 0


@dataclass
class XraySettings:
    """Xray-core proxy profile (VLESS + REALITY or Trojan).

    ``sni`` is the SNI-masking target (REALITY ``serverName`` / TLS SNI):
    the connection is made to look like ordinary HTTPS to that site.
    ``mode`` selects whether the OS proxy is switched automatically
    ("system") or the inbounds stay manual ("manual").
    ``provider`` selects the proxy engine for the Start button: "xray"
    or "samizdat" (whose own profile lives in ``Settings.samizdat``).
    """
    provider: str = "xray"                   # "xray" | "samizdat"
    protocol: str = "vless-reality"          # "vless-reality" | "trojan"
    address: str = ""
    port: int = 443
    name: str = ""
    uuid: str = ""                           # VLESS user id
    public_key: str = ""                     # REALITY pbk
    short_id: str = ""                       # REALITY sid
    flow: str = "xtls-rprx-vision"
    password: str = ""                       # trojan
    sni: str = ""                            # masked SNI (serverName)
    fingerprint: str = "chrome"              # uTLS fingerprint
    allow_insecure: bool = False
    spider_x: str = "/"
    mode: str = "system"                     # "system" | "manual"
    socks_port: int = 10808
    http_port: int = 10809
    ride_bond: bool = True                    # chain through the bond SOCKS

    def normalized(self) -> "XraySettings":
        from .vpn.xrayconf import FINGERPRINTS, FLOWS
        proto = self.protocol if self.protocol in XRAY_PROTOCOLS else "vless-reality"
        fp = self.fingerprint if self.fingerprint in FINGERPRINTS else "chrome"
        flow = self.flow if self.flow in FLOWS else (
            "xtls-rprx-vision" if proto == "vless-reality" else "")
        mode = self.mode if self.mode in ("system", "manual") else "system"
        provider = self.provider if self.provider in PROXY_PROVIDERS else "xray"
        try:
            port = int(self.port)
        except (TypeError, ValueError):
            port = 443
        try:
            socks = int(self.socks_port)
        except (TypeError, ValueError):
            socks = 10808
        try:
            http = int(self.http_port)
        except (TypeError, ValueError):
            http = 10809
        return XraySettings(
            provider=provider,
            protocol=proto, address=self.address.strip(), port=port,
            name=self.name.strip(), uuid=self.uuid.strip(),
            public_key=self.public_key.strip(), short_id=self.short_id.strip(),
            flow=flow, password=self.password, sni=self.sni.strip(),
            fingerprint=fp, allow_insecure=bool(self.allow_insecure),
            spider_x=self.spider_x or "/", mode=mode,
            socks_port=socks if 1 <= socks <= 65535 else 10808,
            http_port=http if 1 <= http <= 65535 else 10809,
            ride_bond=bool(self.ride_bond),
        )


@dataclass
class SamizdatSettings:
    """Samizdat profile (Lantern's censorship-resistance protocol — see
    vpn/samizdatconf.py). ``server_name`` is the masquerade *cover* SNI
    the connection pretends to visit (e.g. ok.ru)."""
    address: str = ""
    port: int = 443
    name: str = ""
    public_key: str = ""                     # server X25519 public key (64 hex)
    short_id: str = ""                       # pre-shared id (16 hex)
    server_name: str = ""                    # cover/masquerade SNI
    fingerprint: str = "chrome"
    padding_profile: str = "chrome"
    max_jitter_ms: int = 30
    max_streams_per_conn: int = 100
    data_threshold: int = 14000
    disable_padding: bool = False
    disable_jitter: bool = False
    disable_tcp_fragmentation: bool = False
    disable_record_fragmentation: bool = False
    idle_timeout: str = "5m"
    connect_timeout: str = "15s"
    mode: str = "system"                     # "system" | "manual"
    mixed_port: int = 10810                  # local SOCKS+HTTP inbound
    ride_bond: bool = True                    # chain through the bond SOCKS

    def normalized(self) -> "SamizdatSettings":
        from .vpn.samizdatconf import FINGERPRINTS, PADDING_PROFILES
        fp = self.fingerprint if self.fingerprint in FINGERPRINTS else "chrome"
        pp = (self.padding_profile if self.padding_profile in PADDING_PROFILES
              else "chrome")
        mode = self.mode if self.mode in ("system", "manual") else "system"

        def clamp(v, lo, hi, dflt):
            try:
                v = int(v)
            except (TypeError, ValueError):
                return dflt
            return max(lo, min(hi, v))

        return SamizdatSettings(
            address=self.address.strip(),
            port=clamp(self.port, 1, 65535, 443),
            name=self.name.strip(),
            public_key=self.public_key.strip().lower(),
            short_id=self.short_id.strip().lower(),
            server_name=self.server_name.strip(),
            fingerprint=fp, padding_profile=pp,
            max_jitter_ms=clamp(self.max_jitter_ms, 0, 1000, 30),
            max_streams_per_conn=clamp(self.max_streams_per_conn, 1, 1000, 100),
            data_threshold=clamp(self.data_threshold, 0, 1_000_000, 14000),
            disable_padding=bool(self.disable_padding),
            disable_jitter=bool(self.disable_jitter),
            disable_tcp_fragmentation=bool(self.disable_tcp_fragmentation),
            disable_record_fragmentation=bool(self.disable_record_fragmentation),
            idle_timeout=self.idle_timeout, connect_timeout=self.connect_timeout,
            mode=mode,
            mixed_port=clamp(self.mixed_port, 1024, 65535, 10810),
            ride_bond=bool(self.ride_bond),
        )


BOND_MODES = ("bond", "balance")


@dataclass
class BondSettings:
    """Link bonding (multi-adapter) — see vpn/bond.py and
    vpn/bondserver.py.

    ``server``/``port`` point at a bond server the user runs on some
    reachable host (``python3 -m proto_clean.bondserver``).
    ``mode``: "bond" splits every stream across all selected adapters
    (combined bandwidth, Speedify-style); "balance" assigns each new
    stream to one adapter round-robin (net-merge style).
    ``interfaces`` holds adapter names ("wlan0"), "name=ip" pairs or
    bare IPv4s; empty = one member on the default route.
    """
    server: str = ""
    port: int = 10820
    token: str = ""                      # shared secret with the server
    mode: str = "bond"                   # "bond" | "balance"
    interfaces: List[str] = field(default_factory=list)
    socks_port: int = 10811              # local SOCKS5 frontend
    mode_proxy: str = "manual"           # "system" | "manual"

    def normalized(self) -> "BondSettings":
        def clamp(v, lo, hi, dflt):
            try:
                v = int(v)
            except (TypeError, ValueError):
                return dflt
            return max(lo, min(hi, v))

        mode = self.mode if self.mode in BOND_MODES else "bond"
        mode_proxy = self.mode_proxy if self.mode_proxy in ("system", "manual") else "manual"
        raw_ifs = self.interfaces or []
        if isinstance(raw_ifs, str):        # friendly manual JSON editing
            raw_ifs = [t for t in raw_ifs.split(",")]
        ifs = []
        for i in raw_ifs:
            tok = str(i).strip()
            if tok and tok not in ifs:
                ifs.append(tok)
        return BondSettings(
            server=str(self.server or "").strip(),
            port=clamp(self.port, 1, 65535, 10820),
            token=str(self.token or ""),
            mode=mode,
            interfaces=ifs,
            socks_port=clamp(self.socks_port, 1024, 65535, 10811),
            mode_proxy=mode_proxy,
        )


@dataclass
class KillSwitchSettings:
    enabled: bool = True
    allow_lan: bool = False


@dataclass
class Settings:
    # Account
    username: str = ""                     # Proton account name (for keyring lookup / prefill)
    # Connection behaviour
    autoconnect_fastest: bool = True       # "Fastest server" toggle shown at the top of the UI
    # Config caching: reuse downloaded configs; re-download only when one fails
    cache_configs: bool = True
    config_verify_timeout: int = 25        # seconds to wait for a WireGuard handshake
    # Feature blocks
    netshield: NetShieldSettings = field(default_factory=NetShieldSettings)
    split_tunnel: SplitTunnelSettings = field(default_factory=SplitTunnelSettings)
    port_forward: PortForwardSettings = field(default_factory=PortForwardSettings)
    vpn_options: VpnOptions = field(default_factory=VpnOptions)
    kill_switch: KillSwitchSettings = field(default_factory=KillSwitchSettings)
    protocol: ProtocolSettings = field(default_factory=ProtocolSettings)
    advanced: AdvancedSettings = field(default_factory=AdvancedSettings)
    xray: XraySettings = field(default_factory=XraySettings)
    samizdat: SamizdatSettings = field(default_factory=SamizdatSettings)
    bond: BondSettings = field(default_factory=BondSettings)
    # UI
    theme: str = "dark"                    # "system" | "light" | "dark"
    prefer_dark_theme: bool = True         # legacy (superseded by `theme`)
    window_geometry: Optional[List[int]] = None
    # Refresh interval for server loads (seconds)
    server_refresh_seconds: int = 60


def load_settings() -> Settings:
    with _lock:
        if not SETTINGS_FILE.exists():
            return Settings()
        try:
            raw = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return Settings()
        theme = raw.get("theme")
        if theme is None:  # migrate the legacy boolean (False meant light)
            theme = "dark" if raw.get("prefer_dark_theme", True) else "light"
        if theme not in THEMES:
            theme = "dark"
        try:
            s = Settings(
                username=raw.get("username", ""),
                autoconnect_fastest=raw.get("autoconnect_fastest", True),
                cache_configs=bool(raw.get("cache_configs", True)),
                config_verify_timeout=int(raw.get("config_verify_timeout", 25)),
                theme=theme,
                prefer_dark_theme=theme != "light",
                window_geometry=raw.get("window_geometry"),
                server_refresh_seconds=int(raw.get("server_refresh_seconds", 60)),
                netshield=_netshield_from_json(_sub(raw, "netshield")),
                split_tunnel=SplitTunnelSettings(**{**asdict(SplitTunnelSettings()), **_sub(raw, "split_tunnel")}),
                port_forward=PortForwardSettings(**{**asdict(PortForwardSettings()), **_sub(raw, "port_forward")}),
                vpn_options=VpnOptions(**{**asdict(VpnOptions()), **_sub(raw, "vpn_options")}),
                kill_switch=KillSwitchSettings(**{**asdict(KillSwitchSettings()), **_sub(raw, "kill_switch")}),
                protocol=_protocol_from_json(_sub(raw, "protocol")),
                advanced=AdvancedSettings(**{**asdict(AdvancedSettings()), **_sub(raw, "advanced")}),
                xray=_xray_from_json(_sub(raw, "xray")),
                samizdat=_samizdat_from_json(_sub(raw, "samizdat")),
                bond=_bond_from_json(_sub(raw, "bond")),
            )
            return s
        except TypeError:
            return Settings()


def _xray_from_json(raw: dict) -> XraySettings:
    """XraySettings with unknown/legacy values coerced back to defaults."""
    base = {**asdict(XraySettings()), **raw}
    return XraySettings(**base).normalized()


def _samizdat_from_json(raw: dict) -> SamizdatSettings:
    """SamizdatSettings with unknown/legacy values coerced to defaults."""
    base = {**asdict(SamizdatSettings()), **raw}
    return SamizdatSettings(**base).normalized()


def _bond_from_json(raw: dict) -> BondSettings:
    """BondSettings with unknown/legacy values coerced to defaults."""
    base = {**asdict(BondSettings()), **raw}
    return BondSettings(**base).normalized()


def _protocol_from_json(raw: dict) -> ProtocolSettings:
    """ProtocolSettings with unknown values coerced back to the defaults."""
    base = {**asdict(ProtocolSettings()), **raw}
    return ProtocolSettings(**base).normalized()


def _netshield_from_json(raw: dict) -> NetShieldSettings:
    """Build NetShieldSettings, migrating legacy `sources: [url, ...]`."""
    base = asdict(NetShieldSettings())
    base.pop("blocklists")  # handled explicitly below
    for k in ("enabled", "update_interval_hours", "block_nxdomain",
              "last_update", "domain_count"):
        if k in raw:
            base[k] = raw[k]
    raw_lists = raw.get("blocklists")
    legacy = raw.get("sources")
    if isinstance(raw_lists, list) and raw_lists:
        lists = [BlocklistSource.from_json(x) for x in raw_lists if x]
    elif isinstance(legacy, list) and legacy:
        # migrate legacy plain-URL sources to named, enabled entries
        lists = [BlocklistSource.from_json(u) for u in legacy if u]
    else:
        lists = default_blocklists()
    if _is_legacy_default(lists):
        # untouched pre-parity default (single StevenBlack entry) —
        # upgrade in place to the uBlock Origin default set
        lists = default_blocklists()
    return NetShieldSettings(blocklists=lists, **base)


def _sub(raw: dict, key: str) -> dict:
    v = raw.get(key)
    return v if isinstance(v, dict) else {}


def save_settings(s: Settings) -> None:
    with _lock:
        ensure_dirs()
        if s.theme not in THEMES:
            s = replace(s, theme="dark")
        # keep the legacy boolean in sync with the new theme field
        s = replace(s, prefer_dark_theme=s.theme != "light")
        tmp = SETTINGS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(s), indent=2), encoding="utf-8")
        tmp.replace(SETTINGS_FILE)


def update(**changes) -> Settings:
    """Return a new Settings with the given fields changed (nested via dotted keys)."""
    current = load_settings()
    nested = {k: v for k, v in changes.items() if "." in k}
    flat = {k: v for k, v in changes.items() if "." not in k}
    s = replace(current, **flat) if flat else current
    for dotted, value in nested.items():
        parent, attr = dotted.split(".", 1)
        child = getattr(s, parent)
        setattr(s, parent, replace(child, **{attr: value}))
    save_settings(s)
    return s
