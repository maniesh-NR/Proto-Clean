"""Application settings, persisted to ~/.config/proton-clean/settings.json."""

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


def default_blocklists() -> List[BlocklistSource]:
    return [
        BlocklistSource(
            name="StevenBlack unified (ads + malware)",
            url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        ),
    ]


# Well-known lists offered as presets in the "Add blocklist" dialog.
BLOCKLIST_PRESETS = [
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
    ("Peter Lowe's ad servers",
     "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
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

# UI themes: "system" follows the desktop color scheme (and live-switches
# when the desktop changes), "light" and "dark" force a fixed look.
THEMES = ("system", "light", "dark")


@dataclass
class ProtocolSettings:
    """Which config type Proton Clean downloads from the Proton Downloads page.

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
    # local blocklist filtering is the Proton Clean alternative.
    proton_netshield_level: int = 0


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
            )
            return s
        except TypeError:
            return Settings()


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
