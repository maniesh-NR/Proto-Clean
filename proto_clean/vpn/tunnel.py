"""Tunnel lifecycle: install config, bring the tunnel up/down with the
firewall features around it in the leak-safe order.

Both protocols are supported — WireGuard (wg-quick) and OpenVPN (the
``openvpn`` binary, driven with the TUN or TAP driver chosen in Settings).
All privileged operations go through the per-OS helper (verbs are identical
on Linux, macOS and Windows); on Windows a whole connect is executed as ONE
elevated batch so the user sees at most one UAC prompt.

Leak-safe order (both protocols):

    arm kill switch (+ IPv6 leak protection) → tunnel up → verify

The kill switch must accept the endpoint *transport* (UDP for WireGuard,
UDP or TCP for OpenVPN), so the endpoint protocol travels to the helper.
"""

from __future__ import annotations

import re
import socket
import time
from typing import List, Optional, Tuple

from .. import paths
from ..log import get
from ..platforms import capabilities, get_platform
from .helper import Helper, HelperError
from .killswitch import KillSwitch
from .ovpnconf import OvpnConf, apply_ovpn_edits
from .split_tunnel import SplitTunnel
from .wgconf import WgQuickConf

log = get("tunnel")

OVPN_IFACE = "proto_clean0"            # OpenVPN tun/tap interface (<=15 chars)


def apply_local_edits(config_text: str, *,
                      excluded_cidrs: Optional[List[str]] = None,
                      dns: Optional[str] = None,
                      ipv6: Optional[bool] = None) -> str:
    """Minimal, comment-preserving edits to the downloaded WireGuard config.

    * excluded_cidrs — split-tunnel destination exclusions, implemented by
      removing the CIDRs from AllowedIPs (portable across all desktop OSes);
    * dns — rewrite the interface DNS (Windows: point it at the local
      blocker on 127.0.0.1, which Windows lets any user bind on port 53);
    * ipv6=False — IPv6 support off: strip IPv6 addresses/routes/DNS so v6
      never enters an IPv4-only tunnel (v6 then either keeps the physical
      route or is blocked by IPv6 leak protection).

    The cached copy of the config keeps Proton's original bytes; only the
    copy handed to the privileged helper is adjusted.
    """
    conf = WgQuickConf.parse(config_text)
    edited = False
    if dns:
        conf.with_dns(dns)
        edited = True
    if excluded_cidrs:
        conf.without_cidrs(excluded_cidrs)
        edited = True
    if ipv6 is False:
        conf.without_ipv6()
        edited = True
    if not edited:
        return config_text                      # byte-identical passthrough

    text = config_text
    new_allowed = [a.strip() for line in conf.peer.get("AllowedIPs", [])
                   for a in line.split(",") if a.strip()]
    if new_allowed:
        merged = ", ".join(new_allowed)
        text = re.sub(r"(?m)^(\s*AllowedIPs\s*=\s*).*$",
                      lambda m: m.group(1) + merged, text)
    if dns:
        if re.search(r"(?m)^\s*DNS\s*=", text):
            text = re.sub(r"(?m)^(\s*DNS\s*=\s*).*$",
                          lambda m: m.group(1) + dns, text)
        else:
            text = text.replace("[Interface]", f"[Interface]\nDNS = {dns}", 1)
    if ipv6 is False:
        for key in ("Address", "DNS"):
            def _fix(match, _key=key):
                kept = [t for t in (x.strip() for x in match.group(2).split(","))
                        if t and ":" not in t]
                if not kept:
                    # the line was IPv6-only — with IPv6 support off it must
                    # not survive (fail loudly at bring-up instead of
                    # silently leaking IPv6 into the tunnel)
                    return ""
                return match.group(1) + ", ".join(kept)
            text = re.sub(rf"(?m)^(\s*{key}\s*=\s*)(.*)$", _fix, text)
    return text


def _resolve_host(host: str) -> str:
    """Endpoint host as an IP (kill-switch rules need a literal)."""
    try:
        import ipaddress
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except (socket.gaierror, IndexError):
        raise RuntimeError(
            f"could not resolve the VPN endpoint {host!r} — are you online?")


def _default_route() -> Tuple[Optional[str], Optional[str]]:
    """(phys_iface, gateway_ip) of the current default route, pre-tunnel."""
    return get_platform().default_route()


class TunnelManager:
    def __init__(self, helper: Optional[Helper] = None) -> None:
        self.helper = helper or Helper()
        self.ks = KillSwitch(self.helper)
        self.split = SplitTunnel(self.helper)
        self.protocol = "wireguard"      # protocol of the tunnel last brought up
        # None = ask the platform backend (production). Tests set True/False to
        # simulate a platform with/without the OpenVPN drivers installed.
        self.supports_openvpn: Optional[bool] = None

    # ------------------------------------------------------------------ up
    def up(
        self,
        config_text: str,
        *,
        kill_switch: bool = True,
        allow_lan: bool = False,
        split_enabled: bool = False,
        excluded_cidrs: Optional[List[str]] = None,
        dns_blocker_uid: Optional[int] = None,
        dns_loopback: Optional[str] = None,
        protocol: str = "wireguard",
        openvpn_driver: str = "tun",
        ipv6: Optional[bool] = None,
        ipv6_leak_protection: bool = False,
    ) -> dict:
        """Bring the tunnel up (WireGuard or OpenVPN, per ``protocol``).

        dns_blocker_uid — enable the OS-level port-53 redirect/relay to the
        in-app blocker (Linux/macOS; None skips it — Windows never needs it).
        dns_loopback — when set (Windows), the config DNS is rewritten to
        this address so the OS resolver talks to the local blocker directly.
        openvpn_driver — TUN or TAP (OpenVPN only; ignored for WireGuard).
        ipv6 — IPv6 support: True routes v6 through the tunnel, False strips
        v6 from the config; None leaves the generated config untouched.
        ipv6_leak_protection — block IPv6 that would bypass the tunnel.
        """
        protocol = "openvpn" if protocol == "openvpn" else "wireguard"
        openvpn_driver = "tap" if openvpn_driver == "tap" else "tun"
        self.protocol = protocol

        ovpn_ok = self.supports_openvpn
        if ovpn_ok is None:                      # production: ask the platform
            ovpn_ok = capabilities().openvpn_tunnel
        if protocol == "openvpn" and not ovpn_ok:
            raise HelperError(
                "OpenVPN tunnels are not supported on this platform — "
                "switch the protocol back to WireGuard (Settings → Protocol)")

        host = port = None
        ks_proto = "udp"
        if protocol == "openvpn":
            ovpn = OvpnConf.parse(config_text)
            r_host, r_port, r_proto = ovpn.endpoint
            ks_proto = (r_proto or ovpn.proto or "udp").lower()
            if ks_proto not in ("udp", "tcp"):
                ks_proto = "udp"
            host = _resolve_host(r_host)
            port = r_port
            text = apply_ovpn_edits(config_text, ipv6=ipv6,
                                    driver=openvpn_driver)
            staged_name = "pending.ovpn"
        else:
            conf = WgQuickConf.parse(config_text)
            wg_host, wg_port = conf.endpoint_host_port
            host, port = _resolve_host(wg_host), wg_port
            text = apply_local_edits(
                config_text, excluded_cidrs=excluded_cidrs,
                dns=dns_loopback, ipv6=ipv6)
            staged_name = "pending.conf"

        paths.DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
        src = paths.DOWNLOADS_DIR / staged_name
        src.write_text(text, encoding="utf-8")

        phys, gw = _default_route()
        if not phys:
            raise RuntimeError("no default route found — are you online?")

        # One batch = one elevation prompt on Windows; a plain loop on
        # Linux/macOS. Order matters: kill switch (and IPv6 leak protection)
        # are armed BEFORE the tunnel exists, so there is no leak window
        # between tunnel-up and firewall.
        if protocol == "openvpn":
            calls: List[tuple] = [("ovpn-install-config", str(src))]
        else:
            calls = [("install-config", str(src))]
        if kill_switch and host and port:
            calls.append(("ks-on", phys, host, str(port),
                          "1" if allow_lan else "0", ks_proto))
        if ipv6_leak_protection:
            calls.append(("v6-on",))
        if split_enabled and capabilities().app_split_tunnel:
            calls.append(("split-on", phys, gw or ""))
        if dns_blocker_uid is not None:
            calls.append(("dns-on", str(dns_blocker_uid)))
        calls.append(("ovpn-up", openvpn_driver) if protocol == "openvpn"
                     else ("tunnel-up",))
        calls.append(("status",))

        results = self.helper.call_batch(calls)
        for call, res in zip(calls, results):
            if not isinstance(res, dict) or res.get("ok") is False:
                raise HelperError(f"helper {call[0]}: "
                                  f"{(res or {}).get('error', 'failed')}")
        status = results[-1]
        log.info("%s tunnel up via %s:%s/%s (driver %s, %s)",
                 protocol, host, port, ks_proto,
                 openvpn_driver if protocol == "openvpn" else "-",
                 capabilities().display)
        return {"status": status, "phys_iface": phys, "gateway": gw,
                "protocol": protocol,
                "tunnel_ip": (status.get("tunnel_ip") or "")}

    # ---------------------------------------------------------------- down
    def down(self, *, dns_blocker: bool = True) -> None:
        calls: List[tuple] = [("tunnel-down",), ("ovpn-down",), ("split-off",)]
        if dns_blocker:
            calls.append(("dns-off",))
        calls.append(("ks-off",))
        calls.append(("v6-off",))
        try:
            results = self.helper.call_batch(calls)
        except HelperError as e:
            log.warning("tunnel down failed: %s", e)
            return
        for call, res in zip(calls, results):
            if not isinstance(res, dict) or res.get("ok") is False:
                msg = f"{call[0]}: {(res or {}).get('error', 'failed')}"
                if call[0] in ("ks-off", "v6-off"):   # never leave firewall armed
                    raise HelperError(f"helper {msg}")
                log.warning("%s failed during teardown", msg)
        self.ks.active = False
        self.split.active = False
        log.info("tunnel down")

    # ------------------------------------------------------------- status
    def status(self) -> dict:
        try:
            return self.helper.call("status")
        except HelperError:
            return {"wg_up": False, "up": False}

    def wait_handshake(self, timeout: float = 20.0, poll: float = 1.5) -> bool:
        """Block until the tunnel is verified.

        WireGuard: wait for the peer handshake. Used to verify a *cached*
        config: a revoked/stale certificate brings the interface up but
        never handshakes, which is exactly the "saved config failed"
        condition that triggers a re-download.

        OpenVPN: the helper reports ``latest_handshake`` as "now" while the
        daemon is alive and the interface has an address, so the same check
        verifies a stale .ovpn (wrong credentials → daemon exits or the
        interface never gets an IP).

        On Windows the waiting happens inside the (already elevated) helper
        verb, so a non-elevated app gets one UAC prompt instead of dozens.
        """
        if capabilities().name == "windows":
            try:
                st = self.helper.call("wait-handshake", str(int(timeout)),
                                      timeout=timeout + 90.0)
                return bool(st.get("wg_up")
                            and int(st.get("latest_handshake", 0) or 0) > 0)
            except HelperError:
                return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                st = self.helper.call("status")
                if st.get("wg_up") and int(st.get("latest_handshake", 0) or 0) > 0:
                    return True
            except (HelperError, TimeoutError):
                pass
            time.sleep(poll)
        return False
