"""Kill switch: blocks all outbound traffic except the tunnel, the
VPN endpoint handshake, loopback and (optionally) LAN.

The endpoint transport (udp for WireGuard, udp or tcp for OpenVPN)
travels to the helper so the firewall rule matches the actual handshake.
"""

from __future__ import annotations

from .helper import Helper, HelperError


class KillSwitch:
    def __init__(self, helper: Helper) -> None:
        self.helper = helper
        self.active = False

    def on(self, phys_iface: str, endpoint_ip: str, endpoint_port: int,
           allow_lan: bool = False, proto: str = "udp") -> None:
        if proto not in ("udp", "tcp"):
            proto = "udp"
        self.helper.call("ks-on", phys_iface, endpoint_ip,
                         str(endpoint_port), "1" if allow_lan else "0", proto)
        self.active = True

    def off(self) -> None:
        try:
            self.helper.call("ks-off")
        except HelperError:
            pass
        self.active = False
