"""Shared contracts for the per-OS backends.

Proto Clean runs on Linux, Windows and macOS. Everything platform-specific —
privilege elevation, the WireGuard tooling, kill switch, DNS interception and
split tunneling — is implemented behind the small interfaces in this module
so the controller, tunnel manager and UI stay OS-agnostic.

The privileged operations are exposed as *verbs* (the same whitelist on every
OS: install-config, tunnel-up, tunnel-down, status, ks-on, ks-off, dns-on,
dns-off, split-on, split-off, …). Linux and macOS implement them in the
installed ``proto-clean-helper`` script (run through sudo); Windows implements
them in ``proto_clean.helper_win``, executed in-process when the app is
elevated and via a single UAC prompt otherwise.
"""

from __future__ import annotations

import abc


class HelperError(RuntimeError):
    def __init__(self, msg: str, stderr: str = "") -> None:
        super().__init__(msg)
        self.stderr = stderr


class Capabilities:
    """What the current OS can do — drives both UI hints and control flow."""

    def __init__(self, name: str, display: str, *,
                 app_split_tunnel: bool,
                 kill_switch_backend: str,
                 dns_backend: str,          # iptables-redirect | root-relay | config-loopback
                 elevation: str,            # sudo | uac | none
                 dns_loopback_in_config: bool,
                 openvpn_tunnel: bool = True) -> None:   # OpenVPN driver present?
        self.name = name
        self.display = display
        self.app_split_tunnel = app_split_tunnel
        self.kill_switch_backend = kill_switch_backend
        self.dns_backend = dns_backend
        self.elevation = elevation
        self.dns_loopback_in_config = dns_loopback_in_config
        self.openvpn_tunnel = openvpn_tunnel

    # ---------------------------------------------------------------- notes
    def split_tunnel_note(self) -> str:
        if self.app_split_tunnel:
            return ("Excluded apps are routed outside the tunnel with cgroups; "
                    "excluded IP ranges are removed from the tunnel's "
                    "AllowedIPs.")
        return ("Per-app routing needs kernel support this OS does not offer "
                "to user space, so only IP-range exclusions apply here "
                "(they are portable: the ranges are removed from the "
                "tunnel's AllowedIPs).")

    def protocol_note(self) -> str:
        """Hint shown in the Protocol tab."""
        if self.openvpn_tunnel:
            return ("Both protocols are available: WireGuard (default) and "
                    "OpenVPN (choose TCP or UDP, and the TUN or TAP network "
                    "driver).")
        return ("Only WireGuard tunnels are supported on this platform — "
                "OpenVPN configs can be selected but the tunnel will not "
                "start. Keep WireGuard selected.")


class HelperClient(abc.ABC):
    """Connection to the privileged verb executor for this OS."""

    @abc.abstractmethod
    def call(self, verb: str, *args: str, timeout: float = 60.0) -> dict:
        """Run one whitelisted verb, return its JSON answer."""

    @abc.abstractmethod
    def call_batch(self, calls, timeout: float = 120.0) -> list:
        """Run several verbs. Batching exists so Windows needs only one
        UAC prompt per connect; the Linux/macOS client simply loops."""

    @abc.abstractmethod
    def available(self) -> bool:
        """True when the helper can be reached (installed + privileges OK)."""


class PlatformBackend(abc.ABC):
    """Per-OS behaviour: helper construction, routes, environment checks."""

    capabilities: Capabilities

    @abc.abstractmethod
    def make_helper(self, binary: str = "") -> HelperClient:
        """Helper client for this OS (binary only used where a script
        helper exists)."""

    @abc.abstractmethod
    def default_route(self) -> tuple:
        """(physical_interface, gateway_ip) of the current default route."""

    @abc.abstractmethod
    def env_check(self) -> list:
        """[(label, ok: bool, hint)] of external tools the app needs."""

    @abc.abstractmethod
    def open_folder(self, path: str) -> None:
        """Open a folder in the OS file manager (logs, configs...)."""
