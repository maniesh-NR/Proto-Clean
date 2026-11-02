"""Samizdat process manager — runs the Lantern censorship-resistance proxy.

Drives a sing-box compatible binary with a generated samizdat client
config (see :mod:`proto_clean.vpn.samizdatconf`). Samizdat ships as
inbound/outbound adapters in **lantern-box**, Lantern's sing-box fork —
install that binary (or a sing-box build with samizdat support) and this
manager runs it exactly like the Xray engine: spawn, wait for the local
mixed (SOCKS+HTTP) inbound, switch the system proxy when asked.

The whole lifecycle, system-proxy integration and status reporting are
inherited from :class:`proto_clean.vpn.xray.XrayManager`; only the binary
discovery, the config format and the inbound layout differ.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Optional

from ..log import get
from ..paths import CACHE_DIR
from .samizdatconf import DEFAULT_MIXED_PORT, SamizdatProfile, write_samizdat_config
from .xray import XrayError, XrayManager

log = get("samizdat")


def find_box_binary(explicit: str = "") -> Optional[str]:
    """Locate the lantern-box / sing-box binary (samizdat support)."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    env = os.environ.get("PROTO_CLEAN_BOX_BIN", "")
    if env:
        candidates.append(env)
    if sys.platform.startswith("win"):
        names = ("lantern-box.exe", "sing-box.exe", "box.exe")
    else:
        names = ("lantern-box", "sing-box", "box")
    for name in names:
        which = shutil.which(name)
        if which:
            candidates.append(which)
    if sys.platform.startswith("win"):
        local = os.path.dirname(os.path.abspath(sys.executable))
        for name in names:
            candidates += [
                os.path.join(local, name),
                os.path.join(os.environ.get("ProgramFiles",
                                            r"C:\Program Files"),
                             "lantern-box", name),
            ]
    else:
        home = os.path.expanduser("~")
        for name in names:
            candidates += [
                f"/usr/local/bin/{name}", f"/usr/bin/{name}",
                f"{home}/bin/{name}", f"/opt/lantern-box/{name}",
                f"/opt/homebrew/bin/{name}",
            ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


class SamizdatManager(XrayManager):
    """The samizdat engine: same lifecycle as Xray, different binary and
    config format, one *mixed* inbound instead of two separate ones."""

    proxy_kind = "samizdat"

    def _find_binary(self, explicit: str = "") -> Optional[str]:
        return find_box_binary(explicit or self._binary)

    def _write_config(self, profile, path: str) -> None:
        write_samizdat_config(profile, path, mixed_port=self.socks_port)

    def _binary_help(self) -> str:
        return ("the lantern-box binary was not found — samizdat ships in "
                "lantern-box (Lantern's sing-box fork, "
                "https://github.com/getlantern/lantern-box); install it or "
                "set PROTO_CLEAN_BOX_BIN")

    def start(self, profile: SamizdatProfile,
              socks_port: int = DEFAULT_MIXED_PORT,
              http_port: int = 0, timeout: float = 10.0,
              binary: str = "") -> None:
        """Start samizdat; ``socks_port`` is the local *mixed* inbound
        (SOCKS5 + HTTP on one port). ``http_port`` is accepted for
        signature compatibility and forced to the same mixed port, so the
        inherited system-proxy switch points both proxy kinds at it."""
        super().start(profile, socks_port=socks_port,
                      http_port=socks_port, timeout=timeout, binary=binary)

    def status(self) -> dict:
        st = super().status()
        # mixed inbound: http_port mirrors socks_port
        st["http_port"] = self.socks_port
        return st
