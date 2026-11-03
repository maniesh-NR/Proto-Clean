"""Samizdat process manager — runs the Lantern censorship-resistance proxy.

Drives a sing-box compatible binary with a generated samizdat client
config (see :mod:`proto_clean.vpn.samizdatconf`). Samizdat ships as
inbound/outbound adapters in **lantern-box**, Lantern's sing-box fork —
the official builds **bundle lantern-box next to the app binary**
(built from the Lantern source in CI; Proto Clean is GPL-3.0-or-later,
so the combination complies with the engine's license). ``find_box_binary``
also picks up PATH installs, the deb/Flatpak locations and
``PROTO_CLEAN_BOX_BIN``.

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
    """Locate the lantern-box / sing-box binary (samizdat support).

    Order: an explicit path, ``PROTO_CLEAN_BOX_BIN``, PATH, the app's
    own bundle directory (the official builds ship lantern-box next to
    the executable — onedir on every OS, .app/Contents/MacOS on macOS,
    /app/bin in the Flatpak, /opt/proto-clean from the debs), and the
    usual install prefixes.
    """
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
    # next to our own executable — the bundled engine (frozen apps and
    # unpackaged runs alike)
    app_dir = os.path.dirname(os.path.abspath(sys.executable))
    meipass = getattr(sys, "_MEIPASS", "")
    if sys.platform.startswith("win"):
        local = app_dir
        for name in names:
            candidates += [
                os.path.join(local, name),
                os.path.join(meipass, name) if meipass else "",
                os.path.join(os.environ.get("ProgramFiles",
                                            r"C:\Program Files"),
                             "lantern-box", name),
            ]
    else:
        home = os.path.expanduser("~")
        for name in names:
            candidates += [
                os.path.join(app_dir, name),
                os.path.join(meipass, name) if meipass else "",
                # deb install tree
                "/opt/proto-clean/" + name,
                f"/usr/local/bin/{name}", f"/usr/bin/{name}",
                # Flatpak sandbox
                f"/app/bin/{name}",
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
        write_samizdat_config(profile, path, mixed_port=self.socks_port,
                              upstream_socks_port=getattr(
                                  self, "upstream_socks_port", 0))

    def _binary_help(self) -> str:
        return ("the lantern-box binary was not found — the official builds "
                "bundle it next to the app; otherwise install lantern-box "
                "(https://github.com/getlantern/lantern-box) or set "
                "PROTO_CLEAN_BOX_BIN")

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
