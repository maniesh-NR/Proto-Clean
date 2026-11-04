"""IKEv2/IPsec engine — per-OS system adapters, no external Go binaries.

IKEv2 is terminated by the operating system itself, so this module only
*generates* the platform-native configuration and drives the native tooling:

* Linux   — strongSwan ``swanctl`` (config written to the app config dir,
            loaded with ``--load-all``, tunnel initiated per connection).
* macOS   — an Apple ``.mobileconfig`` profile that is handed to ``open``;
            once installed the tunnel is started/stopped via ``scutil --nc``.
* Windows — ``Add-VpnConnection`` (PowerShell) + ``rasdial``.

Every subprocess call goes through :func:`_run` so tests can monkeypatch the
module-level helper instead of touching :mod:`subprocess`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from typing import List
from xml.sax.saxutils import escape as _xml_escape

from ...log import get
from ...paths import CONFIG_DIR, PLATFORM_NAME
from .base import ProtocolEngine, ProtocolError, TUNNEL_FAMILY, write_private
from .models import Ikev2Profile

log = get("ikev2")

#: Linux connection name inside swanctl.conf
DEFAULT_CONN = "proto-clean"
#: macOS/Windows profile name as shown by ``scutil --nc list`` / rasdial
DEFAULT_NAME = "Proto Clean IKEv2"

#: IKE proposals advertised by the client stanza
SWANCTL_IKE_PROPOSALS = "aes256-sha256-modp2048,aes128-sha256-modp1536"
#: ESP proposals for the child SA
SWANCTL_ESP_PROPOSALS = "aes256gcm16-modp2048,aes128gcm16-modp2048"

#: status()["tool"] per platform
_TOOL_FOR = {"linux": "swanctl", "windows": "rasdial", "macos": "scutil"}


# ---------------------------------------------------------------------------
# injectable subprocess helper
# ---------------------------------------------------------------------------
def _run(cmd: List[str], timeout: float = 30.0) -> "subprocess.CompletedProcess":
    """Run an OS command and capture output (monkeypatched in tests)."""
    kwargs = {}
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(list(cmd), capture_output=True, text=True,
                          timeout=timeout, **kwargs)


def _stderr(proc) -> str:
    """Last-chance error text from a CompletedProcess (stderr, then stdout)."""
    err = (getattr(proc, "stderr", "") or "").strip()
    out = (getattr(proc, "stdout", "") or "").strip()
    return (err or out)[-2000:]


def _split_cmd(cmd: str) -> List[str]:
    """Quote-aware argv split for plain (non-PowerShell) command strings."""
    import shlex
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def _ps_quote(value: str) -> str:
    """Single-quote a value for PowerShell (inner quotes doubled)."""
    return "'" + str(value).replace("'", "''") + "'"


def _win_quote(value: str) -> str:
    """Double-quote a value for the Windows command line."""
    return '"' + str(value).replace('"', '""') + '"'


def _is_eap(profile: Ikev2Profile) -> bool:
    """True when credentials travel via EAP (username/password), not PSK."""
    return profile.auth != "psk"


# ---------------------------------------------------------------------------
# Linux — strongSwan swanctl.conf
# ---------------------------------------------------------------------------
def _swan_secret(value: str) -> str:
    """Quote a secret the way swanctl.conf double-quoted strings expect."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_swanctl_conf(profile: Ikev2Profile, conn_name: str = DEFAULT_CONN) -> str:
    """Full swanctl.conf file content for a strongSwan client connection."""
    server = profile.server
    local_id = profile.identity or profile.username or server
    remote_id = profile.remote_id or server
    local_auth = ("psk" if profile.auth == "psk"
                  else "eap-mschapv2" if profile.auth == "eap-mschapv2"
                  else "pubkey")
    lines = [
        "connections {",
        "    %s {" % conn_name,
        "        version = 2",
        "        local_addrs = %any",
        "        remote_addrs = %s" % server,
        "        proposals = %s" % SWANCTL_IKE_PROPOSALS,
        "        vips = 0.0.0.0",
        "        local {",
        "            auth = %s" % local_auth,
        "            id = %s" % local_id,
        ]
    if local_auth == "eap-mschapv2":
        lines.append("            eap_id = %s" % (profile.username or local_id))
    lines += [
        "        }",
        "        remote {",
        "            auth = pubkey",
        "            id = %s" % remote_id,
        "        }",
        "        children {",
        "            %s {" % conn_name,
        "                remote_ts = 0.0.0.0/0",
        "                esp_proposals = %s" % SWANCTL_ESP_PROPOSALS,
        "            }",
        "        }",
        "    }",
        "}",
    ]
    if profile.auth == "psk" and profile.psk:
        # PSK lives in its own secrets stanza (never inline in the connection)
        lines += [
            "",
            "secrets {",
            "    ike-%s {" % conn_name,
            "        id = %s" % remote_id,
            "        secret = %s" % _swan_secret(profile.psk),
            "    }",
            "}",
        ]
    elif local_auth == "eap-mschapv2" and profile.password:
        # strongSwan reads EAP credentials from the secrets section too
        lines += [
            "",
            "secrets {",
            "    eap-%s {" % conn_name,
            "        id = %s" % (profile.username or local_id),
            "        secret = %s" % _swan_secret(profile.password),
            "    }",
            "}",
        ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# macOS — Apple .mobileconfig (IKEv2 VPN payload)
# ---------------------------------------------------------------------------
def _plist_dict(pairs, indent: str = "    ") -> str:
    """Render [(key, value), …] as a plist <dict>; values str/int."""
    out = [indent + "<dict>"]
    for key, value in pairs:
        out.append("%s  <key>%s</key>" % (indent, _xml_escape(key)))
        if isinstance(value, int) and not isinstance(value, bool):
            out.append("%s  <integer>%d</integer>" % (indent, value))
        else:
            out.append("%s  <string>%s</string>" % (indent, _xml_escape(str(value))))
    out.append(indent + "</dict>")
    return "\n".join(out)


def build_mobileconfig(profile: Ikev2Profile, name: str = DEFAULT_NAME) -> str:
    """Full Apple .mobileconfig (plist XML) installing an IKEv2 VPN payload."""
    server = profile.server
    remote_id = profile.remote_id or server
    uuid_top = str(uuid.uuid5(uuid.NAMESPACE_URL,
                              "app.protoclean.ikev2:" + server))
    uuid_vpn = str(uuid.uuid5(uuid.NAMESPACE_URL,
                              "app.protoclean.ikev2:vpn:" + server))
    vpn_pairs = [
        ("IPsecType", "IKEv2"),
        ("RemoteAddress", server),
        ("RemoteIdentifier", remote_id),
    ]
    if profile.identity:
        vpn_pairs.append(("LocalIdentifier", profile.identity))
    if profile.auth == "psk":
        # shared-secret auth; AuthName/AuthPassword would switch Apple to EAP
        vpn_pairs += [
            ("AuthenticationMethod", "SharedSecret"),
            ("SharedSecret", profile.psk),
        ]
    else:
        # AuthenticationMethod absent => EAP (MSCHAPv2) via AuthName+AuthPassword
        vpn_pairs += [
            ("AuthName", profile.username),
            ("AuthPassword", profile.password),
        ]
    vpn_pairs += [
        ("PayloadDisplayName", "IKEv2"),
        ("PayloadIdentifier", "app.protoclean.ikev2"),
        ("PayloadType", "com.apple.vpn.managed"),
        ("PayloadUUID", uuid_vpn),
        ("PayloadVersion", 1),
    ]
    top_pairs = [
        ("PayloadDisplayName", name),
        ("PayloadIdentifier", "app.protoclean.ikev2"),
        ("PayloadType", "Configuration"),
        ("PayloadUUID", uuid_top),
        ("PayloadVersion", 1),
    ]
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0">',
        "<dict>",
        "  <key>PayloadContent</key>",
        "  <array>",
        _plist_dict(vpn_pairs, indent="    "),
        "  </array>",
    ]
    for key, value in top_pairs:
        lines.append("  <key>%s</key>" % _xml_escape(key))
        if isinstance(value, int) and not isinstance(value, bool):
            lines.append("  <integer>%d</integer>" % value)
        else:
            lines.append("  <string>%s</string>" % _xml_escape(str(value)))
    lines += ["</dict>", "</plist>"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Windows — PowerShell + rasdial
# ---------------------------------------------------------------------------
def build_windows_ps(profile: Ikev2Profile, name: str = DEFAULT_NAME) -> List[str]:
    """Windows command list.

    Element 0 registers the VPN entry (run via
    ``["powershell", "-NoProfile", "-Command", cmd]``), the last element is
    the ``rasdial`` connect call (run as a plain argv list, see
    :func:`_split_cmd`).
    """
    if _is_eap(profile):
        add = ("Add-VpnConnection -Name %s -ServerAddress %s "
               "-TunnelType IKEv2 -AuthenticationMethod EAP"
               % (_ps_quote(name), _ps_quote(profile.server)))
        dial = "rasdial %s %s %s" % (_win_quote(name),
                                     _win_quote(profile.username),
                                     _win_quote(profile.password))
    else:
        add = ("Add-VpnConnection -Name %s -ServerAddress %s "
               "-TunnelType IKEv2 -AuthenticationMethod PresharedKey "
               "-SharedSecret %s"
               % (_ps_quote(name), _ps_quote(profile.server),
                  _ps_quote(profile.psk)))
        dial = "rasdial %s" % _win_quote(name)
    return [add, dial]


def build_windows_disconnect(name: str = DEFAULT_NAME) -> str:
    """The rasdial hang-up command for a registered IKEv2 connection."""
    return "rasdial %s /disconnect" % _win_quote(name)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class Ikev2Engine(ProtocolEngine):
    """System-tunnel engine driving the OS-native IKEv2 client."""

    proxy_kind = "ikev2"
    family = TUNNEL_FAMILY
    exposes = "tunnel"
    binary_name = ""
    supports_upstream = False

    def __init__(self, socks_port: int = 0) -> None:
        super().__init__(socks_port)
        self._proc = None            # no long-lived child process (subprocess.run)
        self._connected = False
        self._profile_name = ""
        self._tool = ""

    # -- lifecycle --------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._connected

    def start(self, profile: Ikev2Profile, timeout: float = 30.0) -> None:
        if PLATFORM_NAME == "linux":
            self._start_linux(profile, timeout)
        elif PLATFORM_NAME == "macos":
            self._start_macos(profile, timeout)
        elif PLATFORM_NAME == "windows":
            self._start_windows(profile, timeout)
        else:
            raise ProtocolError(
                "IKEv2 is not supported on this platform (%s)" % PLATFORM_NAME)

    # --- Linux: strongSwan swanctl ----------------------------------------
    def _start_linux(self, profile: Ikev2Profile, timeout: float) -> None:
        self._tool = "swanctl"
        if not shutil.which("swanctl"):
            raise ProtocolError(
                "strongSwan swanctl not found — install strongswan-swanctl")
        conf = build_swanctl_conf(profile, DEFAULT_CONN)
        path = os.path.join(str(CONFIG_DIR), "swanctl.conf")
        try:
            write_private(path, conf)
        except OSError as exc:
            raise ProtocolError("cannot write swanctl.conf: %s" % exc)
        log.debug("loading swanctl config %s", path)
        r = _run(["swanctl", "--load-all", "--file", path], timeout=timeout)
        if r.returncode != 0:
            raise ProtocolError("swanctl --load-all failed: %s" % _stderr(r))
        r = _run(["swanctl", "--initiate", "--ike", DEFAULT_CONN,
                  "--child", DEFAULT_CONN], timeout=timeout)
        if r.returncode != 0:
            raise ProtocolError("swanctl --initiate failed: %s" % _stderr(r))
        self._profile_name = DEFAULT_CONN
        self._connected = True

    # --- macOS: mobileconfig + scutil --nc ---------------------------------
    def _start_macos(self, profile: Ikev2Profile, timeout: float) -> None:
        self._tool = "scutil"
        self._profile_name = DEFAULT_NAME
        listing = _run(["scutil", "--nc", "list"], timeout=timeout)
        installed = (listing.returncode == 0
                     and DEFAULT_NAME in (getattr(listing, "stdout", "") or ""))
        if installed:
            r = _run(["scutil", "--nc", "start", DEFAULT_NAME,
                      "--user", profile.username, "--password", profile.password],
                     timeout=timeout)
            if r.returncode != 0:
                raise ProtocolError("scutil --nc start failed: %s" % _stderr(r))
            self._connected = True
            return
        # first install: drop the profile next to our other config files and
        # hand it to the OS; System Settings takes over from here.
        conf = build_mobileconfig(profile, DEFAULT_NAME)
        path = os.path.join(str(CONFIG_DIR), "proto-clean-ikev2.mobileconfig")
        try:
            write_private(path, conf)
        except OSError as exc:
            raise ProtocolError("cannot write mobileconfig: %s" % exc)
        r = _run(["open", path], timeout=timeout)
        if r.returncode != 0:
            raise ProtocolError("could not open IKEv2 profile: %s" % _stderr(r))
        raise ProtocolError("IKEv2 profile imported — confirm it in System "
                            "Settings, then retry to connect")

    # --- Windows: Add-VpnConnection + rasdial -------------------------------
    def _start_windows(self, profile: Ikev2Profile, timeout: float) -> None:
        self._tool = "rasdial"
        self._profile_name = DEFAULT_NAME
        for cmd in build_windows_ps(profile, DEFAULT_NAME):
            argv = (_split_cmd(cmd) if cmd.startswith("rasdial")
                    else ["powershell", "-NoProfile", "-Command", cmd])
            r = _run(argv, timeout=timeout)
            if r.returncode != 0:
                raise ProtocolError("IKEv2 setup failed: %s: %s"
                                    % (cmd, _stderr(r)))
        self._connected = True

    def stop(self, timeout: float = 5.0) -> None:
        self._proc = None
        self._connected = False
        name = self._profile_name or (DEFAULT_CONN if PLATFORM_NAME == "linux"
                                      else DEFAULT_NAME)
        self._tool = _TOOL_FOR.get(PLATFORM_NAME, self._tool)
        try:
            if PLATFORM_NAME == "linux":
                _run(["swanctl", "--terminate", "--ike", name], timeout=timeout)
            elif PLATFORM_NAME == "macos":
                _run(["scutil", "--nc", "stop", name], timeout=timeout)
            elif PLATFORM_NAME == "windows":
                _run(_split_cmd(build_windows_disconnect(name)), timeout=timeout)
        except Exception as exc:                       # best-effort teardown
            log.debug("ikev2 stop ignored error: %s", exc)

    def status(self) -> dict:
        d = super().status()
        d["tool"] = self._tool
        d["profile_name"] = self._profile_name
        return d


def engine(profile: Ikev2Profile, socks_port: int = 0) -> Ikev2Engine:
    """Registry factory: an IKEv2 system-tunnel engine."""
    return Ikev2Engine(socks_port)
