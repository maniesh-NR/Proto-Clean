"""proto_clean.helper_win — privileged verbs for the Windows backend.

Executed either in-process (app running elevated) or once per batch through a
UAC prompt (see platforms/windows.py). The verb whitelist and validation
mirror the Linux/macOS ``proto-clean-helper`` script; the implementations use
the official WireGuard for Windows tools plus PowerShell firewall rules.

Verbs:
    install-config SRC          validate + stage the wg-quick config
    tunnel-up / tunnel-down     wireguard.exe /installtunnelservice|/uninstall…
    status                      wg.exe show dump (JSON)
    wait-handshake TIMEOUT      poll wg until the peer handshakes (elevated)
    ks-on IFACE ENDPOINT PORT ALLOW_LAN [PROTO]
                                kill switch on (firewall rules; PROTO =
                                udp|tcp endpoint transport, default udp)
    ks-off                      kill switch off (rule group removed)
    v6-on / v6-off              IPv6 leak protection: outbound IPv6 block
                                rules on the physical adapters (the tunnel
                                adapter is virtual and untouched)
    ovpn-*                      OpenVPN is not supported on Windows — a
                                clear error is returned instead
    dns-on UID / dns-off        no-ops — DNS blocking is done by rewriting
                                the config DNS to 127.0.0.1 (the blocker
                                binds port 53 directly on Windows)
    split-on / split-off        no-ops — CIDR exclusions live in the config
    split-add-pid / split-launch  unsupported (would need a WFP driver)

Kill switch design: Windows Firewall block rules override allow rules, so
each per-physical-adapter BLOCK rule carries a remote-address list of
"everything except the endpoint (and, optionally, LAN ranges)" computed by
CIDR subtraction from 0.0.0.0/0 — the handshake allow rule then never
collides with a block. The WireGuard tunnel adapter is virtual, so traffic
through the tunnel is not touched. Loopback (our DNS blocker) is not
filtered by Windows Firewall at all.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import List, Optional, Tuple

TUNNEL = "proto_clean"
KS_GROUP = "ProtoCleanKS"
V6_GROUP = "ProtoCleanV6"
LAN_RANGES = ("192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8")

# runner indirection keeps the module unit-testable on non-Windows machines
RUNNER = subprocess.run

_PATH_RE = re.compile(r"^[A-Za-z0-9._/+@=\\: -]+$")
_IFACE_RE = re.compile(r"^[^'\"\\/:*?<>|]{1,64}$")

WG_DIRS = (r"C:\Program Files\WireGuard", r"C:\Program Files (x86)\WireGuard")


class WinHelperError(RuntimeError):
    pass


# --------------------------------------------------------------- validation


def valid_ip(v: str) -> str:
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise WinHelperError(f"invalid IP {v!r}") from None
    return v


def valid_port(p: str) -> int:
    try:
        port = int(p)
    except ValueError:
        raise WinHelperError(f"invalid port {p!r}") from None
    if not 1 <= port <= 65535:
        raise WinHelperError(f"port out of range: {p}")
    return port


def validate_wg_conf(text: str) -> bool:
    section = None
    saw_key = {"Interface": set(), "Peer": set()}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line in ("[Interface]", "[Peer]"):
            section = line[1:-1]
            continue
        if section is None or "=" not in line:
            return False
        key = line.split("=", 1)[0].strip()
        if key not in {
            "PrivateKey", "Address", "DNS", "MTU", "Table", "PreUp", "PostUp",
            "PublicKey", "PresharedKey", "AllowedIPs", "Endpoint",
            "PersistentKeepalive", "PreDown", "PostDown", "SaveConfig",
        }:
            return False
        saw_key[section].add(key)
    if "PrivateKey" not in saw_key["Interface"]:
        return False
    if "PublicKey" not in saw_key["Peer"] or "AllowedIPs" not in saw_key["Peer"]:
        return False
    if "PreUp" in saw_key["Interface"] or "PostUp" in saw_key["Interface"]:
        return False   # refuse surprise shell hooks (parity with the Linux helper)
    return True


def allowed_source_path(src: str) -> bool:
    from .paths import CACHE_DIR, CONFIG_CACHE_DIR, DOWNLOADS_DIR
    import tempfile

    if not os.path.isabs(src) or not _PATH_RE.match(src) or not os.path.isfile(src):
        return False
    roots = [str(CACHE_DIR), str(DOWNLOADS_DIR), str(CONFIG_CACHE_DIR),
             os.path.join(tempfile.gettempdir(), "proto_clean-")]
    return any(src.startswith(r) for r in roots)


# ------------------------------------------------------- CIDR subtraction


def subtract_from_default(endpoint_ip: str,
                          extra_excludes: Tuple[str, ...] = ()) -> List[str]:
    """0.0.0.0/0 and ::/0 minus the endpoint (+ optional LAN ranges).

    Returns a flat prefix list usable as a firewall -RemoteAddress value.
    Block rules built from this list can never match the endpoint, so the
    handshake allow rule always wins despite block-over-allow precedence.
    """
    out: List[str] = []
    try:
        endpoint = ipaddress.ip_address(endpoint_ip)
    except ValueError:
        raise WinHelperError(f"invalid endpoint {endpoint_ip!r}") from None
    for base in (ipaddress.ip_network("0.0.0.0/0"),
                 ipaddress.ip_network("::/0")):
        remaining = [base]
        for ex in (endpoint, *extra_excludes):
            try:
                ex_net = ipaddress.ip_network(ex, strict=False)
            except ValueError:
                continue
            nxt: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
            for r in remaining:
                if ex_net.version == r.version and ex_net.subnet_of(r):
                    try:
                        nxt.extend(r.address_exclude(ex_net))
                    except ValueError:
                        pass       # ex_net covers r entirely (e == r)
                else:
                    nxt.append(r)
            remaining = nxt
        out.extend(str(r) for r in remaining)
    return out


# ------------------------------------------------------------- powershell


def ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def powershell(command: str, timeout: float = 60.0) -> str:
    p = RUNNER(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                command], capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise WinHelperError(f"powershell failed: "
                             f"{(p.stderr or p.stdout).strip()[:300]}")
    return p.stdout


def physical_adapters() -> List[str]:
    out = powershell("Get-NetAdapter -Physical | "
                     "Where-Object Status -eq 'Up' | "
                     "Select-Object -ExpandProperty InterfaceAlias")
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def find_tool(name: str) -> str:
    hit = shutil.which(name)
    if hit:
        return hit
    for d in WG_DIRS:
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    raise WinHelperError(f"{name} not found — install WireGuard for Windows "
                         "from https://download.wireguard.com/windows/")


# ------------------------------------------------------------------ verbs


def conf_dest() -> str:
    from .paths import SYSTEM_CONFIG_DIR
    d = SYSTEM_CONFIG_DIR
    os.makedirs(d, exist_ok=True)
    return os.path.join(str(d), f"{TUNNEL}.conf")


def verb_install_config(src: str) -> dict:
    if not allowed_source_path(src):
        raise WinHelperError("source path not allowed")
    text = open(src, encoding="utf-8").read()
    if not validate_wg_conf(text):
        raise WinHelperError("file is not a valid WireGuard config")
    dest = conf_dest()
    tmp = dest + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, dest)
    return {"ok": True, "installed": dest}


def verb_tunnel_up() -> dict:
    exe = find_tool("wireguard.exe")
    p = RUNNER([exe, "/installtunnelservice", conf_dest()],
               capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise WinHelperError((p.stderr or p.stdout).strip() or
                             "wireguard service install failed")
    return {"ok": True, "state": "up"}


def verb_tunnel_down() -> dict:
    exe = find_tool("wireguard.exe")
    RUNNER([exe, "/uninstalltunnelservice", TUNNEL],
           capture_output=True, text=True, timeout=60)
    return {"ok": True, "state": "down"}   # tolerate "not installed"


def _wg_show() -> str:
    exe = find_tool("wg.exe")
    p = RUNNER([exe, "show", TUNNEL, "dump"],
               capture_output=True, text=True, timeout=15)
    return p.stdout if p.returncode == 0 else ""


def verb_status() -> dict:
    out = _wg_show()
    info: dict = {"ok": True, "up": False, "wg_up": False}
    if out.strip():
        lines = out.strip().splitlines()
        fields = lines[0].split("\t")
        info.update(
            private_key_present=bool(fields[0]),
            public_key=fields[1] if len(fields) > 1 else "",
            listen_port=fields[2] if len(fields) > 2 else "",
        )
        if len(lines) > 1:
            pf = lines[1].split("\t")
            if len(pf) >= 8:
                info.update(
                    peer_key=pf[0], endpoint=pf[2], allowed_ips=pf[3],
                    latest_handshake=int(pf[4] or 0),
                    rx=int(pf[5] or 0), tx=int(pf[6] or 0),
                )
        info["up"] = True
        info["wg_up"] = True
    info["tunnel_ip"] = _conf_tunnel_ip()
    return info


def verb_wait_handshake(timeout_s: str) -> dict:
    """Poll wg inside the (already elevated) helper until a handshake lands."""
    try:
        timeout = max(3, min(int(timeout_s), 300))
    except ValueError:
        raise WinHelperError("invalid timeout") from None
    deadline = time.time() + timeout
    st = verb_status()
    while time.time() < deadline:
        if st.get("wg_up") and int(st.get("latest_handshake", 0) or 0) > 0:
            break
        time.sleep(1.5)
        st = verb_status()
    st["handshake"] = bool(st.get("wg_up")
                           and int(st.get("latest_handshake", 0) or 0) > 0)
    return st


def _conf_tunnel_ip() -> str:
    try:
        with open(conf_dest(), encoding="utf-8") as fh:
            for line in fh:
                if line.strip().startswith("Address"):
                    return line.split("=", 1)[1].split(",")[0].split("/")[0].strip()
    except OSError:
        pass
    return ""


def verb_ks_on(iface: str, endpoint_ip: str, port: int, allow_lan: bool,
               proto: str = "udp") -> dict:
    valid_ip(endpoint_ip)
    if proto not in ("udp", "tcp"):
        raise WinHelperError("endpoint transport must be udp or tcp")
    if not _IFACE_RE.match(iface or "ignored"):
        raise WinHelperError("invalid interface name")
    verb_ks_off()
    excl: Tuple[str, ...] = (LAN_RANGES if allow_lan else ())
    block_list = ",".join(subtract_from_default(endpoint_ip, excl))
    try:
        adapters = physical_adapters()
    except WinHelperError:
        adapters = []
    n = 0
    powershell(
        f"New-NetFirewallRule -DisplayName 'Proto Clean KS endpoint' "
        f"-Group {ps_quote(KS_GROUP)} -Direction Outbound -Action Allow "
        f"-Protocol {proto.upper()} -RemoteAddress {ps_quote(endpoint_ip)} "
        f"-RemotePort {port} -Profile Any | Out-Null")
    for alias in adapters:
        powershell(
            f"New-NetFirewallRule -DisplayName "
            f"{ps_quote('Proto Clean KS block ' + alias)} "
            f"-Group {ps_quote(KS_GROUP)} -Direction Outbound -Action Block "
            f"-RemoteAddress {ps_quote(block_list)} "
            f"-InterfaceAlias {ps_quote(alias)} -Profile Any | Out-Null")
        n += 1
    if not adapters:
        # graceful degradation: block everything except endpoint + loopback
        powershell(
            f"New-NetFirewallRule -DisplayName 'Proto Clean KS block all' "
            f"-Group {ps_quote(KS_GROUP)} -Direction Outbound -Action Block "
            f"-RemoteAddress {ps_quote(block_list)} -Profile Any | Out-Null")
    return {"ok": True, "group": KS_GROUP, "adapters": n, "proto": proto}


def verb_ks_off() -> dict:
    powershell(f"Remove-NetFirewallRule -Group {ps_quote(KS_GROUP)} "
               f"-ErrorAction SilentlyContinue")
    return {"ok": True, "group": KS_GROUP, "state": "off"}


# ------------------------------------------------- IPv6 leak protection


def verb_v6_on() -> dict:
    """Block outbound IPv6 on the physical adapters (the tunnel adapter is
    virtual, so IPv6 inside the tunnel is untouched) — the Windows
    equivalent of the Linux PROTO_CLEAN_V6 ip6tables chain."""
    verb_v6_off()
    try:
        adapters = physical_adapters()
    except WinHelperError:
        adapters = []
    n = 0
    for alias in adapters:
        powershell(
            f"New-NetFirewallRule -DisplayName "
            f"{ps_quote('Proto Clean IPv6 block ' + alias)} "
            f"-Group {ps_quote(V6_GROUP)} -Direction Outbound -Action Block "
            f"-RemoteAddress '::/0' -InterfaceAlias {ps_quote(alias)} "
            f"-Profile Any | Out-Null")
        n += 1
    if not adapters:
        powershell(
            f"New-NetFirewallRule -DisplayName 'Proto Clean IPv6 block' "
            f"-Group {ps_quote(V6_GROUP)} -Direction Outbound -Action Block "
            f"-RemoteAddress '::/0' -Profile Any | Out-Null")
    return {"ok": True, "group": V6_GROUP, "adapters": n}


def verb_v6_off() -> dict:
    powershell(f"Remove-NetFirewallRule -Group {ps_quote(V6_GROUP)} "
               f"-ErrorAction SilentlyContinue")
    return {"ok": True, "group": V6_GROUP, "state": "off"}


def _noop(**extra) -> dict:
    return {"ok": True, **extra}


# ------------------------------------------------------------ dispatching


def validate_call(verb: str, args: Tuple[str, ...]) -> None:
    """Same whitelist shape as the Linux helper (plus wait-handshake)."""
    n = len(args)
    if verb == "install-config" and n == 1:
        return
    if verb in ("tunnel-up", "tunnel-down", "status", "ks-off", "dns-off",
                "split-on", "split-off", "cgroup-ensure",
                "v6-on", "v6-off", "ovpn-down") and n == 0:
        return
    if verb == "wait-handshake" and n == 1:
        if not args[0].isdigit() or not 1 <= int(args[0]) <= 600:
            raise WinHelperError("timeout must be 1..600 seconds")
        return
    if verb == "ks-on" and n in (4, 5):
        valid_ip(args[1])
        valid_port(args[2])
        if args[3] not in ("0", "1"):
            raise WinHelperError("allow_lan must be 0 or 1")
        if n == 5 and args[4] not in ("udp", "tcp"):
            raise WinHelperError("endpoint transport must be udp or tcp")
        return
    if verb == "ovpn-up" and n == 1:
        if args[0] not in ("tun", "tap"):
            raise WinHelperError("driver must be tun or tap")
        return
    if verb == "ovpn-install-config" and n == 1:
        return
    if verb == "dns-on" and n == 1:
        if not args[0].isdigit():
            raise WinHelperError("bad uid")
        return
    raise WinHelperError(f"unknown verb or bad arguments: {verb}")


_OVPN_UNSUPPORTED = (
    "OpenVPN tunnels are not supported by the Windows build — the bundled "
    "tunnel driver is WireGuard only. Switch the protocol back to WireGuard "
    "(Settings → Protocol).")


def execute(verb: str, args: Tuple[str, ...]) -> dict:
    if verb == "install-config":
        return verb_install_config(args[0])
    if verb == "tunnel-up":
        return verb_tunnel_up()
    if verb == "tunnel-down":
        return verb_tunnel_down()
    if verb == "status":
        return verb_status()
    if verb == "wait-handshake":
        return verb_wait_handshake(args[0])
    if verb == "ks-on":
        proto = args[4] if len(args) == 5 else "udp"
        return verb_ks_on(args[0], args[1], int(args[2]), args[3] == "1", proto)
    if verb == "ks-off":
        return verb_ks_off()
    if verb == "v6-on":
        return verb_v6_on()
    if verb == "v6-off":
        return verb_v6_off()
    if verb in ("ovpn-install-config", "ovpn-up", "ovpn-down"):
        raise WinHelperError(_OVPN_UNSUPPORTED)
    if verb in ("dns-on", "dns-off"):
        return _noop(note="DNS handled via config DNS=127.0.0.1 + port-53 "
                          "binder (no firewall rule needed on Windows)")
    if verb in ("split-on", "split-off"):
        return _noop(note="CIDR exclusions are applied inside the WireGuard "
                          "config (AllowedIPs)")
    if verb == "cgroup-ensure":
        return _noop()
    if verb in ("split-add-pid", "split-launch"):
        raise WinHelperError(
            "per-app split tunneling is not supported on Windows — exclude "
            "destination ranges instead (Settings → Split tunneling)")
    raise WinHelperError(f"unknown verb: {verb}")


def run_calls(calls) -> list:
    """Validate + execute a batch, returning one dict per call.

    Raises on the first failure so callers surface real errors; the elevated
    wrapper catches this and reports it as {"ok": false, ...}.
    """
    out = []
    for call in calls:
        verb, args = call[0], tuple(str(a) for a in call[1:])
        validate_call(verb, args)
        try:
            out.append(execute(verb, args))
        except WinHelperError as e:
            out.append({"ok": False, "error": str(e)})
    return out


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point of the elevated helper process.

    usage: python -m proto_clean.helper_win --out RESULT --calls CALLS
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    out_path = calls_path = ""
    i = 0
    while i < len(argv):
        if argv[i] == "--out" and i + 1 < len(argv):
            out_path = argv[i + 1]
            i += 2
        elif argv[i] == "--calls" and i + 1 < len(argv):
            calls_path = argv[i + 1]
            i += 2
        else:
            i += 1
    if not (out_path and calls_path):
        print(json.dumps({"ok": False, "error": "--out/--calls required"}))
        return 2
    try:
        with open(calls_path, encoding="utf-8") as fh:
            calls = json.load(fh)
        results = run_calls(calls)
        payload = results
    except Exception as e:  # noqa: BLE001
        payload = [{"ok": False, "error": str(e)}]
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
