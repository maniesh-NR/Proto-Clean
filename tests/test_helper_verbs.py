"""Whitelist/validation tests for the privileged helper scripts.

Argument validation happens *before* any privileged side effect, so these
tests run unprivileged: bad input must exit non-zero with a JSON error and
must never reach iptables/openvpn. The pure validators are also imported
directly (the helper has no .py extension — loaded via importlib).
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

HELPER = Path(__file__).resolve().parent.parent / "helper" / "proto-clean-helper"


def _load_helper():
    spec = importlib.util.spec_from_loader(
        "proto_clean_helper_test", importlib.machinery.SourceFileLoader(
            "proto_clean_helper_test", str(HELPER)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(*args):
    return subprocess.run([sys.executable, str(HELPER), *args],
                          capture_output=True, text=True, timeout=30)


def _err(proc):
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"ok": None, "error": proc.stdout + proc.stderr}


# ------------------------------------------------------------- pure checks

def test_validate_ovpn_conf():
    h = _load_helper()
    assert h.validate_ovpn_conf("client\nremote 1.2.3.4 443\n")
    assert not h.validate_ovpn_conf("client\n")          # no remote
    assert not h.validate_ovpn_conf(                     # shell hook
        "client\nremote 1.2.3.4 443\nup /bin/sh\n")
    assert not h.validate_ovpn_conf(                     # shell hook
        "client\nremote 1.2.3.4 443\nscript-security 2\n")
    # certificate block content must not look like directives
    assert h.validate_ovpn_conf(
        "client\nremote 1.2.3.4 443\n<ca>\nup /bin/sh\n</ca>\n")


def test_validate_wg_conf_still_enforced():
    h = _load_helper()
    assert h.validate_wg_conf("[Interface]\nPrivateKey = k\n\n[Peer]\n"
                              "PublicKey = p\nAllowedIPs = 0.0.0.0/0\n")
    assert not h.validate_wg_conf("[Interface]\nPrivateKey = k\nPreUp = x\n")


# --------------------------------------------------- argument whitelist

def test_ovpn_up_rejects_bad_driver():
    out = _err(_run("ovpn-up", "vEthernet"))
    assert out.get("ok") is False
    assert "driver must be tun or tap" in out.get("error", "")


def test_ovpn_up_accepts_tun_and_tap_validation():
    for driver in ("tun", "tap"):
        out = _err(_run("ovpn-up", driver))
        # validation passed; the failure must be environmental (no config as
        # root), never the driver check
        assert "driver must be tun or tap" not in out.get("error", "")


def test_ks_on_rejects_bad_transport():
    out = _err(_run("ks-on", "eth0", "1.2.3.4", "51820", "0", "sctp"))
    assert out.get("ok") is False
    assert "protocol must be udp or tcp" in out.get("error", "")


def test_ovpn_install_config_rejects_outside_paths():
    out = _err(_run("ovpn-install-config", "/etc/passwd"))
    assert out.get("ok") is False
    assert "source path not allowed" in out.get("error", "")


def test_unknown_verb_rejected():
    out = _err(_run("rm-rf", "--", "/"))
    assert out.get("ok") is False
    assert "unknown verb" in out.get("error", "")


# ------------------------------------------------- regression tests (review)

def test_split_launch_dispatch_matches_documented_format(monkeypatch):
    """split-launch UID GID -- CMD… — the '--' separator sits at rest[2] and
    the command is rest[3:] (regression: the dispatcher used to look for
    '--' at rest[3] and dropped the first command token)."""
    helper = _load_helper()
    captured = {}
    monkeypatch.setattr(helper, "verb_split_launch",
                        lambda uid, gid, cmd: captured.update(uid=uid,
                                                              gid=gid,
                                                              cmd=list(cmd)))
    argv = ["proto-clean-helper", "split-launch", "1000", "1000", "--",
            "/usr/bin/firefox", "--new-window"]
    old = sys.argv
    sys.argv = argv
    try:
        helper.main()
    finally:
        sys.argv = old
    assert captured == {"uid": 1000, "gid": 1000,
                        "cmd": ["/usr/bin/firefox", "--new-window"]}


# ------------------------------------------------------- Xray proxy verbs

def test_proxy_on_rejects_bad_service_name():
    out = _err(_run("proxy-on", "*all", "127.0.0.1", "10808"))
    assert out.get("ok") is False
    assert "invalid network service name" in out.get("error", "")


def test_proxy_on_rejects_bad_host():
    out = _err(_run("proxy-on", "Wi-Fi", "127.0.0.1 ; rm -rf /", "10808"))
    assert out.get("ok") is False
    assert "invalid proxy host" in out.get("error", "")


def test_proxy_on_rejects_bad_port():
    out = _err(_run("proxy-on", "Wi-Fi", "127.0.0.1", "99999"))
    assert out.get("ok") is False
    assert "port out of range" in out.get("error", "")
    out = _err(_run("proxy-on", "Wi-Fi", "127.0.0.1", "0"))
    assert out.get("ok") is False
    assert "port out of range" in out.get("error", "")


def test_proxy_off_rejects_bad_service_name():
    out = _err(_run("proxy-off", "-h"))
    assert out.get("ok") is False
    assert "invalid network service name" in out.get("error", "")


def test_proxy_verbs_are_macos_only_on_linux():
    import sys as _sys
    if not _sys.platform.startswith("linux"):
        return  # macOS CI: covered by validation tests above
    out = _err(_run("proxy-on", "Wi-Fi", "127.0.0.1", "10808"))
    assert out.get("ok") is False
    assert "macOS-only" in out.get("error", "")
    out = _err(_run("proxy-off", "Wi-Fi"))
    assert out.get("ok") is False
    assert "macOS-only" in out.get("error", "")


def test_proxy_verb_dispatch_calls_implementation(monkeypatch):
    helper = _load_helper()
    captured = {}
    monkeypatch.setattr(helper, "DARWIN", True)
    monkeypatch.setattr(helper, "verb_proxy_on",
                        lambda svc, host, port: captured.update(
                            svc=svc, host=host, port=port))
    monkeypatch.setattr(helper, "verb_proxy_off",
                        lambda svc: captured.update(off=svc))
    old = sys.argv
    try:
        sys.argv = ["h", "proxy-on", "Wi-Fi", "127.0.0.1", "10808"]
        helper.main()
        sys.argv = ["h", "proxy-off", "Wi-Fi"]
        helper.main()
    except SystemExit:
        pass
    finally:
        sys.argv = old
    assert captured == {"svc": "Wi-Fi", "host": "127.0.0.1", "port": 10808,
                        "off": "Wi-Fi"}
