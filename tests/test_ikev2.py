"""Tests for the IKEv2 system adapter.

Golden tests cover the three config generators (swanctl.conf, Apple
.mobileconfig, Windows PowerShell/rasdial) and the engine lifecycle runs
entirely on a monkeypatched :func:`proto_clean.vpn.protocols.ikev2._run` +
``shutil.which`` — no OS tooling is ever invoked. The platform branch is
selected by monkeypatching the module-level ``PLATFORM_NAME`` (same pattern
as tests/test_xray.py).
"""

import os
import xml.etree.ElementTree as ET

import pytest

from proto_clean.vpn.protocols import ikev2 as IK
from proto_clean.vpn.protocols.base import ProtocolError
from proto_clean.vpn.protocols.ikev2 import (
    build_mobileconfig,
    build_swanctl_conf,
    build_windows_disconnect,
    build_windows_ps,
)
from proto_clean.vpn.protocols.models import Ikev2Profile

EAP = Ikev2Profile(server="vpn.example.com", port=500, auth="eap-mschapv2",
                   username="alice", password="s3cret<pw>",
                   identity="alice@protoclean", remote_id="gw.example.com")

PSK = Ikev2Profile(server="vpn2.example.com", port=500, auth="psk",
                   psk="shared-key", identity="bob", remote_id="")


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_run(monkeypatch, responder=None):
    """Replace IK._run with a recorder; returns the captured call list."""
    calls = []

    def fake_run(cmd, **kw):
        calls.append(list(cmd))
        if responder is not None:
            return responder(list(cmd), kw)
        return _FakeProc()

    monkeypatch.setattr(IK, "_run", fake_run)
    return calls


def _patch_linux(monkeypatch, tmp_path):
    """Force the linux branch with swanctl present and a temp CONFIG_DIR."""
    monkeypatch.setattr(IK.shutil, "which", lambda n: "/usr/bin/swanctl")
    monkeypatch.setattr(IK, "PLATFORM_NAME", "linux")
    monkeypatch.setattr(IK, "CONFIG_DIR", tmp_path)


# ----------------------------------------------------- swanctl.conf (Linux)

def test_swanctl_conf_eap():
    conf = build_swanctl_conf(EAP)
    assert "remote_addrs = vpn.example.com" in conf
    assert "local_addrs = %any" in conf
    assert "version = 2" in conf
    assert "auth = eap-mschapv2" in conf
    assert "eap_id = alice" in conf
    assert "id = alice@protoclean" in conf          # local identity
    assert "auth = pubkey" in conf and "id = gw.example.com" in conf
    # EAP credentials travel through a secrets stanza
    assert "eap-proto-clean {" in conf
    assert "id = alice" in conf and 'secret = "s3cret<pw>"' in conf
    assert "connections {" in conf and "children {" in conf
    assert "remote_ts = 0.0.0.0/0" in conf and "esp_proposals" in conf


def test_swanctl_conf_psk_secret_stanza():
    conf = build_swanctl_conf(PSK)
    assert "remote_addrs = vpn2.example.com" in conf
    assert "auth = psk" in conf
    assert "ike-proto-clean {" in conf              # dedicated PSK stanza
    assert 'secret = "shared-key"' in conf
    assert "eap-" not in conf and "eap_id" not in conf


def test_swanctl_conf_is_plain_text_not_xml():
    plain = Ikev2Profile(server="vpn.example.com", auth="eap-mschapv2",
                         username="alice", password="s3cret",
                         identity="alice@protoclean", remote_id="gw.example.com")
    for profile in (plain, PSK):
        conf = build_swanctl_conf(profile)
        assert "<" not in conf and ">" not in conf and "&" not in conf


def test_swanctl_secret_quoting():
    tricky = Ikev2Profile(server="vpn.example.com", auth="psk",
                          psk='a"b\\c')
    conf = build_swanctl_conf(tricky)
    assert 'secret = "a\\"b\\\\c"' in conf     # " and \\ escaped


def test_swanctl_conf_custom_conn_name():
    conf = build_swanctl_conf(EAP, conn_name="hop1")
    assert "connections {" in conf and "    hop1 {" in conf
    assert "eap-hop1 {" in conf


# ------------------------------------------------- .mobileconfig (macOS)

def _parse_plist(xml_text):
    """ElementTree-parse a mobileconfig and return (top_dict, vpn_payload)."""
    top = ET.fromstring(xml_text).find("dict")

    def as_dict(node):
        out, kids = {}, list(node)
        i = 0
        while i < len(kids):
            if kids[i].tag == "key":
                out[kids[i].text] = kids[i + 1]
                i += 2
            else:
                i += 1
        return out

    d = as_dict(top)
    assert d["PayloadContent"].tag == "array"
    return d, as_dict(list(d["PayloadContent"])[0])


def test_mobileconfig_eap_payload():
    top, vpn = _parse_plist(build_mobileconfig(EAP))
    assert top["PayloadType"].text == "Configuration"
    assert top["PayloadIdentifier"].text == "app.protoclean.ikev2"
    assert top["PayloadDisplayName"].text == "Proto Clean IKEv2"
    assert top["PayloadVersion"].text == "1"
    assert vpn["IPsecType"].text == "IKEv2"
    assert vpn["RemoteAddress"].text == "vpn.example.com"
    assert vpn["RemoteIdentifier"].text == "gw.example.com"
    assert vpn["LocalIdentifier"].text == "alice@protoclean"
    # EAP: AuthName/AuthPassword present, AuthenticationMethod absent
    assert vpn["AuthName"].text == "alice"
    assert vpn["AuthPassword"].text == "s3cret<pw>"
    assert "AuthenticationMethod" not in vpn
    assert "SharedSecret" not in vpn


def test_mobileconfig_psk_payload():
    _top, vpn = _parse_plist(build_mobileconfig(PSK))
    assert vpn["RemoteAddress"].text == "vpn2.example.com"
    assert vpn["AuthenticationMethod"].text == "SharedSecret"
    assert vpn["SharedSecret"].text == "shared-key"
    assert "AuthPassword" not in vpn and "AuthName" not in vpn


def test_mobileconfig_payload_uuid_stable():
    top1, vpn1 = _parse_plist(build_mobileconfig(EAP))
    top2, vpn2 = _parse_plist(build_mobileconfig(EAP))
    assert top1["PayloadUUID"].text == top2["PayloadUUID"].text
    assert vpn1["PayloadUUID"].text == vpn2["PayloadUUID"].text
    # derived from the server: a different server yields a different UUID
    other = _parse_plist(
        build_mobileconfig(Ikev2Profile(server="other.example",
                                        auth="eap-mschapv2")))[0]
    assert other["PayloadUUID"].text != top1["PayloadUUID"].text


def test_mobileconfig_escapes_xml_values():
    nasty = Ikev2Profile(server="a&b.example", auth="psk", psk='k"<x>&y')
    _top, vpn = _parse_plist(build_mobileconfig(nasty))   # must parse cleanly
    assert vpn["RemoteAddress"].text == "a&b.example"
    assert vpn["SharedSecret"].text == 'k"<x>&y'


# ------------------------------------------- Windows PowerShell + rasdial

def test_windows_ps_eap():
    cmds = build_windows_ps(EAP)
    assert len(cmds) == 2
    add, dial = cmds
    assert add.startswith("Add-VpnConnection")
    assert "-Name 'Proto Clean IKEv2'" in add
    assert "-ServerAddress 'vpn.example.com'" in add
    assert "-TunnelType IKEv2" in add and "-AuthenticationMethod EAP" in add
    assert dial.startswith("rasdial ")
    assert '"Proto Clean IKEv2"' in dial and '"alice"' in dial \
        and '"s3cret<pw>"' in dial


def test_windows_ps_psk():
    cmds = build_windows_ps(PSK)
    add, dial = cmds
    assert "Add-VpnConnection" in add and "-TunnelType IKEv2" in add
    assert "-AuthenticationMethod PresharedKey" in add
    assert "-SharedSecret 'shared-key'" in add
    assert dial == 'rasdial "Proto Clean IKEv2"'     # PSK: no credentials


def test_windows_disconnect_helper():
    d = build_windows_disconnect("Proto Clean IKEv2")
    assert d.startswith("rasdial ") and "/disconnect" in d
    assert '"Proto Clean IKEv2"' in d


# ------------------------------------------------------------ engine: Linux

def test_engine_metadata_and_factory():
    e = IK.engine(EAP, socks_port=0)
    assert isinstance(e, IK.Ikev2Engine)
    assert e.proxy_kind == "ikev2"
    assert e.family == "tunnel"
    assert e.exposes == "tunnel"
    assert e.binary_name == ""
    assert e.running is False


def test_linux_start_success(monkeypatch, tmp_path):
    calls = _patch_run(monkeypatch)
    _patch_linux(monkeypatch, tmp_path)
    e = IK.engine(EAP)
    e.start(EAP, timeout=5)
    assert e.running is True
    assert calls[0][:2] == ["swanctl", "--load-all"]
    assert calls[0][2] == "--file" and calls[0][3].endswith("swanctl.conf")
    assert calls[1] == ["swanctl", "--initiate", "--ike", "proto-clean",
                        "--child", "proto-clean"]
    # config was written into CONFIG_DIR
    conf_path = os.path.join(str(tmp_path), "swanctl.conf")
    assert os.path.isfile(conf_path)
    with open(conf_path, encoding="utf-8") as f:
        assert "remote_addrs = vpn.example.com" in f.read()
    st = e.status()
    assert st["tool"] == "swanctl" and st["profile_name"] == "proto-clean"
    assert st["running"] is True and st["kind"] == "ikev2"


def test_linux_missing_swanctl_raises(monkeypatch, tmp_path):
    _patch_run(monkeypatch)
    monkeypatch.setattr(IK.shutil, "which", lambda n: None)
    monkeypatch.setattr(IK, "PLATFORM_NAME", "linux")
    monkeypatch.setattr(IK, "CONFIG_DIR", tmp_path)
    e = IK.engine(EAP)
    with pytest.raises(ProtocolError) as ei:
        e.start(EAP)
    assert "not found" in str(ei.value) and "swanctl" in str(ei.value)
    assert "strongswan-swanctl" in str(ei.value)
    assert e.running is False


def test_linux_load_failure_surfaces_stderr(monkeypatch, tmp_path):
    _patch_run(monkeypatch, lambda cmd, kw: _FakeProc(
        returncode=1, stderr="parse error: invalid stanza"))
    _patch_linux(monkeypatch, tmp_path)
    e = IK.engine(EAP)
    with pytest.raises(ProtocolError) as ei:
        e.start(EAP)
    assert "parse error: invalid stanza" in str(ei.value)
    assert e.running is False


def test_linux_initiate_failure_surfaces_stderr(monkeypatch, tmp_path):
    def responder(cmd, kw):
        if cmd[1] == "--initiate":
            return _FakeProc(returncode=1, stderr="no IKE config named x")
        return _FakeProc()
    _patch_run(monkeypatch, responder)
    _patch_linux(monkeypatch, tmp_path)
    e = IK.engine(EAP)
    with pytest.raises(ProtocolError) as ei:
        e.start(EAP)
    assert "no IKE config" in str(ei.value)
    assert e.running is False


def test_linux_stop_terminates(monkeypatch, tmp_path):
    calls = _patch_run(monkeypatch)
    _patch_linux(monkeypatch, tmp_path)
    e = IK.engine(EAP)
    e.start(EAP, timeout=5)
    e.stop()
    assert calls[-1] == ["swanctl", "--terminate", "--ike", "proto-clean"]
    assert e.running is False
    e.stop()   # idempotent, still best-effort terminate
    assert calls[-1] == ["swanctl", "--terminate", "--ike", "proto-clean"]


# ------------------------------------------------------------ engine: macOS

def test_macos_first_install_opens_profile(monkeypatch, tmp_path):
    calls = _patch_run(monkeypatch)
    monkeypatch.setattr(IK, "PLATFORM_NAME", "macos")
    monkeypatch.setattr(IK, "CONFIG_DIR", tmp_path)
    e = IK.engine(EAP)
    with pytest.raises(ProtocolError) as ei:
        e.start(EAP, timeout=5)
    assert "confirm it in System Settings" in str(ei.value)
    assert e.running is False
    # detection happens first, then the profile is opened for import
    assert calls[0] == ["scutil", "--nc", "list"]
    assert calls[1] == ["open", os.path.join(str(tmp_path),
                                             "proto-clean-ikev2.mobileconfig")]
    mc = os.path.join(str(tmp_path), "proto-clean-ikev2.mobileconfig")
    with open(mc, encoding="utf-8") as f:
        assert "<key>IPsecType</key>" in f.read()


def test_macos_start_when_already_installed(monkeypatch, tmp_path):
    calls = _patch_run(monkeypatch, lambda cmd, kw: _FakeProc(
        stdout="<dictionary> … * [Proto Clean IKEv2] …</dictionary>"
        if cmd[:3] == ["scutil", "--nc", "list"] else ""))
    monkeypatch.setattr(IK, "PLATFORM_NAME", "macos")
    monkeypatch.setattr(IK, "CONFIG_DIR", tmp_path)
    e = IK.engine(EAP)
    e.start(EAP, timeout=5)
    assert e.running is True
    assert ["scutil", "--nc", "start", "Proto Clean IKEv2",
            "--user", "alice", "--password", "s3cret<pw>"] in calls
    assert all(c[0] != "open" for c in calls)        # no re-import
    assert e.status()["tool"] == "scutil"
    assert e.status()["profile_name"] == "Proto Clean IKEv2"


def test_macos_stop_uses_scutil(monkeypatch):
    calls = _patch_run(monkeypatch)
    monkeypatch.setattr(IK, "PLATFORM_NAME", "macos")
    e = IK.engine(EAP)
    e.stop()
    assert calls[-1] == ["scutil", "--nc", "stop", "Proto Clean IKEv2"]
    assert e.running is False


# ---------------------------------------------------------- engine: Windows

def test_windows_start_runs_powershell_and_rasdial(monkeypatch):
    calls = _patch_run(monkeypatch)
    monkeypatch.setattr(IK, "PLATFORM_NAME", "windows")
    e = IK.engine(EAP)
    e.start(EAP, timeout=5)
    assert e.running is True
    ps = [c for c in calls if c[0] == "powershell"]
    assert ps and ps[0][:3] == ["powershell", "-NoProfile", "-Command"]
    assert "Add-VpnConnection" in ps[0][3]
    assert "-AuthenticationMethod EAP" in ps[0][3]
    ras = [c for c in calls if c[0] == "rasdial"]
    assert ras == [["rasdial", "Proto Clean IKEv2", "alice", "s3cret<pw>"]]
    assert e.status()["tool"] == "rasdial"
    assert e.status()["profile_name"] == "Proto Clean IKEv2"


def test_windows_psk_start_args(monkeypatch):
    calls = _patch_run(monkeypatch)
    monkeypatch.setattr(IK, "PLATFORM_NAME", "windows")
    e = IK.engine(PSK)
    e.start(PSK, timeout=5)
    ps = [c for c in calls if c[0] == "powershell"][0]
    assert "PresharedKey" in ps[3] and "SharedSecret" in ps[3]
    assert ["rasdial", "Proto Clean IKEv2"] in calls


def test_windows_setup_failure_raises(monkeypatch):
    _patch_run(monkeypatch, lambda cmd, kw: _FakeProc(
        returncode=87, stderr="The parameter is incorrect."))
    monkeypatch.setattr(IK, "PLATFORM_NAME", "windows")
    e = IK.engine(EAP)
    with pytest.raises(ProtocolError) as ei:
        e.start(EAP)
    assert "The parameter is incorrect." in str(ei.value)
    assert e.running is False


def test_windows_stop_disconnects(monkeypatch):
    calls = _patch_run(monkeypatch)
    monkeypatch.setattr(IK, "PLATFORM_NAME", "windows")
    e = IK.engine(PSK)
    e.start(PSK, timeout=5)
    e.stop()
    assert calls[-1] == ["rasdial", "Proto Clean IKEv2", "/disconnect"]
    assert e.running is False


# ------------------------------------------------------------------ misc

def test_unsupported_platform_raises(monkeypatch):
    _patch_run(monkeypatch)
    monkeypatch.setattr(IK, "PLATFORM_NAME", "freebsd")
    e = IK.engine(EAP)
    with pytest.raises(ProtocolError):
        e.start(EAP)
    assert e.running is False
