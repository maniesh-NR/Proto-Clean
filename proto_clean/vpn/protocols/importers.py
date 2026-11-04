"""Import center — one facade for every way a config can arrive.

* **Clipboard** — any text: share links (one per line), Clash YAML,
  V2ray/sing-box JSON, base64 subscriptions.
* **QR on the screen** — grab the screen with Qt and decode with
  zxing-cpp; every QR found is imported.
* **QR in an image** — decode a PNG/JPEG the user picked.
* **Config files** — ``.txt`` (links), ``.yaml``/``.yml`` (Clash),
  ``.json`` (V2ray, sing-box, Xray client configs, subscriptions),
  ``.conf`` (WireGuard / AmneziaWG), ``.ovpn`` (OpenVPN, incl. Cloak
  compositions), Tor bridge lines.
* **Subscription URLs** — fetched with httpx, format auto-detected.

Everything funnels into :class:`ProfileStore`; the returned summary tells
the UI exactly what happened.
"""

from __future__ import annotations

import os
from typing import Callable, Dict, List, Optional, Tuple

from ...log import get
from . import convert, links, models as M
from .base import ProtocolError, ProtocolProfile

log = get("protocols.importers")

try:
    import zxingcpp
    HAVE_ZXING = True
except ImportError:                                  # pragma: no cover
    zxingcpp = None
    HAVE_ZXING = False

try:
    import segno
    HAVE_SEGNO = True
except ImportError:                                  # pragma: no cover
    segno = None
    HAVE_SEGNO = False


class ImportSummary:
    """What an import produced — for the result toast/dialog."""

    def __init__(self) -> None:
        self.added: List[Tuple[str, str]] = []       # (kind, name)
        self.skipped: List[str] = []
        self.errors: List[str] = []

    @property
    def ok(self) -> bool:
        return bool(self.added)

    def __repr__(self) -> str:  # pragma: no cover
        return "ImportSummary(added=%d skipped=%d errors=%d)" % (
            len(self.added), len(self.skipped), len(self.errors))


# ---------------------------------------------------------------------------
# text parsing (the core every source funnels through)
# ---------------------------------------------------------------------------
def parse_text(text: str) -> List[ProtocolProfile]:
    """Parse arbitrary text into profiles (links, YAML, JSON, base64)."""
    text = (text or "").strip()
    if not text:
        return []
    # whole text is a single share link?
    first = text.splitlines()[0].strip()
    non_comment = [ln for ln in text.splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]
    if links.looks_like_link(first) and len(non_comment) == 1:
        _kind, prof = links.parse_link(first)
        return [prof]
    # multi-link text (possibly base64-wrapped)?
    found = links.extract_links(text)
    if len(found) >= 1 and not _looks_like_config(text):
        profiles: List[ProtocolProfile] = []
        for link in found:
            try:
                _k, prof = links.parse_link(link)
                profiles.append(prof)
            except ProtocolError as exc:
                log.debug("link skipped: %s", exc)
        if profiles:
            return profiles
    # configs / subscriptions
    return convert.decode_subscription(text)


def _looks_like_config(text: str) -> bool:
    head = text[:4000]
    return (head.lstrip().startswith("{")
            or convert._looks_like_clash(head)
            or "[Interface]" in head or "[Peer]" in head
            or _starts_with_client_directive(head))


def _starts_with_client_directive(text: str) -> bool:
    """OpenVPN configs open with a bare `client` directive on its own
    line (``client\ndev tun...``) or as ``client dev tun``; accept the
    keyword followed by any whitespace (or end of input)."""
    head = text.lstrip()
    return head.startswith("client") and (
        len(head) == 6 or head[6] in " \t\r\n")


def parse_file(path: str) -> List[ProtocolProfile]:
    """Parse a config file by extension and content."""
    ext = os.path.splitext(path or "")[1].lower()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as exc:
        raise ProtocolError("cannot read %s: %s" % (path, exc)) from None
    if not text.strip():
        return []
    if ext in (".conf", ".txt") or "[Interface]" in text[:400]:
        profiles = _parse_wireguard_text(text, path)
        if profiles:
            return profiles
    if ext == ".ovpn" or _starts_with_client_directive(text[:400]):
        return [M.CloakProfile(server="", port=443,
                               openvpn_config=text)]
    profiles = parse_text(text)
    if profiles:
        return profiles
    raise ProtocolError("nothing importable in %s" % path)


def _parse_wireguard_text(text: str, path: str) -> List[ProtocolProfile]:
    """WireGuard / AmneziaWG .conf files (extra WG junk params included)."""
    try:
        from ..wgconf import parse_wg_config
    except Exception:                                 # pragma: no cover
        return []
    try:
        parsed = parse_wg_config(text)
    except Exception as exc:
        log.debug("wg conf %s not parseable: %s", path, exc)
        return []
    if not parsed:
        return []
    interface, peer = parsed[0], parsed[1] if len(parsed) > 1 else {}
    junk: Dict[str, int] = {}
    extra: Dict[str, str] = {}
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
        if key in interface:
            try:
                junk[key] = int(interface[key])
            except (TypeError, ValueError):
                pass
    for key, value in interface.items():
        if key not in ("Address", "PrivateKey", "DNS", "MTU",
                       "Jc", "Jmin", "Jmax", "S1", "S2",
                       "H1", "H2", "H3", "H4") and \
                not key.startswith("#"):
            extra[str(key)] = str(value)
    endpoint = str(peer.get("Endpoint") or "")
    server, _, port_s = endpoint.partition(":")
    try:
        port = int(port_s or "51820")
    except ValueError:
        port = 51820
    addrs = [str(a).strip() for a in
             str(interface.get("Address") or "").split(",")
             if str(a).strip()]
    dns = [str(d).strip() for d in
           str(interface.get("DNS") or "").split(",")
           if str(d).strip()]
    if not server or not interface.get("PrivateKey"):
        return []
    profile = M.AwgProfile(
        server=server, port=port,
        private_key=str(interface.get("PrivateKey") or ""),
        peer_public_key=str(peer.get("PublicKey") or ""),
        preshared_key=str(peer.get("PresharedKey") or ""),
        address=addrs or ["10.8.1.2/32"], dns=dns,
        mtu=int(interface.get("MTU") or 0) or 0,
        allowed_ips=[str(a).strip() for a in
                     str(peer.get("AllowedIPs") or "0.0.0.0/0").split(",")
                     if str(a).strip()] or ["0.0.0.0/0"],
        junk=junk, extra=extra,
        tag=os.path.splitext(os.path.basename(path))[0])
    return [profile]


def parse_bridge_lines(text: str) -> List[M.TorProfile]:
    """Tor bridge lines (obfs4/snowflake/webtunnel/plain)."""
    from .tor import parse_bridge_line
    bridges: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parse_bridge_line(line)
            bridges.append(line)
        except ProtocolError:
            continue
    if not bridges:
        return []
    return [M.TorProfile(bridges=bridges)]


# ---------------------------------------------------------------------------
# QR
# ---------------------------------------------------------------------------
def decode_qr_image(image) -> List[str]:
    """Decode every QR in a PIL image / numpy array → payload strings."""
    if not HAVE_ZXING:                                # pragma: no cover
        raise ProtocolError("QR decoding needs zxing-cpp "
                            "(pip install zxing-cpp)")
    results = zxingcpp.read_barcodes(image)
    return [r.text for r in results if r.text]


def decode_qr_file(path: str) -> List[str]:
    """Decode every QR code in an image file."""
    try:
        from PIL import Image
    except ImportError:                               # pragma: no cover
        raise ProtocolError("QR image import needs Pillow "
                            "(pip install pillow)")
    img = Image.open(path)
    return decode_qr_image(img)


def decode_qr_screen() -> List[str]:
    """Grab every screen with Qt and decode all QR codes on them."""
    try:
        from ...qtcompat import QtWidgets  # noqa: F401
    except Exception:                                 # pragma: no cover
        raise ProtocolError("QR screen capture needs the Qt UI running")
    from ...qtcompat import QtGui
    payloads: List[str] = []
    app = QtWidgets.QApplication.instance()
    if app is None:                                   # pragma: no cover
        raise ProtocolError("no Qt application for screen capture")
    for screen in app.screens():
        pixmap = screen.grabWindow(0)
        image = pixmap.toImage()
        # convert QImage → PIL via bytes
        try:
            from PIL import Image
        except ImportError:                           # pragma: no cover
            raise ProtocolError("QR screen capture needs Pillow")
        image = image.convertToFormat(QtGui.QImage.Format.Format_RGBA8888)
        width, height = image.width(), image.height()
        data = image.constBits().tobytes() if hasattr(image, "constBits") \
            else bytes(image.bits().asstring(width * height * 4))
        pil = Image.frombytes("RGBA", (width, height), data, "raw",
                              "RGBA")
        payloads.extend(decode_qr_image(pil))
    return payloads


def make_qr(text: str, path: str = "", scale: int = 8) -> object:
    """Generate a QR image (segno) for sharing a profile."""
    if not HAVE_SEGNO:                                # pragma: no cover
        raise ProtocolError("QR generation needs segno "
                            "(pip install segno)")
    qr = segno.make(text, error="m")
    if path:
        qr.save(path, scale=scale, border=2)
    return qr


# ---------------------------------------------------------------------------
# subscriptions
# ---------------------------------------------------------------------------
def fetch_subscription(url: str, timeout: float = 20.0) -> List[ProtocolProfile]:
    """Fetch and parse a subscription URL (auto-detects the format)."""
    import httpx
    headers = {"User-Agent": "ProtoClean/protocols"}
    with httpx.Client(timeout=timeout, follow_redirects=True,
                      headers=headers) as client:
        resp = client.get(url)
    if resp.status_code >= 400:
        raise ProtocolError("subscription fetch failed (HTTP %d)"
                            % resp.status_code)
    return convert.decode_subscription(resp.text)


# ---------------------------------------------------------------------------
# the facade
# ---------------------------------------------------------------------------
class ImportCenter:
    """Import from any source into a :class:`.profiles.ProfileStore`."""

    def __init__(self, store) -> None:
        self.store = store

    def _absorb(self, profiles: List[ProtocolProfile],
                summary: ImportSummary) -> ImportSummary:
        for prof in profiles:
            kind = getattr(prof, "kind", "") or ""
            try:
                entry = self.store.add(kind, prof)
                summary.added.append((entry.kind, entry.name))
            except ProtocolError as exc:
                summary.errors.append(str(exc))
        return summary

    def import_text(self, text: str) -> ImportSummary:
        summary = ImportSummary()
        try:
            profiles = parse_text(text)
        except ProtocolError as exc:
            summary.errors.append(str(exc))
            return summary
        if not profiles:
            summary.errors.append("nothing importable found")
            return summary
        return self._absorb(profiles, summary)

    def import_file(self, path: str) -> ImportSummary:
        summary = ImportSummary()
        try:
            profiles = parse_file(path)
        except ProtocolError as exc:
            summary.errors.append(str(exc))
            return summary
        return self._absorb(profiles, summary)

    def import_qr_payloads(self, payloads: List[str]) -> ImportSummary:
        summary = ImportSummary()
        for payload in payloads:
            try:
                profiles = parse_text(payload)
                self._absorb(profiles, summary)
            except ProtocolError as exc:
                summary.errors.append(str(exc))
        return summary

    def import_qr_image(self, path: str) -> ImportSummary:
        return self.import_qr_payloads(decode_qr_file(path))

    def import_qr_screen(self) -> ImportSummary:
        return self.import_qr_payloads(decode_qr_screen())

    def import_subscription(self, url: str) -> ImportSummary:
        summary = ImportSummary()
        try:
            profiles = fetch_subscription(url)
        except ProtocolError as exc:
            summary.errors.append(str(exc))
            return summary
        if not profiles:
            summary.errors.append("subscription contained no profiles")
            return summary
        return self._absorb(profiles, summary)

    def import_clipboard(self, clipboard_text: str) -> ImportSummary:
        return self.import_text(clipboard_text)
