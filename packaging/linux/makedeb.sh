#!/usr/bin/env bash
# Proto Clean — Debian package builder (Linux Mint / Ubuntu / Debian).
# Run from the repository root AFTER packaging/linux/build.sh (it reuses
# the dist/proto-clean onedir; runs PyInstaller itself if that is missing):
#   bash packaging/linux/build.sh
#   bash packaging/linux/makedeb.sh
# Produces dist/proto-clean_0.1.0_amd64.deb
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

VERSION="${PROTO_CLEAN_VERSION:-$(python3 -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])" 2>/dev/null || grep -m1 'version = "' pyproject.toml | cut -d\" -f2)}"
ARCH=amd64
PKGDIR="dist/deb-root"

if [ ! -d dist/proto-clean ]; then
    echo "dist/proto-clean missing — running packaging/linux/build.sh first…"
    bash packaging/linux/build.sh
fi

rm -rf "$PKGDIR"
install -d "$PKGDIR/opt/proto-clean" \
            "$PKGDIR/usr/bin" \
            "$PKGDIR/usr/share/applications" \
            "$PKGDIR/usr/share/icons/hicolor/512x512/apps" \
            "$PKGDIR/DEBIAN"

# ---------------------------------------------------------------- app bundle
cp -R dist/proto-clean/. "$PKGDIR/opt/proto-clean/"

# ---------------------------------------------------------------- launcher
cat > "$PKGDIR/usr/bin/proto-clean" <<'EOF'
#!/bin/sh
# Proto Clean launcher (Debian package)
exec "/opt/proto-clean/proto-clean" "$@"
EOF
chmod 0755 "$PKGDIR/usr/bin/proto-clean"

# ---------------------------------------------------------------- integration
cp packaging/linux/proto-clean.desktop "$PKGDIR/usr/share/applications/proto-clean.desktop"
cp packaging/linux/proto-clean.png     "$PKGDIR/usr/share/icons/hicolor/512x512/apps/proto-clean.png"

# the privileged helper ships in the package (activation is left to the user)
install -m 0755 helper/proto-clean-helper "$PKGDIR/opt/proto_clean/proto-clean-helper"

# ---------------------------------------------------------------- control
cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: proto-clean
Version: ${VERSION}-1
Section: net
Priority: optional
Architecture: ${ARCH}
Installed-Size: $(du -sk "$PKGDIR/opt" | cut -f1)
Depends: libegl1, libgl1, libxkbcommon0
Recommends: wireguard-tools
Suggests: openvpn
Maintainer: Proto Clean contributors <proto-clean@users.noreply.github.com>
Homepage: https://github.com/maniesh-NR/Proto-Clean
Description: Independent VPN client for Proton accounts (WireGuard / OpenVPN)
 Clean-room desktop client featuring backend-browser login with saved
 credentials and TOTP auto-fill, a free-server list with live loads,
 fastest-server auto-connect, local blocklist ad-blocking, split
 tunneling, NAT-PMP port forwarding, IPv6 controls and dark/light/system
 themes. Not affiliated with Proton AG.
EOF

# ---------------------------------------------------------------- scripts
cat > "$PKGDIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
HELPER=/opt/proto_clean/proto-clean-helper
if [ -x "$HELPER" ]; then
    install -m 0755 "$HELPER" /usr/local/bin/proto-clean-helper 2>/dev/null || true
fi
echo ""
echo "Proto Clean installed."
echo ""
echo "Optional — passwordless privileged verbs (recommended):"
echo "  echo \"$USER ALL=(root) NOPASSWD: /usr/local/bin/proto-clean-helper\" \\"
echo "    | sudo tee /etc/sudoers.d/proto-clean && sudo chmod 0440 /etc/sudoers.d/proto-clean"
echo ""
echo "Without it, Proto Clean asks for your password once per connect batch."
echo "First launch may download a Playwright Chromium for the login browser;"
echo "or pre-install it:  python3 -m playwright install chromium"
exit 0
EOF
chmod 0755 "$PKGDIR/DEBIAN/postinst"

# ---------------------------------------------------------------- build
mkdir -p dist
dpkg-deb --root-owner-group --build "$PKGDIR" \
    "dist/proto-clean_${VERSION}-1_${ARCH}.deb"
echo ""
echo "Built: dist/proto-clean_${VERSION}-1_${ARCH}.deb"
# sed instead of head: head closes the pipe early, and with
# pipefail dpkg-deb then dies of SIGPIPE (exit 141)
dpkg-deb --info "dist/proto-clean_${VERSION}-1_${ARCH}.deb" | sed -n 1,8p
