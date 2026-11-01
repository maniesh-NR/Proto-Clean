#!/usr/bin/env bash
# Cleanroom — Debian package builder (Linux Mint / Ubuntu / Debian).
# Run from the repository root AFTER packaging/linux/build.sh (it reuses
# the dist/cleanroom onedir; runs PyInstaller itself if that is missing):
#   bash packaging/linux/build.sh
#   bash packaging/linux/makedeb.sh
# Produces dist/cleanroom_0.1.0_amd64.deb
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

VERSION="$(python3 -c "import tomllib;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")"
ARCH=amd64
PKGDIR="dist/deb-root"

if [ ! -d dist/cleanroom ]; then
    echo "dist/cleanroom missing — running packaging/linux/build.sh first…"
    bash packaging/linux/build.sh
fi

rm -rf "$PKGDIR"
install -d "$PKGDIR/opt/cleanroom" \
            "$PKGDIR/usr/bin" \
            "$PKGDIR/usr/share/applications" \
            "$PKGDIR/usr/share/icons/hicolor/512x512/apps" \
            "$PKGDIR/DEBIAN"

# ---------------------------------------------------------------- app bundle
cp -R dist/cleanroom/. "$PKGDIR/opt/cleanroom/"

# ---------------------------------------------------------------- launcher
cat > "$PKGDIR/usr/bin/cleanroom" <<'EOF'
#!/bin/sh
# Cleanroom launcher (Debian package)
exec "/opt/cleanroom/cleanroom" "$@"
EOF
chmod 0755 "$PKGDIR/usr/bin/cleanroom"

# ---------------------------------------------------------------- integration
cp packaging/linux/cleanroom.desktop "$PKGDIR/usr/share/applications/cleanroom.desktop"
cp packaging/linux/cleanroom.png     "$PKGDIR/usr/share/icons/hicolor/512x512/apps/cleanroom.png"

# the privileged helper ships in the package (activation is left to the user)
install -m 0755 helper/cleanroom-helper "$PKGDIR/opt/cleanroom/cleanroom-helper"

# ---------------------------------------------------------------- control
cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: cleanroom
Version: ${VERSION}-1
Section: net
Priority: optional
Architecture: ${ARCH}
Installed-Size: $(du -sk "$PKGDIR/opt" | cut -f1)
Depends: libegl1, libgl1, libxkbcommon0
Recommends: wireguard-tools
Suggests: openvpn
Maintainer: Cleanroom contributors <cleanroom@users.noreply.github.com>
Homepage: https://github.com/maniesh-NR/Proton-Clean
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
HELPER=/opt/cleanroom/cleanroom-helper
if [ -x "$HELPER" ]; then
    install -m 0755 "$HELPER" /usr/local/bin/cleanroom-helper 2>/dev/null || true
fi
echo ""
echo "Cleanroom installed."
echo ""
echo "Optional — passwordless privileged verbs (recommended):"
echo "  echo \"$USER ALL=(root) NOPASSWD: /usr/local/bin/cleanroom-helper\" \\"
echo "    | sudo tee /etc/sudoers.d/cleanroom && sudo chmod 0440 /etc/sudoers.d/cleanroom"
echo ""
echo "Without it, Cleanroom asks for your password once per connect batch."
echo "First launch may download a Playwright Chromium for the login browser;"
echo "or pre-install it:  python3 -m playwright install chromium"
exit 0
EOF
chmod 0755 "$PKGDIR/DEBIAN/postinst"

# ---------------------------------------------------------------- build
mkdir -p dist
dpkg-deb --root-owner-group --build "$PKGDIR" \
    "dist/cleanroom_${VERSION}-1_${ARCH}.deb"
echo ""
echo "Built: dist/cleanroom_${VERSION}-1_${ARCH}.deb"
dpkg-deb --info "dist/cleanroom_${VERSION}-1_${ARCH}.deb" | head -8
