#!/usr/bin/env bash
# Proto Clean — Linux build script (PyInstaller onedir + optional AppImage).
# Run from the repository root:
#   bash packaging/linux/build.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

python3 -m pip install --user -q -r requirements.txt pyinstaller 2>/dev/null \
  || python3 -m pip install -q -r requirements.txt pyinstaller

python3 -m PyInstaller --noconfirm --clean \
    --name proto-clean --windowed --onedir \
    --paths "$ROOT" \
    --hidden-import proto_clean.platforms.linux \
    --hidden-import dnslib \
    proto_clean/__main__.py

echo ""
echo "Built: $ROOT/dist/proto-clean/proto-clean (run: dist/proto-clean/proto-clean)"
echo "Then install the privileged helper:  bash scripts/install.sh"
echo ""
echo "Optional AppImage (requires appimagetool on PATH):"
if command -v appimagetool >/dev/null; then
    APPDIR=dist/ProtoClean.AppDir
    mkdir -p "$APPDIR/usr" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/512x512/apps"
    cp -R dist/proto-clean/* "$APPDIR/usr/"
    cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/proto-clean" "$@"
EOF
    chmod +x "$APPDIR/AppRun"
    cp packaging/linux/proto-clean.desktop "$APPDIR/usr/share/applications/" || true
    cp packaging/linux/proto-clean.png "$APPDIR/usr/share/icons/hicolor/512x512/apps/proto-clean.png" || true
    cp packaging/linux/proto-clean.png "$APPDIR/proto-clean.png" || true
    appimagetool "$APPDIR" dist/Proto-Clean-x86_64.AppImage || echo "appimagetool failed — onedir build still available"
else
    echo "  appimagetool not found — skipping (onedir build above is ready)"
fi
