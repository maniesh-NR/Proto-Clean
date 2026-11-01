#!/usr/bin/env bash
# Cleanroom — Linux build script (PyInstaller onedir + optional AppImage).
# Run from the repository root:
#   bash packaging/linux/build.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

python3 -m pip install --user -q -r requirements.txt pyinstaller 2>/dev/null \
  || python3 -m pip install -q -r requirements.txt pyinstaller

python3 -m PyInstaller --noconfirm --clean \
    --name cleanroom --windowed --onedir \
    --paths "$ROOT" \
    --hidden-import cleanroom.platforms.linux \
    --hidden-import dnslib \
    cleanroom/__main__.py

echo ""
echo "Built: $ROOT/dist/cleanroom/Cleanroom (run: dist/cleanroom/cleanroom)"
echo "Then install the privileged helper:  bash scripts/install.sh"
echo ""
echo "Optional AppImage (requires appimagetool on PATH):"
if command -v appimagetool >/dev/null; then
    APPDIR=dist/Cleanroom.AppDir
    mkdir -p "$APPDIR/usr" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/512x512/apps"
    cp -R dist/cleanroom/* "$APPDIR/usr/"
    cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/cleanroom" "$@"
EOF
    chmod +x "$APPDIR/AppRun"
    cp packaging/linux/cleanroom.desktop "$APPDIR/usr/share/applications/" || true
    cp packaging/linux/cleanroom.png "$APPDIR/usr/share/icons/hicolor/512x512/apps/cleanroom.png" || true
    cp packaging/linux/cleanroom.png "$APPDIR/cleanroom.png" || true
    appimagetool "$APPDIR" dist/Cleanroom-x86_64.AppImage || echo "appimagetool failed — onedir build still available"
else
    echo "  appimagetool not found — skipping (onedir build above is ready)"
fi
