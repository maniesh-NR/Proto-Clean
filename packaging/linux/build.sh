#!/usr/bin/env bash
# Proton Clean — Linux build script (PyInstaller onedir + optional AppImage).
# Run from the repository root:
#   bash packaging/linux/build.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

python3 -m pip install --user -q -r requirements.txt pyinstaller 2>/dev/null \
  || python3 -m pip install -q -r requirements.txt pyinstaller

python3 -m PyInstaller --noconfirm --clean \
    --name proton-clean --windowed --onedir \
    --paths "$ROOT" \
    --hidden-import proton_clean.platforms.linux \
    --hidden-import dnslib \
    proton_clean/__main__.py

echo ""
echo "Built: $ROOT/dist/proton-clean/proton-clean (run: dist/proton-clean/proton-clean)"
echo "Then install the privileged helper:  bash scripts/install.sh"
echo ""
echo "Optional AppImage (requires appimagetool on PATH):"
if command -v appimagetool >/dev/null; then
    APPDIR=dist/ProtonClean.AppDir
    mkdir -p "$APPDIR/usr" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/512x512/apps"
    cp -R dist/proton-clean/* "$APPDIR/usr/"
    cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/proton-clean" "$@"
EOF
    chmod +x "$APPDIR/AppRun"
    cp packaging/linux/proton-clean.desktop "$APPDIR/usr/share/applications/" || true
    cp packaging/linux/proton-clean.png "$APPDIR/usr/share/icons/hicolor/512x512/apps/proton-clean.png" || true
    cp packaging/linux/proton-clean.png "$APPDIR/proton-clean.png" || true
    appimagetool "$APPDIR" dist/Proton-Clean-x86_64.AppImage || echo "appimagetool failed — onedir build still available"
else
    echo "  appimagetool not found — skipping (onedir build above is ready)"
fi
