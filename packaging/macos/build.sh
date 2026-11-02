#!/usr/bin/env bash
# Proto Clean — macOS build script.
# Run from the repository root:
#   bash packaging/macos/build.sh
# Produces dist/Proto Clean.app.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

command -v python3 >/dev/null || { echo "python3 required"; exit 1; }

python3 -m pip install --user -q -r requirements.txt pyinstaller 2>/dev/null \
  || python3 -m pip install -q -r requirements.txt pyinstaller

python3 -m PyInstaller --noconfirm --clean packaging/macos/proto-clean.spec

# Wrap the onedir build into a proper .app bundle
APP="dist/Proto Clean.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp -R dist/ProtoClean/* "$APP/Contents/MacOS/"
cp packaging/macos/Info.plist "$APP/Contents/Info.plist"
# the real executable is the PyInstaller binary inside MacOS/
ln -sf ./ProtoClean "$APP/Contents/MacOS/ProtoClean" 2>/dev/null || true

# ad-hoc signature (Gatekeeper-sufficient for local runs; use a Developer ID
# for distribution)
codesign --force --deep --sign - "$APP" 2>/dev/null || \
  echo "codesign skipped (install Xcode command line tools to sign)"

echo ""
echo "Built: $ROOT/dist/Proto Clean.app"
echo "Requirements on the target machine:"
echo "  - WireGuard tools:  brew install wireguard-tools"
echo "  - The privileged helper:  bash scripts/install_macos.sh"
echo "    (installs /usr/local/bin/proto-clean-helper + sudoers entry)"
echo "  - Playwright Chromium is downloaded per-user on first launch"
