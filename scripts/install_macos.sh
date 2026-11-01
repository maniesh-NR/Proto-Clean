#!/usr/bin/env bash
# Proton Clean installer for macOS — run:  bash scripts/install_macos.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER_SRC="$HERE/helper/proton-clean-helper"
HELPER_DST="/usr/local/bin/proton-clean-helper"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m ->\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] && die "Run as your normal user; sudo is used where needed."

# ---------------------------------------------------------------- system deps
log "Checking system tools…"
for tool in python3 pip3; do
    command -v "$tool" >/dev/null || die "missing required tool: $tool (install from python.org or brew)"
done

if ! command -v wg >/dev/null || ! command -v wg-quick >/dev/null; then
    if command -v brew >/dev/null; then
        warn "installing wireguard-tools (needs brew)"
        brew install wireguard-tools
    else
        die "WireGuard tools not found — install Homebrew (brew.sh), then: brew install wireguard-tools"
    fi
fi
command -v pfctl >/dev/null || die "pfctl not found (should be built into macOS)"
command -v networksetup >/dev/null || die "networksetup not found (should be built into macOS)"

# ---------------------------------------------------------------- python env
log "Installing Python dependencies…"
PIP_TARGET="--user"
if python3 -c "import sys; sys.exit(0 if hasattr(sys, 'real_prefix') or sys.base_prefix != sys.prefix else 1)"; then
    PIP_TARGET=""   # already inside a venv
fi
python3 -m pip install $PIP_TARGET -q -r "$HERE/requirements.txt" \
    || die "pip install failed"

log "Installing Chromium for Playwright (~170MB, one time)…"
python3 -m playwright install chromium \
    || die "playwright install chromium failed"

# ---------------------------------------------------------------- helper
log "Installing the privileged helper…"
sudo install -m 0755 "$HELPER_SRC" "$HELPER_DST"

log "Creating the sudoers entry (passwordless, limited to the helper)…"
SUDOERS_FILE="/etc/sudoers.d/proton-clean"
echo "$USER ALL=(root) NOPASSWD: $HELPER_DST" | sudo tee "$SUDOERS_FILE" >/dev/null
sudo chmod 0440 "$SUDOERS_FILE"
sudo visudo -cf "$SUDOERS_FILE" >/dev/null || {
    sudo rm -f "$SUDOERS_FILE"; die "sudoers check failed — entry removed";
}

# ---------------------------------------------------------------- .app wrapper
log "Creating ~/Applications/Proton Clean.app (launcher wrapper)…"
APP_DIR="$HOME/Applications/Proton Clean.app"
mkdir -p "$APP_DIR/Contents/MacOS"
cat > "$APP_DIR/Contents/MacOS/ProtonClean" <<EOF
#!/bin/bash
cd "$HERE" || exit 1
exec python3 -m proton_clean
EOF
chmod +x "$APP_DIR/Contents/MacOS/ProtonClean"
cat > "$APP_DIR/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key> <string>ProtonClean</string>
  <key>CFBundleIdentifier</key> <string>app.protonclean.vpn</string>
  <key>CFBundleName</key> <string>Proton Clean</string>
  <key>CFBundlePackageType</key> <string>APPL</string>
  <key>CFBundleShortVersionString</key> <string>0.1.0</string>
  <key>LSMinimumSystemVersion</key> <string>12.0</string>
  <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
EOF

log "Done. Start with:  open ~/Applications/Proton Clean.app"
warn "First launch: Settings → Account → enter your Proton credentials."
warn "The sudoers entry grants your user passwordless access to the helper"
warn "binary ONLY — review $SUDOERS_FILE any time."
