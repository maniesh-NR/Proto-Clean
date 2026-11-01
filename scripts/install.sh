#!/usr/bin/env bash
# Proton Clean installer — run:  bash scripts/install.sh
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
for tool in python3 pip wg wg-quick ip; do
    command -v "$tool" >/dev/null || die "missing required tool: $tool"
done
if ! command -v iptables >/dev/null && ! command -v iptables-nft >/dev/null; then
    die "iptables not found (install 'iptables' or 'iptables-nft')"
fi

if command -v apt-get >/dev/null; then
    if ! dpkg -s wireguard-tools >/dev/null 2>&1; then
        warn "installing wireguard-tools (needs sudo)"
        sudo apt-get update -qq && sudo apt-get install -y wireguard-tools
    fi
elif command -v pacman >/dev/null; then
    pacman -Qi wireguard-tools >/dev/null 2>&1 || sudo pacman -S --noconfirm wireguard-tools
elif command -v dnf >/dev/null; then
    rpm -q wireguard-tools >/dev/null 2>&1 || sudo dnf install -y wireguard-tools
fi

# optional: the OpenVPN protocol (Settings → Protocol) needs the openvpn
# package; WireGuard alone is enough if you never switch protocols
if ! command -v openvpn >/dev/null; then
    warn "openvpn not found — optional; install it (e.g. 'sudo apt install openvpn') to use the OpenVPN protocol (TCP/UDP, TUN/TAP)"
fi

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
warn "If the app later complains about missing system libraries, run: sudo python3 -m playwright install-deps chromium"

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

# ---------------------------------------------------------------- desktop entry
log "Installing desktop entry + app icon…"
mkdir -p "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/512x512/apps"
if [ -f "$ROOT/packaging/linux/proton-clean.png" ]; then
    cp "$ROOT/packaging/linux/proton-clean.png" \
       "$HOME/.local/share/icons/hicolor/512x512/apps/proton-clean.png"
else
    warn "packaging/linux/proton-clean.png missing — desktop entry falls back to a generic icon"
fi
cat > "$HOME/.local/share/applications/proton-clean.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Proton Clean
Comment=Independent VPN client for Proton accounts (WireGuard / OpenVPN)
Exec=python3 -m proton_clean
Icon=proton-clean
Categories=Network;
StartupNotify=true
EOF

log "Done. Start with:  python3 -m proton_clean"
warn "First launch: Settings → Account → enter your Proton credentials."
warn "The sudoers entry grants your user passwordless access to the helper"
warn "binary ONLY — review $SUDOERS_FILE any time."
