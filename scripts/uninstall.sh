#!/usr/bin/env bash
# Remove everything install.sh created (does not touch ~/.config/cleanroom
# or ~/.cache/cleanroom — delete those manually if you want).
set -euo pipefail

die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] && die "Run as your normal user."

sudo rm -f /usr/local/bin/cleanroom-helper
sudo rm -f /etc/sudoers.d/cleanroom
rm -f "$HOME/.local/share/applications/cleanroom.desktop"
# staged tunnel configs contain private keys — remove them too
sudo rm -f /etc/wireguard/cleanroom.conf
sudo rm -rf /etc/openvpn/cleanroom
echo "Removed helper, sudoers entry, desktop file and staged tunnel configs."
echo "Left in place: ~/.config/cleanroom (credentials/settings),"
echo "               ~/.cache/cleanroom (blocklists, configs)."
