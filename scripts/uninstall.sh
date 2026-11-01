#!/usr/bin/env bash
# Remove everything install.sh created (does not touch ~/.config/proton-clean
# or ~/.cache/proton-clean — delete those manually if you want).
set -euo pipefail

die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] && die "Run as your normal user."

sudo rm -f /usr/local/bin/proton-clean-helper
sudo rm -f /etc/sudoers.d/proton-clean
rm -f "$HOME/.local/share/applications/proton-clean.desktop"
# staged tunnel configs contain private keys — remove them too
sudo rm -f /etc/wireguard/proton_clean.conf
sudo rm -rf /etc/openvpn/protonclean
echo "Removed helper, sudoers entry, desktop file and staged tunnel configs."
echo "Left in place: ~/.config/proton-clean (credentials/settings),"
echo "               ~/.cache/proton-clean (blocklists, configs)."
