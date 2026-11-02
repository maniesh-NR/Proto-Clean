#!/bin/sh
# Flatpak entry point for Proto Clean.
# NOTE (sandbox limits): the privileged WireGuard/OpenVPN helper cannot
# run inside the sandbox — use the Xray proxy (needs the xray binary on
# the host PATH via PROTO_CLEAN_XRAY_BIN, or manual SOCKS) and the
# ad-blocker DNS-filter mode here.
export PYTHONPATH="/app/lib/python3.12/site-packages${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m proto_clean "$@"
