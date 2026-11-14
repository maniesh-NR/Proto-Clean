#!/usr/bin/env python3
"""Rename: Proton Clean -> Proto Clean.

Distinctive tokens only — references to the *Proton service*
("Proton account", "ProtonVPN", "Proton AG", "proton session") are
intentionally untouched.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

MOVES = [
    ("proton_clean", "proto_clean"),                              # python package
    ("proton-clean.spec", "proto-clean.spec"),                    # root spec
    ("helper/proton-clean-helper", "helper/proto-clean-helper"),
    ("packaging/linux/proton-clean.desktop", "packaging/linux/proto-clean.desktop"),
    ("packaging/linux/proton-clean.png", "packaging/linux/proto-clean.png"),
    ("packaging/windows/proton-clean.ico", "packaging/windows/proto-clean.ico"),
    ("packaging/windows/proton-clean.spec", "packaging/windows/proto-clean.spec"),
    ("packaging/macos/proton-clean.spec", "packaging/macos/proto-clean.spec"),
    ("android/app/src/main/java/app/protonclean",
     "android/app/src/main/java/app/protoclean"),
]
KT_RENAMES = [  # paths AFTER the app dir move above
    ("android/app/src/main/java/app/protoclean/ProtonCleanApp.kt",
     "android/app/src/main/java/app/protoclean/ProtoCleanApp.kt"),
    ("android/app/src/main/java/app/protoclean/vpn/ProtonCleanVpnService.kt",
     "android/app/src/main/java/app/protoclean/vpn/ProtoCleanVpnService.kt"),
]

RULES = [
    (r"ProtonClean", "ProtoClean"),
    (r"protonclean", "protoclean"),
    (r"PROTON_CLEAN_", "PROTO_CLEAN_"),
    (r"proton_clean", "proto_clean"),
    (r"proton-clean", "proto-clean"),
    (r"Proton Clean", "Proto Clean"),
]


def main() -> None:
    for src, dst in MOVES:
        subprocess.run(["git", "mv", src, dst], cwd=ROOT, check=True)
    for src, dst in KT_RENAMES:
        subprocess.run(["git", "mv", src, dst], cwd=ROOT, check=True)
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, check=True,
                           capture_output=True, text=True).stdout.splitlines()
    n = 0
    for rel in files:
        p = ROOT / rel
        if p.suffix.lower() in {".png", ".ico"}:
            continue
        try:
            t = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        new = t
        for a, b in RULES:
            new = re.sub(a, b, new)
        if new != t:
            p.write_text(new, encoding="utf-8")
            n += 1
    print(f"rewrote {n} of {len(files)} tracked files")


if __name__ == "__main__":
    main()
