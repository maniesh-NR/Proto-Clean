#!/usr/bin/env python3
"""Rename the project: Cleanroom -> Proton Clean.

Mapping:
  * display name            Cleanroom        -> Proton Clean
  * python package/import   cleanroom        -> proton_clean
  * distribution / PyPI     cleanroom-vpn    -> proton-clean
  * console script / bins   cleanroom        -> proton-clean
  * helper binary           cleanroom-helper -> proton-clean-helper
  * android app package     app.cleanroom    -> app.protonclean
  * android classes         CleanroomApp/CleanroomVpnService/CleanroomTheme/
                            CleanroomTunnel  -> ProtonClean*
  * artifacts               Cleanroom-0.1.0-*-> Proton-Clean-0.1.0-*,
                            Cleanroom.exe    -> ProtonClean.exe,
                            Cleanroom.app    -> Proton Clean.app

Run from the repository root. Uses `git mv` for renames so history follows.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()

# ---------------------------------------------------------------- git mv step
MOVES = [
    "cleanroom",
    "cleanroom.spec",
    "helper/cleanroom-helper",
    "packaging/linux/cleanroom.desktop",
    "packaging/linux/cleanroom.png",
    "packaging/windows/cleanroom.ico",
    "packaging/windows/cleanroom.spec",
    "packaging/macos/cleanroom.spec",
    "android/app/src/main/java/app/cleanroom",
]
FILE_RENAMES_IN_ANDROID = [   # paths AFTER the app/cleanroom -> app/protonclean dir move
    ("android/app/src/main/java/app/protonclean/CleanroomApp.kt",
     "android/app/src/main/java/app/protonclean/ProtonCleanApp.kt"),
    ("android/app/src/main/java/app/protonclean/vpn/CleanroomVpnService.kt",
     "android/app/src/main/java/app/protonclean/vpn/ProtonCleanVpnService.kt"),
]

def git(*args: str) -> None:
    subprocess.run(["git", *args], cwd=ROOT, check=True)

def do_moves() -> None:
    for src in MOVES:
        if src == "cleanroom":          # the python package dir (underscore)
            dst = "proton_clean"
        else:
            parent, _, base = src.rpartition("/")
            base_new = base.replace("cleanroom", "proton-clean")
            dst = f"{parent}/{base_new}" if parent else base_new
            # android kotlin paths use the dotted-less app id: app/protonclean
            if src.startswith("android/"):
                dst = dst.replace("proton-clean", "protonclean")
        git("mv", src, dst)
    for src, dst in FILE_RENAMES_IN_ANDROID:
        git("mv", src, dst)

# -------------------------------------------------------------- content rules
# (pattern, replacement, classes)  classes: 0=all, "py"=python-like only
RULES: list[tuple[str, str, object]] = [
    # 1. compound tokens that contain shorter patterns handled later
    (r"--cleanroom-helper-win", "--protonclean-helper-win", 0),
    (r"cleanroom-helper", "proton-clean-helper", 0),
    (r"cleanroom\.desktop", "proton-clean.desktop", 0),
    (r"cleanroom\.png", "proton-clean.png", 0),
    (r"cleanroom\.ico", "proton-clean.ico", 0),
    (r"cleanroom\.spec", "proton-clean.spec", 0),
    # 2. Android identifiers / package
    (r"CleanroomApp", "ProtonCleanApp", 0),
    (r"CleanroomVpnService", "ProtonCleanVpnService", 0),
    (r"CleanroomTheme", "ProtonCleanTheme", 0),
    (r"CleanroomTunnel", "ProtonCleanTunnel", 0),
    (r"CleanroomKS", "ProtonCleanKS", 0),
    (r"CleanroomV6", "ProtonCleanV6", 0),
    (r"Theme\.Cleanroom", "Theme.ProtonClean", 0),
    (r"app\.cleanroom", "app.protonclean", 0),
    (r"app/cleanroom", "app/protonclean", 0),
    # 3. project / dist names
    (r"cleanroom-vpn", "proton-clean", 0),
    (r"CLEANROOM_", "PROTON_CLEAN_", 0),
    (r"cleanroom\*", "proton_clean*", 0),          # setuptools packages.find
    # 4. Android runtime strings
    (r"window\.Cleanroom", "window.ProtonClean", 0),
    (r"'Cleanroom-Android'", "'ProtonClean-Android'", 0),
    (r'"Cleanroom\.', '"ProtonClean.', 0),          # log TAGs
    (r'"Cleanroom"', '"ProtonClean"', 0),           # JS bridge + spec name=
    # 5. macOS bundle naming (executable no-space, bundle display with space)
    (r"<key>CFBundleExecutable</key> <string>Cleanroom</string>",
     "<key>CFBundleExecutable</key> <string>ProtonClean</string>", 0),
    (r"MacOS/Cleanroom", "MacOS/ProtonClean", 0),
    (r"\./Cleanroom", "./ProtonClean", 0),
    (r"Cleanroom\.app", "Proton Clean.app", 0),
    (r"Cleanroom\.AppDir", "ProtonClean.AppDir", 0),
    (r"Cleanroom\.exe", "ProtonClean.exe", 0),
    (r"dist/cleanroom/Cleanroom", "dist/proton-clean/proton-clean", 0),
    (r"Cleanroom-", "Proton-Clean-", 0),            # release asset names
    (r"dist/Cleanroom", "dist/ProtonClean", 0),
    (r"dist/cleanroom", "dist/proton-clean", 0),
    (r"-C dist cleanroom", "-C dist proton-clean", 0),
    (r"cleanroom/cleanroom", "proton-clean/proton-clean", 0),
    (r"compileall -q cleanroom", "compileall -q proton_clean", 0),
    (r"pathex=\['/home/z/my-project/cleanroom'\]", "pathex=['.']", 0),
    # 6. runtime paths that must match between helper, uninstaller, docs
    (r"/etc/openvpn/cleanroom", "/etc/openvpn/protonclean", 0),
    (r"/etc/wireguard/cleanroom", "/etc/wireguard/proton_clean", 0),
    (r"/var/run/cleanroom-", "/var/run/protonclean-", 0),
    (r"/var/log/cleanroom-", "/var/log/protonclean-", 0),
    (r"/tmp/cleanroom-", "/tmp/protonclean-", 0),
    (r"\.config/cleanroom", ".config/proton-clean", 0),
    (r"\.cache/cleanroom", ".cache/proton-clean", 0),
    # 7. python module references (docs, yml, sh, py)
    (r"-m cleanroom\b", "-m proton_clean", 0),
    (r"import cleanroom\b", "import proton_clean", 0),
    (r"from cleanroom\b", "from proton_clean", 0),
    (r"cleanroom\.([A-Za-z_])", r"proton_clean.\1", 0),
    (r"cleanroom/", "proton_clean/", 0),
    # 8. pathlib dir parts (python only)
    (r'/ "cleanroom"', '/ "proton-clean"', "py"),
    # 9. display name last (leftover human-readable text)
    (r"Cleanroom", "Proton Clean", 0),
]

PY_SUFFIXES = {".py", ".spec"}
PY_FILES = {"helper/proton-clean-helper"}

def is_py(rel: str) -> bool:
    p = Path(rel)
    return p.suffix in PY_SUFFIXES or rel in PY_FILES

def main() -> None:
    do_moves()
    files = subprocess.run(["git", "ls-files"], cwd=ROOT, check=True,
                           capture_output=True, text=True).stdout.splitlines()
    changed = 0
    for rel in files:
        p = ROOT / rel
        if p.suffix.lower() in {".png", ".ico", ".jar", ".keystore"}:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        py = is_py(rel)
        new = text
        for pat, repl, cls in RULES:
            if cls == "py" and not py:
                continue
            new = re.sub(pat, repl, new)
        # class-specific generic
        generic = r"\bcleanroom\b"
        new = re.sub(generic, "proton_clean" if py else "proton-clean", new)
        if new != text:
            p.write_text(new, encoding="utf-8")
            changed += 1
    print(f"rewrote {changed} of {len(files)} tracked files")

if __name__ == "__main__":
    main()
