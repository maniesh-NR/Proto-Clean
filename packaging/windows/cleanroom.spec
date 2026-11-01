# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Cleanroom on Windows.
# Build (from the repository root, in a venv with the app deps + pyinstaller):
#   pyinstaller packaging/windows/cleanroom.spec
#
# Notes
# * Run the result as Administrator to avoid UAC prompts per connect
#   (not required — verbs elevate themselves one batch at a time).
# * The frozen exe re-executes itself with --cleanroom-helper-win to run the
#   privileged helper verbs (dispatch lives in cleanroom/__main__.py).
# * Playwright's Chromium is NOT bundled; the backend browser is installed
#   per-user on first run (ms-playwright cache). See packaging/windows/README.

import sys
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = (
    collect_submodules("cleanroom")
    + ["cleanroom.platforms.windows", "cleanroom.helper_win",
       "dnslib", "httpx", "keyring.backends.Windows"]
)

a = Analysis(
    ["../../cleanroom/__main__.py"],
    pathex=["../.."],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    excludes=["tkinter"],
    runtime_hooks=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Cleanroom",
    debug=False,
    strip=False,
    upx=False,
    console=False,                 # GUI app (PySide6)
    icon=None,                     # drop an .ico next to this file to use it
)
