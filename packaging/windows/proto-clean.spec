# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Proto Clean on Windows.
# Build (from the repository root, in a venv with the app deps + pyinstaller):
#   pyinstaller packaging/windows/proto-clean.spec
#
# Notes
# * Run the result as Administrator to avoid UAC prompts per connect
#   (not required — verbs elevate themselves one batch at a time).
# * The frozen exe re-executes itself with --protoclean-helper-win to run the
#   privileged helper verbs (dispatch lives in proto_clean/__main__.py).
# * Playwright's Chromium is NOT bundled; the backend browser is installed
#   per-user on first run (ms-playwright cache). See packaging/windows/README.

import sys
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = (
    collect_submodules("proto_clean")
    + ["proto_clean.platforms.windows", "proto_clean.helper_win",
       "dnslib", "httpx", "keyring.backends.Windows"]
)

a = Analysis(
    ["../../proto_clean/__main__.py"],
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
    name="ProtoClean",
    debug=False,
    strip=False,
    upx=False,
    console=False,                 # GUI app (PySide6)
    icon="proto-clean.ico",       # Proto Clean emblem, multi-resolution .ico
)
