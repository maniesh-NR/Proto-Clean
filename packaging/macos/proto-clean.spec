# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Proto Clean on macOS.
# Build (from the repository root, in a venv with the app deps + pyinstaller):
#   pyinstaller packaging/macos/proto-clean.spec
# Produces dist/Proto Clean.app (ad-hoc signed; sign with your Developer ID
# for distribution: codesign --deep --options runtime --sign "Developer ID
# Application: …" dist/Proto Clean.app)

import sys
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = (
    collect_submodules("proto_clean")
    + ["proto_clean.platforms.macos", "dnslib", "httpx",
       "keyring.backends.macOS"]
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
    [],
    exclude_binaries=True,
    name="ProtoClean",
    debug=False,
    strip=False,
    upx=False,
    console=False,                 # .app bundle, GUI only
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="ProtoClean",
)
