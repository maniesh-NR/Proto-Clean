# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for the LEGACY Windows builds (Windows 7+, x86 & x64).
# Stack: Python 3.8 + PySide2 (Qt 5.15) via proto_clean/qtcompat.py.
# Build (from the repository root, in a Python 3.8 venv with
# packaging/windows/requirements-legacy.txt + PyInstaller==5.13.2):
#   pyinstaller packaging/windows/proto-clean-legacy.spec
import os

import PyInstaller.utils.hooks as hooks  # noqa: E402

hiddenimports = (
    ["shiboken2", "PySide2.QtCore", "PySide2.QtGui", "PySide2.QtWidgets",
     "proto_clean.platforms.windows", "proto_clean.helper_win",
     "dnslib", "httpx", "keyring.backends.Windows"]
    + hooks.collect_submodules("proto_clean")
)

a = Analysis(
    ["../../proto_clean/__main__.py"],
    pathex=["../.."],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    excludes=["tkinter", "PySide6", "PySide6.QtCore", "PySide6.QtGui",
              "PySide6.QtWidgets"],
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
    console=False,
    icon=os.path.join(SPECPATH, "proto-clean.ico"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="ProtoClean",
)
