"""Entry point: python -m proto_clean"""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    # Frozen Windows builds re-exec themselves with this marker to run the
    # privileged helper verbs through a UAC prompt (see platforms/windows.py).
    if "--protoclean-helper-win" in sys.argv:
        from . import helper_win
        return helper_win.main(sys.argv[1:])

    parser = argparse.ArgumentParser(
        prog="proto_clean",
        description="Proto Clean — clean-room ProtonVPN client "
                    "(WireGuard; Windows, macOS, Linux)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="debug logging")
    parser.add_argument("--version", action="version",
                        version=__import__("proto_clean").__version__)
    parser.add_argument("--cli", action="store_true",
                        help="headless check: verify environment and exit")
    args = parser.parse_args()

    from .log import setup_logging

    setup_logging(verbose=args.verbose)

    if args.cli:
        return _env_check()

    return _run_gui()


def _env_check() -> int:
    from . import credentials
    from .paths import PLATFORM_NAME, ensure_dirs
    from .platforms import capabilities, get_platform
    from .vpn.helper import helper_installed

    ensure_dirs()
    ok = True
    print(f"== Proto Clean environment check ({capabilities().display}) ==")
    for mod, name in (
        ("playwright", "playwright (backend browser)"),
        ("dnslib", "dnslib (DNS blocker)"),
        ("httpx", "httpx (blocklist downloads)"),
        ("PySide6", "PySide6 (GUI)"),
    ):
        try:
            __import__(mod)
            print(f"  ok      {name}")
        except ImportError:
            ok = False
            print(f"  MISSING {name}")
    print(f"  {'ok' if helper_installed() else 'MISSING'}     privileged helper"
          f" ({PLATFORM_NAME} backend)")
    print(f"  {'ok' if credentials.keyring_available() else 'note'}     "
          "system keyring (falls back to a chmod-600 file)")
    u, p = credentials.load_credentials()
    print(f"  {'ok' if u and p else 'none'}     stored Proton credentials")
    for label, good, hint in get_platform().env_check():
        print(f"  {'ok' if good else 'MISSING'}     {label}")
    return 0 if ok else 1


def _run_gui() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("PySide6 is required for the GUI: pip install PySide6",
              file=sys.stderr)
        return 1

    from . import APP_NAME
    from .controller import Controller
    from .settings import load_settings
    from .ui.main_window import MainWindow
    from .ui.theme import apply_theme
    from .ui.tray import Tray

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    apply_theme(app, load_settings().theme)
    app.setProperty("proto_clean_theme_applied", True)
    app.setQuitOnLastWindowClosed(False)

    controller = Controller()
    window = MainWindow(controller)
    window.tray = Tray(window, controller)
    window.tray.show()
    window.show()

    code = app.exec()
    controller.shutdown()
    return code


if __name__ == "__main__":
    sys.exit(main())
