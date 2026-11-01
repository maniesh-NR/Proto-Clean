"""Platform factory: pick the backend for the OS we are running on."""

from __future__ import annotations

import sys

from .base import Capabilities, HelperClient, HelperError, PlatformBackend  # noqa: F401

_backend: PlatformBackend | None = None


def get_platform() -> PlatformBackend:
    """The singleton backend for this OS."""
    global _backend
    if _backend is None:
        if sys.platform.startswith("win"):
            from .windows import WindowsBackend
            _backend = WindowsBackend()
        elif sys.platform == "darwin":
            from .macos import MacOsBackend
            _backend = MacOsBackend()
        else:
            from .linux import LinuxBackend
            _backend = LinuxBackend()
    return _backend


def capabilities() -> Capabilities:
    return get_platform().capabilities
