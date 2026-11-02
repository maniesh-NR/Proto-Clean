"""Client for the privileged helper.

Facade over the per-OS backends in ``proto_clean.platforms``:

* Linux/macOS — the installed ``proto-clean-helper`` script, run through
  passwordless sudo (NOPASSWD sudoers entry).
* Windows — verbs implemented by ``proto_clean.helper_win``, run in-process
  when elevated or through one UAC prompt per batch otherwise.

The verb whitelist is identical everywhere, so the tunnel manager, kill
switch, split tunnel and monitor code below is OS-agnostic.
"""

from __future__ import annotations

from ..platforms import get_platform
from ..platforms.base import HelperError  # noqa: F401 — re-exported (API compat)


def helper_installed() -> bool:
    """Cheap check that the privileged side is present.

    Linux/macOS: the helper script exists at the expected path.
    Windows: always True — verbs run in-process or via UAC on demand.
    """
    from .. import paths

    if paths.IS_WINDOWS:
        return True
    import os
    return os.path.isfile(paths.HELPER_BIN)


def helper_available() -> bool:
    """True if the helper is installed AND a real verb round-trips."""
    try:
        Helper().call("status")
        return True
    except HelperError:
        return False


class Helper:
    """Runs whitelisted verbs on the current OS backend."""

    def __init__(self, binary: str = "") -> None:
        self._client = get_platform().make_helper(binary)
        self.binary = getattr(self._client, "binary", "")

    def call(self, verb: str, *args: str, timeout: float = 60.0) -> dict:
        return self._client.call(verb, *[str(a) for a in args],
                                 timeout=timeout)

    def call_batch(self, calls, timeout: float = 180.0) -> list:
        """Run several verbs — one UAC prompt on Windows, a loop elsewhere."""
        return self._client.call_batch(calls, timeout=timeout)
