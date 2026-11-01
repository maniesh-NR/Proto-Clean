"""Proton account credential storage.

Prefers the system keyring (secret-service / kwallet); falls back to a
chmod-0600 JSON file when no keyring daemon is available (e.g. headless
boxes, some WSL setups). Never logs the secrets themselves.
"""

from __future__ import annotations

from typing import Optional, Tuple

from .log import get
from .paths import CREDENTIALS_FILE, ensure_dirs

log = get("credentials")

_SERVICE = "cleanroom"
_USER_KEY = "proton-username"
_PASS_KEY = "proton-password"
_TOTP_KEY = "proton-totp-secret"


def _keyring():
    try:
        import keyring  # noqa: PLC0415
        from keyring.errors import KeyringError  # noqa: PLC0415

        backend = keyring.get_keyring()
        if backend and not isinstance(backend, keyring.backends.fail.Keyring):
            return keyring, KeyringError
    except Exception:  # pragma: no cover - environment dependent
        pass
    return None, None


def keyring_available() -> bool:
    keyring, _ = _keyring()
    return keyring is not None


def store_credentials(username: str, password: str) -> None:
    keyring, KeyringError = _keyring()
    if keyring is not None:
        try:
            keyring.set_password(_SERVICE, _USER_KEY, username)
            keyring.set_password(_SERVICE, _PASS_KEY, password)
            _wipe_fallback()
            log.info("credentials stored in system keyring")
            return
        except KeyringError:
            log.warning("keyring write failed, falling back to file storage")
    import json
    import os
    import stat

    ensure_dirs()
    # merge with whatever else is in the file (e.g. the TOTP secret) so a
    # credential update never silently drops it
    data = {}
    if CREDENTIALS_FILE.exists():
        try:
            data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
    data["username"] = username
    data["password"] = password
    CREDENTIALS_FILE.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(CREDENTIALS_FILE, stat.S_IRUSR | stat.S_IWUSR)
    log.info("credentials stored in restricted file %s", CREDENTIALS_FILE)


def load_credentials() -> Tuple[Optional[str], Optional[str]]:
    keyring, KeyringError = _keyring()
    if keyring is not None:
        try:
            u = keyring.get_password(_SERVICE, _USER_KEY)
            p = keyring.get_password(_SERVICE, _PASS_KEY)
            if u is not None and p is not None:
                return u, p
        except KeyringError:
            pass
    import json

    if CREDENTIALS_FILE.exists():
        try:
            data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
            return data.get("username"), data.get("password")
        except (json.JSONDecodeError, OSError):
            log.error("could not parse fallback credential file")
    return None, None


def store_totp_secret(secret: str) -> None:
    """Persist the TOTP secret used to answer 2FA prompts automatically."""
    keyring, KeyringError = _keyring()
    if keyring is not None:
        try:
            if secret:
                keyring.set_password(_SERVICE, _TOTP_KEY, secret)
            else:
                keyring.delete_password(_SERVICE, _TOTP_KEY)
            _wipe_totp_fallback()
            log.info("TOTP secret stored in system keyring")
            return
        except KeyringError:
            log.warning("keyring write failed, falling back to file storage")
    import json
    import os
    import stat

    data = {}
    if CREDENTIALS_FILE.exists():
        try:
            data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
    if secret:
        data["totp_secret"] = secret
    else:
        data.pop("totp_secret", None)
    if data:
        ensure_dirs()
        CREDENTIALS_FILE.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(CREDENTIALS_FILE, stat.S_IRUSR | stat.S_IWUSR)
    log.info("TOTP secret %s", "stored" if secret else "cleared")


def load_totp_secret() -> Optional[str]:
    keyring, KeyringError = _keyring()
    if keyring is not None:
        try:
            s = keyring.get_password(_SERVICE, _TOTP_KEY)
            if s is not None:
                return s
        except KeyringError:
            pass
    import json

    if CREDENTIALS_FILE.exists():
        try:
            return json.loads(CREDENTIALS_FILE.read_text(
                encoding="utf-8")).get("totp_secret")
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _wipe_totp_fallback() -> None:
    """Remove the totp_secret key from the fallback file (keyring is used)."""
    import json

    if not CREDENTIALS_FILE.exists():
        return
    try:
        data = json.loads(CREDENTIALS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    if data.pop("totp_secret", None) is not None:
        CREDENTIALS_FILE.write_text(json.dumps(data), encoding="utf-8")


def clear_credentials() -> None:
    keyring, KeyringError = _keyring()
    if keyring is not None:
        try:
            keyring.delete_password(_SERVICE, _USER_KEY)
            keyring.delete_password(_SERVICE, _PASS_KEY)
            keyring.delete_password(_SERVICE, _TOTP_KEY)
        except KeyringError:
            pass
    _wipe_fallback()
    log.info("credentials cleared")


def _wipe_fallback() -> None:
    if CREDENTIALS_FILE.exists():
        try:
            CREDENTIALS_FILE.unlink()
        except OSError:
            pass
