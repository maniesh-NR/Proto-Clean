"""Tests for the login flow: event relay (CAPTCHA etc.), remember-me
credential saving, one-shot logins and interactive mode."""

from __future__ import annotations

import threading
import types

import pytest

from proton_clean import credentials as creds
from proton_clean.account.browser import AccountSession, LoginOutcome, LoginResult
from proton_clean.controller import Controller, State


# --------------------------------------------------------------- session

def test_session_emits_login_events():
    s = AccountSession.__new__(AccountSession)
    events = []
    s.on_event = lambda kind, detail: events.append((kind, detail))
    s._emit("captcha", "human verification required")
    s._emit("interactive_open", "waiting")
    assert events == [("captcha", "human verification required"),
                      ("interactive_open", "waiting")]


def test_session_emit_survives_bad_callback():
    s = AccountSession.__new__(AccountSession)
    s.on_event = lambda kind, detail: (_ for _ in ()).throw(RuntimeError("boom"))
    s._emit("captcha", "must not raise")     # logged, not raised


def test_session_has_interactive_login_api():
    s = AccountSession.__new__(AccountSession)
    assert hasattr(s, "login_interactive")


# ------------------------------------------------------------- controller

@pytest.fixture()
def controller(tmp_path, monkeypatch):
    monkeypatch.setattr(creds, "CREDENTIALS_FILE", tmp_path / "credentials.json")
    monkeypatch.setattr(creds, "_keyring", lambda: (None, None))

    ctl = Controller.__new__(Controller)
    ctl.state = State.LOGGED_OUT
    ctl.state_detail = ""
    ctl.session = types.SimpleNamespace(
        logged_in=False,
        on_event=None,
        user_plan_hint=None,
        try_session=lambda: False,
        login=lambda u, p, totp_code_provider=None: LoginResult(
            LoginOutcome.SUCCESS, "logged in", fresh_login=True),
        login_interactive=lambda u="", p="": LoginResult(
            LoginOutcome.SUCCESS, "logged in via interactive window",
            fresh_login=True),
        logout=lambda: None,
    )
    ctl._op_lock = threading.Lock()
    ctl._login_request = None
    ctl.settings = types.SimpleNamespace(
        netshield=types.SimpleNamespace(enabled=False),
        cache_configs=False)
    ctl.downloads = types.SimpleNamespace(harvest_configs=lambda: {})
    ctl.store = types.SimpleNamespace(servers=[])
    ctl.messages = []
    ctl.login_events = []
    ctl.states = []
    ctl.on_message = lambda t, l: ctl.messages.append((t, l))
    ctl.on_login_event = lambda k, d: ctl.login_events.append((k, d))
    ctl.on_state = lambda s, d: ctl.states.append((getattr(s, "value", s), d))
    ctl.on_servers = lambda s: None
    ctl.totp_provider = lambda: None
    ctl.refresh_servers_async = lambda: None
    ctl._spawn = lambda fn, name="": fn()          # run workers inline
    return ctl


def test_captcha_event_is_relayed(controller):
    controller._on_session_event("captcha", "human verification required")
    kinds = [k for k, _ in controller.login_events]
    assert "captcha" in kinds
    # user-visible message explains what to do
    captcha_msgs = [m for m in controller.messages if "verification" in m[0]]
    assert captcha_msgs and "browser window" in captcha_msgs[0][0]


def test_interactive_events_relayed(controller):
    for kind in ("interactive_open", "interactive_done", "totp_needed"):
        controller._on_session_event(kind, "detail")
    kinds = [k for k, _ in controller.login_events]
    assert {"interactive_open", "interactive_done", "totp_needed"} <= set(kinds)


def test_login_once_with_remember_stores_credentials(controller):
    controller.login_once_async("alice", "s3cret", totp_secret="JBSWY3DPEHPK3PXP",
                                remember=True)
    u, p = creds.load_credentials()
    assert (u, p) == ("alice", "s3cret")
    assert creds.load_totp_secret() == "JBSWY3DPEHPK3PXP"
    assert controller.state is State.LOGGED_IN


def test_login_once_without_remember_keeps_memory_only(controller):
    controller.login_once_async("bob", "one-time", remember=False)
    # login still happened
    assert controller.state is State.LOGGED_IN
    # but nothing was persisted
    assert creds.load_credentials() == (None, None)
    assert creds.load_totp_secret() is None


def test_fresh_credentials_skip_cached_session(controller):
    """A login with freshly typed credentials must not reuse the cached
    session — it may belong to a different account."""
    calls = {"try_session": 0}

    def try_session():
        calls["try_session"] += 1
        return True

    controller.session.try_session = try_session
    controller.login_once_async("carol", "pw", remember=True)
    assert calls["try_session"] == 0     # skipped in "once" mode

    controller.login_async()             # stored mode probes the session
    assert calls["try_session"] == 1


def test_interactive_login_mode(controller):
    controller.login_interactive_async("dave", "pw")
    assert controller.state is State.LOGGED_IN


def test_no_credentials_emits_credentials_needed(controller):
    controller._login_worker()
    kinds = [k for k, _ in controller.login_events]
    assert "credentials_needed" in kinds


def test_bad_credentials_emits_event(controller):
    controller.session.login = lambda u, p, totp_code_provider=None: LoginResult(
        LoginOutcome.BAD_CREDENTIALS, "wrong")
    creds.store_credentials("alice", "wrongpw")
    controller._login_worker()
    kinds = [k for k, _ in controller.login_events]
    assert "bad_credentials" in kinds
    assert controller.state is State.LOGGED_OUT


def test_totp_secret_from_storage_used(controller):
    captured = {}

    def login(u, p, totp_code_provider=None):
        captured["provider"] = totp_code_provider
        return LoginResult(LoginOutcome.SUCCESS, "ok", fresh_login=True)

    controller.session.login = login
    creds.store_totp_secret("JBSWY3DPEHPK3PXP")
    creds.store_credentials("alice", "pw")
    controller._login_worker()
    code = captured["provider"]()
    assert code is not None and len(code) == 6      # valid TOTP code
