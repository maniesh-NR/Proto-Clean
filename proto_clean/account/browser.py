"""Backend browser session for the Proton account.

Wraps Playwright (bundled Chromium) and performs the *hybrid* login:

  1. Try the cached browser storage-state (cookies/localStorage) first —
     most logins after the first one never see a login form.
  2. Fully automated headless login with the stored credentials.
  3. TOTP two-factor is answered automatically if the user stored their
     2FA secret, otherwise the UI is asked for a code via callback.
  4. If Proton challenges with a CAPTCHA / human-verification step, a
     *visible* Chromium window opens on exactly that step so a human can
     solve it; the session is captured when it completes and everything
     continues headless.

All Playwright calls happen on the single BrowserWorker thread (its sync
API is not thread-safe).
"""

from __future__ import annotations

import os
import queue
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from ..log import get
from ..paths import BROWSER_STATE_FILE

log = get("account")

ACCOUNT_URL = "https://account.protonvpn.com/downloads"
LOGIN_URL = "https://account.protonvpn.com/login"

USERNAME_SELECTORS = [
    "#username", "#email", "input[name='username']", "input[autocomplete='username']",
    "input[type='email']",
]
PASSWORD_SELECTORS = [
    "#password", "input[type='password']", "input[autocomplete='current-password']",
]
SUBMIT_SELECTORS = ["button[type='submit']", "#login_btn", "button:has-text('Sign in')"]
TOTP_SELECTORS = [
    "input[autocomplete='one-time-code']", "input[data-testid='two-factor-code-0']",
    "input.totp-input", "input[name='totp']", "input[inputmode='numeric']",
]
ERROR_SELECTORS = [".alert-danger", "[role='alert']", ".notification-content"]

CHALLENGE_HINTS = [
    "iframe[src*='hcaptcha']", "iframe[src*='turnstile']", "iframe[src*='captcha']",
    "[data-testid*='human-verification']", "[data-testid*='captcha']",
]


class LoginOutcome(Enum):
    SUCCESS = "success"
    NEEDS_INTERACTION = "needs_interaction"   # solved via visible window
    BAD_CREDENTIALS = "bad_credentials"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass
class LoginResult:
    outcome: LoginOutcome
    message: str = ""
    fresh_login: bool = False     # True when a login form was actually used


def settle(page, timeout: float = 15000, extra: float = 1.0) -> None:
    """Best-effort network settle — modern SPAs rarely reach networkidle."""
    try:
        page.wait_for_load_state("networkidle", timeout=timeout)
    except Exception:  # noqa: BLE001
        pass
    time.sleep(extra)


class BrowserClosedError(RuntimeError):
    pass


class BrowserWorker:
    """Single-thread executor for all Playwright operations."""

    def __init__(self) -> None:
        self._queue: "queue.Queue" = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="proto_clean-browser")
        self._thread.start()

    def _run(self) -> None:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            self._pw = pw
            self._started.set()
            while True:
                job = self._queue.get()
                if job is None:
                    break
                fn, future = job
                if future.cancelled():
                    continue
                try:
                    future.set_result(fn(pw))
                except BaseException as e:  # noqa: BLE001
                    if not future.cancelled():
                        future.set_exception(e)
        self._pw = None

    def submit(self, fn, timeout: float = 120.0):
        fut = _Future()
        self.start()
        self._queue.put((fn, fut))
        return fut.result(timeout)

    def stop(self) -> None:
        self._queue.put(None)


class _Future:
    """Minimal future with result()/exception()."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._result = None
        self._exc: Optional[BaseException] = None
        self._cancelled = False

    def cancelled(self) -> bool:
        return self._cancelled

    def set_result(self, value) -> None:
        self._result = value
        self._event.set()

    def set_exception(self, exc: BaseException) -> None:
        self._exc = exc
        self._event.set()

    def result(self, timeout: float = 120.0):
        if not self._event.wait(timeout):
            self._cancelled = True
            raise TimeoutError(f"browser operation timed out after {timeout}s")
        if self._exc:
            raise self._exc
        return self._result


class AccountSession:
    """The backend browser: login + scraping, driven through BrowserWorker.

    Login progress is relayed through ``on_event(kind, detail)`` so the UI
    can tell the user what is happening — most importantly when a CAPTCHA /
    human-verification step opens a visible browser window that needs a
    human to finish it. Kinds emitted:

      session_restored   cached storage-state still valid
      login_started      headless login attempt begun
      captcha            human verification required (visible window)
      interactive_open   visible window open, waiting for the user
      interactive_done   the user finished in the window, session captured
      totp_needed        two-factor code requested
    """

    def __init__(self, worker: Optional[BrowserWorker] = None,
                 state_file: str = str(BROWSER_STATE_FILE)) -> None:
        self.worker = worker or BrowserWorker()
        self.state_file = state_file
        self.logged_in = False
        self.user_plan_hint: Optional[str] = None
        self.on_event: Callable[[str, str], None] = lambda kind, detail: None

    def _emit(self, kind: str, detail: str = "") -> None:
        """Relay a login event to the UI (called on the browser thread)."""
        log.info("login event: %s (%s)", kind, detail)
        try:
            self.on_event(kind, detail)
        except Exception:  # noqa: BLE001
            log.exception("on_event callback failed")

    # ------------------------------------------------------- small helpers
    def _launch(self, pw, headless: bool):
        args = ["--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage"]
        # os.geteuid does not exist on Windows — Chromium refuses --no-sandbox
        # there anyway, and elevation is handled by UAC instead.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.append("--no-sandbox")
        browser = pw.chromium.launch(headless=headless, args=args)
        ua = None
        if headless:
            # Avoid the HeadlessChrome UA fingerprint.
            ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
        ctx = browser.new_context(
            storage_state=self.state_file if os.path.exists(self.state_file) else None,
            user_agent=ua or None,
            locale="en-US",
            viewport={"width": 1366, "height": 900},
        )
        return browser, ctx

    # ---------------------------------------------------------------- login
    def try_session(self) -> bool:
        """Try the cached storage state against the downloads page."""
        def job(pw):
            browser, ctx = self._launch(pw, headless=True)
            try:
                page = ctx.new_page()
                page.goto(ACCOUNT_URL, wait_until="domcontentloaded", timeout=45000)
                settle(page)
                return "/login" not in page.url
            finally:
                browser.close()
        try:
            self.logged_in = self.worker.submit(job, timeout=90)
        except Exception as e:  # noqa: BLE001
            log.warning("session probe failed: %s", e)
            self.logged_in = False
        if self.logged_in:
            log.info("cached Proton session still valid")
            self._emit("session_restored", "cached session still valid")
        return self.logged_in

    def login(
        self,
        username: str,
        password: str,
        totp_code_provider: Optional[Callable[[], Optional[str]]] = None,
        interactive_fallback: bool = True,
    ) -> LoginResult:
        """Hybrid headless login; falls back to a visible window on challenge."""

        def job(pw):
            return self._login_headless(
                pw, username, password, totp_code_provider, interactive_fallback)

        result: LoginResult = self.worker.submit(job, timeout=420)
        self.logged_in = result.outcome is LoginOutcome.SUCCESS
        return result

    def login_interactive(self, username: str = "",
                          password: str = "") -> LoginResult:
        """Log in through a visible browser window from the start.

        Everything (credentials, CAPTCHA, 2FA) is done by hand in the
        window; the session is captured automatically when it completes.
        """
        self._emit("interactive_open",
                   "log in (and solve any verification) in the browser window")

        def job(pw):
            return self._interactive_window(pw, username, password)

        result: LoginResult = self.worker.submit(job, timeout=420)
        self.logged_in = result.outcome is LoginOutcome.SUCCESS
        return result

    # ------------------------------------------------------- headless path
    def _login_headless(self, pw, username, password, totp_provider,
                        interactive_fallback) -> LoginResult:
        browser, ctx = self._launch(pw, headless=True)
        try:
            page = ctx.new_page()
            page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=45000)
            settle(page)
            # Proton uses a two-step form (2026): username -> Continue -> password.
            self._fill(page, USERNAME_SELECTORS, username)
            if self._visible(page, PASSWORD_SELECTORS):
                self._fill(page, PASSWORD_SELECTORS, password)
                self._click(page, SUBMIT_SELECTORS)
            else:
                self._click(page, SUBMIT_SELECTORS)          # "Continue"
                try:
                    page.locator(",".join(PASSWORD_SELECTORS)).first \
                        .wait_for(state="visible", timeout=30000)
                except Exception as e:  # noqa: BLE001
                    return LoginResult(
                        LoginOutcome.FAILED,
                        f"password step never appeared after Continue: {e}")
                self._fill(page, PASSWORD_SELECTORS, password)
                self._click(page, SUBMIT_SELECTORS)          # "Sign in"
            return self._await_login_outcome(page, ctx, pw, username, password,
                                             totp_provider, interactive_fallback)
        finally:
            try:
                browser.close()
            except Exception:
                pass

    def _await_login_outcome(self, page, ctx, pw, username, password,
                             totp_provider, interactive_fallback,
                             deadline: float = 90.0) -> LoginResult:
        start = time.time()
        while time.time() - start < deadline:
            time.sleep(1.5)
            state = self._login_state(page)
            log.debug("login state: %s url=%s", state, page.url)
            if state == "ok":
                ctx.storage_state(path=self.state_file)
                self.user_plan_hint = self._plan_hint(page)
                return LoginResult(LoginOutcome.SUCCESS, "logged in", fresh_login=True)
            if state == "captcha":
                if interactive_fallback:
                    self._emit(
                        "captcha",
                        "human verification required — completing it opens "
                        "a browser window for you")
                    return self._interactive_window(pw, username, password)
                return LoginResult(LoginOutcome.FAILED,
                                   "CAPTCHA/human verification required")
            if state == "totp":
                self._emit("totp_needed", "two-factor code requested")
                code = totp_provider() if totp_provider else None
                if not code:
                    return LoginResult(
                        LoginOutcome.FAILED,
                        "two-factor code required — add your 2FA secret in "
                        "settings or provide a code when prompted")
                if not self._fill_totp(page, code):
                    return LoginResult(LoginOutcome.FAILED, "could not fill 2FA field")
                continue
            if state.startswith("error:"):
                msg = state.split(":", 1)[1]
                if "credentials" in msg.lower() or "password" in msg.lower():
                    return LoginResult(LoginOutcome.BAD_CREDENTIALS, msg)
                return LoginResult(LoginOutcome.FAILED, msg)
        return LoginResult(LoginOutcome.FAILED, "login timed out")

    def _login_state(self, page) -> str:
        url = page.url
        if "/login" not in url and "auth.proton" not in url:
            return "ok"
        if page.locator(",".join(CHALLENGE_HINTS)).count() > 0:
            return "captcha"
        if page.locator(",".join(TOTP_SELECTORS)).count() > 0:
            visible_totp = [s for s in TOTP_SELECTORS
                            if page.locator(s).first.is_visible()]
            if visible_totp:
                return "totp"
        for sel in ERROR_SELECTORS:
            loc = page.locator(sel)
            if loc.count() and loc.first.is_visible():
                txt = (loc.first.inner_text() or "").strip()[:200]
                if txt:
                    return f"error:{txt}"
        return "pending"

    def _fill_totp(self, page, code: str) -> bool:
        code = code.replace(" ", "")
        # multi-box variant: two-factor-code-0 … two-factor-code-5
        try:
            boxes = page.locator("[data-testid^='two-factor-code-']")
            if boxes.count() >= 6 and len(code) == 6:
                for i in range(6):
                    page.locator(
                        f"[data-testid='two-factor-code-{i}']").first.fill(code[i])
                page.keyboard.press("Enter")
                return True
        except Exception:  # noqa: BLE001
            pass
        for sel in TOTP_SELECTORS:
            loc = page.locator(sel)
            if loc.count() and loc.first.is_visible():
                try:
                    loc.first.fill(code)
                    page.keyboard.press("Enter")
                    return True
                except Exception:  # noqa: BLE001
                    continue
        return False

    # ------------------------------------------------------- interactive
    def _interactive_window(self, pw, username, password) -> LoginResult:
        """Open a visible Chromium window so a human can pass the challenge."""
        log.info("opening visible browser window for CAPTCHA/2FA")
        self._emit("interactive_open",
                   "finish logging in in the browser window "
                   "(5 minutes to complete)")
        browser = pw.chromium.launch(headless=False)
        try:
            ctx = browser.new_context(
                storage_state=self.state_file if os.path.exists(self.state_file) else None
            )
            page = ctx.new_page()
            page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=45000)
            settle(page, timeout=8000, extra=0.5)
            # Pre-fill credentials to make it a one-click experience.
            try:
                if username:
                    self._fill(page, USERNAME_SELECTORS, username)
                    if self._visible(page, PASSWORD_SELECTORS) and password:
                        self._fill(page, PASSWORD_SELECTORS, password)
            except Exception:
                pass
            deadline = time.time() + 300  # 5 minutes for the human
            last_relay = time.time()
            while time.time() < deadline:
                time.sleep(2.0)
                if time.time() - last_relay > 60:
                    remaining = int((deadline - time.time()) / 60) + 1
                    self._emit("interactive_open",
                               f"still waiting — about {remaining} min left in "
                               "the browser window")
                    last_relay = time.time()
                if "/login" not in page.url and "auth.proton" not in page.url:
                    ctx.storage_state(path=self.state_file)
                    self.user_plan_hint = self._plan_hint(page)
                    self._emit("interactive_done",
                               "verification completed — session captured")
                    return LoginResult(LoginOutcome.SUCCESS,
                                       "logged in via interactive window",
                                       fresh_login=True)
            self._emit("interactive_timeout",
                       "the browser login window timed out")
            return LoginResult(LoginOutcome.CANCELLED,
                               "interactive login window timed out")
        finally:
            browser.close()

    # -------------------------------------------------------------- utils
    @staticmethod
    def _visible(page, selectors) -> bool:
        for sel in selectors:
            try:
                loc = page.locator(sel).first
                if loc.count() and loc.is_visible():
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False

    @staticmethod
    def _fill(page, selectors, value: str) -> None:
        from playwright.sync_api import TimeoutError as PWTimeout

        for sel in selectors:
            try:
                loc = page.locator(sel).first
                loc.wait_for(state="visible", timeout=8000)
                loc.fill(value)
                return
            except (PWTimeout, Exception):  # noqa: B014
                continue
        raise RuntimeError(f"none of the selectors matched for fill: {selectors}")

    @staticmethod
    def _click(page, selectors) -> None:
        from playwright.sync_api import TimeoutError as PWTimeout

        for sel in selectors:
            try:
                loc = page.locator(sel).first
                loc.wait_for(state="visible", timeout=8000)
                loc.click()
                return
            except (PWTimeout, Exception):  # noqa: B014
                continue
        raise RuntimeError(f"none of the selectors matched for click: {selectors}")

    @staticmethod
    def _plan_hint(page) -> Optional[str]:
        """Best-effort plan detection from the account UI text."""
        try:
            body = page.inner_text("body")[:5000].lower()
        except Exception:
            return None
        for plan in ("unlimited", "visionary", "plus", "basic", "free"):
            if plan in body:
                return plan
        return None

    def logout(self) -> None:
        def job(pw):
            browser, ctx = self._launch(pw, headless=True)
            try:
                page = ctx.new_page()
                # Clearing the API session cookie is enough for our purposes.
                page.goto("https://account.protonvpn.com/logout",
                          wait_until="domcontentloaded", timeout=45000)
                page.evaluate("() => { try { localStorage.clear(); } catch (e) {} }")
                ctx.clear_cookies()
                return True
            finally:
                browser.close()
        try:
            self.worker.submit(job, timeout=90)
        except Exception as e:  # noqa: BLE001
            log.warning("logout failed: %s", e)
        try:
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
        except OSError:
            pass
        self.logged_in = False
