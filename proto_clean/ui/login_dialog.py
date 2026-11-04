"""Login dialog: save Proton credentials for auto-login, or log in by hand
in a visible browser window (CAPTCHA-friendly). Also offers Material 3
"Continue as guest" — Proton's credentialless Tier=0 session (no account,
no CAPTCHA, no Playwright)."""

from __future__ import annotations

from proto_clean.qtcompat import Qt
from proto_clean.qtcompat import (
    QCheckBox, QDialog, QFrame, QHBoxLayout, QFormLayout, QLabel,
    QLineEdit, QPushButton, QVBoxLayout,
)

from .. import credentials as creds


class LoginDialog(QDialog):
    """Enter Proton credentials once; Proto Clean then auto-logs-in forever.

    * "Remember me" saves username/password (system keyring, or a
      chmod-600 file) plus the optional TOTP secret, enabling automatic
      login at launch and whenever the session expires.
    * Un-checking it uses the credentials for this login only.
    * "Log in in browser…" opens a visible Chromium window where you can
      type everything by hand and solve any CAPTCHA yourself.
    * "Continue as guest" uses Proton's credentialless API flow
      (``POST /auth/v4/sessions`` -> ``POST /auth/v4/credentialless``)
      to obtain a Tier=0 session bound to a client-generated Ed25519
      keypair. No account, no CAPTCHA, free servers only.
    """

    def __init__(self, controller, parent=None,
                 prefill_username: str = "") -> None:
        super().__init__(parent)
        self.controller = controller
        self.setWindowTitle("Log in to Proton VPN")
        self.setMinimumWidth(560)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Save your Proton credentials so Proto Clean can log in "
            "automatically (at launch and whenever the session expires). "
            "Credentials are kept in your system keyring — or a "
            "chmod-600 file when no keyring is available.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.user_edit = QLineEdit(prefill_username)
        self.user_edit.setPlaceholderText("Proton account name (or email)")
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        self.pass_edit.setPlaceholderText("Proton password")
        self.totp_edit = QLineEdit()
        self.totp_edit.setPlaceholderText(
            "optional — TOTP secret (otpauth://… or raw base32) for "
            "automatic 2FA")
        self.remember = QCheckBox(
            "Remember me — save credentials for automatic login")
        self.remember.setChecked(True)
        self.remember.setToolTip(
            "Stored in the system keyring when available (otherwise a "
            "chmod-600 file). Clear them any time with Log out & forget.")

        form.addRow("Username", self.user_edit)
        form.addRow("Password", self.pass_edit)
        form.addRow("2FA secret", self.totp_edit)
        form.addRow(self.remember)
        layout.addLayout(form)

        note = QLabel(
            "If Proton asks for human verification (CAPTCHA), a browser "
            "window will open automatically — complete it there and login "
            "continues by itself.")
        note.setWordWrap(True)
        note.setObjectName("LoginNote")
        layout.addWidget(note)

        # ---- Material 3 "Continue as guest" — filled tonal button with
        # a divider above it. Mirrors Proton's own Android first-run UI:
        # the guest option is the low-emphasis fallback below the primary
        # account-login CTAs.
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setObjectName("M3Divider")
        layout.addWidget(divider)

        guest_row = QHBoxLayout()
        guest_blurb = QLabel(
            "No account? Continue as guest — uses Proton's credentialless "
            "API to obtain a free-tier (Tier=0) session. Free servers "
            "only (NL, JP, PL, RO, US); one connection at a time.")
        guest_blurb.setWordWrap(True)
        guest_blurb.setObjectName("LoginNote")
        guest_row.addWidget(guest_blurb, 1)
        self.guest_btn = QPushButton("Continue as guest")
        self.guest_btn.setObjectName("GuestButton")
        self.guest_btn.setToolTip(
            "Proton's credentialless login: no account, no CAPTCHA, "
            "no Playwright. Free-tier servers only.")
        self.guest_btn.clicked.connect(self._on_guest_login)
        guest_row.addWidget(self.guest_btn, 0)
        layout.addLayout(guest_row)

        buttons = QHBoxLayout()
        self.login_btn = QPushButton("Log in")
        self.login_btn.setObjectName("Connect")
        self.login_btn.setDefault(True)
        self.login_btn.clicked.connect(self._on_login)
        self.browser_btn = QPushButton("Log in in browser…")
        self.browser_btn.setToolTip(
            "Open a visible browser window and log in by hand "
            "(best when you expect a CAPTCHA)")
        self.browser_btn.clicked.connect(self._on_browser_login)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(self.browser_btn)
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(self.login_btn)
        layout.addLayout(buttons)

        # stored TOTP secret is shown for editing convenience
        stored_totp = creds.load_totp_secret()
        if stored_totp and not self.totp_edit.text():
            self.totp_edit.setText(stored_totp)

    # ---------------------------------------------------------------- actions
    def _on_login(self) -> None:
        u = self.user_edit.text().strip()
        p = self.pass_edit.text()
        if not u or not p:
            self.login_btn.setText("Username + password required")
            return
        remember = self.remember.isChecked()
        self.controller.login_once_async(u, p,
                                         totp_secret=self.totp_edit.text().strip(),
                                         remember=remember)
        self.accept()

    def _on_browser_login(self) -> None:
        # remember me + typed credentials -> pre-fill the browser window too
        if self.remember.isChecked():
            u = self.user_edit.text().strip()
            p = self.pass_edit.text()
            if u and p:
                self.controller.login_interactive_async(u, p)
                self.accept()
                return
        self.controller.login_interactive_async()
        self.accept()

    def _on_guest_login(self) -> None:
        """Trigger the credentialless guest login flow."""
        self.controller.login_guest_async()
        self.accept()
