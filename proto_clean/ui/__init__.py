"""Proto Clean Qt UI package.

Submodules (theme, main_window, settings_dialog, login_dialog,
protocols_dialog, blocklists_dialog, tray, bridge, resources, md3) are
imported explicitly by callers; this ``__init__`` does not eagerly pull
in the Qt-requiring modules so that headless environments (no Qt
binding) can still import ``proto_clean.ui.theme`` for its QSS strings.
"""
