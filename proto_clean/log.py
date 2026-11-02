"""Logging setup."""

from __future__ import annotations

import logging
import logging.handlers
import sys

from .paths import LOG_FILE, ensure_dirs

_FMT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"


def setup_logging(verbose: bool = False) -> None:
    ensure_dirs()
    root = logging.getLogger("proto_clean")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    if root.handlers:  # already configured
        return
    fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(logging.Formatter(_FMT))
    root.addHandler(fh)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter(_FMT))
    sh.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root.addHandler(sh)


def get(name: str) -> logging.Logger:
    return logging.getLogger(f"proto_clean.{name}")
