"""Logging: short prefixed console messages, full detail in a file, secrets masked.

Named ``log.py`` (not ``logging.py``) so it never shadows the standard library.

Authenticated scans pass headers such as ``Cookie`` or ``Authorization``.
:class:`SecretFilter` replaces those values with ``***`` in every record before
any handler writes it, so a session token never ends up in the console, the log
file or a pasted bug report, not even inside a logged command line.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable
from pathlib import Path

LOGGER_NAME = "web_enum"
MASK = "***"
MIN_SECRET_LEN = 6  # shorter values would mask random words in normal messages

_PREFIXES = {
    logging.DEBUG: "[d]",
    logging.INFO: "[*]",
    logging.WARNING: "[!]",
    logging.ERROR: "[x]",
    logging.CRITICAL: "[x]",
}
_FILE_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return f"{_PREFIXES.get(record.levelno, '[?]')} {record.getMessage()}"


class SecretFilter(logging.Filter):
    """Mask every configured secret in the final message of a record."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        # Longest first, so a secret containing another one is masked whole.
        self.secrets = sorted(
            {s for s in secrets if len(s) >= MIN_SECRET_LEN}, key=len, reverse=True
        )

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secrets:
            message = record.getMessage()
            masked = mask_secrets(message, self.secrets)
            if masked != message:
                record.msg, record.args = masked, None
        return True


def mask_secrets(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, MASK)
    return text


def get_logger(name: str | None = None) -> logging.Logger:
    if name is None or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    if name.startswith(LOGGER_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def setup_logging(level: str = "INFO", secrets: Iterable[str] = ()) -> logging.Logger:
    """(Re)configure the package logger with a console handler. Idempotent."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    _remove_handlers(logger)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level.upper())
    console.setFormatter(ConsoleFormatter())
    console.addFilter(SecretFilter(secrets))
    logger.addHandler(console)
    logger.propagate = False
    return logger


def add_file_handler(path: Path, secrets: Iterable[str] = ()) -> Path:
    """Also log everything (DEBUG and up) to ``path``, appending, secrets masked."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(_FILE_FORMAT))
    handler.addFilter(SecretFilter(secrets))
    logging.getLogger(LOGGER_NAME).addHandler(handler)
    return path


def reset_logging() -> None:
    """Remove all handlers and restore defaults (used by tests)."""
    logger = logging.getLogger(LOGGER_NAME)
    _remove_handlers(logger)
    logger.setLevel(logging.NOTSET)
    logger.propagate = True


def _remove_handlers(logger: logging.Logger) -> None:
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
