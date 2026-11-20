"""Logging: console prefixes, file handler and secret masking."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from web_enum.log import (
    MASK,
    SecretFilter,
    add_file_handler,
    get_logger,
    mask_secrets,
    setup_logging,
)

COOKIE = "PHPSESSID=0123456789abcdef"


def test_console_prefixes_and_level(capsys: pytest.CaptureFixture[str]) -> None:
    setup_logging("INFO")
    log = get_logger("web_enum.test")
    log.debug("hidden")
    log.info("hello")
    log.warning("careful")
    log.error("broken")
    err = capsys.readouterr().err
    assert "hidden" not in err
    assert "[*] hello" in err and "[!] careful" in err and "[x] broken" in err


def test_secrets_masked_on_console_and_in_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    setup_logging("DEBUG", secrets=[COOKIE])
    log_file = add_file_handler(tmp_path / "logs" / "web-enum.log", secrets=[COOKIE])
    get_logger().info("running ffuf -H 'Cookie: %s' -u http://x", COOKIE)
    for handler in logging.getLogger("web_enum").handlers:
        handler.flush()
    err = capsys.readouterr().err
    content = log_file.read_text(encoding="utf-8")
    for text in (err, content):
        assert COOKIE not in text
        assert f"Cookie: {MASK}" in text


def test_short_values_are_not_treated_as_secrets() -> None:
    assert SecretFilter(["abc", "", "longsecret"]).secrets == ["longsecret"]


def test_longest_secret_masked_first() -> None:
    secrets = SecretFilter(["token123", "token123-extended"]).secrets
    assert mask_secrets("a token123-extended b", secrets) == f"a {MASK} b"


def test_setup_is_idempotent() -> None:
    setup_logging()
    setup_logging()
    assert len(logging.getLogger("web_enum").handlers) == 1


def test_get_logger_namespacing() -> None:
    assert get_logger().name == "web_enum"
    assert get_logger("web_enum").name == "web_enum"
    assert get_logger("web_enum.http").name == "web_enum.http"
    assert get_logger("other").name == "web_enum.other"
