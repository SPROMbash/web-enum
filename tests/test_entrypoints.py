"""Smoke tests running the package as a real separate process.

They prove the package starts on its own (imports, bundled YAML/wordlist data,
``python -m``) and that exit codes reach the operating system, something the
in-process CliRunner tests cannot show. None of them sends a request: only
--version, the scope refusal and a dry run. XDG_CONFIG_HOME is isolated by the
autouse fixture (monkeypatch.setenv changes os.environ, inherited here).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from web_enum import __version__


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "web_enum", *args],
        capture_output=True, text=True, cwd=cwd, timeout=60, check=False,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


def test_version(tmp_path: Path) -> None:
    result = run("--version", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"web-enum {__version__}"


def test_scope_refusal_exit_code(tmp_path: Path) -> None:
    result = run("scan", "http://box.htb/", cwd=tmp_path)
    assert result.returncode == 4
    assert "not in your authorised scope" in result.stderr
    assert list(tmp_path.iterdir()) == []  # no report, no log, nothing


def test_dry_run_uses_bundled_data(tmp_path: Path) -> None:
    words = tmp_path / "w.txt"
    words.write_text("admin\n", encoding="utf-8")
    result = run("scan", "http://box.htb/", "--authorized", "--dry-run", "-w", str(words),
                 cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "DRY RUN: no request will be sent." in result.stdout
    assert "[RUN ] discovery" in result.stdout and "(1 words)" in result.stdout
    assert sorted(p.name for p in tmp_path.iterdir()) == ["w.txt"]  # nothing written


def test_invalid_option_exit_code(tmp_path: Path) -> None:
    result = run("scan", "http://box.htb/", "--authorized", "--dry-run", "--concurrency", "0",
                 cwd=tmp_path)
    assert result.returncode == 2
    assert "'limits.concurrency' must be between 1 and 100" in result.stderr
