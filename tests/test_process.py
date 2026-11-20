"""Running external processes: real subprocesses using the Python interpreter itself.

``sys.executable`` is the one program guaranteed to exist on every platform, so
these tests exercise the real ``create_subprocess_exec`` path (output capture,
exit codes, timeout kill) without any Kali tool.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import time

import pytest

from web_enum.errors import ModuleError
from web_enum.tools.process import ProcessResult, find_tool, run_process

PY = sys.executable


async def test_captures_output_and_exit_code() -> None:
    # Write explicit UTF-8 bytes: print() would use the console's code page (cp1252 on a
    # Windows terminal), which made this test depend on the shell it was launched from.
    code = ("import sys; sys.stdout.buffer.write('out ñ\\n'.encode('utf-8')); "
            "print('bad', file=sys.stderr); sys.exit(3)")
    result = await run_process([PY, "-c", code], timeout=30)
    assert result.returncode == 3
    assert result.stdout.strip() == "out ñ"
    assert result.stderr.strip() == "bad"


async def test_invalid_utf8_output_is_replaced_not_fatal() -> None:
    code = "import sys; sys.stdout.buffer.write(b'caf\\xe9 \\xff')"
    result = await run_process([PY, "-c", code], timeout=30)
    assert result.stdout == "caf� �"


async def test_arguments_are_not_interpreted_by_a_shell() -> None:
    payload = "a; echo INJECTED $(whoami) `id` | cat"
    result = await run_process([PY, "-c", "import sys; print(sys.argv[1])", payload], timeout=30)
    assert result.stdout.strip() == payload  # received verbatim as one argument


async def test_timeout_kills_the_process() -> None:
    start = time.monotonic()
    with pytest.raises(ModuleError, match="timed out after 0.5s"):
        await run_process([PY, "-c", "import time; time.sleep(30)"], timeout=0.5)
    assert time.monotonic() - start < 15


async def test_missing_binary() -> None:
    with pytest.raises(ModuleError, match="cannot run /nonexistent/ffuf"):
        await run_process(["/nonexistent/ffuf", "-h"], timeout=5)


def test_last_error_line() -> None:
    assert ProcessResult(1, "", "a\n\n  b failed  \n\n").last_error_line() == "b failed"
    assert ProcessResult(2, "", "").last_error_line() == "exit code 2"


async def test_cancellation_kills_the_process_and_propagates() -> None:
    task = asyncio.create_task(run_process([PY, "-c", "import time; time.sleep(30)"], timeout=60))
    await asyncio.sleep(0.5)  # let it start
    start = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - start < 15  # killed, not waited for


def test_find_tool(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    available = {"ffuf": "/usr/bin/ffuf", "/opt/ffuf/ffuf": "/opt/ffuf/ffuf"}
    monkeypatch.setattr(shutil, "which", available.get)
    assert find_tool("ffuf", {}) == "/usr/bin/ffuf"
    assert find_tool("ffuf", {"ffuf": "/opt/ffuf/ffuf"}) == "/opt/ffuf/ffuf"
    assert find_tool("whatweb", {}) is None
    # a broken configured path falls back to PATH, with a warning
    assert find_tool("ffuf", {"ffuf": "/wrong/ffuf"}) == "/usr/bin/ffuf"
    assert "tools.paths.ffuf = /wrong/ffuf is not an executable file" in caplog.text
