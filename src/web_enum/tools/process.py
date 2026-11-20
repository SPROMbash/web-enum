"""Running external tools safely.

* argv is always a list and goes to ``create_subprocess_exec``: there is no
  shell, so a URL containing ``;`` or ``$(...)`` is just an argument.
* stdin is closed, output is captured, and a timeout kills the process (and so
  does Ctrl+C / task cancellation): a hung tool never hangs the scan.
* The runner is injectable (:class:`ProcessRunner`), which is how the tests run
  "ffuf" and "whatweb" on Windows without either being installed.
"""

from __future__ import annotations

import asyncio
import contextlib
import shlex
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from web_enum.errors import ModuleError
from web_enum.log import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str

    def last_error_line(self) -> str:
        lines = [line.strip() for line in self.stderr.splitlines() if line.strip()]
        return lines[-1][:200] if lines else f"exit code {self.returncode}"


class ProcessRunner(Protocol):
    async def __call__(self, argv: Sequence[str], *, timeout: float) -> ProcessResult: ...


async def run_process(argv: Sequence[str], *, timeout: float) -> ProcessResult:
    """Run ``argv`` (no shell) and capture its output; kill it on timeout or cancel."""
    log.debug("Running: %s", shlex.join(argv))  # header secrets are masked by SecretFilter
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:  # not found, not executable...
        raise ModuleError(f"cannot run {argv[0]}: {exc}") from exc
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        _kill(proc)
        await proc.wait()
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise ModuleError(f"{argv[0]} timed out after {timeout:g}s and was stopped") from None
    return ProcessResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=out.decode("utf-8", errors="replace"),
        stderr=err.decode("utf-8", errors="replace"),
    )


def _kill(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError):  # it may have just finished
        proc.kill()


def find_tool(name: str, paths: Mapping[str, str]) -> str | None:
    """Path of tool ``name``: the configured path if usable, else a PATH lookup."""
    configured = paths.get(name)
    if configured:
        found = shutil.which(configured)
        if found is not None:
            return found
        log.warning("tools.paths.%s = %s is not an executable file; looking in PATH",
                    name, configured)
    return shutil.which(name)
