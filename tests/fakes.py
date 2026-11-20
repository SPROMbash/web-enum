"""Test doubles shared by several test modules."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import httpx

from web_enum.tools.process import ProcessResult


class FakeRunner:
    """Stands in for an external tool: records argv and writes canned output files.

    ``files`` maps an option prefix (``--log-json=``) to the text to write at the
    path glued to it (whatweb style); ``files_after`` maps a flag (``-o``) to the
    text to write at the path given in the NEXT argument (ffuf style).
    """

    def __init__(
        self, *, files: dict[str, str] | None = None, files_after: dict[str, str] | None = None,
        stdout: str = "", stderr: str = "", returncode: int = 0,
    ) -> None:
        self.files = files or {}
        self.files_after = files_after or {}
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.calls: list[list[str]] = []
        self.timeouts: list[float] = []
        self.inputs: dict[str, str] = {}  # contents of files passed with -w/--wordlist

    async def __call__(self, argv: Sequence[str], *, timeout: float) -> ProcessResult:
        argv = list(argv)
        self.calls.append(argv)
        self.timeouts.append(timeout)
        # Blocking file I/O is fine in a test double (tiny local files).
        for i, arg in enumerate(argv):
            for prefix, text in self.files.items():
                if arg.startswith(prefix):
                    Path(arg[len(prefix):]).write_text(text, encoding="utf-8")  # noqa: ASYNC240
            if arg in self.files_after and i + 1 < len(argv):
                Path(argv[i + 1]).write_text(self.files_after[arg], encoding="utf-8")  # noqa: ASYNC240
            if arg in ("-w", "--wordlist") and i + 1 < len(argv):
                self.inputs["wordlist"] = Path(argv[i + 1]).read_text(encoding="utf-8")  # noqa: ASYNC240
        return ProcessResult(self.returncode, self.stdout, self.stderr)


Page = tuple[int, dict[str, str], bytes | str]


class FakeSite:
    """A tiny fake web server for respx: responds by path, records every request.

    ``not_found`` builds the answer for unknown paths (default: a real 404), which
    lets tests model soft-404 servers.
    """

    def __init__(
        self, pages: Mapping[str, Page] | None = None, *,
        not_found: Callable[[str], httpx.Response] | None = None,
        fail: set[str] | None = None,
    ) -> None:
        self.pages = pages or {}
        self.not_found = not_found or (lambda path: httpx.Response(404, text="Not Found"))
        self.fail = fail or set()
        self.requests: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append(path)
        if path in self.fail:
            raise httpx.ConnectError("connection reset")
        if path in self.pages:
            status, headers, body = self.pages[path]
            content = body.encode() if isinstance(body, str) else body
            return httpx.Response(status, headers=headers, content=content)
        return self.not_found(path)


class FakeClock:
    """A controllable monotonic clock whose ``sleep`` records and (optionally) advances time.

    ``advance=False`` models many tasks booking slots "at the same instant",
    which is how concurrent requests reach the limiter.
    """

    def __init__(self, *, advance: bool = True) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self.advance = advance

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(round(seconds, 6))
        if self.advance:
            self.now += seconds
