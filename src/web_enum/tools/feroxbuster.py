"""feroxbuster backend (Kali / Parrot): recursive Rust content discoverer.

Options used (``feroxbuster -h``): ``--url --wordlist --json --output --threads
--rate-limit --status-codes --timeout --time-limit --user-agent --headers
--extensions --silent --insecure --dont-extract-links`` and ``--no-recursion``
or ``--depth N+1`` (feroxbuster counts the base URL as depth 1; 0 would mean
*infinite*, which is why recursion is always explicit here). Link extraction is
disabled so the request count stays predictable.

JSON output: one object per line; lines with ``"type": "response"`` carry
``url, status, content_length, word_count, line_count, headers``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from web_enum.discovery.external import ExternalEngine
from web_enum.discovery.native import DiscoveryJob
from web_enum.models import DiscoveredPath


class FeroxbusterEngine(ExternalEngine):
    name = "feroxbuster"
    flavor = "feroxbuster"

    def argv(self, job: DiscoveryJob, wordlist: Path, output: Path, max_seconds: int) -> list[str]:
        argv = [
            self.path,
            "--url", job.base_url,
            "--wordlist", str(wordlist),
            "--json",
            "--output", str(output),
            "--threads", str(self.limiter.concurrency),
            "--rate-limit", str(self.rate),
            "--timeout", str(max(1, round(self.timeout))),
            "--time-limit", f"{max_seconds}s",
            "--user-agent", self.user_agent,
            "--silent",
            "--insecure",
            "--dont-extract-links",
        ]
        for code in job.status_codes:
            argv += ["--status-codes", str(code)]
        for name, value in self.headers.items():
            argv += ["--headers", f"{name}: {value}"]
        for ext in job.extensions:
            argv += ["--extensions", ext]
        if job.recursion_depth > 0:
            argv += ["--depth", str(job.recursion_depth + 1)]
        else:
            argv.append("--no-recursion")
        return argv

    def parse(self, text: str) -> list[DiscoveredPath]:
        paths: list[DiscoveredPath] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue  # a partial last line if the time limit stopped it mid-write
            if isinstance(item, dict) and item.get("type") == "response":
                path = _path(item)
                if path is not None:
                    paths.append(path)
        return paths


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _path(item: dict[str, Any]) -> DiscoveredPath | None:
    url = item.get("url")
    status = _int(item.get("status"))
    if not isinstance(url, str) or not 100 <= status <= 599:
        return None
    headers = item.get("headers")
    location = ""
    if isinstance(headers, dict):
        value = next((v for k, v in headers.items()
                      if isinstance(k, str) and k.lower() == "location"), "")
        location = value if isinstance(value, str) else ""
    return DiscoveredPath(
        url=url, status=status, length=_int(item.get("content_length")),
        words=_int(item.get("word_count")), lines=_int(item.get("line_count")),
        redirect=location, source="feroxbuster",
    )
