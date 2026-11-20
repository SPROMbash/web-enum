"""ffuf backend (Kali / Parrot): fast Go fuzzer.

Options used (``ffuf -h``): ``-u URL/FUZZ -w wordlist -of json -o file -t threads
-rate N -mc codes -timeout s -maxtime s -H header -e .ext1,.ext2 -recursion
-recursion-depth N -noninteractive -s``. No ``-ac``: auto-calibration is done
by web-enum itself (same criterion for every engine). Redirects are not
followed (no ``-r``).

JSON output: ``{"results": [{"url", "status", "length", "words", "lines",
"redirectlocation", ...}], ...}``. Every field is type-checked.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from web_enum.discovery.external import ExternalEngine
from web_enum.discovery.native import DiscoveryJob
from web_enum.errors import ModuleError
from web_enum.models import DiscoveredPath


class FfufEngine(ExternalEngine):
    name = "ffuf"
    flavor = "ffuf"

    def argv(self, job: DiscoveryJob, wordlist: Path, output: Path, max_seconds: int) -> list[str]:
        argv = [
            self.path,
            "-u", job.base_url + "FUZZ",
            "-w", str(wordlist),
            "-of", "json",
            "-o", str(output),
            "-t", str(self.limiter.concurrency),
            "-rate", str(self.rate),
            "-mc", ",".join(str(c) for c in job.status_codes),
            "-timeout", str(max(1, round(self.timeout))),
            "-maxtime", str(max_seconds),
            "-H", f"User-Agent: {self.user_agent}",
            "-noninteractive",
            "-s",
        ]
        for name, value in self.headers.items():
            argv += ["-H", f"{name}: {value}"]
        if job.extensions:
            argv += ["-e", ",".join(f".{ext}" for ext in job.extensions)]
        if job.recursion_depth > 0:
            argv += ["-recursion", "-recursion-depth", str(job.recursion_depth)]
        return argv

    def parse(self, text: str) -> list[DiscoveredPath]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ModuleError(f"ffuf output is not valid JSON: {exc}") from None
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            raise ModuleError("ffuf output has no 'results' list")
        return [p for item in results if (p := _path(item)) is not None]


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _path(item: Any) -> DiscoveredPath | None:
    if not isinstance(item, dict) or not isinstance(item.get("url"), str):
        return None
    status = _int(item.get("status"))
    if not 100 <= status <= 599:
        return None
    redirect = item.get("redirectlocation")
    return DiscoveredPath(
        url=item["url"], status=status, length=_int(item.get("length")),
        words=_int(item.get("words")), lines=_int(item.get("lines")),
        redirect=redirect if isinstance(redirect, str) else "", source="ffuf",
    )
