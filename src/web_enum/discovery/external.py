"""Shared machinery for external discovery engines (ffuf, feroxbuster).

The tool does the fuzzing; web-enum keeps the guarantees:

* **Sanitised input**: the tool gets our cleaned wordlist (written to a private
  temporary file), never the raw one.
* **Budget**: requests are booked in the shared limiter (``reserve``); if the
  wordlist does not fit, it is cut to fit. A wall-clock cap of
  ``booked / rate`` seconds is passed too, so even recursion cannot exceed the
  budget (at R requests/s for T seconds a tool sends at most R*T requests).
* **Same criteria as the native engine**: results are filtered with our status
  codes, our soft-404 profile (word/line counts computed the way *this* tool
  counts them) and the target's origin boundary.
"""

from __future__ import annotations

import math
import tempfile
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from urllib.parse import urljoin

from web_enum.discovery.native import DiscoveryJob, EngineResult
from web_enum.discovery.wordlist import expand
from web_enum.errors import ModuleError
from web_enum.log import get_logger
from web_enum.models import DiscoveredPath
from web_enum.ratelimit import RateLimiter
from web_enum.target import Target
from web_enum.tools.process import ProcessRunner, run_process

log = get_logger(__name__)


def fit_words(words: tuple[str, ...], extensions: tuple[str, ...], budget: int) -> list[str]:
    """Longest prefix of ``words`` whose expansion fits in ``budget`` requests."""
    per_word = 1 + len(extensions)
    if len(words) * per_word <= budget:
        return list(words)
    kept: list[str] = []
    used = 0
    for word in words:
        cost = len(expand([word], extensions))
        if used + cost > budget:
            break
        kept.append(word)
        used += cost
    return kept


class ExternalEngine:
    """Base class: subclasses define ``name``, ``flavor``, ``argv`` and ``parse``."""

    name = "external"
    flavor = "native"
    output_suffix = ".json"

    def __init__(
        self, path: str, *, target: Target, limiter: RateLimiter, user_agent: str,
        timeout: float, headers: Mapping[str, str] | None = None,
        runner: ProcessRunner = run_process,
    ) -> None:
        self.path = path
        self.target = target
        self.limiter = limiter
        self.user_agent = user_agent
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.runner = runner

    # -- to implement --------------------------------------------------------
    def argv(self, job: DiscoveryJob, wordlist: Path, output: Path,
             max_seconds: int) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def parse(self, text: str) -> list[DiscoveredPath]:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- shared --------------------------------------------------------------
    @property
    def rate(self) -> int:
        return max(1, math.floor(self.limiter.rate))

    async def run(self, job: DiscoveryJob) -> EngineResult:
        result = EngineResult()
        estimate = len(expand(job.words, job.extensions))
        granted = self.limiter.reserve(estimate)
        if granted == 0:
            result.truncated = True
            result.notes.append("request budget exhausted before discovery")
            return result
        words = fit_words(job.words, job.extensions, granted)
        if len(words) < len(job.words):
            result.truncated = True
            result.notes.append(
                f"wordlist cut to {len(words)} of {len(job.words)} words to fit the request "
                f"budget ({granted} requests)"
            )
        max_seconds = math.ceil(granted / self.rate) + 5

        with tempfile.TemporaryDirectory(prefix=f"web-enum-{self.name}-") as tmp:
            wordlist = Path(tmp) / "words.txt"
            output = Path(tmp) / f"out{self.output_suffix}"
            wordlist.write_text("\n".join(words) + "\n", encoding="utf-8")
            argv = self.argv(job, wordlist, output, max_seconds)
            log.info("%s: %d words, %d workers, %d req/s, time cap %ds", self.name, len(words),
                     self.limiter.concurrency, self.rate, max_seconds)
            process = await self.runner(argv, timeout=max_seconds + 60)
            text = output.read_text(encoding="utf-8", errors="replace") \
                if output.is_file() else ""

        if not text.strip():
            if process.returncode != 0:
                raise ModuleError(f"{self.name} failed: {process.last_error_line()}")
            text = ""  # ran fine and found nothing
        raw = self.parse(text) if text else []
        result.paths = self.filter(raw, job, result)
        return result

    def filter(self, raw: list[DiscoveredPath], job: DiscoveryJob,
               result: EngineResult) -> list[DiscoveredPath]:
        kept: dict[str, DiscoveredPath] = {}
        off_origin = 0
        for item in raw:
            if not self.target.same_origin(item.url) or not item.url.startswith(job.base_url):
                off_origin += 1
                continue
            if item.redirect:  # tools may report a relative Location
                item = replace(item, redirect=urljoin(item.url, item.redirect))
            if item.status not in job.status_codes:
                continue
            path = item.url[len(job.base_url):]
            if job.profile.is_not_found(path=path, status=item.status, length=item.length,
                                        words=item.words, lines=item.lines,
                                        location=item.redirect or None, flavor=self.flavor):
                continue
            kept.setdefault(item.url, item)
        if off_origin:
            result.notes.append(f"{off_origin} {self.name} result(s) outside the target ignored")
        return sorted(kept.values(), key=lambda p: p.url)
