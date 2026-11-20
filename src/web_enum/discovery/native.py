"""Native discovery engine (pure Python, works everywhere).

A pool of ``concurrency`` workers pulls URLs from a queue: there are never more
than N tasks alive, however long the wordlist. Every request goes through the
shared HttpClient (origin boundary, rate limit, budget, retries). Redirects are
*recorded*, not followed: "/admin -> /admin/" is itself the discovery.

Recursion (``recursion_depth`` > 0): a found directory (a redirect to the same
path plus '/', or a path ending in '/' that answers 200/401/403) is queued again
with the whole wordlist under it, one level deeper.

When the budget runs out the workers stop taking new work, the queue is
drained, and the result is marked ``truncated``: a partial result, honestly
labelled, is better than an exception that throws everything away.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import quote, urljoin

from web_enum.discovery.soft404 import NotFoundProfile, count_words_lines
from web_enum.discovery.wordlist import expand
from web_enum.errors import BudgetExhaustedError, ModuleError
from web_enum.http import HttpClient, HttpResponse
from web_enum.log import get_logger
from web_enum.models import DiscoveredPath

log = get_logger(__name__)

DIRECTORY_STATUSES = frozenset({200, 401, 403})
# Apache/nginx/IIS/Python http.server/lighttpd auto-index pages
_LISTING = re.compile(
    r"<title>\s*(Index of /|Directory listing for /|.{0,80} - /</title>)|"
    r"<h1>\s*(Index of /|Directory listing for /)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DiscoveryJob:
    base_url: str  # ends with '/'
    words: tuple[str, ...]  # raw words (engines add extensions themselves)
    extensions: tuple[str, ...]
    status_codes: tuple[int, ...]
    recursion_depth: int
    profile: NotFoundProfile


@dataclass
class EngineResult:
    paths: list[DiscoveredPath] = field(default_factory=list)
    listings: list[str] = field(default_factory=list)  # URLs showing a directory listing
    notes: list[str] = field(default_factory=list)
    truncated: bool = False
    errors: int = 0


def word_url(base: str, word: str) -> str:
    return urljoin(base, quote(word, safe="/.-_~%@!$&'()*+,;=:"))


def is_listing(response: HttpResponse) -> bool:
    return response.status == 200 and response.is_html and bool(_LISTING.search(response.text))


def is_directory(path: DiscoveredPath) -> bool:
    if (path.redirect.endswith("/") and not path.url.endswith("/")
            and path.redirect.rstrip("/") == path.url):
        return True
    return path.url.endswith("/") and path.status in DIRECTORY_STATUSES


class NativeEngine:
    name = "native"

    def __init__(self, http: HttpClient, *, concurrency: int) -> None:
        self.http = http
        self.concurrency = concurrency

    async def run(self, job: DiscoveryJob) -> EngineResult:
        result = EngineResult()
        words = expand(job.words, job.extensions)
        queue: asyncio.Queue[tuple[str, str, int]] = asyncio.Queue()  # (url, path, depth)
        seen: set[str] = set()
        stop = False

        def enqueue(base: str, depth: int) -> None:
            for word in words:
                url = word_url(base, word)
                if url not in seen and url.startswith(job.base_url):
                    seen.add(url)
                    queue.put_nowait((url, url[len(base):], depth))

        async def worker() -> None:
            nonlocal stop
            while True:
                url, path, depth = await queue.get()
                try:
                    if stop:
                        continue
                    found = await self._check(url, path, job, result)
                    if found and depth < job.recursion_depth and is_directory(found):
                        enqueue(found.url if found.url.endswith("/") else found.url + "/",
                                depth + 1)
                except BudgetExhaustedError:
                    if not stop:
                        stop = True
                        result.truncated = True
                        result.notes.append("request budget exhausted: discovery stopped early")
                finally:
                    queue.task_done()

        enqueue(job.base_url, 0)
        log.info("Native discovery: %d candidate URLs, %d workers", queue.qsize(),
                 self.concurrency)
        workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
        try:
            await queue.join()
        finally:
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        if result.errors:
            result.notes.append(f"{result.errors} request(s) failed (network errors/timeouts)")
        result.paths.sort(key=lambda p: p.url)
        return result

    async def _check(
        self, url: str, path: str, job: DiscoveryJob, result: EngineResult
    ) -> DiscoveredPath | None:
        return await check_url(self.http, url, path, job, result, source=self.name)


async def check_url(
    http: HttpClient, url: str, path: str, job: DiscoveryJob, result: EngineResult, *,
    source: str,
) -> DiscoveredPath | None:
    """Request one candidate; record it in ``result`` if it is a real finding."""
    try:
        response = await http.fetch(url)
    except BudgetExhaustedError:
        raise
    except ModuleError as exc:
        result.errors += 1
        log.debug("%s: %s", url, exc)
        return None
    if response.status not in job.status_codes:
        return None
    if job.profile.matches_response(path, response):
        return None
    words, lines = count_words_lines(response.body, "native")
    found = DiscoveredPath(url=url, status=response.status, length=len(response.body),
                           words=words, lines=lines, redirect=response.location or "",
                           source=source)
    result.paths.append(found)
    if is_listing(response):
        result.listings.append(url)
    log.info("  %d %s%s", found.status, url, f" -> {found.redirect}" if found.redirect else "")
    return found
