"""HTTP engine shared by every native module.

* One ``httpx.AsyncClient`` (one connection pool) for the whole scan.
* :class:`HttpClient.fetch` enforces the **same-origin boundary on every
  request** (defence in depth: even a buggy module cannot leave the target) and
  follows redirects *manually*, only while they stay on the target. A redirect
  elsewhere is not followed; it is returned as ``blocked_redirect`` so modules
  can report it (e.g. http -> https upgrade).
* Retries on 429 / 502 / 503 / 504 and network errors. Retries never sleep on
  their own: they push the shared :class:`RateLimiter` back (Retry-After or
  exponential backoff), so the whole scan slows down, and a 429 also halves the
  global rate.
* Bodies are streamed and cut at ``max_body`` bytes *after* decompression, so a
  huge page or a gzip bomb cannot exhaust memory.
* Modules get :class:`HttpResponse`, a small immutable value object, never httpx
  objects: analysers stay independent of the HTTP library and easy to test.
"""

from __future__ import annotations

import codecs
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urldefrag, urljoin

import httpx

from web_enum.config import Config
from web_enum.errors import ConfigError, OutOfScopeRequestError, RequestFailedError
from web_enum.log import get_logger
from web_enum.ratelimit import RateLimiter
from web_enum.target import Target

log = get_logger(__name__)

RETRY_STATUSES = frozenset({429, 502, 503, 504})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 5


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]  # (lower-case name, value), repeated names kept
    body: bytes
    truncated: bool = False
    elapsed: float = 0.0
    redirects: tuple[str, ...] = ()  # URLs visited before reaching this one
    blocked_redirect: str | None = None  # off-origin Location that was NOT followed

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k == name), None)

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k == name]

    @property
    def content_type(self) -> str:
        """Media type without parameters, lower-case ('' if missing)."""
        return (self.header("content-type") or "").split(";", 1)[0].strip().lower()

    @property
    def is_html(self) -> bool:
        return self.content_type in ("text/html", "application/xhtml+xml")

    @property
    def is_redirect(self) -> bool:
        return self.status in REDIRECT_STATUSES

    @property
    def location(self) -> str | None:
        """Absolute redirect target, if any (fragment removed)."""
        value = (self.header("location") or "").strip()
        if not value:  # missing, empty or blank: a blank one would resolve to self
            return None
        return urldefrag(urljoin(self.url, value)).url

    @property
    def text(self) -> str:
        """Body decoded with the declared charset (fallback UTF-8, never raises)."""
        return self.body.decode(self._charset(), errors="replace")

    def _charset(self) -> str:
        for param in (self.header("content-type") or "").split(";")[1:]:
            key, _, value = param.partition("=")
            if key.strip().lower() == "charset":
                charset = value.strip().strip("\"'")
                try:
                    return codecs.lookup(charset).name
                except LookupError:
                    break
        return "utf-8"


# --------------------------------------------------------------------------- #
# Client construction
# --------------------------------------------------------------------------- #
def parse_header(text: str) -> tuple[str, str]:
    """Parse a ``--header 'Name: value'`` option."""
    name, sep, value = text.partition(":")
    name, value = name.strip(), value.strip()
    if not sep or not name or any(c in text for c in "\r\n") or " " in name:
        raise ConfigError(f"Invalid header '{text}': expected 'Name: value'")
    return name, value


def make_async_client(
    config: Config, extra_headers: Mapping[str, str] | None = None
) -> httpx.AsyncClient:
    headers = {"User-Agent": config.http.user_agent, **(extra_headers or {})}
    return httpx.AsyncClient(
        headers=headers,
        timeout=config.http.timeout,
        verify=config.http.verify_tls,
        follow_redirects=False,  # redirects are followed by HttpClient, origin-checked
        limits=httpx.Limits(max_connections=config.limits.concurrency),
    )


def make_limiter(config: Config) -> RateLimiter:
    return RateLimiter(
        rate=config.limits.rate,
        concurrency=config.limits.concurrency,
        max_requests=config.limits.max_requests,
    )


# --------------------------------------------------------------------------- #
# HttpClient
# --------------------------------------------------------------------------- #
class HttpClient:
    def __init__(
        self,
        client: httpx.AsyncClient,
        limiter: RateLimiter,
        target: Target,
        *,
        max_retries: int = 2,
        max_retry_wait: float = 60.0,
        max_body: int = 1024 * 1024,
        backoff_base: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.limiter = limiter
        self.target = target
        self.max_retries = max_retries
        self.max_retry_wait = max_retry_wait
        self.max_body = max_body
        self.backoff_base = backoff_base
        self._clock = clock

    @classmethod
    def from_config(
        cls, client: httpx.AsyncClient, limiter: RateLimiter, target: Target, config: Config
    ) -> HttpClient:
        return cls(
            client, limiter, target,
            max_retries=config.http.max_retries,
            max_retry_wait=config.http.max_retry_wait,
            max_body=config.http.max_body_kb * 1024,
        )

    @property
    def requests_sent(self) -> int:
        return self.limiter.used

    async def fetch(
        self,
        url: str,
        *,
        follow_redirects: bool = False,
        headers: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        """GET ``url``; optionally follow redirects that stay on the target origin.

        ``headers`` are added to this request only (e.g. an Origin for a CORS check).
        """
        visited: list[str] = []
        current = urldefrag(url).url
        while True:
            response = await self._request(current, headers)
            location = response.location
            if not (follow_redirects and response.is_redirect and location):
                return replace(response, redirects=tuple(visited))
            if not self.target.same_origin(location):
                log.debug("Not following off-origin redirect %s -> %s", current, location)
                return replace(response, redirects=tuple(visited), blocked_redirect=location)
            visited.append(current)
            if len(visited) > MAX_REDIRECTS or location in visited:
                raise RequestFailedError(f"Too many redirects or redirect loop from {url}")
            current = location

    async def _request(self, url: str, headers: Mapping[str, str] | None = None) -> HttpResponse:
        if not self.target.same_origin(url):
            raise OutOfScopeRequestError(f"Refusing request outside the target origin: {url}")
        attempt = 0
        while True:
            try:
                async with self.limiter:
                    response = await self._send(url, headers)
            except httpx.TransportError as exc:  # connection errors and timeouts
                if attempt >= self.max_retries:
                    raise RequestFailedError(f"{url}: {type(exc).__name__}: {exc}") from exc
                log.debug("%s: %s, retrying", url, type(exc).__name__)
                self.limiter.penalize(self._backoff(attempt))
                attempt += 1
                continue

            if response.status in RETRY_STATUSES and attempt < self.max_retries:
                wait = parse_retry_after(response.header("retry-after"))
                if response.status == 429:
                    rate = self.limiter.slow_down()
                    log.warning("Server answered 429 Too Many Requests: slowing down to "
                                "%.2g req/s", rate)
                delay = wait if wait is not None else self._backoff(attempt)
                self.limiter.penalize(min(delay, self.max_retry_wait))
                attempt += 1
                continue
            return response

    async def _send(self, url: str, headers: Mapping[str, str] | None = None) -> HttpResponse:
        start = self._clock()
        async with self.client.stream("GET", url, headers=headers) as raw:
            body = bytearray()
            truncated = False
            async for chunk in raw.aiter_bytes():  # decoded (decompressed) bytes
                room = self.max_body - len(body)
                if len(chunk) > room:
                    body += chunk[:room]
                    truncated = True
                    break
                body += chunk
            response = HttpResponse(
                url=url,
                status=raw.status_code,
                headers=tuple((k.lower(), v) for k, v in raw.headers.multi_items()),
                body=bytes(body),
                truncated=truncated,
                elapsed=self._clock() - start,
            )
        log.debug("GET %s -> %d (%d bytes%s)", url, response.status, len(response.body),
                  ", truncated" if truncated else "")
        return response

    def _backoff(self, attempt: int) -> float:
        return float(self.backoff_base * (2 ** attempt))


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP date)."""
    if value is None:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return max(0.0, (when - reference).total_seconds())
