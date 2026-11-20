"""Shared fixtures. Every test is hermetic: no real user config, no network, no tools."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path

import httpx
import pytest
import respx

from tests.fakes import FakeClock
from web_enum.http import HttpClient
from web_enum.log import reset_logging
from web_enum.ratelimit import RateLimiter
from web_enum.target import parse_target

FIXTURES = Path(__file__).parent / "fixtures"
BASE = "http://example.com"

WriteConfig = Callable[[str], Path]
MakeHttp = Callable[..., HttpClient]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    # A real ~/.config/web-enum/config.yaml must never leak into tests.
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    yield
    reset_logging()


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture()
def write_config(tmp_path: Path) -> WriteConfig:
    """Write a YAML text to a temporary config file and return its path."""

    def factory(text: str) -> Path:
        path = tmp_path / "config.yaml"
        path.write_text(text, encoding="utf-8")
        return path

    return factory


# HTTP ----------------------------------------------------------------------
@pytest.fixture()
def router() -> Iterator[respx.MockRouter]:
    # assert_all_mocked (default): any request without a mock fails the test.
    with respx.mock(assert_all_called=False) as mock:
        yield mock


@pytest.fixture()
async def raw_client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as client:
        yield client


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def make_http(raw_client: httpx.AsyncClient, clock: FakeClock) -> MakeHttp:
    """HttpClient over respx with a fake clock: retries and rate limits cost no time."""

    def factory(*, max_retries: int = 2, max_body: int = 1024 * 1024, budget: int = 100,
                max_retry_wait: float = 60, target: str = BASE + "/") -> HttpClient:
        limiter = RateLimiter(rate=10, concurrency=5, max_requests=budget,
                              clock=clock, sleep=clock.sleep)
        return HttpClient(raw_client, limiter, parse_target(target), max_retries=max_retries,
                          max_body=max_body, max_retry_wait=max_retry_wait, clock=clock)

    return factory
