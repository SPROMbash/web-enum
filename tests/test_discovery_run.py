"""Discovery pipeline: engine selection and the full run against a fake site."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

import httpx
import pytest
import respx

from tests.conftest import MakeHttp
from tests.fakes import FakeRunner, FakeSite
from web_enum.config import Config, load_config
from web_enum.discovery.native import NativeEngine
from web_enum.discovery.run import build_engine, calibrate, choose_engine, run_discovery
from web_enum.discovery.wordlist import Wordlist
from web_enum.errors import ToolNotFoundError
from web_enum.models import Severity
from web_enum.target import parse_target
from web_enum.tools.ffuf import FfufEngine

TARGET = parse_target("http://example.com/")
BASE = "http://example.com/"


def finder(available: dict[str, str]) -> object:
    def find(name: str, paths: Mapping[str, str]) -> str | None:
        return available.get(name)
    return find


@pytest.fixture()
def config() -> Config:
    cfg = load_config(search_user_config=False)
    return replace(cfg, discovery=replace(cfg.discovery, soft404_probes=2))


# --------------------------------------------------------------------------- #
# Engine selection
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("setting", "available", "expected"),
    [
        ("auto", {"ffuf": "/usr/bin/ffuf", "feroxbuster": "/usr/bin/feroxbuster"},
         ("ffuf", "/usr/bin/ffuf")),
        ("auto", {"feroxbuster": "/usr/bin/feroxbuster"}, ("feroxbuster", "/usr/bin/feroxbuster")),
        ("auto", {}, ("native", None)),
        ("native", {"ffuf": "/usr/bin/ffuf"}, ("native", None)),
        ("feroxbuster", {"ffuf": "/x", "feroxbuster": "/y"}, ("feroxbuster", "/y")),
    ],
)
def test_choose_engine(setting: str, available: dict[str, str],
                       expected: tuple[str, str | None]) -> None:
    assert choose_engine(setting, {}, finder(available)) == expected  # type: ignore[arg-type]


def test_explicit_engine_missing_is_an_error() -> None:
    with pytest.raises(ToolNotFoundError, match="sudo apt install ffuf") as info:
        choose_engine("ffuf", {}, finder({}))  # type: ignore[arg-type]
    assert info.value.exit_code == 3


async def test_build_engine(make_http: MakeHttp, config: Config) -> None:
    http = make_http()
    assert isinstance(build_engine("native", None, http=http, target=TARGET, config=config),
                      NativeEngine)
    engine = build_engine("ffuf", "/usr/bin/ffuf", http=http, target=TARGET, config=config,
                          headers={"Cookie": "a=b"})
    assert isinstance(engine, FfufEngine)
    assert engine.limiter is http.limiter and engine.headers == {"Cookie": "a=b"}


# --------------------------------------------------------------------------- #
# Full pipeline
# --------------------------------------------------------------------------- #
LISTING = "<html><title>Index of /images</title><h1>Index of /images</h1></html>"
SITE = {
    "/robots.txt": (200, {"content-type": "text/plain"}, "Disallow: /secret-area/\n"),
    "/secret-area/": (403, {"content-type": "text/html"}, "Forbidden"),
    "/.git/HEAD": (200, {}, "ref: refs/heads/main\n"),
    "/admin": (301, {"location": "/admin/"}, ""),
    "/images": (301, {"location": "/images/"}, ""),
    "/images/": (200, {"content-type": "text/html"}, LISTING),
    "/manager/html": (401, {"www-authenticate": "Basic"}, "auth"),
}


async def test_full_native_pipeline(router: respx.MockRouter, make_http: MakeHttp,
                                    config: Config) -> None:
    site = FakeSite(SITE)
    router.route(host="example.com").mock(side_effect=site)
    http = make_http(budget=1000)
    words = Wordlist("<bundled>", ("admin", "images/", "manager/html", "nothing"))
    result = await run_discovery(http, TARGET, config, NativeEngine(http, concurrency=3), words)

    urls = {p.url: p for p in result.paths}
    assert set(urls) == {BASE + "admin", BASE + "images/", BASE + "manager/html",
                         BASE + "secret-area/"}
    assert urls[BASE + "secret-area/"].source == "robots.txt"
    assert result.engine == "native" and result.words == 4 and not result.truncated
    assert result.profile.startswith("random paths answer 404")

    by_id = {f.id: f for f in result.findings}
    assert by_id["sensitive-git-head"].severity is Severity.HIGH
    assert by_id["directory-listing"].url == BASE + "images/"
    assert by_id["directory-listing"].severity is Severity.MEDIUM
    # '/admin' -> '/admin/' was fetched once to look for a listing (it is not one);
    # 'images/' was already fetched by the engine, so it is not requested twice
    assert site.requests.count("/admin/") == 1
    assert site.requests.count("/images/") == 1
    admin = by_id["admin-interfaces"]
    assert admin.severity is Severity.INFO
    assert "301 http://example.com/admin" in admin.evidence
    assert "401 http://example.com/manager/html" in admin.evidence


async def test_pipeline_with_ffuf_checks_listings_natively(
    router: respx.MockRouter, make_http: MakeHttp, config: Config
) -> None:
    site = FakeSite(SITE)
    router.route(host="example.com").mock(side_effect=site)
    ffuf_out = ('{"results": [{"url": "http://example.com/images", "status": 301, "length": 0,'
                ' "words": 1, "lines": 1, "redirectlocation": "/images/"}]}')
    http = make_http(budget=1000)
    engine = build_engine("ffuf", "/usr/bin/ffuf", http=http, target=TARGET, config=config,
                          runner=FakeRunner(files_after={"-o": ffuf_out}))
    result = await run_discovery(http, TARGET, config, engine,
                                 Wordlist("/usr/share/wordlists/x.txt", ("images",)))
    assert result.engine == "ffuf"
    assert "/images/" in site.requests  # fetched by web-enum to look for a listing
    assert any(f.id == "directory-listing" for f in result.findings)


async def test_listing_check_tolerates_errors(
    router: respx.MockRouter, make_http: MakeHttp, config: Config
) -> None:
    site = FakeSite(SITE, fail={"/images/"})
    router.route(host="example.com").mock(side_effect=site)
    ffuf_out = ('{"results": [{"url": "http://example.com/images", "status": 301, "length": 0,'
                ' "words": 1, "lines": 1, "redirectlocation": "/images/"}]}')
    http = make_http(budget=1000, max_retries=0)
    engine = build_engine("ffuf", "/usr/bin/ffuf", http=http, target=TARGET, config=config,
                          runner=FakeRunner(files_after={"-o": ffuf_out}))
    result = await run_discovery(http, TARGET, config, engine, Wordlist("x", ("images",)))
    assert not any(f.id == "directory-listing" for f in result.findings)
    assert [p.url for p in result.paths if p.source == "ffuf"] == [BASE + "images"]


async def test_pipeline_survives_tool_failure(
    router: respx.MockRouter, make_http: MakeHttp, config: Config
) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE))
    http = make_http(budget=1000)
    engine = build_engine("ffuf", "/usr/bin/ffuf", http=http, target=TARGET, config=config,
                          runner=FakeRunner(returncode=2, stderr="flag provided but not defined"))
    result = await run_discovery(http, TARGET, config, engine, Wordlist("x", ("admin",)))
    assert any(n.startswith("ffuf failed:") for n in result.notes)
    assert any(f.id == "sensitive-git-head" for f in result.findings)  # earlier steps kept
    assert BASE + "secret-area/" in {p.url for p in result.paths}  # seeds still checked


async def test_pipeline_budget_exhausted_keeps_partial_results(
    router: respx.MockRouter, make_http: MakeHttp, config: Config
) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE))
    http = make_http(budget=6)  # robots + sitemap + 2 calibration probes + 2 sensitive...
    result = await run_discovery(http, TARGET, config, NativeEngine(http, concurrency=2),
                                 Wordlist("x", ("admin",), rejected=2))
    assert result.truncated
    assert "request budget exhausted: discovery stopped early" in result.notes
    assert "2 unsafe wordlist entries skipped" in result.notes


async def test_calibrate_skips_failed_probes(
    router: respx.MockRouter, make_http: MakeHttp, config: Config
) -> None:
    router.route(host="example.com").mock(side_effect=httpx.ConnectError("down"))
    profile = await calibrate(make_http(max_retries=0), TARGET, config)
    assert profile.probes == () and profile.describe() == "no calibration"
