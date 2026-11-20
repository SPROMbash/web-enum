"""Native discovery engine against a fake site."""

from __future__ import annotations

import httpx
import respx

from tests.conftest import MakeHttp
from tests.fakes import FakeSite
from web_enum.discovery.native import (
    DiscoveryJob,
    NativeEngine,
    is_directory,
    is_listing,
    word_url,
)
from web_enum.discovery.soft404 import NotFoundProfile, Probe
from web_enum.http import HttpClient, HttpResponse
from web_enum.models import DiscoveredPath

BASE = "http://example.com/"
CODES = (200, 204, 301, 302, 307, 308, 401, 403, 405)
LISTING = "<html><head><title>Index of /images</title></head><body><h1>Index of /images</h1>"

SITE_PAGES = {
    "/admin": (301, {"location": "/admin/"}, ""),
    "/admin/": (200, {"content-type": "text/html"}, "<h1>Admin</h1>"),
    "/admin/config.php": (200, {"content-type": "text/html"}, "config"),
    "/login.php": (200, {"content-type": "text/html"}, "<form>login</form>"),
    "/images/": (200, {"content-type": "text/html"}, LISTING),
    "/server-error": (500, {}, "boom"),
}


def job(words: tuple[str, ...], *, profile: NotFoundProfile | None = None,
        extensions: tuple[str, ...] = (), recursion: int = 0) -> DiscoveryJob:
    return DiscoveryJob(BASE, words, extensions, CODES, recursion, profile or NotFoundProfile([]))


async def run(http: HttpClient, j: DiscoveryJob) -> dict[str, DiscoveredPath]:
    result = await NativeEngine(http, concurrency=3).run(j)
    return {p.url: p for p in result.paths}


async def test_finds_real_paths(router: respx.MockRouter, make_http: MakeHttp) -> None:
    site = FakeSite(SITE_PAGES)
    router.route(host="example.com").mock(side_effect=site)
    found = await run(make_http(), job(("admin", "login", "images/", "nothing", "server-error"),
                                       extensions=("php",)))
    assert set(found) == {BASE + "admin", BASE + "login.php", BASE + "images/"}
    assert found[BASE + "admin"].redirect == BASE + "admin/"  # recorded, not followed
    assert "/admin/" not in site.requests
    assert found[BASE + "login.php"].source == "native"
    assert "/server-error" in site.requests  # 500 is not in the status codes: dropped


async def test_soft_404_site(router: respx.MockRouter, make_http: MakeHttp) -> None:
    soft = b"<html><body>Oops, nothing here.</body></html>"
    site = FakeSite(SITE_PAGES, not_found=lambda path: httpx.Response(200, content=soft))
    router.route(host="example.com").mock(side_effect=site)
    profile = NotFoundProfile([Probe("abcdefghij", 200, soft, len(soft), None)])
    found = await run(make_http(), job(("admin", "login.php", "a", "b", "c", "d"),
                                       profile=profile))
    assert set(found) == {BASE + "admin", BASE + "login.php"}  # a/b/c/d were soft-404s


async def test_recursion_into_directories(router: respx.MockRouter, make_http: MakeHttp) -> None:
    site = FakeSite(SITE_PAGES)
    router.route(host="example.com").mock(side_effect=site)
    found = await run(make_http(), job(("admin", "config.php"), recursion=1))
    assert BASE + "admin/config.php" in found
    found_flat = await run(make_http(), job(("admin", "config.php"), recursion=0))
    assert BASE + "admin/config.php" not in found_flat


async def test_budget_exhaustion_truncates(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE_PAGES))
    words = tuple(f"w{i}" for i in range(50)) + ("login.php",)
    result = await NativeEngine(make_http(budget=10), concurrency=3).run(job(words))
    assert result.truncated
    assert result.notes == ["request budget exhausted: discovery stopped early"]


async def test_network_errors_counted(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE_PAGES, fail={"/broken"}))
    result = await NativeEngine(make_http(max_retries=0), concurrency=2).run(
        job(("broken", "login.php")))
    assert result.errors == 1
    assert result.notes == ["1 request(s) failed (network errors/timeouts)"]
    assert [p.url for p in result.paths] == [BASE + "login.php"]


async def test_listing_detected(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE_PAGES))
    result = await NativeEngine(make_http(), concurrency=2).run(job(("images/", "login.php")))
    assert result.listings == [BASE + "images/"]


def test_word_url_quotes_but_keeps_structure() -> None:
    assert word_url(BASE, "api/v1") == BASE + "api/v1"
    assert word_url(BASE, "my file.txt") == BASE + "my%20file.txt"
    assert word_url(BASE, "~admin") == BASE + "~admin"
    assert word_url("http://example.com/app/", "x") == "http://example.com/app/x"


def test_is_directory() -> None:
    assert is_directory(DiscoveredPath(BASE + "admin", 301, 0, redirect=BASE + "admin/"))
    assert not is_directory(DiscoveredPath(BASE + "admin", 301, 0, redirect=BASE + "login"))
    assert is_directory(DiscoveredPath(BASE + "uploads/", 403, 0))
    assert not is_directory(DiscoveredPath(BASE + "uploads/", 405, 0))
    assert not is_directory(DiscoveredPath(BASE + "file.php", 200, 0))


def test_is_listing_variants() -> None:
    def page(body: str, ctype: str = "text/html") -> HttpResponse:
        return HttpResponse(BASE, 200, (("content-type", ctype),), body.encode())

    assert is_listing(page(LISTING))
    assert is_listing(page("<title>Directory listing for /files/</title>"))  # python http.server
    assert is_listing(page("<html><title>10.10.10.5 - /</title>"))  # IIS
    assert not is_listing(page("<title>Welcome</title>"))
    assert not is_listing(page(LISTING, ctype="text/plain"))
