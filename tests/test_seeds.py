"""robots.txt and sitemap.xml seeds."""

from __future__ import annotations

import pytest
import respx

from tests.conftest import MakeHttp
from tests.fakes import FakeSite
from web_enum.discovery.seeds import MAX_SEEDS, Seeds, collect_seeds, parse_robots, parse_sitemap
from web_enum.errors import BudgetExhaustedError, ModuleError
from web_enum.target import parse_target

TARGET = parse_target("http://example.com/")

ROBOTS = """\
this line is garbage without a colon
User-agent: *
Disallow: /admin-secret/   # do not crawl
Disallow: /backup/*.zip$
Disallow: /
Allow: /public/
Disallow:
Disallow: relative-ignored
Crawl-delay: 10
Sitemap: http://example.com/sitemap_index.xml
Sitemap: http://cdn.example.net/other.xml
Sitemap: http://example.com/sitemap-pages.xml
"""

URLSET = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://example.com/about</loc></url>
  <url><loc> http://example.com/blog/post-1 </loc></url>
  <url><loc>https://elsewhere.test/page</loc></url>
  <url><loc></loc></url>
</urlset>"""

INDEX = b"""<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>http://example.com/sitemap-pages.xml</loc></sitemap>
</sitemapindex>"""


def test_parse_robots() -> None:
    paths, sitemaps = parse_robots(ROBOTS)
    assert paths == ["/admin-secret/", "/backup/", "/public/"]
    assert sitemaps == ["http://example.com/sitemap_index.xml", "http://cdn.example.net/other.xml",
                        "http://example.com/sitemap-pages.xml"]


def test_parse_sitemap_urlset_and_index() -> None:
    pages, nested = parse_sitemap(URLSET)
    assert pages == ["http://example.com/about", "http://example.com/blog/post-1",
                     "https://elsewhere.test/page"]
    assert nested == []
    assert parse_sitemap(INDEX) == ([], ["http://example.com/sitemap-pages.xml"])


def test_parse_sitemap_invalid() -> None:
    with pytest.raises(ModuleError, match="invalid sitemap XML"):
        parse_sitemap(b"<html><body>not xml")


def test_sitemap_external_entities_are_not_resolved() -> None:
    xxe = (b'<?xml version="1.0"?><!DOCTYPE u [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
           b"<urlset><url><loc>&e;</loc></url></urlset>")
    try:
        pages, _ = parse_sitemap(xxe)
    except ModuleError:
        return  # refused outright: also safe
    assert all("root:" not in page for page in pages)


def test_seed_limit_and_origin() -> None:
    seeds = Seeds()
    seeds.add(TARGET, "https://example.com/x", "sitemap")
    assert seeds.off_origin == 1 and not seeds.paths
    for i in range(MAX_SEEDS + 10):
        seeds.add(TARGET, f"/p{i}", "robots.txt")
    assert len(seeds.paths) == MAX_SEEDS


async def test_collect_seeds_end_to_end(router: respx.MockRouter, make_http: MakeHttp) -> None:
    site = FakeSite({
        "/robots.txt": (200, {"content-type": "text/plain"}, ROBOTS),
        "/sitemap_index.xml": (200, {"content-type": "application/xml"}, INDEX),
        "/sitemap-pages.xml": (200, {"content-type": "application/xml"}, URLSET),
        "/sitemap.xml": (200, {"content-type": "text/html"}, "<html>soft 200</html>"),
    })
    router.route(host="example.com").mock(side_effect=site)
    seeds = await collect_seeds(make_http(), TARGET)
    assert seeds.robots_found
    assert seeds.paths == {
        "http://example.com/admin-secret/": "robots.txt",
        "http://example.com/backup/": "robots.txt",
        "http://example.com/public/": "robots.txt",
        "http://example.com/about": "sitemap",
        "http://example.com/blog/post-1": "sitemap",
    }
    # sitemap-pages.xml is listed in robots.txt AND in the index: fetched only once
    assert seeds.sitemaps == ["http://example.com/sitemap_index.xml",
                              "http://example.com/sitemap-pages.xml"]
    assert site.requests.count("/sitemap-pages.xml") == 1
    assert seeds.off_origin == 2  # cdn sitemap + elsewhere.test page, never requested
    assert "/other.xml" not in site.requests
    assert seeds.notes == ["2 seed URL(s) on other origins ignored"]


async def test_no_robots_no_sitemap(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite())
    seeds = await collect_seeds(make_http(), TARGET)
    assert not seeds.robots_found and not seeds.paths and seeds.notes == []


async def test_broken_sitemap_and_network_error_noted(
    router: respx.MockRouter, make_http: MakeHttp
) -> None:
    site = FakeSite({"/sitemap.xml": (200, {"content-type": "application/xml"}, "<urlset")},
                    fail={"/robots.txt"})
    router.route(host="example.com").mock(side_effect=site)
    seeds = await collect_seeds(make_http(max_retries=0), TARGET)
    assert any(n.startswith("/robots.txt:") for n in seeds.notes)
    assert any("invalid sitemap XML" in n for n in seeds.notes)


async def test_budget_exhaustion_propagates(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite())
    with pytest.raises(BudgetExhaustedError):
        await collect_seeds(make_http(budget=1), TARGET)


async def test_robots_html_is_ignored(router: respx.MockRouter, make_http: MakeHttp) -> None:
    site = FakeSite({"/robots.txt": (200, {"content-type": "text/html"},
                                     "<html>Disallow: /fake</html>")})
    router.route(host="example.com").mock(side_effect=site)
    seeds = await collect_seeds(make_http(), TARGET)
    assert not seeds.robots_found and not seeds.paths
