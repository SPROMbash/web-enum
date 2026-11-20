"""Seeds: paths the site itself publishes in robots.txt and sitemap.xml.

robots.txt ``Disallow`` lines are a classic source of "hidden" paths (it is
public information, and a tester reads it first). Sitemaps list real pages.
Both are parsed defensively:

* robots.txt: only Allow/Disallow/Sitemap lines; wildcards (``*``, ``$``) are
  cut at the first wildcard; at most MAX_SEEDS paths.
* sitemap.xml: ElementTree (Python's expat does not resolve external entities,
  so no XXE), body already capped by the HTTP engine, namespace-agnostic
  ``<loc>`` lookup, nested sitemap indexes followed one level. URLs on other
  origins are ignored (and counted), never requested.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from web_enum.errors import BudgetExhaustedError, ModuleError
from web_enum.http import HttpClient, HttpResponse
from web_enum.log import get_logger
from web_enum.target import Target

log = get_logger(__name__)

MAX_SEEDS = 200
MAX_SITEMAPS = 5


@dataclass
class Seeds:
    paths: dict[str, str] = field(default_factory=dict)  # absolute URL -> source
    robots_found: bool = False
    sitemaps: list[str] = field(default_factory=list)
    off_origin: int = 0
    notes: list[str] = field(default_factory=list)

    def add(self, target: Target, url: str, source: str) -> None:
        if len(self.paths) >= MAX_SEEDS:
            return
        if not target.same_origin(url):
            self.off_origin += 1
            return
        absolute = target.join(url)
        self.paths.setdefault(absolute, source)


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    """Return (paths, sitemap URLs) from a robots.txt body."""
    paths: list[str] = []
    sitemaps: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == "sitemap" and value:
            sitemaps.append(value)
        elif key in ("disallow", "allow") and value.startswith("/"):
            path = value.split("*", 1)[0].split("$", 1)[0]
            if path and path != "/":
                paths.append(path)
    return list(dict.fromkeys(paths)), list(dict.fromkeys(sitemaps))


def parse_sitemap(body: bytes) -> tuple[list[str], list[str]]:
    """Return (page URLs, nested sitemap URLs) from a sitemap or sitemap index."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise ModuleError(f"invalid sitemap XML: {exc}") from None
    pages: list[str] = []
    nested: list[str] = []
    is_index = root.tag.rsplit("}", 1)[-1] == "sitemapindex"
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "loc" and element.text and element.text.strip():
            (nested if is_index else pages).append(element.text.strip())
    return pages, nested


async def collect_seeds(http: HttpClient, target: Target) -> Seeds:
    seeds = Seeds()
    robots_url = target.origin + "/robots.txt"
    sitemap_queue = [target.origin + "/sitemap.xml"]

    robots = await _get(http, robots_url, seeds)
    if robots is not None and robots.status == 200 and not robots.is_html:
        seeds.robots_found = True
        paths, sitemaps = parse_robots(robots.text)
        for path in paths:
            seeds.add(target, path, "robots.txt")
        sitemap_queue = list(dict.fromkeys(sitemaps + sitemap_queue))

    done: set[str] = set()
    while sitemap_queue and len(done) < MAX_SITEMAPS:
        url = sitemap_queue.pop(0)
        if url in done:
            continue
        done.add(url)
        if not target.same_origin(url):
            seeds.off_origin += 1
            continue
        response = await _get(http, url, seeds)
        if response is None or response.status != 200 or response.is_html:
            continue
        try:
            pages, nested = parse_sitemap(response.body)
        except ModuleError as exc:
            seeds.notes.append(f"{url}: {exc}")
            continue
        seeds.sitemaps.append(url)
        for page in pages:
            seeds.add(target, page, "sitemap")
        sitemap_queue.extend(nested)

    if seeds.off_origin:
        seeds.notes.append(f"{seeds.off_origin} seed URL(s) on other origins ignored")
    log.debug("Seeds: %d paths (robots.txt: %s, sitemaps: %d)", len(seeds.paths),
              seeds.robots_found, len(seeds.sitemaps))
    return seeds


async def _get(http: HttpClient, url: str, seeds: Seeds) -> HttpResponse | None:
    try:
        return await http.fetch(url)
    except BudgetExhaustedError:
        raise  # out of budget: the whole discovery must stop, not just this seed
    except ModuleError as exc:
        seeds.notes.append(f"{urlsplit(url).path}: {exc}")
        return None
