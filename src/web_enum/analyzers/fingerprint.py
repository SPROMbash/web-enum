"""Technology fingerprinting.

Two engines, merged into one list:

* **native** (always on): the page is reduced to :class:`PageSignals` (headers,
  cookie names, generator meta, script URLs, title, HTML) and every rule of
  ``data/tech_rules.yaml`` is tested against it. Free: it reuses the page the
  scan already downloaded, no extra request.
* **whatweb** (Kali / Parrot, optional): far more plugins. See
  :mod:`web_enum.tools.whatweb`. If it is missing or fails, the native result
  stands on its own and the report says why.

Merging is by name (case-insensitive, with aliases for whatweb plugin names), so
"JQuery 3.6.0" from whatweb and "jQuery" from our rules become one entry that
records both sources: two independent engines agreeing raises confidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from html.parser import HTMLParser
from importlib import resources
from typing import Any, Protocol

import yaml

from web_enum.errors import ConfigError, ModuleError
from web_enum.http import HttpResponse
from web_enum.log import get_logger
from web_enum.models import Technology

log = get_logger(__name__)

MAX_HTML = 500_000  # only the first 500 KB of a page are searched
_RULE_KEYS = ("name", "category", "headers", "cookies", "meta", "scripts", "title", "html",
              "implies")


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    headers: tuple[tuple[str, re.Pattern[str]], ...] = ()
    cookies: tuple[re.Pattern[str], ...] = ()
    meta: re.Pattern[str] | None = None
    scripts: re.Pattern[str] | None = None
    title: re.Pattern[str] | None = None
    html: re.Pattern[str] | None = None
    implies: tuple[str, ...] = ()


@dataclass(frozen=True)
class PageSignals:
    url: str
    headers: tuple[tuple[str, str], ...] = ()  # (lower-case name, value)
    cookies: tuple[str, ...] = ()  # cookie names
    generators: tuple[str, ...] = ()
    scripts: tuple[str, ...] = ()
    title: str = ""
    html: str = ""


@dataclass(frozen=True)
class FingerprintResult:
    technologies: tuple[Technology, ...]
    title: str = ""
    notes: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=1)
def default_rules() -> tuple[Rule, ...]:
    text = (
        resources.files("web_enum").joinpath("data").joinpath("tech_rules.yaml")
        .read_text(encoding="utf-8")
    )
    return parse_rules(text)


def parse_rules(text: str) -> tuple[Rule, ...]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"tech rules: invalid YAML ({exc})") from None
    if not isinstance(data, list):
        raise ConfigError("tech rules: top level must be a list")
    rules = tuple(_rule(item, i) for i, item in enumerate(data))
    names = [r.name.lower() for r in rules]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ConfigError(f"tech rules: duplicated names: {', '.join(duplicates)}")
    return rules


def _rule(item: Any, index: int) -> Rule:
    if not isinstance(item, dict) or not isinstance(item.get("name"), str):
        raise ConfigError(f"tech rule #{index}: needs at least a 'name'")
    where = f"tech rule '{item['name']}'"
    unknown = sorted(set(item) - set(_RULE_KEYS))
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(map(str, unknown))}")
    headers = item.get("headers") or {}
    cookies = item.get("cookies") or []
    implies = item.get("implies") or []
    if not isinstance(headers, dict):
        raise ConfigError(f"{where}: 'headers' must be a mapping")
    if not isinstance(cookies, list) or not isinstance(implies, list):
        raise ConfigError(f"{where}: 'cookies' and 'implies' must be lists")
    matchers = ("headers", "cookies", "meta", "scripts", "title", "html")
    if not any(item.get(k) for k in matchers):
        raise ConfigError(f"{where}: needs at least one matcher ({', '.join(matchers)})")
    return Rule(
        name=item["name"],
        category=str(item.get("category", "Other")),
        headers=tuple((str(h).lower(), _compile(p, where)) for h, p in headers.items()),
        cookies=tuple(_compile(f"(?:{c})", where) for c in cookies),
        meta=_compile_opt(item.get("meta"), where),
        scripts=_compile_opt(item.get("scripts"), where),
        title=_compile_opt(item.get("title"), where),
        html=_compile_opt(item.get("html"), where),
        implies=tuple(str(name) for name in implies),
    )


def _compile(pattern: Any, where: str) -> re.Pattern[str]:
    try:
        return re.compile(str(pattern), re.IGNORECASE)
    except re.error as exc:
        raise ConfigError(f"{where}: invalid regex {pattern!r} ({exc})") from None


def _compile_opt(pattern: Any, where: str) -> re.Pattern[str] | None:
    return None if pattern is None else _compile(pattern, where)


# --------------------------------------------------------------------------- #
# Page signals
# --------------------------------------------------------------------------- #
class _PageParser(HTMLParser):
    """Collect generator metas, script URLs and the title. Never executes anything."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.generators: list[str] = []
        self.scripts: list[str] = []
        self.title_parts: list[str] = []
        self._in_title = False
        self._title_done = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta" and values.get("name", "").lower() == "generator":
            if values.get("content"):
                self.generators.append(values["content"].strip())
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"].strip())
        elif tag == "title" and not self._title_done:
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title" and self._in_title:
            self._in_title = False
            self._title_done = True  # only the first <title> counts

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def cookie_names(response: HttpResponse) -> tuple[str, ...]:
    names = []
    for value in response.header_all("set-cookie"):
        name = value.split(";", 1)[0].split("=", 1)[0].strip()
        if name:
            names.append(name)
    return tuple(dict.fromkeys(names))


def page_signals(response: HttpResponse) -> PageSignals:
    html = response.text[:MAX_HTML] if response.is_html or not response.content_type else ""
    parser = _PageParser()
    if html:
        parser.feed(html)
        parser.close()
    title = " ".join("".join(parser.title_parts).split())[:200]
    return PageSignals(
        url=response.url,
        headers=response.headers,
        cookies=cookie_names(response),
        generators=tuple(parser.generators),
        scripts=tuple(parser.scripts),
        title=title,
        html=html,
    )


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def detect(page: PageSignals, rules: Sequence[Rule] | None = None) -> list[Technology]:
    """Apply every rule to the page; add implied technologies."""
    rules = default_rules() if rules is None else rules
    found: dict[str, Technology] = {}
    for rule in rules:
        version = ""
        evidence: list[str] = []

        for header, pattern in rule.headers:
            for name, value in page.headers:
                if name == header and (match := pattern.search(value)):
                    evidence.append(f"header {header}: {value[:80]}")
                    version = version or _version(match)
        for pattern in rule.cookies:
            evidence.extend(f"cookie {c}" for c in page.cookies if pattern.fullmatch(c))
        for label, single, values in (
            ("meta generator", rule.meta, page.generators),
            ("script", rule.scripts, page.scripts),
            ("title", rule.title, (page.title,) if page.title else ()),
        ):
            if single is None:
                continue
            for value in values:
                if match := single.search(value):
                    evidence.append(f"{label}: {value[:100]}")
                    version = version or _version(match)
                    break
        if rule.html and (match := rule.html.search(page.html)):
            evidence.append(f"html: {match.group(0)[:60]}")
            version = version or _version(match)

        if evidence:
            found[rule.name.lower()] = Technology(
                name=rule.name, category=rule.category, version=version,
                evidence=tuple(dict.fromkeys(evidence)), sources=("native",),
            )

    by_name = {r.name.lower(): r for r in rules}
    for tech in list(found.values()):
        for implied in by_name[tech.name.lower()].implies:
            key = implied.lower()
            if key not in found:
                category = by_name[key].category if key in by_name else "Other"
                found[key] = Technology(name=implied, category=category,
                                        evidence=(f"implied by {tech.name}",),
                                        sources=("native",))
    return list(found.values())


def _version(match: re.Match[str]) -> str:
    if "version" in match.re.groupindex:
        return match.group("version") or ""
    return next((group for group in match.groups() if group), "")


# --------------------------------------------------------------------------- #
# Merging and orchestration
# --------------------------------------------------------------------------- #
def merge_technologies(*groups: Iterable[Technology]) -> list[Technology]:
    """Merge by case-insensitive name: union of evidence and sources, best version."""
    merged: dict[str, Technology] = {}
    for tech in (t for group in groups for t in group):
        key = tech.name.lower()
        old = merged.get(key)
        if old is None:
            merged[key] = tech
            continue
        merged[key] = Technology(
            name=old.name,
            category=old.category if old.category != "Other" else tech.category,
            version=_best_version(old.version, tech.version),
            evidence=tuple(dict.fromkeys(old.evidence + tech.evidence)),
            sources=tuple(dict.fromkeys(old.sources + tech.sources)),
        )
    return sorted(merged.values(), key=lambda t: (t.category.lower(), t.name.lower()))


def _best_version(a: str, b: str) -> str:
    """Prefer the more specific version ('2.4.52' over '2.4' over '')."""
    return a if len(a.split(".")) >= len(b.split(".")) and a else b


class TechScanner(Protocol):
    """Anything that can fingerprint a URL (structural type: WhatWeb fits it)."""

    name: str

    async def scan(self, url: str) -> list[Technology]: ...


async def fingerprint(
    page: HttpResponse,
    *,
    external: TechScanner | None = None,
    rules: Sequence[Rule] | None = None,
) -> FingerprintResult:
    """Native rules on ``page`` (already downloaded) + the external scanner, merged."""
    signals = page_signals(page)
    technologies = detect(signals, rules)
    notes: list[str] = []
    if external is not None:
        try:
            technologies.extend(await external.scan(page.url))
        except ModuleError as exc:
            log.warning("%s failed (%s): using native fingerprints only", external.name, exc)
            notes.append(f"{external.name} failed: {exc}; native rules only")
    return FingerprintResult(
        technologies=tuple(merge_technologies(technologies)),
        title=signals.title,
        notes=tuple(notes),
    )
