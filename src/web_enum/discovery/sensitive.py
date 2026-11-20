"""Sensitive files (.git, .env, backups, dumps, keys...) verified by content.

A status code alone proves nothing: many servers answer 200 to everything. A
file is reported only if (1) the status is 200, (2) the response is not the
server's soft-404 page and (3) the body matches the rule's ``verify`` regex.
The body is decoded as latin-1 (a 1:1 byte mapping), so binary signatures such
as ``PK\\x03\\x04`` (zip) or ``SQLite format 3`` can be matched with regexes.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

from web_enum.discovery.soft404 import NotFoundProfile
from web_enum.errors import BudgetExhaustedError, ConfigError, ModuleError
from web_enum.http import HttpClient, HttpResponse
from web_enum.log import get_logger
from web_enum.models import Finding, Severity
from web_enum.target import Target

log = get_logger(__name__)

_KEYS = ("path", "title", "severity", "verify", "fix")


@dataclass(frozen=True)
class SensitiveRule:
    path: str
    title: str
    severity: Severity
    verify: re.Pattern[str]
    fix: str


@lru_cache(maxsize=1)
def default_sensitive_rules() -> tuple[SensitiveRule, ...]:
    text = (resources.files("web_enum").joinpath("data").joinpath("sensitive_paths.yaml")
            .read_text(encoding="utf-8"))
    return parse_sensitive_rules(text)


def parse_sensitive_rules(text: str) -> tuple[SensitiveRule, ...]:
    data = yaml.safe_load(text)
    if not isinstance(data, list):
        raise ConfigError("sensitive paths: top level must be a list")
    return tuple(_rule(item, i) for i, item in enumerate(data))


def _rule(item: Any, index: int) -> SensitiveRule:
    if not isinstance(item, dict) or set(item) != set(_KEYS):
        raise ConfigError(f"sensitive path #{index}: needs exactly the keys {', '.join(_KEYS)}")
    try:
        severity = Severity(str(item["severity"]))
        verify = re.compile(str(item["verify"]))
    except (ValueError, re.error) as exc:
        raise ConfigError(f"sensitive path '{item['path']}': {exc}") from None
    return SensitiveRule(str(item["path"]).lstrip("/"), str(item["title"]), severity, verify,
                         str(item["fix"]))


def verify(rule: SensitiveRule, response: HttpResponse, profile: NotFoundProfile) -> bool:
    if response.status != 200:
        return False
    if profile.matches_response(rule.path, response):
        return False
    return bool(rule.verify.search(response.body.decode("latin-1")))


def _evidence(response: HttpResponse) -> str:
    preview = response.body[:80].decode("utf-8", errors="replace")
    printable = "".join(c if c.isprintable() else "." for c in preview)
    return f"HTTP 200, {len(response.body)} bytes, starts with: {printable!r}"


async def probe_sensitive(
    http: HttpClient, target: Target, profile: NotFoundProfile,
    rules: tuple[SensitiveRule, ...] | None = None,
) -> tuple[list[Finding], list[str]]:
    """Request every rule's path; return verified findings and notes."""
    rules = default_sensitive_rules() if rules is None else rules
    notes: list[str] = []

    async def one(rule: SensitiveRule) -> Finding | None:
        url = target.join(rule.path)
        try:
            response = await http.fetch(url)
        except BudgetExhaustedError:
            raise
        except ModuleError as exc:
            notes.append(f"{rule.path}: {exc}")
            return None
        if not verify(rule, response, profile):
            return None
        log.warning("Sensitive file: %s (%s)", url, rule.title)
        return Finding(
            id=f"sensitive-{re.sub(r'[^a-z0-9]+', '-', rule.path.lower()).strip('-')}",
            title=rule.title, severity=rule.severity, category="content", url=url,
            evidence=_evidence(response), recommendation=rule.fix,
        )

    results = await asyncio.gather(*(one(rule) for rule in rules))
    return [f for f in results if f is not None], notes
