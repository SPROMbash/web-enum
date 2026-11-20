"""Data model: immutable results produced by the modules.

Severity policy (applied consistently by every module, so reports can be sorted
and compared):

* HIGH   — direct exposure that can lead to compromise (exposed .git/.env or
  backups, password sent over HTTP or in a URL, CORS reflecting any origin with
  credentials).
* MEDIUM — a weakness that commonly enables an attack (session cookie without
  HttpOnly / Secure, CORS reflecting any origin, directory listing).
* LOW    — missing hardening or information disclosure (no CSP, no clickjacking
  protection, version in the Server header).
* INFO   — useful observations (missing Referrer-Policy, interesting paths).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 = most severe; used to sort findings."""
        return _RANK[self]


_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


@dataclass(frozen=True)
class Finding:
    id: str  # stable machine id, e.g. "csp-missing"
    title: str
    severity: Severity
    category: str  # headers | cookies | cors | transport | disclosure | content | forms
    url: str
    evidence: str
    recommendation: str
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiscoveredPath:
    url: str
    status: int
    length: int
    words: int = 0
    lines: int = 0
    redirect: str = ""  # Location header, if any
    source: str = ""  # wordlist engine (native / ffuf / feroxbuster), robots, sitemap...


@dataclass(frozen=True)
class FormField:
    name: str
    type: str  # lower-case input type ("text", "password", "hidden", "file", "textarea"...)
    autocomplete: str = ""


@dataclass(frozen=True)
class Form:
    page: str  # URL of the page containing the form
    action: str  # absolute URL the form submits to
    method: str  # "GET" or "POST"
    enctype: str = ""
    autocomplete: str = ""  # form-level autocomplete attribute
    fields: tuple[FormField, ...] = ()

    @property
    def has_password(self) -> bool:
        return any(f.type == "password" for f in self.fields)

    @property
    def has_file_upload(self) -> bool:
        return any(f.type == "file" for f in self.fields)

    @property
    def signature(self) -> tuple[str, str, tuple[str, ...]]:
        """Same action + method + field names = the same form (e.g. a login box on every page)."""
        return self.action, self.method, tuple(sorted(f.name for f in self.fields))


@dataclass(frozen=True)
class Technology:
    name: str
    category: str
    version: str = ""
    evidence: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()  # "native" (our rules) and/or "whatweb"


MODULE_STATUSES = ("ok", "error", "skipped", "interrupted")


@dataclass(frozen=True)
class ModuleStatus:
    name: str
    status: str  # one of MODULE_STATUSES
    duration: float = 0.0
    message: str = ""  # why it failed / was skipped
    notes: tuple[str, ...] = ()  # non-fatal remarks (tool failed, budget hit...)


@dataclass(frozen=True)
class Report:
    target: str  # URL given by the user (normalised)
    final_url: str  # after same-origin redirects
    status: int  # HTTP status of the main page
    title: str
    generated: str  # ISO 8601, UTC
    tool_version: str
    authorization: str  # why the scan was allowed (scope entry or --authorized)
    partial: bool
    limits: str  # human summary of the limits in force
    requests_sent: int
    modules: tuple[ModuleStatus, ...]
    findings: tuple[Finding, ...]  # sorted, most severe first
    technologies: tuple[Technology, ...] = ()
    paths: tuple[DiscoveredPath, ...] = ()
    forms: tuple[Form, ...] = ()
    passed_checks: tuple[str, ...] = ()
    discovery_engine: str = ""
    wordlist: str = ""
    calibration: str = ""

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
