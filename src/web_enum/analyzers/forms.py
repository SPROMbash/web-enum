"""HTML form analysis. Forms are parsed and judged; they are NEVER submitted.

Pages analysed: the main page plus discovered HTML pages (status 200, not static
files), up to ``forms.max_pages``. A form that appears on many pages (a login
box in the header) is reported once: forms are de-duplicated by action, method
and field names.

Checks (severity per the policy in models.py):

* password field and the action is ``http://``      -> HIGH  (credentials in cleartext)
* password field on an http page, action https      -> MEDIUM (the form itself can be
  tampered with in transit, e.g. its action rewritten)
* password field sent with GET                      -> HIGH  (password in the URL: logs,
  history, Referer)
* action on another origin                          -> MEDIUM with a password, else LOW
* POST form without an anti-CSRF token              -> LOW (heuristic: hidden field
  named like csrf/xsrf/token/nonce...)
* file upload                                       -> INFO (worth testing by hand)
* password field with autocomplete enabled          -> INFO
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from web_enum.errors import BudgetExhaustedError, ModuleError
from web_enum.http import HttpClient, HttpResponse
from web_enum.log import get_logger
from web_enum.models import DiscoveredPath, Finding, Form, FormField, Severity
from web_enum.target import Target

log = get_logger(__name__)

MAX_FORMS_PER_PAGE = 50
_CSRF_NAME = re.compile(
    r"csrf|xsrf|token|nonce|authenticity|__requestverificationtoken|_wpnonce|"
    r"csrfmiddlewaretoken|__viewstate", re.IGNORECASE,
)
_STATIC = re.compile(
    r"\.(js|css|png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|map|zip|gz|tgz|rar|7z|pdf|"
    r"txt|xml|json|csv|mp4|mp3|avi|webm)$", re.IGNORECASE,
)
_OWASP_AUTH = "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
_OWASP_CSRF = ("https://cheatsheetseries.owasp.org/cheatsheets/"
               "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html")


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
class _FormParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: list[Form] = []
        self._current: dict[str, str] | None = None
        self._fields: list[FormField] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "").strip() for k, v in attrs}
        if tag == "form":
            if self._current is not None:  # nested/unclosed <form>: close the previous one
                self._close()
            self._current = values
            self._fields = []
        elif self._current is not None and tag in ("input", "textarea", "select"):
            kind = values.get("type", "text").lower() if tag == "input" else tag
            name = values.get("name") or values.get("id") or ""
            self._fields.append(FormField(name, kind, values.get("autocomplete", "").lower()))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self._close()

    def close(self) -> None:
        super().close()
        if self._current is not None:  # unclosed form at the end of the page
            self._close()

    def _close(self) -> None:
        assert self._current is not None
        attrs = self._current
        action = urldefrag(urljoin(self.page_url, attrs.get("action", "") or "")).url
        method = attrs.get("method", "get").upper()
        if len(self.forms) < MAX_FORMS_PER_PAGE:
            self.forms.append(Form(
                page=self.page_url, action=action,
                method="POST" if method == "POST" else "GET",
                enctype=attrs.get("enctype", "").lower(),
                autocomplete=attrs.get("autocomplete", "").lower(),
                fields=tuple(self._fields),
            ))
        self._current = None
        self._fields = []


def parse_forms(response: HttpResponse) -> list[Form]:
    if not response.is_html:
        return []
    parser = _FormParser(response.url)
    parser.feed(response.text)
    parser.close()
    return parser.forms


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    default = {"http": 80, "https": 443}.get(parts.scheme)
    try:
        port = parts.port or default
    except ValueError:
        port = None
    return parts.scheme, (parts.hostname or ""), port


def _describe(form: Form) -> str:
    names = ", ".join(f"{f.name or '?'}:{f.type}" for f in form.fields[:12])
    return f"<form method={form.method} action={form.action}> fields: {names or '(none)'}"


def check_form(form: Form) -> list[Finding]:
    findings: list[Finding] = []
    page_scheme = urlsplit(form.page).scheme
    action_scheme = urlsplit(form.action).scheme
    evidence = f"On {form.page}: {_describe(form)}"

    def add(id_: str, title: str, severity: Severity, fix: str, *refs: str) -> None:
        findings.append(Finding(id_, title, severity, "forms", form.action, evidence, fix, refs))

    if form.has_password:
        if action_scheme == "http":
            add("form-password-cleartext", "Password submitted over plain HTTP", Severity.HIGH,
                "Serve the login page and its form action over HTTPS only.", _OWASP_AUTH)
        elif page_scheme == "http":
            add("form-password-http-page", "Login form served over plain HTTP", Severity.MEDIUM,
                "Serve the page containing the form over HTTPS too: over HTTP an attacker in "
                "the middle can rewrite the form before the user submits it.", _OWASP_AUTH)
        if form.method == "GET":
            add("form-password-get", "Password sent in the URL (GET form)", Severity.HIGH,
                "Use method=POST: GET puts the password in the URL, so it ends up in server "
                "logs, browser history and Referer headers.", _OWASP_AUTH)
        # Any explicit autocomplete value is a deliberate choice (current-password even
        # helps password managers); only report when nobody decided anything.
        decided = form.autocomplete == "off" or all(
            f.autocomplete for f in form.fields if f.type == "password")
        if not decided:
            add("form-password-autocomplete", "Password field without an autocomplete policy",
                Severity.INFO,
                "Set autocomplete explicitly: 'current-password' / 'new-password' to help "
                "password managers, or 'off' for shared or kiosk computers.")

    cross_origin = _origin(form.action) != _origin(form.page)
    if cross_origin and action_scheme in ("http", "https"):
        add("form-cross-origin-action", "Form submits to another origin",
            Severity.MEDIUM if form.has_password else Severity.LOW,
            "Check that sending this data to that origin is intended; credentials should only "
            "be submitted to the site itself.")

    # A CSRF token protects the site RECEIVING the form; for a third-party action that
    # is not the target, so it is not this target's finding.
    if form.method == "POST" and not cross_origin and not any(
        f.type == "hidden" and _CSRF_NAME.search(f.name) for f in form.fields
    ):
        add("form-no-csrf-token", "POST form without an anti-CSRF token", Severity.LOW,
            "Add a per-session anti-CSRF token (or rely on SameSite cookies plus Origin "
            "checks). Heuristic: no hidden field named like csrf/token/nonce was found.",
            _OWASP_CSRF)

    if form.has_file_upload:
        add("form-file-upload", "File upload form", Severity.INFO,
            "Test it by hand: allowed extensions and content types, where files are stored and "
            "whether they can be executed or served back.",
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload")
    return findings


# --------------------------------------------------------------------------- #
# Module
# --------------------------------------------------------------------------- #
@dataclass
class FormsResult:
    forms: list[Form] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)  # pages analysed
    notes: list[str] = field(default_factory=list)


def candidate_pages(
    target: Target, main_url: str, discovered: Iterable[DiscoveredPath], limit: int
) -> list[str]:
    """Main page first, then discovered pages that may contain HTML."""
    pages = [main_url]
    for path in discovered:
        url = path.url
        if path.status in (301, 302, 303, 307, 308) and path.redirect:
            url = path.redirect
        elif path.status != 200:
            continue
        if _STATIC.search(urlsplit(url).path) or not target.same_origin(url):
            continue
        if url not in pages:
            pages.append(url)
    return pages[:limit]


def analyse_responses(responses: Sequence[HttpResponse]) -> FormsResult:
    """Pure part: parse and judge forms in already-downloaded pages."""
    result = FormsResult()
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for response in responses:
        result.pages.append(response.url)
        for form in parse_forms(response):
            if form.signature in seen:
                continue
            seen.add(form.signature)
            result.forms.append(form)
            result.findings.extend(check_form(form))
    return result


async def run_forms(
    http: HttpClient, target: Target, main: HttpResponse, discovered: Iterable[DiscoveredPath],
    *, max_pages: int,
) -> FormsResult:
    """Fetch candidate pages (GET only, same origin) and analyse their forms."""
    responses = [main]
    notes: list[str] = []
    for url in candidate_pages(target, main.url, discovered, max_pages)[1:]:
        try:
            response = await http.fetch(url, follow_redirects=True)
        except BudgetExhaustedError:
            notes.append("request budget exhausted: not every page was checked for forms")
            break
        except ModuleError as exc:
            notes.append(f"{url}: {exc}")
            continue
        if response.status == 200 and response.is_html:
            responses.append(response)
    result = analyse_responses(responses)
    result.notes.extend(notes)
    log.info("Forms: %d unique form(s) in %d page(s)", len(result.forms), len(result.pages))
    return result
