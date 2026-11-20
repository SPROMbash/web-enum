"""Security headers, cookies, CORS and transport analysis.

Every check is a pure function ``(response) -> findings``, so each one is tested
in isolation with hand-made responses. The only extra traffic is one CORS probe:
a normal GET of the same page with ``Origin: https://web-enum.invalid`` (the
``.invalid`` TLD is reserved by RFC 2606 and can never exist) to see whether the
server reflects arbitrary origins.

Scope of the checks is deliberately conservative: each finding is something a
tester would actually put in a report, with a concrete recommendation. Headers
that only matter for HTML (CSP, clickjacking) are not demanded from APIs.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from web_enum.errors import InvalidTargetError, ModuleError
from web_enum.http import HttpClient, HttpResponse
from web_enum.log import get_logger
from web_enum.models import Finding, Severity
from web_enum.target import Target, parse_target

log = get_logger(__name__)

PROBE_ORIGIN = "https://web-enum.invalid"
HSTS_MIN_AGE = 15_552_000  # 180 days: the usual minimum recommendation
_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
_SESSION_COOKIE = re.compile(
    r"sess|sid$|^sid|token|auth|jwt|remember|login|^phpsessid$|^jsessionid$|"
    r"asp\.net_sessionid|\.aspxauth|laravel_session|connect\.sid",
    re.IGNORECASE,
)
_CSRF_COOKIE = re.compile(r"csrf|xsrf", re.IGNORECASE)  # meant to be read by JS
_VERSION = re.compile(r"\d+\.\d+")
_DISCLOSURE_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                       "x-generator", "x-runtime-version")


@dataclass
class HeaderAnalysis:
    findings: list[Finding] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)  # checks the target passed
    notes: list[str] = field(default_factory=list)


def _finding(id_: str, title: str, severity: Severity, category: str, url: str,
             evidence: str, recommendation: str, *refs: str) -> Finding:
    return Finding(id_, title, severity, category, url, evidence, recommendation, refs)


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #
def check_transport(target: Target, page: HttpResponse, out: HeaderAnalysis) -> None:
    if target.scheme == "https":
        check_hsts(page, out)
        return
    upgrade = page.blocked_redirect or ""
    if upgrade and _is_https_upgrade(target, upgrade):
        out.passed.append(f"HTTP redirects to HTTPS ({upgrade})")
        return
    out.findings.append(_finding(
        "cleartext-http", "Site served over plain HTTP", Severity.LOW, "transport", page.url,
        "The page is served over http:// and does not redirect to https://",
        "Serve the site only over HTTPS and redirect every HTTP request to it; credentials "
        "and session cookies currently travel in cleartext.",
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
    ))


def _is_https_upgrade(target: Target, location: str) -> bool:
    """True if ``location`` is https:// on the SAME host (compared parsed, not as text:
    'https://box.htb.evil.test' must not count as an upgrade of 'box.htb')."""
    try:
        other = parse_target(location)
    except InvalidTargetError:
        return False
    return other.scheme == "https" and other.host == target.host


def check_hsts(page: HttpResponse, out: HeaderAnalysis) -> None:
    value = page.header("strict-transport-security")
    if value is None:
        out.findings.append(_finding(
            "hsts-missing", "Strict-Transport-Security header missing", Severity.LOW,
            "headers", page.url, "No Strict-Transport-Security header on an HTTPS page",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' so browsers "
            "never downgrade to HTTP.", _MDN + "Strict-Transport-Security",
        ))
        return
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    age = int(match.group(1)) if match else 0
    if age < HSTS_MIN_AGE:
        out.findings.append(_finding(
            "hsts-short", "HSTS max-age too short", Severity.LOW, "headers", page.url,
            f"Strict-Transport-Security: {value}",
            f"Use a max-age of at least {HSTS_MIN_AGE} seconds (180 days), ideally one year.",
            _MDN + "Strict-Transport-Security",
        ))
    else:
        out.passed.append(f"HSTS enabled (max-age={age})")


# --------------------------------------------------------------------------- #
# Content Security Policy and clickjacking
# --------------------------------------------------------------------------- #
def parse_csp(value: str) -> dict[str, list[str]]:
    """'default-src 'self'; script-src a b' -> {'default-src': ["'self'"], ...}."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives  # first occurrence wins, as browsers do


def check_csp(page: HttpResponse, out: HeaderAnalysis) -> None:
    value = page.header("content-security-policy")
    if value is None:
        report_only = page.header("content-security-policy-report-only")
        if report_only is not None:
            out.findings.append(_finding(
                "csp-report-only", "CSP only in report-only mode", Severity.INFO, "headers",
                page.url, f"Content-Security-Policy-Report-Only: {report_only[:150]}",
                "Report-only policies are not enforced: switch to Content-Security-Policy "
                "once the reports are clean.", _MDN + "Content-Security-Policy-Report-Only",
            ))
        out.findings.append(_finding(
            "csp-missing", "Content-Security-Policy header missing", Severity.LOW, "headers",
            page.url, "No Content-Security-Policy header on an HTML page",
            "Define a restrictive CSP (e.g. default-src 'self'; object-src 'none'; "
            "frame-ancestors 'none') to limit the impact of XSS.",
            _MDN + "Content-Security-Policy", _OWASP_HEADERS,
        ))
        return

    csp = parse_csp(value)
    script = csp.get("script-src", csp.get("default-src"))
    if script is None:
        out.findings.append(_finding(
            "csp-no-script-restriction", "CSP does not restrict scripts", Severity.LOW,
            "headers", page.url, f"Content-Security-Policy: {value[:150]}",
            "Add script-src (or default-src) so the policy actually limits where scripts "
            "come from.", _MDN + "Content-Security-Policy/script-src",
        ))
        return
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                            for s in script)
    weak: list[tuple[str, str, str]] = []
    if "'unsafe-inline'" in script and not has_nonce_or_hash:
        weak.append(("csp-unsafe-inline", "CSP allows inline scripts ('unsafe-inline')",
                     "Remove 'unsafe-inline'; use nonces or hashes for inline scripts."))
    if "'unsafe-eval'" in script:
        weak.append(("csp-unsafe-eval", "CSP allows eval() ('unsafe-eval')",
                     "Remove 'unsafe-eval' and refactor code that relies on eval()."))
    wildcards = [s for s in script if s in ("*", "http:", "https:", "data:")]
    if wildcards:
        weak.append(("csp-wildcard-source",
                     f"CSP allows scripts from any source ({', '.join(wildcards)})",
                     "List the exact hosts that may serve scripts instead of wildcards."))
    for id_, title, fix in weak:
        out.findings.append(_finding(
            id_, title, Severity.LOW, "headers", page.url,
            f"Content-Security-Policy: {value[:150]}", fix, _MDN + "Content-Security-Policy",
        ))
    if not weak:
        out.passed.append("Content-Security-Policy restricts scripts")


def check_clickjacking(page: HttpResponse, out: HeaderAnalysis) -> None:
    raw_xfo = (page.header("x-frame-options") or "").strip()
    xfo = raw_xfo.upper()  # compare normalised, but report what the server sent
    csp = parse_csp(page.header("content-security-policy") or "")
    if "frame-ancestors" in csp:
        out.passed.append("Clickjacking protection (CSP frame-ancestors)")
    elif xfo in ("DENY", "SAMEORIGIN"):
        out.passed.append(f"Clickjacking protection (X-Frame-Options: {xfo})")
    else:
        evidence = (f"X-Frame-Options: {raw_xfo}" if raw_xfo
                    else "No X-Frame-Options nor frame-ancestors")
        out.findings.append(_finding(
            "clickjacking", "No clickjacking protection", Severity.LOW, "headers", page.url,
            evidence,
            "Send 'Content-Security-Policy: frame-ancestors 'none'' (or 'self'), and "
            "X-Frame-Options: DENY for older browsers.",
            "https://owasp.org/www-community/attacks/Clickjacking",
        ))


# --------------------------------------------------------------------------- #
# Simple hardening headers and disclosure
# --------------------------------------------------------------------------- #
def check_simple_headers(page: HttpResponse, out: HeaderAnalysis) -> None:
    nosniff = page.header("x-content-type-options")
    if (nosniff or "").strip().lower() == "nosniff":
        out.passed.append("X-Content-Type-Options: nosniff")
    else:
        out.findings.append(_finding(
            "nosniff-missing", "X-Content-Type-Options: nosniff missing", Severity.LOW,
            "headers", page.url,
            f"X-Content-Type-Options: {nosniff}" if nosniff else "No X-Content-Type-Options header",
            "Add 'X-Content-Type-Options: nosniff' so browsers do not guess content types.",
            _MDN + "X-Content-Type-Options",
        ))
    for header, title, fix in (
        ("referrer-policy", "Referrer-Policy header missing",
         "Add 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter) so URLs with "
         "tokens do not leak to other sites."),
        ("permissions-policy", "Permissions-Policy header missing",
         "Add a Permissions-Policy disabling features the site does not use "
         "(camera=(), microphone=(), geolocation=())."),
    ):
        if page.header(header) is None:
            out.findings.append(_finding(
                f"{header}-missing", title, Severity.INFO, "headers", page.url,
                f"No {header.title()} header", fix, _MDN + header.title(),
            ))
        else:
            out.passed.append(f"{header.title()} set")


def check_disclosure(page: HttpResponse, out: HeaderAnalysis) -> None:
    server = page.header("server")
    if server and _VERSION.search(server):
        out.findings.append(_finding(
            "version-disclosure-server", "Server version disclosed", Severity.LOW,
            "disclosure", page.url, f"Server: {server}",
            "Hide version numbers (Apache: ServerTokens Prod; nginx: server_tokens off; "
            "IIS: removeServerHeader). Versions let attackers look up known CVEs instantly.",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_"
            "Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        ))
    for header in _DISCLOSURE_HEADERS:
        value = page.header(header)
        if value:
            out.findings.append(_finding(
                f"version-disclosure-{header}", f"{header.title()} header discloses the stack",
                Severity.LOW, "disclosure", page.url, f"{header.title()}: {value}",
                f"Remove the {header.title()} header (e.g. PHP: expose_php = Off; "
                "Express: app.disable('x-powered-by')).",
            ))


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Cookie:
    name: str
    secure: bool
    httponly: bool
    samesite: str  # "" if absent, else lower-case value

    @property
    def is_session(self) -> bool:
        return bool(_SESSION_COOKIE.search(self.name))


def parse_set_cookie(value: str) -> Cookie | None:
    first, *attributes = value.split(";")
    name = first.split("=", 1)[0].strip()
    if not name:
        return None
    flags: dict[str, str] = {}
    for attribute in attributes:
        key, _, val = attribute.partition("=")
        flags[key.strip().lower()] = val.strip().lower()
    return Cookie(name=name, secure="secure" in flags, httponly="httponly" in flags,
                  samesite=flags.get("samesite", ""))


def check_cookies(target: Target, page: HttpResponse, out: HeaderAnalysis) -> None:
    cookies = [c for v in page.header_all("set-cookie") if (c := parse_set_cookie(v))]
    if not cookies:
        return
    https = target.scheme == "https"

    def report(id_: str, title: str, selected: list[Cookie], fix: str,
               severity_for: Callable[[list[Cookie]], Severity]) -> None:
        if selected:
            out.findings.append(_finding(
                id_, title, severity_for(selected), "cookies", page.url,
                "Cookies: " + ", ".join(sorted({c.name for c in selected})), fix,
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",
            ))

    def session_medium(selected: list[Cookie]) -> Severity:
        return Severity.MEDIUM if any(c.is_session for c in selected) else Severity.LOW

    report("cookie-no-httponly", "Cookies without HttpOnly",
           [c for c in cookies if not c.httponly and not _CSRF_COOKIE.search(c.name)],
           "Set HttpOnly on session and authentication cookies so XSS cannot steal them.",
           session_medium)
    if https:
        report("cookie-no-secure", "Cookies without Secure on an HTTPS site",
               [c for c in cookies if not c.secure],
               "Set Secure so the cookie is never sent over plain HTTP.", session_medium)
    report("cookie-samesite-none-insecure", "SameSite=None without Secure",
           [c for c in cookies if c.samesite == "none" and not c.secure],
           "SameSite=None requires Secure (browsers reject it otherwise); prefer Lax or Strict.",
           lambda _: Severity.LOW)
    report("cookie-no-samesite", "Cookies without an explicit SameSite attribute",
           [c for c in cookies if not c.samesite],
           "Set SameSite=Lax (or Strict) explicitly as defence in depth against CSRF.",
           lambda _: Severity.INFO)


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #
def check_cors(page: HttpResponse, probe: HttpResponse | None, out: HeaderAnalysis) -> None:
    for response, origin_sent in ((page, None), (probe, PROBE_ORIGIN)):
        if response is None:
            continue
        acao = (response.header("access-control-allow-origin") or "").strip()
        creds = (response.header("access-control-allow-credentials") or "").strip().lower()
        evidence = f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: " \
                   f"{creds or '(absent)'}"
        if origin_sent and acao == origin_sent:
            with_creds = creds == "true"
            out.findings.append(_finding(
                "cors-reflected-origin-credentials" if with_creds else "cors-reflected-origin",
                "CORS reflects arbitrary origins" + (" with credentials" if with_creds else ""),
                Severity.HIGH if with_creds else Severity.MEDIUM, "cors", response.url,
                f"Request with Origin: {origin_sent} -> {evidence}",
                "Validate the Origin against an explicit allow-list; never reflect it. With "
                "credentials, any website can read authenticated responses of this user.",
                "https://portswigger.net/web-security/cors",
            ))
            return
        if acao == "*" and creds == "true":
            out.findings.append(_finding(
                "cors-wildcard-credentials", "CORS wildcard combined with credentials",
                Severity.LOW, "cors", response.url, evidence,
                "Browsers reject '*' with credentials, but it shows a misconfigured CORS "
                "policy: use an explicit allow-list.",
                "https://portswigger.net/web-security/cors",
            ))
            return
    if probe is not None:  # only claim it if we actually tested it
        out.passed.append("CORS does not reflect arbitrary origins")


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def analyze_headers(
    target: Target, page: HttpResponse, cors_probe: HttpResponse | None = None
) -> HeaderAnalysis:
    """Run every check on the main page (pure: no network)."""
    out = HeaderAnalysis()
    check_transport(target, page, out)
    if page.is_html:  # CSP and framing protect documents, not APIs or images
        check_csp(page, out)
        check_clickjacking(page, out)
    check_simple_headers(page, out)
    check_disclosure(page, out)
    check_cookies(target, page, out)
    check_cors(page, cors_probe, out)
    return out


async def run_headers(http: HttpClient, target: Target, page: HttpResponse) -> HeaderAnalysis:
    """The headers module: one CORS probe request, then the pure analysis."""
    probe: HttpResponse | None = None
    try:
        probe = await http.fetch(page.url, headers={"Origin": PROBE_ORIGIN})
    except ModuleError as exc:
        log.warning("CORS probe failed (%s); CORS checked passively only", exc)
    result = analyze_headers(target, page, probe)
    if probe is None:
        result.notes.append("CORS probe request failed: CORS checked passively only")
    return result
