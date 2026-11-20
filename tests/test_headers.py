"""Security headers, cookies, CORS and transport checks."""

from __future__ import annotations

import httpx
import pytest
import respx

from tests.conftest import MakeHttp
from web_enum.analyzers.headers import (
    PROBE_ORIGIN,
    analyze_headers,
    parse_csp,
    parse_set_cookie,
    run_headers,
)
from web_enum.http import HttpResponse
from web_enum.models import Finding, Severity
from web_enum.target import parse_target

HTTP = parse_target("http://box.htb/")
HTTPS = parse_target("https://example.com/")

HARDENED = (
    ("content-type", "text/html; charset=utf-8"),
    ("strict-transport-security", "max-age=31536000; includeSubDomains"),
    ("content-security-policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("permissions-policy", "camera=()"),
    ("server", "nginx"),
    ("set-cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"),
)


def page(*headers: tuple[str, str], url: str = "https://example.com/",
         html: bool = True, blocked: str | None = None) -> HttpResponse:
    base = (("content-type", "text/html"),) if html else (("content-type", "application/json"),)
    return HttpResponse(url, 200, base + headers, b"", blocked_redirect=blocked)


def by_id(findings: list[Finding]) -> dict[str, Finding]:
    return {f.id: f for f in findings}


def ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


# --------------------------------------------------------------------------- #
# Whole-page scenarios
# --------------------------------------------------------------------------- #
def test_hardened_https_site_has_no_findings() -> None:
    clean_probe = HttpResponse("https://example.com/", 200, (), b"")
    response = HttpResponse("https://example.com/", 200, HARDENED, b"")
    result = analyze_headers(HTTPS, response, clean_probe)
    assert result.findings == []
    assert "HSTS enabled (max-age=31536000)" in result.passed
    assert "Clickjacking protection (CSP frame-ancestors)" in result.passed
    assert "CORS does not reflect arbitrary origins" in result.passed


def test_typical_htb_box() -> None:
    response = page(
        ("server", "Apache/2.4.52 (Ubuntu)"), ("x-powered-by", "PHP/8.1.2"),
        ("set-cookie", "PHPSESSID=abc; path=/"), url="http://box.htb/",
    )
    found = by_id(analyze_headers(HTTP, response).findings)
    assert set(found) == {
        "cleartext-http", "csp-missing", "clickjacking", "nosniff-missing",
        "referrer-policy-missing", "permissions-policy-missing", "version-disclosure-server",
        "version-disclosure-x-powered-by", "cookie-no-httponly", "cookie-no-samesite",
    }
    assert "hsts-missing" not in found and "cookie-no-secure" not in found  # n/a over HTTP
    assert found["cookie-no-httponly"].severity is Severity.MEDIUM  # PHPSESSID is a session
    assert found["version-disclosure-server"].evidence == "Server: Apache/2.4.52 (Ubuntu)"
    assert found["version-disclosure-x-powered-by"].title == \
        "X-Powered-By header discloses the stack"
    assert all(f.recommendation for f in found.values())


def test_api_responses_are_not_asked_for_csp_or_framing() -> None:
    assert not ids(analyze_headers(HTTPS, page(html=False)).findings) & {
        "csp-missing", "clickjacking"}


# --------------------------------------------------------------------------- #
# Transport / HSTS
# --------------------------------------------------------------------------- #
def test_http_redirecting_to_https_passes() -> None:
    result = analyze_headers(HTTP, page(url="http://box.htb/", blocked="https://box.htb/"))
    assert "cleartext-http" not in ids(result.findings)
    assert "HTTP redirects to HTTPS (https://box.htb/)" in result.passed


@pytest.mark.parametrize(
    "location",
    ["https://box.htb.evil.test/", "https://evil.test/?u=box.htb", "http://box.htb:8080/",
     "javascript:alert(1)"],
)
def test_redirect_elsewhere_is_not_an_https_upgrade(location: str) -> None:
    result = analyze_headers(HTTP, page(url="http://box.htb/", blocked=location))
    assert "cleartext-http" in ids(result.findings)


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "hsts-missing"), ("max-age=300", "hsts-short"), ("includeSubDomains", "hsts-short"),
     ('max-age="31536000"', None)],
)
def test_hsts(value: str | None, expected: str | None) -> None:
    headers = (("strict-transport-security", value),) if value is not None else ()
    found = ids(analyze_headers(HTTPS, page(*headers)).findings)
    assert ({"hsts-missing", "hsts-short"} & found) == ({expected} if expected else set())


# --------------------------------------------------------------------------- #
# CSP and clickjacking
# --------------------------------------------------------------------------- #
def test_parse_csp_first_directive_wins() -> None:
    assert parse_csp("Script-Src 'self'; script-src *; ;img-src data:") == {
        "script-src": ["'self'"], "img-src": ["data:"]}


@pytest.mark.parametrize(
    ("csp", "expected"),
    [
        ("default-src 'self'", set()),
        ("script-src 'self' 'unsafe-inline'", {"csp-unsafe-inline"}),
        ("script-src 'self' 'unsafe-inline' 'nonce-abc123'", set()),  # nonce neutralises it
        ("script-src 'self' 'unsafe-inline' 'sha256-xyz'", set()),
        ("default-src 'self' 'unsafe-eval'", {"csp-unsafe-eval"}),
        ("script-src https: 'self'", {"csp-wildcard-source"}),
        ("default-src *", {"csp-wildcard-source"}),
        ("script-src data: 'unsafe-inline' 'unsafe-eval'",
         {"csp-wildcard-source", "csp-unsafe-inline", "csp-unsafe-eval"}),
        ("frame-ancestors 'none'", {"csp-no-script-restriction"}),
        ("default-src *; script-src 'self'", set()),  # script-src overrides default-src
    ],
)
def test_csp_weaknesses(csp: str, expected: set[str]) -> None:
    found = ids(analyze_headers(HTTPS, page(("content-security-policy", csp))).findings)
    assert {i for i in found if i.startswith("csp-")} == expected


def test_report_only_csp() -> None:
    response = page(("content-security-policy-report-only", "default-src 'self'"))
    found = by_id(analyze_headers(HTTPS, response).findings)
    assert found["csp-report-only"].severity is Severity.INFO
    assert "csp-missing" in found  # report-only does not protect anything


@pytest.mark.parametrize(
    ("headers", "protected"),
    [
        ((("x-frame-options", "DENY"),), True),
        ((("x-frame-options", "sameorigin"),), True),
        ((("content-security-policy", "frame-ancestors 'self'"),), True),
        ((("x-frame-options", "ALLOW-FROM https://a.test"),), False),  # obsolete, ignored
        ((), False),
    ],
)
def test_clickjacking(headers: tuple[tuple[str, str], ...], protected: bool) -> None:
    found = by_id(analyze_headers(HTTPS, page(*headers)).findings)
    assert ("clickjacking" not in found) is protected
    if headers and not protected:
        assert found["clickjacking"].evidence == "X-Frame-Options: ALLOW-FROM https://a.test"


# --------------------------------------------------------------------------- #
# Simple headers and disclosure
# --------------------------------------------------------------------------- #
def test_nosniff_wrong_value_is_reported_with_it() -> None:
    found = by_id(analyze_headers(HTTPS, page(("x-content-type-options", "sniff"))).findings)
    assert found["nosniff-missing"].evidence == "X-Content-Type-Options: sniff"


@pytest.mark.parametrize(
    ("server", "reported"),
    [("Apache", False), ("nginx", False), ("cloudflare", False), ("nginx/1.18.0", True),
     ("Microsoft-IIS/10.0", True), ("Werkzeug/2.2.2 Python/3.10.6", True)],
)
def test_server_version_disclosure(server: str, reported: bool) -> None:
    found = ids(analyze_headers(HTTPS, page(("server", server))).findings)
    assert ("version-disclosure-server" in found) is reported


def test_aspnet_headers_disclosure() -> None:
    response = page(("x-aspnet-version", "4.0.30319"), ("x-aspnetmvc-version", "5.2"))
    found = ids(analyze_headers(HTTPS, response).findings)
    assert {"version-disclosure-x-aspnet-version", "version-disclosure-x-aspnetmvc-version"} <= \
        found


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a=1; Secure; HttpOnly; SameSite=Strict", ("a", True, True, "strict")),
        ("b=2;secure;httponly", ("b", True, True, "")),
        ("c=; Path=/; SameSite = None", ("c", False, False, "none")),
        ("noequals", ("noequals", False, False, "")),
    ],
)
def test_parse_set_cookie(value: str, expected: tuple[str, bool, bool, str]) -> None:
    cookie = parse_set_cookie(value)
    assert cookie is not None
    assert (cookie.name, cookie.secure, cookie.httponly, cookie.samesite) == expected


def test_nameless_cookie_ignored() -> None:
    assert parse_set_cookie("=value; Secure") is None


def test_cookie_findings_are_grouped_and_graded() -> None:
    response = page(
        ("set-cookie", "theme=dark; SameSite=Lax"),
        ("set-cookie", "lang=es; SameSite=Lax"),
        ("set-cookie", "csrftoken=x; Secure; SameSite=Lax"),  # readable by JS on purpose
        ("set-cookie", "track=1; SameSite=None"),
    )
    found = by_id(analyze_headers(HTTPS, response).findings)
    assert found["cookie-no-httponly"].evidence == "Cookies: lang, theme, track"
    assert found["cookie-no-httponly"].severity is Severity.LOW  # no session cookie among them
    assert found["cookie-no-secure"].evidence == "Cookies: lang, theme, track"
    assert found["cookie-samesite-none-insecure"].evidence == "Cookies: track"
    assert "cookie-no-samesite" not in found


def test_session_cookie_without_secure_on_https_is_medium() -> None:
    response = page(("set-cookie", "JSESSIONID=1; HttpOnly; SameSite=Lax"))
    found = by_id(analyze_headers(HTTPS, response).findings)
    assert found["cookie-no-secure"].severity is Severity.MEDIUM
    assert "cookie-no-httponly" not in found


# --------------------------------------------------------------------------- #
# CORS
# --------------------------------------------------------------------------- #
def probe(*headers: tuple[str, str]) -> HttpResponse:
    return HttpResponse("https://example.com/", 200, headers, b"")


def test_cors_reflection_with_credentials_is_high() -> None:
    response = probe(("access-control-allow-origin", PROBE_ORIGIN),
                     ("access-control-allow-credentials", "true"))
    found = by_id(analyze_headers(HTTPS, page(), response).findings)
    finding = found["cors-reflected-origin-credentials"]
    assert finding.severity is Severity.HIGH
    assert finding.evidence.startswith(f"Request with Origin: {PROBE_ORIGIN} ->")


def test_cors_reflection_without_credentials_is_medium() -> None:
    response = probe(("access-control-allow-origin", PROBE_ORIGIN))
    found = by_id(analyze_headers(HTTPS, page(), response).findings)
    assert found["cors-reflected-origin"].severity is Severity.MEDIUM


def test_cors_wildcard_with_credentials() -> None:
    response = page(("access-control-allow-origin", "*"),
                    ("access-control-allow-credentials", "TRUE"))
    found = by_id(analyze_headers(HTTPS, response, probe()).findings)
    assert found["cors-wildcard-credentials"].severity is Severity.LOW


def test_cors_public_wildcard_is_fine() -> None:
    response = probe(("access-control-allow-origin", "*"))  # public API: legitimate
    result = analyze_headers(HTTPS, page(), response)
    assert not {i for i in ids(result.findings) if i.startswith("cors")}
    assert "CORS does not reflect arbitrary origins" in result.passed


def test_no_cors_claim_without_probe() -> None:
    result = analyze_headers(HTTPS, page())
    assert "CORS does not reflect arbitrary origins" not in result.passed


# --------------------------------------------------------------------------- #
# The module (one probe request)
# --------------------------------------------------------------------------- #
async def test_run_headers_sends_one_probe(router: respx.MockRouter, make_http: MakeHttp) -> None:
    route = router.get("http://example.com/").mock(return_value=httpx.Response(
        200, headers={"Access-Control-Allow-Origin": PROBE_ORIGIN,
                      "Access-Control-Allow-Credentials": "true"}))
    http = make_http()
    main = page(url="http://example.com/")
    result = await run_headers(http, parse_target("http://example.com/"), main)
    assert route.call_count == 1 and http.requests_sent == 1
    assert route.calls[0].request.headers["Origin"] == PROBE_ORIGIN
    assert "cors-reflected-origin-credentials" in ids(result.findings)
    assert result.notes == []


async def test_run_headers_survives_probe_failure(
    router: respx.MockRouter, make_http: MakeHttp
) -> None:
    router.get("http://example.com/").mock(side_effect=httpx.ConnectError("refused"))
    result = await run_headers(make_http(max_retries=0), parse_target("http://example.com/"),
                               page(url="http://example.com/"))
    assert result.notes == ["CORS probe request failed: CORS checked passively only"]
    assert "csp-missing" in ids(result.findings)  # the rest of the analysis still ran
