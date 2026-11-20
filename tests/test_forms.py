"""Form parsing and checks. Forms are never submitted: tests assert only GETs happen."""

from __future__ import annotations

from pathlib import Path

import respx

from tests.conftest import MakeHttp
from tests.fakes import FakeSite
from web_enum.analyzers.forms import (
    analyse_responses,
    candidate_pages,
    check_form,
    parse_forms,
    run_forms,
)
from web_enum.http import HttpResponse
from web_enum.models import DiscoveredPath, Finding, Form, FormField, Severity
from web_enum.target import parse_target

HTML = (("content-type", "text/html; charset=utf-8"),)
TARGET = parse_target("http://example.com/")


def html_page(url: str, body: str) -> HttpResponse:
    return HttpResponse(url, 200, HTML, body.encode())


def form(page: str = "https://example.com/login", action: str = "https://example.com/login",
         method: str = "POST", *fields: FormField, autocomplete: str = "") -> Form:
    return Form(page, action, method, autocomplete=autocomplete, fields=fields)


PASSWORD = FormField("password", "password")
TOKEN = FormField("csrf", "hidden")


def ids(findings: list[Finding]) -> set[str]:
    return {f.id for f in findings}


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def test_parse_realistic_page(fixtures_dir: Path) -> None:
    body = (fixtures_dir / "forms_page.html").read_text(encoding="utf-8")
    forms = parse_forms(html_page("http://example.com/portal/index.php", body))
    assert [(f.method, f.action) for f in forms] == [
        ("POST", "http://example.com/login.php"),  # fragment dropped
        ("GET", "http://example.com/portal/index.php"),  # no action = this page
        ("POST", "http://example.com/portal/upload.php"),
        ("POST", "https://newsletter.example.net/subscribe"),
        ("GET", "http://example.com/legacy-login"),  # unclosed form still parsed
    ]
    login, search, upload, _, legacy = forms
    assert login.has_password and not login.has_file_upload
    assert [f.type for f in login.fields] == ["hidden", "text", "password"]
    assert search.fields == (FormField("q", "search"),)
    assert upload.has_file_upload and upload.enctype == "multipart/form-data"
    assert [(f.name, f.type) for f in upload.fields] == [
        ("avatar", "file"), ("comment", "textarea"), ("visibility", "select")]
    assert legacy.has_password


def test_nested_forms_are_split() -> None:
    forms = parse_forms(html_page("http://example.com/",
                                  "<form action=a><input name=x><form action=b><input name=y>"))
    assert [(f.action.rsplit("/", 1)[-1], [x.name for x in f.fields]) for f in forms] == [
        ("a", ["x"]), ("b", ["y"])]


def test_inputs_outside_forms_ignored_and_non_html_skipped() -> None:
    assert parse_forms(html_page("http://example.com/", "<input type=password name=p>")) == []
    json = HttpResponse("http://example.com/", 200, (("content-type", "application/json"),),
                        b'"<form></form>"')
    assert parse_forms(json) == []


def test_form_limit_per_page() -> None:
    forms = parse_forms(html_page("http://example.com/", "<form></form>" * 80))
    assert len(forms) == 50


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def test_safe_login_form_has_no_findings() -> None:
    safe = form("https://example.com/login", "https://example.com/login", "POST", TOKEN,
                FormField("password", "password", "current-password"))
    assert check_form(safe) == []


def test_password_over_http_action_is_high() -> None:
    findings = {f.id: f for f in check_form(
        form("http://box.htb/", "http://box.htb/login.php", "POST", TOKEN, PASSWORD))}
    assert findings["form-password-cleartext"].severity is Severity.HIGH
    assert "form-password-http-page" not in findings  # one finding, not two, for the same risk
    assert findings["form-password-cleartext"].url == "http://box.htb/login.php"
    assert "password:password" in findings["form-password-cleartext"].evidence


def test_http_page_posting_to_https_is_medium() -> None:
    findings = {f.id: f for f in check_form(
        form("http://example.com/", "https://example.com/login", "POST", TOKEN, PASSWORD))}
    assert findings["form-password-http-page"].severity is Severity.MEDIUM
    assert "form-password-cleartext" not in findings
    # http://example.com -> https://example.com is a different origin (scheme), reported too
    assert findings["form-cross-origin-action"].severity is Severity.MEDIUM


def test_password_in_get_is_high() -> None:
    found = {f.id: f for f in check_form(form("https://example.com/", "https://example.com/",
                                              "GET", PASSWORD))}
    assert found["form-password-get"].severity is Severity.HIGH
    assert "form-no-csrf-token" not in found  # CSRF tokens are a POST concern


def test_autocomplete_policy() -> None:
    assert "form-password-autocomplete" in ids(check_form(form("https://e.test/", "https://e.test/",
                                                               "POST", TOKEN, PASSWORD)))
    off = form("https://e.test/", "https://e.test/", "POST", TOKEN, PASSWORD, autocomplete="off")
    assert "form-password-autocomplete" not in ids(check_form(off))


def test_cross_origin_action_without_password_is_low() -> None:
    found = {f.id: f for f in check_form(form(
        "https://example.com/", "https://newsletter.example.net/s", "POST",
        FormField("email", "email")))}
    assert found["form-cross-origin-action"].severity is Severity.LOW
    # no CSRF finding: the token would protect the third party, not this target
    assert "form-no-csrf-token" not in found


def test_same_origin_with_default_port_is_not_cross_origin() -> None:
    same = form("https://example.com/a", "https://example.com:443/b", "POST", TOKEN)
    assert check_form(same) == []
    odd = form("https://example.com/a", "javascript:void(0)", "POST", TOKEN)
    assert "form-cross-origin-action" not in ids(check_form(odd))
    bad_port = form("https://example.com/a", "https://example.com:99999/b", "POST", TOKEN)
    assert "form-cross-origin-action" in ids(check_form(bad_port))  # unparsable port: differs


def test_csrf_token_heuristics() -> None:
    for name in ("csrfmiddlewaretoken", "_token", "authenticity_token",
                 "__RequestVerificationToken", "_wpnonce", "__VIEWSTATE"):
        with_token = form("https://e.test/", "https://e.test/", "POST", FormField(name, "hidden"))
        assert "form-no-csrf-token" not in ids(check_form(with_token)), name
    visible = form("https://e.test/", "https://e.test/", "POST", FormField("token", "text"))
    assert "form-no-csrf-token" in ids(check_form(visible))  # must be a hidden field


def test_file_upload_is_info() -> None:
    upload = form("https://e.test/", "https://e.test/up", "POST", TOKEN, FormField("f", "file"))
    found = {f.id: f for f in check_form(upload)}
    assert found["form-file-upload"].severity is Severity.INFO


# --------------------------------------------------------------------------- #
# Pages and the module
# --------------------------------------------------------------------------- #
def test_candidate_pages() -> None:
    discovered = [
        DiscoveredPath("http://example.com/login.php", 200, 10),
        DiscoveredPath("http://example.com/admin", 301, 0, redirect="http://example.com/admin/"),
        DiscoveredPath("http://example.com/app.js", 200, 10),
        DiscoveredPath("http://example.com/secret/", 403, 10),
        DiscoveredPath("http://example.com/out", 302, 0, redirect="https://sso.example.net/"),
        DiscoveredPath("http://example.com/login.php", 200, 10),
    ]
    assert candidate_pages(TARGET, "http://example.com/", discovered, 10) == [
        "http://example.com/", "http://example.com/login.php", "http://example.com/admin/"]
    assert candidate_pages(TARGET, "http://example.com/", discovered, 2) == [
        "http://example.com/", "http://example.com/login.php"]


def test_same_form_on_many_pages_reported_once() -> None:
    box = '<form method=post action="/login"><input type=password name=p></form>'
    result = analyse_responses([html_page("http://example.com/", box),
                                html_page("http://example.com/about", box)])
    assert len(result.forms) == 1
    assert result.pages == ["http://example.com/", "http://example.com/about"]
    assert sum(f.id == "form-password-cleartext" for f in result.findings) == 1


async def test_run_forms_only_reads(router: respx.MockRouter, make_http: MakeHttp,
                                    fixtures_dir: Path) -> None:
    body = (fixtures_dir / "forms_page.html").read_text(encoding="utf-8")
    site = FakeSite({
        "/login.php": (200, {"content-type": "text/html"}, body),
        "/broken": (200, {"content-type": "text/html"}, ""),
        "/data": (200, {"content-type": "application/json"}, "{}"),
    }, fail={"/broken"})
    route = router.route(host="example.com").mock(side_effect=site)
    main = html_page("http://example.com/", "<p>no forms here</p>")
    discovered = [DiscoveredPath(f"http://example.com{p}", 200, 1)
                  for p in ("/login.php", "/broken", "/data")]
    result = await run_forms(make_http(max_retries=0), TARGET, main, discovered, max_pages=10)

    assert {call.request.method for call in route.calls} == {"GET"}  # never submitted
    assert result.pages == ["http://example.com/", "http://example.com/login.php"]
    assert len(result.forms) == 5
    found = ids(result.findings)
    assert {"form-password-cleartext", "form-password-get", "form-no-csrf-token",
            "form-file-upload", "form-cross-origin-action"} <= found
    assert result.notes and result.notes[0].startswith("http://example.com/broken:")


async def test_run_forms_stops_on_budget(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite())
    discovered = [DiscoveredPath(f"http://example.com/p{i}", 200, 1) for i in range(5)]
    result = await run_forms(make_http(budget=2), TARGET, html_page("http://example.com/", ""),
                             discovered, max_pages=10)
    assert result.notes == ["request budget exhausted: not every page was checked for forms"]
