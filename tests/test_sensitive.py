"""Sensitive files verified by content."""

from __future__ import annotations

import httpx
import pytest
import respx

from tests.conftest import MakeHttp
from tests.fakes import FakeSite
from web_enum.discovery.sensitive import (
    default_sensitive_rules,
    parse_sensitive_rules,
    probe_sensitive,
    verify,
)
from web_enum.discovery.soft404 import NotFoundProfile, Probe
from web_enum.errors import BudgetExhaustedError, ConfigError
from web_enum.http import HttpResponse
from web_enum.models import Severity
from web_enum.target import parse_target

TARGET = parse_target("http://example.com/")
NO_PROFILE = NotFoundProfile([])
RULES = {r.path: r for r in default_sensitive_rules()}


def ok(body: bytes | str, status: int = 200) -> HttpResponse:
    data = body.encode() if isinstance(body, str) else body
    return HttpResponse("http://example.com/x", status, (), data)


def test_bundled_rules_are_valid() -> None:
    assert len(RULES) >= 30
    assert RULES[".git/HEAD"].severity is Severity.HIGH


@pytest.mark.parametrize(
    ("path", "body", "expected"),
    [
        (".git/HEAD", "ref: refs/heads/main\n", True),
        (".git/HEAD", "4b825dc642cb6eb9a060e54bf8d69288fbee4904\n", True),
        (".git/HEAD", "<html>ref: refs/heads/main</html>", False),
        (".env", "APP_KEY=base64:abc\nDB_PASSWORD=s3cret\n", True),
        (".env", "<!DOCTYPE html><html>Welcome</html>", False),
        (".env", "# only a comment\nlowercase=1\n", False),
        ("backup.zip", b"PK\x03\x04\x14\x00\x00\x00", True),
        ("backup.zip", "<html>PK</html>", False),
        ("backup.tar.gz", b"\x1f\x8b\x08\x00", True),
        (".svn/wc.db", b"SQLite format 3\x00", True),
        (".DS_Store", b"\x00\x00\x00\x01Bud1\x00", True),
        ("dump.sql", "-- MySQL dump 10.13\nCREATE TABLE users (", True),
        ("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl", True),
        (".htpasswd", "admin:$apr1$xyz$abcdefghijk\n", True),
        (".htpasswd", "<html>admin:pass</html>", False),
        ("phpinfo.php", "<title>phpinfo()</title>", True),
        ("actuator/env", '{"activeProfiles":[],"propertySources":[]}', True),
        ("crossdomain.xml", '<allow-access-from domain="*" />', True),
        ("crossdomain.xml", '<allow-access-from domain="example.com" />', False),
    ],
)
def test_verify_by_content(path: str, body: bytes | str, expected: bool) -> None:
    assert verify(RULES[path], ok(body), NO_PROFILE) is expected


def test_verify_requires_200() -> None:
    assert not verify(RULES[".git/HEAD"], ok("ref: refs/heads/main", status=403), NO_PROFILE)


def test_verify_rejects_soft_404() -> None:
    body = b"ref: refs/heads/main"  # absurd, but the soft-404 check must win
    profile = NotFoundProfile([Probe("abcdefghij", 200, body, len(body), None)])
    assert not verify(RULES[".git/HEAD"], ok(body), profile)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("path: x\n", "top level must be a list"),
        ("- {path: x, title: t, severity: high, verify: a}\n", "needs exactly the keys"),
        ("- {path: x, title: t, severity: huge, verify: a, fix: f}\n", "'x'"),
        ("- {path: x, title: t, severity: high, verify: '(', fix: f}\n", "'x'"),
    ],
)
def test_parse_rules_rejects(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_sensitive_rules(text)


async def test_probe_finds_only_verified_files(
    router: respx.MockRouter, make_http: MakeHttp
) -> None:
    site = FakeSite({
        "/.git/HEAD": (200, {}, "ref: refs/heads/master\n"),
        "/.env": (200, {"content-type": "text/html"}, "<html><body>Home</body></html>"),
        "/backup.zip": (403, {}, "Forbidden"),
    }, fail={"/id_rsa"})
    router.route(host="example.com").mock(side_effect=site)
    http = make_http(max_retries=0)
    findings, notes = await probe_sensitive(http, TARGET, NO_PROFILE)
    assert [(f.id, f.severity, f.url) for f in findings] == [
        ("sensitive-git-head", Severity.HIGH, "http://example.com/.git/HEAD")]
    assert findings[0].evidence.startswith("HTTP 200, 23 bytes, starts with: 'ref: refs/heads/")
    assert findings[0].recommendation.startswith("Block access to .git/")
    assert notes and notes[0].startswith("id_rsa:")
    assert http.requests_sent == len(RULES)


async def test_probe_paths_relative_to_base(router: respx.MockRouter, make_http: MakeHttp) -> None:
    site = FakeSite({"/app/.env": (200, {}, "SECRET_KEY=abc\n")})
    router.route(host="example.com").mock(side_effect=site)
    findings, _ = await probe_sensitive(make_http(target="http://example.com/app/"),
                                        parse_target("http://example.com/app/"), NO_PROFILE)
    assert [f.url for f in findings] == ["http://example.com/app/.env"]


async def test_probe_budget_exhaustion(router: respx.MockRouter, make_http: MakeHttp) -> None:
    router.route(host="example.com").mock(return_value=httpx.Response(404))
    with pytest.raises(BudgetExhaustedError):
        await probe_sensitive(make_http(budget=3), TARGET, NO_PROFILE)
