"""Scan orchestration: planning, isolation of modules, partial results, prioritisation."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from tests.fakes import FakeClock, FakeRunner, FakeSite
from web_enum import runner as runner_mod
from web_enum.config import Config, load_config
from web_enum.discovery.wordlist import Wordlist
from web_enum.errors import ConfigError, TargetUnreachableError, ToolNotFoundError
from web_enum.models import Finding, Severity
from web_enum.ratelimit import RateLimiter
from web_enum.runner import (
    ScanPlan,
    ScanState,
    build_report,
    limits_summary,
    parse_modules,
    plan_scan,
    prioritise,
    run_scan,
)
from web_enum.target import parse_target

TARGET = parse_target("http://example.com/")
NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)

HOME = """<html><head><title>Acme</title>
<meta name="generator" content="WordPress 6.4.2"></head>
<body><form method="post" action="/login.php"><input type="password" name="p"></form></body>
</html>"""
SITE = {
    "/": (200, {"content-type": "text/html", "server": "Apache/2.4.52 (Ubuntu)",
                "set-cookie": "PHPSESSID=abc; path=/"}, HOME),
    "/.git/HEAD": (200, {}, "ref: refs/heads/main\n"),
    "/upload.php": (200, {"content-type": "text/html"},
                    '<form method="post" enctype="multipart/form-data">'
                    '<input type="file" name="f"></form>'),
}
WHATWEB_JSON = '[{"plugins":{"Apache":{"version":["2.4.52"]},"WordPress":{"version":["6.4.2"]}}}]'


def finder(available: dict[str, str]) -> Any:
    def find(name: str, paths: Mapping[str, str]) -> str | None:
        return available.get(name)
    return find


@pytest.fixture()
def config() -> Config:
    cfg = load_config(search_user_config=False)
    return replace(cfg, discovery=replace(cfg.discovery, soft404_probes=2))


@pytest.fixture()
def wordlist() -> Wordlist:
    return Wordlist("/tmp/words.txt", ("upload.php", "nothing"))  # no extensions configured


def plan(wordlist: Wordlist | None, *,
         modules: tuple[str, ...] = ("fingerprint", "headers", "discovery", "forms"),
         whatweb: str | None = None) -> ScanPlan:
    return ScanPlan(modules=modules, skipped={}, whatweb=whatweb, discovery_engine="native",
                    discovery_tool=None, wordlist=wordlist)


def fast_limiter() -> RateLimiter:
    clock = FakeClock()
    return RateLimiter(rate=100, concurrency=5, max_requests=1000, clock=clock, sleep=clock.sleep)


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #
def test_plan_defaults(config: Config) -> None:
    p = plan_scan(config, find=finder({"whatweb": "/usr/bin/whatweb", "ffuf": "/usr/bin/ffuf"}))
    assert p.modules == ("fingerprint", "headers", "discovery", "forms")
    assert p.whatweb == "/usr/bin/whatweb"
    assert (p.discovery_engine, p.discovery_tool) == ("ffuf", "/usr/bin/ffuf")
    assert p.wordlist is not None and p.wordlist.words  # bundled or a system list
    assert p.skipped == {}


def test_plan_bad_wordlist_fails_before_any_request(config: Config, tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing usable\n", encoding="utf-8")
    cfg = replace(config, discovery=replace(config.discovery, wordlist=str(empty)))
    with pytest.raises(ConfigError, match="no usable entries"):
        plan_scan(cfg, find=finder({}))
    # ...but it is not even loaded when discovery will not run
    assert plan_scan(cfg, skip={"discovery"}, find=finder({})).wordlist is None


def test_plan_only_skip_and_config(config: Config) -> None:
    p = plan_scan(config, only={"headers", "forms"}, find=finder({}))
    assert p.modules == ("headers", "forms")
    assert p.skipped["discovery"] == "not selected (--only)"
    assert p.discovery_engine == "" and p.whatweb is None  # nothing resolved for unused modules

    p = plan_scan(config, skip={"discovery"}, find=finder({}))
    assert p.skipped == {"discovery": "skipped (--skip)"}

    disabled = replace(config, modules={**config.modules, "forms": False})
    p = plan_scan(disabled, find=finder({}))
    assert p.skipped == {"forms": "disabled in config (modules)"}
    # --only overrides the config switches: asking explicitly means "run it"
    assert plan_scan(disabled, only={"forms"}, find=finder({})).modules == ("forms",)


def test_plan_nothing_to_run(config: Config) -> None:
    with pytest.raises(ConfigError, match="No module left"):
        plan_scan(config, only={"forms"}, skip={"forms"}, find=finder({}))


def test_plan_native_fingerprint_never_looks_for_whatweb(config: Config) -> None:
    cfg = replace(config, tools=replace(config.tools, fingerprint="native"))
    assert plan_scan(cfg, find=finder({"whatweb": "/usr/bin/whatweb"})).whatweb is None


def test_plan_explicit_whatweb_missing(config: Config) -> None:
    cfg = replace(config, tools=replace(config.tools, fingerprint="whatweb"))
    with pytest.raises(ToolNotFoundError, match="sudo apt install whatweb"):
        plan_scan(cfg, find=finder({}))


@pytest.mark.parametrize(("text", "expected"),
                         [(None, None), ("Headers, forms", {"headers", "forms"})])
def test_parse_modules(text: str | None, expected: set[str] | None) -> None:
    assert parse_modules(text, "--only") == expected


@pytest.mark.parametrize("text", ["exploit", " , ", "headers,sqli"])
def test_parse_modules_rejects(text: str) -> None:
    with pytest.raises(ConfigError, match="--skip: unknown module"):
        parse_modules(text, "--skip")


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #
async def test_full_scan(router: respx.MockRouter, raw_client: httpx.AsyncClient,
                         config: Config, wordlist: Wordlist) -> None:
    site = FakeSite(SITE)
    router.route(host="example.com").mock(side_effect=site)
    whatweb = FakeRunner(files={"--log-json=": WHATWEB_JSON})
    state = ScanState()
    await run_scan(TARGET, config, plan(wordlist, whatweb="/usr/bin/whatweb"), state,
                   client=raw_client, runner=whatweb, limiter=fast_limiter())
    report = build_report(TARGET, config, plan(wordlist), state,
                          authorization="--authorized given by the user", now=NOW)

    assert [(m.name, m.status) for m in report.modules] == [
        ("fingerprint", "ok"), ("headers", "ok"), ("discovery", "ok"), ("forms", "ok")]
    assert report.title == "Acme" and report.status == 200 and not report.partial
    assert report.generated == "2026-11-20T12:00:00+00:00"
    techs = {t.name: t for t in report.technologies}
    assert techs["WordPress"].sources == ("native", "whatweb")
    assert techs["Apache HTTP Server"].version == "2.4.52"
    assert [p.url for p in report.paths] == ["http://example.com/upload.php"]
    assert len(report.forms) == 2  # login (main page) + upload (discovered page)

    severities = [f.severity.rank for f in report.findings]
    assert severities == sorted(severities)  # most severe first
    assert report.findings[0].severity is Severity.HIGH
    ids = {f.id for f in report.findings}
    assert {"sensitive-git-head", "form-password-cleartext", "version-disclosure-server",
            "cookie-no-httponly", "form-file-upload"} <= ids
    assert report.requests_sent == state.requests_sent > 30
    assert report.discovery_engine == "native" and report.wordlist == wordlist.source
    assert report.severity_counts()["high"] >= 2


async def test_unreachable_target(router: respx.MockRouter, raw_client: httpx.AsyncClient,
                                  config: Config, wordlist: Wordlist) -> None:
    router.route(host="example.com").mock(side_effect=httpx.ConnectError("refused"))
    cfg = replace(config, http=replace(config.http, max_retries=0))
    with pytest.raises(TargetUnreachableError, match="did not answer") as info:
        await run_scan(TARGET, cfg, plan(wordlist), ScanState(), client=raw_client,
                       limiter=fast_limiter())
    assert info.value.exit_code == 5


async def test_a_crashing_module_does_not_stop_the_others(
    router: respx.MockRouter, raw_client: httpx.AsyncClient, config: Config, wordlist: Wordlist,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE))

    async def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("bug in headers")

    monkeypatch.setattr(runner_mod, "run_headers", broken)
    state = ScanState()
    await run_scan(TARGET, config, plan(wordlist), state, client=raw_client,
                   limiter=fast_limiter())
    report = build_report(TARGET, config, plan(wordlist), state, authorization="x")
    status = {m.name: m for m in report.modules}
    assert status["headers"].status == "error"
    assert status["headers"].message == "unexpected RuntimeError: bug in headers"
    assert all(status[n].status == "ok" for n in ("fingerprint", "discovery", "forms"))
    assert "sensitive-git-head" in {f.id for f in report.findings}


async def test_whatweb_failure_is_a_note(router: respx.MockRouter, raw_client: httpx.AsyncClient,
                                         config: Config, wordlist: Wordlist) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE))
    state = ScanState()
    await run_scan(TARGET, config, plan(wordlist, modules=("fingerprint",), whatweb="/x/whatweb"),
                   state, client=raw_client, limiter=fast_limiter(),
                   runner=FakeRunner(returncode=1, stderr="ruby: not found"))
    fp = state.statuses["fingerprint"]
    assert fp.status == "ok"
    assert fp.notes and "whatweb failed" in fp.notes[0]


async def test_module_error_recorded(router: respx.MockRouter, raw_client: httpx.AsyncClient,
                                     config: Config) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE))
    state = ScanState()
    await run_scan(TARGET, config, plan(None, modules=("discovery", "forms")), state,
                   client=raw_client, limiter=fast_limiter())
    assert state.statuses["discovery"].status == "error"
    assert state.statuses["discovery"].message == "no wordlist in the scan plan"
    assert state.statuses["forms"].status == "ok"  # forms still ran (on the main page)


async def test_forms_without_discovery_uses_main_page(
    router: respx.MockRouter, raw_client: httpx.AsyncClient, config: Config, wordlist: Wordlist,
) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE))
    state = ScanState()
    await run_scan(TARGET, config, plan(wordlist, modules=("forms",)), state,
                   client=raw_client, limiter=fast_limiter())
    assert state.forms is not None and len(state.forms.forms) == 1


async def test_interrupted_scan_keeps_finished_modules(
    router: respx.MockRouter, raw_client: httpx.AsyncClient, config: Config, wordlist: Wordlist,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    router.route(host="example.com").mock(side_effect=FakeSite(SITE))

    async def endless(*args: object, **kwargs: object) -> None:
        await asyncio.Event().wait()  # never finishes, like a long wordlist

    monkeypatch.setattr(runner_mod, "run_discovery", endless)
    state = ScanState()
    task = asyncio.create_task(run_scan(TARGET, config, plan(wordlist), state,
                                        client=raw_client, limiter=fast_limiter()))
    for _ in range(200):  # wait until the quick modules are done
        if {"fingerprint", "headers"} <= set(state.statuses):
            break
        await asyncio.sleep(0.01)
    task.cancel()  # what Ctrl+C does to the running tasks
    with pytest.raises(asyncio.CancelledError):
        await task

    report = build_report(TARGET, config, plan(wordlist), state, authorization="x",
                          partial=True)
    status = {m.name: m.status for m in report.modules}
    assert status == {"fingerprint": "ok", "headers": "ok", "discovery": "interrupted",
                      "forms": "interrupted"}
    assert report.partial and report.findings  # header findings survived
    assert report.title == "Acme"


def test_report_for_skipped_and_not_run_modules(config: Config) -> None:
    p = ScanPlan(modules=("headers",), skipped={"forms": "skipped (--skip)"})
    report = build_report(TARGET, config, p, ScanState(), authorization="x")
    status = {m.name: (m.status, m.message) for m in report.modules}
    assert status["forms"] == ("skipped", "skipped (--skip)")
    assert status["headers"] == ("skipped", "not run")
    assert report.status == 0 and report.final_url == TARGET.url and report.requests_sent == 0


# --------------------------------------------------------------------------- #
# Prioritisation
# --------------------------------------------------------------------------- #
def finding(id_: str, severity: Severity, category: str = "headers", url: str = "u") -> Finding:
    return Finding(id_, id_.title(), severity, category, url, "e", "r")


def test_prioritise_sorts_and_deduplicates() -> None:
    ordered = prioritise([
        finding("b", Severity.INFO), finding("a", Severity.HIGH, "forms"),
        finding("c", Severity.LOW), finding("a", Severity.HIGH, "forms"),
        finding("d", Severity.HIGH, "content"), finding("a", Severity.HIGH, "forms", url="v"),
    ])
    assert [(f.id, f.url) for f in ordered] == [
        ("d", "u"), ("a", "u"), ("a", "v"), ("c", "u"), ("b", "u")]


def test_limits_summary(config: Config) -> None:
    assert limits_summary(config) == "10 concurrent, 20 req/s, budget 5000 requests"
