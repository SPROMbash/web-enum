"""CLI: commands, ethical gate, options as config, dry run, scan, Ctrl+C, exit codes."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import httpx
import pytest
import respx
import typer
import yaml
from typer.testing import CliRunner

from tests.conftest import WriteConfig
from tests.fakes import FakeSite
from web_enum import __version__, cli
from web_enum.cli import _guard, _overrides, app
from web_enum.errors import ConfigError, ScopeError
from web_enum.http import HttpResponse
from web_enum.runner import ScanState

runner = CliRunner()
COOKIE = "PHPSESSID=s3cr3tsession"
SITE = {
    "/": (200, {"content-type": "text/html", "server": "nginx/1.18.0"},
          "<title>Box</title><form method=post action=/login><input type=password name=p>"),
    "/.git/HEAD": (200, {}, "ref: refs/heads/main\n"),
    "/admin": (301, {"location": "/admin/"}, ""),
}


@pytest.fixture(autouse=True)
def no_tools(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Hermetic tool detection: nothing installed unless a test says so."""
    available: dict[str, str] = {}

    def find(name: str, paths: Mapping[str, str]) -> str | None:
        return available.get(name)

    monkeypatch.setattr(cli, "find_tool", find)
    return available


@pytest.fixture()
def words(tmp_path: Path) -> str:
    path = tmp_path / "words.txt"
    path.write_text("admin\nnothing\n", encoding="utf-8")
    return str(path)


def fast(words: str, out: Path) -> list[str]:
    """Options that make a scan instant in tests (fast rate, tiny wordlist)."""
    return ["--rate", "1000", "-t", "20", "-w", words, "-o", str(out)]


# --------------------------------------------------------------------------- #
# Basics
# --------------------------------------------------------------------------- #
def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"web-enum {__version__}"


def test_help_shows_ethics_and_exit_codes() -> None:
    result = runner.invoke(app, [])
    assert "AUTHORISED" in result.stdout
    for command in ("scan", "tools", "config"):
        assert command in result.stdout
    assert "4 target not authorised" in result.stdout


def test_config_command_prints_effective_yaml(write_config: WriteConfig) -> None:
    path = write_config("scope: [lab.local]\nlimits: {rate: 5}\n")
    result = runner.invoke(app, ["config", "-c", str(path)])
    assert result.exit_code == 0, result.output
    first, _, body = result.stdout.partition("\n")
    assert first == f"# Loaded from: <bundled defaults> <- {path}"
    data = yaml.safe_load(body)
    assert data["scope"] == ["lab.local"] and data["limits"]["rate"] == 5


def test_config_error_exits_2(write_config: WriteConfig) -> None:
    result = runner.invoke(app, ["config", "-c", str(write_config("limits: {rate: -1}\n"))])
    assert result.exit_code == 2
    assert "'limits.rate' must be >= 0.1" in result.stderr


# --------------------------------------------------------------------------- #
# The ethical gate
# --------------------------------------------------------------------------- #
def test_scan_refuses_unauthorised_target(router: respx.MockRouter, tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", "http://box.htb/", "-o", str(tmp_path / "out")])
    assert result.exit_code == 4
    assert "'box.htb' is not in your authorised scope" in result.stderr
    assert not router.calls  # not a single request
    assert not (tmp_path / "out").exists()  # nothing written either


def test_dry_run_is_also_gated(router: respx.MockRouter) -> None:
    assert runner.invoke(app, ["scan", "http://box.htb/", "--dry-run"]).exit_code == 4


def test_scope_from_config_authorises(write_config: WriteConfig, router: respx.MockRouter) -> None:
    cfg = write_config("scope: [10.10.10.0/24]\n")
    result = runner.invoke(app, ["scan", "10.10.10.5", "-c", str(cfg), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "Authorised   in scope (10.10.10.0/24)" in result.stdout


# --------------------------------------------------------------------------- #
# Dry run and options
# --------------------------------------------------------------------------- #
def test_dry_run_shows_plan_and_sends_nothing(router: respx.MockRouter, words: str,
                                              no_tools: dict[str, str]) -> None:
    no_tools.update({"ffuf": "/usr/bin/ffuf", "whatweb": "/usr/bin/whatweb"})
    result = runner.invoke(app, ["scan", "box.htb:8080/app/login.php", "--authorized",
                                 "--dry-run", "-w", words, "-x", "php,.TXT", "--skip", "forms"])
    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "DRY RUN: no request will be sent." in out
    assert "http://box.htb:8080/app/login.php  (discovery base: http://box.htb:8080/app/)" in out
    assert "--authorized given by the user" in out
    assert "[RUN ] fingerprint  native rules + whatweb (/usr/bin/whatweb)" in out
    assert "[RUN ] discovery    ffuf (/usr/bin/ffuf); wordlist" in out
    assert "(2 words); extensions php, txt; depth 0" in out
    assert "[skip] forms        skipped (--skip)" in out
    assert "Estimate     ~" in out and "exceeds" not in out
    assert not router.calls


def test_dry_run_warns_when_budget_is_too_small(words: str) -> None:
    result = runner.invoke(app, ["scan", "http://box.htb/", "--authorized", "--dry-run",
                                 "-w", words, "--max-requests", "5"])
    assert result.exit_code == 0
    assert "exceeds the budget: discovery will be cut" in result.stdout


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--concurrency", "500"], "'limits.concurrency' must be between 1 and 100"),
        (["--rate", "0"], "'limits.rate' must be >= 0.1"),
        (["--depth", "9"], "'discovery.recursion_depth' must be between 0 and 5"),
        (["-x", "p h p"], "not a valid extension"),
        (["-H", "NoColon"], "Invalid header 'NoColon'"),
        (["--only", "exploit"], "--only: unknown module(s) exploit"),
        (["-w", "/nonexistent/list.txt"], "Wordlist not found"),
    ],
)
def test_invalid_options_exit_2(args: list[str], message: str) -> None:
    result = runner.invoke(app, ["scan", "http://box.htb/", "--authorized", "--dry-run", *args])
    assert result.exit_code == 2, result.output
    assert message in result.stderr


def test_invalid_url_exits_2() -> None:
    result = runner.invoke(app, ["scan", "ftp://box.htb/", "--authorized"])
    assert result.exit_code == 2 and "Unsupported scheme 'ftp'" in result.stderr


def test_requested_engine_missing_exits_3() -> None:
    result = runner.invoke(app, ["scan", "http://box.htb/", "--authorized", "--dry-run",
                                 "--engine", "ffuf"])
    assert result.exit_code == 3
    assert "sudo apt install ffuf" in result.stderr


def test_overrides_only_include_given_options(tmp_path: Path) -> None:
    assert _overrides(wordlist=None, extensions=None, engine=None, depth=None,
                      concurrency=None, rate=None, max_requests=None, verify_tls=False,
                      output_dir=None) == {}
    got = _overrides(wordlist="w.txt", extensions="php,,txt", engine=cli.EngineChoice.native,
                     depth=1, concurrency=5, rate=2.5, max_requests=100, verify_tls=True,
                     output_dir=tmp_path)
    assert got == {
        "discovery": {"wordlist": "w.txt", "extensions": ["php", "txt"], "recursion_depth": 1},
        "tools": {"discovery": "native"},
        "limits": {"concurrency": 5, "rate": 2.5, "max_requests": 100},
        "http": {"verify_tls": True},
        "output_dir": str(tmp_path),
    }


# --------------------------------------------------------------------------- #
# Real scans (HTTP mocked)
# --------------------------------------------------------------------------- #
def test_full_scan_writes_reports_and_masks_secrets(router: respx.MockRouter, words: str,
                                                    tmp_path: Path) -> None:
    site = FakeSite(SITE)
    route = router.route(host="box.htb").mock(side_effect=site)
    out = tmp_path / "reports"
    result = runner.invoke(app, ["scan", "http://box.htb/", "--authorized", "-v",
                                 "-H", f"Cookie: {COOKIE}", *fast(words, out)])
    assert result.exit_code == 0, result.output

    md = sorted(out.glob("box.htb-*.md"))
    js = sorted(out.glob("box.htb-*.json"))
    assert len(md) == 1 and len(js) == 1
    data = json.loads(js[0].read_text(encoding="utf-8"))
    assert data["schema"] == "web-enum/report@1"
    assert data["authorization"] == "--authorized given by the user"
    assert {m["status"] for m in data["modules"]} == {"ok"}
    assert data["findings"][0]["severity"] == "high"
    assert "Git repository exposed" in md[0].read_text(encoding="utf-8")

    sent = route.calls[0].request.headers
    assert sent["Cookie"] == COOKIE  # the session header reached the target...
    assert sent["User-Agent"].startswith("web-enum/")
    log_text = (out / "web-enum.log").read_text(encoding="utf-8")
    assert "GET http://box.htb/" in log_text  # debug detail goes to the file
    assert COOKIE not in log_text and COOKIE not in result.output  # ...but never to logs

    assert data["summary"]["high"] == 2  # exposed .git + password form over HTTP
    assert "Findings: 2 high" in result.stderr
    assert "[HIGH] Git repository exposed (.git/HEAD)" in result.stderr
    assert "[HIGH] Password submitted over plain HTTP" in result.stderr
    assert "Report: " in result.stderr


def test_json_only_format(router: respx.MockRouter, words: str, tmp_path: Path) -> None:
    router.route(host="box.htb").mock(side_effect=FakeSite(SITE))
    out = tmp_path / "r"
    result = runner.invoke(app, ["scan", "http://box.htb/", "--authorized", "-f", "json",
                                 "--only", "headers", *fast(words, out)])
    assert result.exit_code == 0, result.output
    assert [p.suffix for p in out.glob("box.htb-*")] == [".json"]


def test_unreachable_target_exits_5(router: respx.MockRouter, words: str,
                                    write_config: WriteConfig, tmp_path: Path) -> None:
    router.route(host="box.htb").mock(side_effect=httpx.ConnectError("refused"))
    cfg = write_config("http: {max_retries: 0}\n")
    result = runner.invoke(app, ["scan", "http://box.htb/", "--authorized", "-c", str(cfg),
                                 *fast(words, tmp_path / "r")])
    assert result.exit_code == 5
    assert "did not answer" in result.stderr


def test_ctrl_c_writes_partial_report(monkeypatch: pytest.MonkeyPatch, words: str,
                                      tmp_path: Path) -> None:
    async def interrupted(target: object, cfg: object, plan: object, state: ScanState,
                          **kwargs: object) -> None:
        state.main = HttpResponse("http://box.htb/", 200, (), b"")
        raise KeyboardInterrupt  # what Ctrl+C raises out of asyncio.run

    monkeypatch.setattr(cli, "run_scan", interrupted)
    out = tmp_path / "r"
    result = runner.invoke(app, ["scan", "http://box.htb/", "--authorized", *fast(words, out)])
    assert result.exit_code == 130
    assert "PARTIAL report" in result.stderr
    [report] = out.glob("*-partial.json")
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["partial"] is True
    assert {m["status"] for m in data["modules"]} == {"interrupted"}


# --------------------------------------------------------------------------- #
# tools
# --------------------------------------------------------------------------- #
def test_tools_command(no_tools: dict[str, str], write_config: WriteConfig,
                       tmp_path: Path) -> None:
    no_tools["whatweb"] = "/usr/bin/whatweb"
    common = tmp_path / "common.txt"
    common.write_text("admin\n", encoding="utf-8")
    cfg = write_config(f"discovery: {{wordlist_candidates: ['{common.as_posix()}']}}\n")
    result = runner.invoke(app, ["tools", "-c", str(cfg)])
    assert result.exit_code == 0, result.output
    assert "whatweb       found    /usr/bin/whatweb" in result.stdout
    assert "ffuf          missing  -  (sudo apt install ffuf)" in result.stdout
    assert "Discovery engine with 'auto': native (configured: auto)" in result.stdout
    assert f"Wordlist with 'auto':         {common.as_posix()}" in result.stdout.replace("\\", "/")


def test_tools_command_bundled_wordlist(write_config: WriteConfig, tmp_path: Path) -> None:
    cfg = write_config(f"discovery: {{wordlist_candidates: ['{(tmp_path / 'x').as_posix()}']}}\n")
    result = runner.invoke(app, ["tools", "-c", str(cfg)])
    assert "bundled list (install seclists for better coverage)" in result.stdout


# --------------------------------------------------------------------------- #
# Error mapping
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("exc", "code"),
    [(ConfigError("bad"), 2), (ScopeError("out of scope"), 4), (KeyboardInterrupt(), 130),
     (RuntimeError("boom"), 1)],
)
def test_guard_maps_errors_to_exit_codes(exc: BaseException, code: int) -> None:
    def action() -> None:
        raise exc

    with pytest.raises(typer.Exit) as info:
        _guard(action, verbose=False)
    assert info.value.exit_code == code


def test_guard_lets_deliberate_exit_through() -> None:
    def action() -> None:
        raise typer.Exit(130)

    with pytest.raises(typer.Exit) as info:
        _guard(action, verbose=True)
    assert info.value.exit_code == 130


def test_unexpected_error_message(capsys: pytest.CaptureFixture[str]) -> None:
    def action() -> None:
        raise RuntimeError("boom")

    with pytest.raises(typer.Exit):
        _guard(action, verbose=False)
    assert "Unexpected error: RuntimeError: boom" in capsys.readouterr().err
