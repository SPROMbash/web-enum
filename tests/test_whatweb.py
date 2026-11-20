"""whatweb backend: argv, JSON parsing (tolerant, type-checked), error handling."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeRunner
from web_enum.errors import ModuleError
from web_enum.ratelimit import RateLimiter
from web_enum.tools.whatweb import WhatWeb, parse_whatweb_json

URL = "http://203.0.113.10/"


def make(runner: FakeRunner, **kwargs: object) -> WhatWeb:
    clock = FakeClock()
    limiter = RateLimiter(rate=10, concurrency=2, max_requests=10, clock=clock, sleep=clock.sleep)
    return WhatWeb("/usr/bin/whatweb", limiter=limiter, user_agent="web-enum/0.1.0",
                   timeout=10, runner=runner, **kwargs)  # type: ignore[arg-type]


def test_argv_is_stealthy_and_has_no_shell(tmp_path: Path) -> None:
    ww = make(FakeRunner(), headers={"Cookie": "PHPSESSID=abc"})
    argv = ww.argv("http://203.0.113.10/a;id", tmp_path / "out.json")
    assert argv[0] == "/usr/bin/whatweb"
    assert "--aggression=1" in argv
    assert "--follow-redirect=never" in argv
    assert "--user-agent=web-enum/0.1.0" in argv
    assert "--open-timeout=10" in argv and "--read-timeout=10" in argv
    assert f"--log-json={tmp_path / 'out.json'}" in argv
    assert "--header=Cookie:PHPSESSID=abc" in argv
    assert argv[-1] == "http://203.0.113.10/a;id"  # one plain argument; no shell parses it


async def test_scan_parses_fixture_and_uses_the_limiter(fixtures_dir: Path) -> None:
    runner = FakeRunner(files={"--log-json=": (fixtures_dir / "whatweb.json").read_text()})
    ww = make(runner)
    techs = {t.name: t for t in await ww.scan(URL)}
    assert runner.calls[0][-1] == URL
    assert runner.timeouts == [70.0]  # 4 x timeout + 30
    assert ww.limiter.used == 1  # whatweb's request counts toward the budget
    assert techs["Apache HTTP Server"].version == "2.4.52"  # alias -> our rule name
    assert techs["jQuery"].version == "3.6.0"
    assert techs["WordPress"].version == "6.4.2"
    assert techs["PHP"].version == "8.1.2"
    assert "Bootstrap" in techs and "MetaGenerator" in techs
    for skipped in ("Title", "IP", "Country", "HTTPServer", "PasswordField", "X-Powered-By"):
        assert skipped not in techs
    assert all(t.sources == ("whatweb",) for t in techs.values())


async def test_temporary_output_is_removed(fixtures_dir: Path) -> None:
    runner = FakeRunner(files={"--log-json=": (fixtures_dir / "whatweb.json").read_text()})
    await make(runner).scan(URL)
    out = next(a for a in runner.calls[0] if a.startswith("--log-json="))
    assert not Path(out.split("=", 1)[1]).parent.exists()


async def test_no_output_is_an_error_with_stderr() -> None:
    runner = FakeRunner(returncode=1, stderr="warning\nERROR: Connection refused\n")
    with pytest.raises(ModuleError, match="no output .ERROR: Connection refused"):
        await make(runner).scan(URL)


async def test_empty_output_file_is_an_error() -> None:
    with pytest.raises(ModuleError, match="exit code 0"):
        await make(FakeRunner(files={"--log-json=": "  \n"})).scan(URL)


def test_parse_tolerates_trailing_commas() -> None:
    text = '[\n{"target":"u","plugins":{"nginx":{"version":["1.18.0"]},},},\n]\n'
    assert {t.name: t.version for t in parse_whatweb_json(text)} == {"nginx": "1.18.0"}


def test_parse_single_object_and_garbage_types() -> None:
    text = (
        '{"target":"u","plugins":{"Foo":{"version":[1.2, {"x":1}], "string":"bar"},'
        '"Baz":"not-a-dict","Qux":{"version":{"weird":true}}}}'
    )
    techs = {t.name: t for t in parse_whatweb_json(text)}
    assert techs["Foo"].version == "1.2"
    assert techs["Foo"].evidence == ("whatweb Foo", "whatweb Foo string: bar")
    assert techs["Baz"].version == "" and techs["Qux"].version == ""


def test_parse_ignores_entries_without_plugins() -> None:
    assert parse_whatweb_json('[{}, {"plugins": []}, 5]') == []


def test_parse_duplicate_plugins_across_entries_kept_once() -> None:
    text = '[{"plugins":{"PHP":{"version":["8.1"]}}},{"plugins":{"PHP":{"version":["7.4"]}}}]'
    assert [(t.name, t.version) for t in parse_whatweb_json(text)] == [("PHP", "8.1")]


def test_parse_invalid_json() -> None:
    with pytest.raises(ModuleError, match="not valid JSON"):
        parse_whatweb_json("ERROR Opening: http://x - Connection refused")
