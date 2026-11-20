"""ffuf and feroxbuster engines: argv, budget sizing, parsing, shared filtering."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeRunner
from web_enum.discovery.external import fit_words
from web_enum.discovery.native import DiscoveryJob
from web_enum.discovery.soft404 import NotFoundProfile, Probe
from web_enum.errors import ModuleError
from web_enum.ratelimit import RateLimiter
from web_enum.target import parse_target
from web_enum.tools.feroxbuster import FeroxbusterEngine
from web_enum.tools.ffuf import FfufEngine

BASE = "http://example.com/"
CODES = (200, 301, 302, 403)
SOFT = b"Page not found here"  # ffuf: 4 words, 1 line (matches the fixture's 'randomish')


def limiter(budget: int = 1000, rate: float = 20) -> RateLimiter:
    clock = FakeClock()
    return RateLimiter(rate=rate, concurrency=10, max_requests=budget, clock=clock,
                       sleep=clock.sleep)


def job(words: tuple[str, ...] = ("admin", "login"), *, extensions: tuple[str, ...] = (),
        recursion: int = 0) -> DiscoveryJob:
    profile = NotFoundProfile([Probe("abcdefghij", 200, SOFT, len(SOFT), None)])
    return DiscoveryJob(BASE, words, extensions, CODES, recursion, profile)


def ffuf(runner: FakeRunner, **kwargs: object) -> FfufEngine:
    return FfufEngine("/usr/bin/ffuf", target=parse_target(BASE),
                      limiter=kwargs.pop("lim", limiter()),  # type: ignore[arg-type]
                      user_agent="web-enum/0.1.0", timeout=10, runner=runner,
                      headers={"Cookie": "sid=abc"})


def ferox(runner: FakeRunner, lim: RateLimiter | None = None) -> FeroxbusterEngine:
    return FeroxbusterEngine("/usr/bin/feroxbuster", target=parse_target(BASE),
                             limiter=lim or limiter(), user_agent="web-enum/0.1.0", timeout=10,
                             runner=runner)


# --------------------------------------------------------------------------- #
# Budget sizing
# --------------------------------------------------------------------------- #
def test_fit_words() -> None:
    words = ("a", "b.php", "c", "d")
    assert fit_words(words, ("php", "txt"), 100) == list(words)
    assert fit_words(words, ("php", "txt"), 4) == ["a", "b.php"]  # 3 + 1 requests
    assert fit_words(words, (), 2) == ["a", "b.php"]
    assert fit_words(words, ("php",), 1) == []
    assert fit_words(("a.php", "b.php"), ("php",), 2) == ["a.php", "b.php"]  # 1 request each


# --------------------------------------------------------------------------- #
# ffuf
# --------------------------------------------------------------------------- #
def test_ffuf_argv(tmp_path: Path) -> None:
    engine = ffuf(FakeRunner())
    argv = engine.argv(job(extensions=("php", "txt"), recursion=2), tmp_path / "w.txt",
                       tmp_path / "o.json", 120)
    joined = " ".join(argv)
    assert argv[0] == "/usr/bin/ffuf"
    assert argv[argv.index("-u") + 1] == BASE + "FUZZ"
    assert argv[argv.index("-t") + 1] == "10" and argv[argv.index("-rate") + 1] == "20"
    assert argv[argv.index("-mc") + 1] == "200,301,302,403"
    assert argv[argv.index("-maxtime") + 1] == "120"
    assert argv[argv.index("-e") + 1] == ".php,.txt"
    assert "-recursion-depth 2" in joined and "-noninteractive" in argv
    assert "User-Agent: web-enum/0.1.0" in argv and "Cookie: sid=abc" in argv
    assert "-ac" not in argv and "-r" not in argv  # our calibration; redirects not followed
    plain = engine.argv(job(), tmp_path / "w.txt", tmp_path / "o.json", 60)
    assert "-e" not in plain and "-recursion" not in plain


async def test_ffuf_run_parses_and_filters(fixtures_dir: Path) -> None:
    runner = FakeRunner(files_after={"-o": (fixtures_dir / "ffuf.json").read_text()})
    lim = limiter()
    result = await ffuf(runner, lim=lim).run(job(("admin", "login.php", "randomish")))
    found = {p.url: p for p in result.paths}
    assert set(found) == {BASE + "admin", BASE + "login.php", BASE + "uploads/"}
    assert found[BASE + "admin"].redirect == BASE + "admin/"  # relative Location normalised
    assert found[BASE + "admin"].source == "ffuf"
    assert result.notes == ["1 ffuf result(s) outside the target ignored"]
    assert runner.inputs["wordlist"] == "admin\nlogin.php\nrandomish\n"  # sanitised copy
    assert lim.used == 3  # booked in the shared budget
    assert runner.timeouts == [1 + 5 + 60]  # ceil(3/20) + 5, plus 60 s grace


async def test_ffuf_wordlist_cut_to_budget() -> None:
    runner = FakeRunner(files_after={"-o": '{"results": []}'})
    words = tuple(f"w{i}" for i in range(10))
    result = await ffuf(runner, lim=limiter(budget=4)).run(job(words, extensions=("php",)))
    assert result.truncated
    assert runner.inputs["wordlist"] == "w0\nw1\n"  # 2 words x (1 + 1 ext) = 4 requests
    assert "wordlist cut to 2 of 10 words" in result.notes[0]


async def test_no_budget_left_means_no_run() -> None:
    lim = limiter(budget=1)
    lim.reserve(1)
    runner = FakeRunner()
    result = await ffuf(runner, lim=lim).run(job())
    assert result.truncated and runner.calls == []
    assert result.notes == ["request budget exhausted before discovery"]


async def test_ffuf_failure_and_empty_output() -> None:
    with pytest.raises(ModuleError, match="ffuf failed: .*no such host"):
        await ffuf(FakeRunner(returncode=1, stderr="Encountered error(s): no such host")).run(
            job())
    result = await ffuf(FakeRunner(returncode=0)).run(job())  # nothing written: no results
    assert result.paths == []


@pytest.mark.parametrize(
    ("text", "message"),
    [("not json", "not valid JSON"), ('{"commandline": "x"}', "no 'results' list"),
     ("[1, 2]", "no 'results' list")],
)
def test_ffuf_parse_errors(text: str, message: str) -> None:
    with pytest.raises(ModuleError, match=message):
        ffuf(FakeRunner()).parse(text)


# --------------------------------------------------------------------------- #
# feroxbuster
# --------------------------------------------------------------------------- #
def test_feroxbuster_argv(tmp_path: Path) -> None:
    engine = ferox(FakeRunner())
    argv = engine.argv(job(extensions=("php",)), tmp_path / "w.txt", tmp_path / "o.json", 90)
    assert argv[argv.index("--url") + 1] == BASE
    assert argv[argv.index("--time-limit") + 1] == "90s"
    assert argv[argv.index("--rate-limit") + 1] == "20"
    assert "--no-recursion" in argv and "--depth" not in argv
    assert "--dont-extract-links" in argv and "--json" in argv
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--status-codes"] == [
        "200", "301", "302", "403"]
    assert argv[argv.index("--extensions") + 1] == "php"
    deep = engine.argv(job(recursion=2), tmp_path / "w.txt", tmp_path / "o.json", 90)
    assert deep[deep.index("--depth") + 1] == "3" and "--no-recursion" not in deep


async def test_feroxbuster_run(fixtures_dir: Path) -> None:
    runner = FakeRunner(files_after={"--output": (fixtures_dir / "feroxbuster.jsonl").read_text()})
    result = await ferox(runner).run(job(("admin", "backup.txt", "notreal")))
    found = {p.url: p for p in result.paths}
    assert set(found) == {BASE + "admin", BASE + "backup.txt"}  # 'notreal' is a soft-404
    assert found[BASE + "admin"].redirect == BASE + "admin/"
    assert found[BASE + "backup.txt"].words == 80 and found[BASE + "backup.txt"].lines == 20


def test_rate_never_below_one() -> None:
    assert ferox(FakeRunner(), limiter(rate=0.2)).rate == 1


def test_feroxbuster_headers_and_odd_lines(tmp_path: Path) -> None:
    engine = FeroxbusterEngine("/usr/bin/feroxbuster", target=parse_target(BASE),
                               limiter=limiter(), user_agent="ua", timeout=10,
                               runner=FakeRunner(), headers={"Cookie": "sid=1"})
    argv = engine.argv(job(), tmp_path / "w", tmp_path / "o", 10)
    assert argv[argv.index("--headers") + 1] == "Cookie: sid=1"
    text = ('\n\n{"type":"response","url":"http://example.com/a","status":200,'
            '"headers":"not-a-dict"}\n[1,2]\n')
    assert [(p.url, p.redirect) for p in engine.parse(text)] == [("http://example.com/a", "")]
