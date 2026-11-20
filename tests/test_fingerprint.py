"""Native fingerprinting: rules, page signals, detection, merging, orchestration."""

from __future__ import annotations

from pathlib import Path

import pytest

from web_enum.analyzers.fingerprint import (
    PageSignals,
    default_rules,
    detect,
    fingerprint,
    merge_technologies,
    page_signals,
    parse_rules,
)
from web_enum.errors import ConfigError, ModuleError
from web_enum.http import HttpResponse
from web_enum.models import Technology


def response(
    body: str = "", *headers: tuple[str, str], content_type: str = "text/html; charset=utf-8"
) -> HttpResponse:
    all_headers = ((("content-type", content_type),) if content_type else ()) + headers
    return HttpResponse("http://203.0.113.10/", 200, all_headers, body.encode())


def names(techs: list[Technology] | tuple[Technology, ...]) -> dict[str, str]:
    return {t.name: t.version for t in techs}


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
def test_bundled_rules_are_valid() -> None:
    rules = default_rules()
    assert len(rules) >= 40
    by_name = {r.name: r for r in rules}
    # every implied technology exists as a rule (so it gets a proper category)
    for rule in rules:
        for implied in rule.implies:
            assert implied in by_name, f"{rule.name} implies unknown {implied}"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("name: x\n", "top level must be a list"),
        ("- [unclosed\n", "invalid YAML"),
        ("- category: CMS\n", "needs at least a 'name'"),
        ("- {name: X, html: a, scirpts: b}\n", "unknown key"),
        ("- {name: X}\n", "needs at least one matcher"),
        ("- {name: X, headers: [Server]}\n", "'headers' must be a mapping"),
        ("- {name: X, cookies: abc}\n", "'cookies' and 'implies' must be lists"),
        ("- {name: X, html: '(unclosed'}\n", "invalid regex"),
        ("- {name: X, html: a}\n- {name: x, html: b}\n", "duplicated names: x"),
    ],
)
def test_parse_rules_rejects(text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_rules(text)


# --------------------------------------------------------------------------- #
# Page signals
# --------------------------------------------------------------------------- #
def test_page_signals_from_real_looking_page(fixtures_dir: Path) -> None:
    html = (fixtures_dir / "wordpress_home.html").read_text(encoding="utf-8")
    signals = page_signals(response(
        html, ("set-cookie", "PHPSESSID=abc; path=/; HttpOnly"),
        ("set-cookie", "wp-settings=1"), ("set-cookie", "PHPSESSID=again"),
    ))
    assert signals.title == "Acme Portal & Login"  # whitespace collapsed, first <title> only
    assert signals.generators == ("WordPress 6.4.2",)
    assert signals.scripts[0] == "/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"
    assert len(signals.scripts) == 2  # inline <script> has no src
    assert signals.cookies == ("PHPSESSID", "wp-settings")


def test_stray_tags_and_nameless_cookies() -> None:
    signals = page_signals(response(
        "</title><meta name=generator><title>Real</title>",
        ("set-cookie", "=orphan; path=/"), ("set-cookie", "ok=1"),
    ))
    assert signals.title == "Real"
    assert signals.generators == ()  # generator meta without content
    assert signals.cookies == ("ok",)


def test_non_html_bodies_are_not_parsed() -> None:
    signals = page_signals(response('{"title": "<title>x</title>"}',
                                    content_type="application/json"))
    assert signals.html == "" and signals.title == ""


def test_missing_content_type_is_parsed_as_html() -> None:
    assert page_signals(response("<title>Hi</title>", content_type="")).title == "Hi"


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def test_detect_wordpress_stack(fixtures_dir: Path) -> None:
    html = (fixtures_dir / "wordpress_home.html").read_text(encoding="utf-8")
    page = page_signals(response(html, ("server", "nginx/1.18.0"),
                                 ("x-powered-by", "PHP/8.1.2"),
                                 ("set-cookie", "PHPSESSID=abc")))
    found = {t.name: t for t in detect(page)}
    assert found["WordPress"].version == "6.4.2"
    assert found["nginx"].version == "1.18.0"
    assert found["PHP"].version == "8.1.2"
    assert "cookie PHPSESSID" in found["PHP"].evidence
    assert "jQuery" in found and "Bootstrap" in found
    assert found["WordPress"].category == "CMS"
    assert all(t.sources == ("native",) for t in found.values())


def test_implied_technology_added_once() -> None:
    page = PageSignals(url="u", generators=("WordPress 6.4",))
    found = {t.name: t for t in detect(page)}
    assert found["PHP"].evidence == ("implied by WordPress",)
    assert found["PHP"].category == "Language"
    # ...but a directly detected PHP keeps its own evidence and version
    page = PageSignals(url="u", generators=("WordPress",), headers=(("x-powered-by", "PHP/7.4"),))
    assert {t.name: t for t in detect(page)}["PHP"].version == "7.4"


def test_implied_unknown_technology_gets_other_category() -> None:
    rules = parse_rules("- {name: Foo, html: foo, implies: [Bar]}\n")
    found = {t.name: t for t in detect(PageSignals(url="u", html="foo"), rules)}
    assert found["Bar"].category == "Other"


@pytest.mark.parametrize(
    ("server", "expected"),
    [
        ("Apache/2.4.52 (Ubuntu)", {"Apache HTTP Server": "2.4.52"}),
        ("Apache", {"Apache HTTP Server": ""}),
        ("Apache-Coyote/1.1", {"Apache Tomcat": "", "Java": ""}),  # Tomcat, NOT Apache httpd
        ("Microsoft-IIS/10.0", {"Microsoft IIS": "10.0"}),
        ("Werkzeug/2.2.2 Python/3.10.6", {"Werkzeug": "2.2.2", "Python": "3.10.6"}),
        ("gunicorn", {"Gunicorn": "", "Python": ""}),
    ],
)
def test_server_header_rules(server: str, expected: dict[str, str]) -> None:
    assert names(detect(PageSignals(url="u", headers=(("server", server),)))) == expected


@pytest.mark.parametrize(
    ("src", "name", "version"),
    [
        ("/js/jquery-3.6.0.min.js", "jQuery", "3.6.0"),
        ("/js/jquery.3.5.1.js", "jQuery", "3.5.1"),
        ("/wp-includes/js/jquery/jquery.min.js?ver=3.7.1", "jQuery", "3.7.1"),
        ("https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js", "jQuery", "3.7.1"),
        ("/static/jquery.slim.min.js", "jQuery", ""),
        ("https://cdn.example.com/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js",
         "Bootstrap", "5.3.2"),
        ("/assets/bootstrap-4.6.2.min.js", "Bootstrap", "4.6.2"),
        ("/assets/bootstrap.min.js?ver=5.1", "Bootstrap", "5.1"),
        ("https://unpkg.com/vue@3.4.21/dist/vue.global.prod.js", "Vue.js", "3.4.21"),
    ],
)
def test_script_versions(src: str, name: str, version: str) -> None:
    assert names(detect(PageSignals(url="u", scripts=(src,))))[name] == version


def test_repeated_header_values_all_checked() -> None:
    page = PageSignals(url="u", headers=(("via", "1.1 proxy"), ("via", "1.1 varnish")))
    assert "Varnish" in names(detect(page))


def test_title_and_html_rules() -> None:
    assert names(detect(PageSignals(url="u", title="Apache Tomcat/9.0.65"))) == {
        "Apache Tomcat": "9.0.65", "Java": ""}
    assert "Angular" in names(detect(PageSignals(url="u", html='<app ng-version="16.2.1">')))
    assert names(detect(PageSignals(url="u", html='<app ng-version="16.2.1">')))["Angular"] == \
        "16.2.1"


def test_named_version_group_wins() -> None:
    rules = parse_rules(r"- {name: App, html: 'v(\d) build (?P<version>[\d.]+)'}" + "\n")
    assert names(detect(PageSignals(url="u", html="v1 build 2.3.4"), rules)) == {"App": "2.3.4"}
    rules = parse_rules(r"- {name: App, html: 'v(?P<version>\d)?x'}" + "\n")
    assert names(detect(PageSignals(url="u", html="vx"), rules)) == {"App": ""}


def test_nothing_detected_on_plain_page() -> None:
    assert detect(PageSignals(url="u", html="<p>hello</p>", headers=(("server", "custom"),))) == []


# --------------------------------------------------------------------------- #
# Merging and orchestration
# --------------------------------------------------------------------------- #
def test_merge_combines_engines() -> None:
    native = [Technology("jQuery", "JavaScript library", "", ("script x",), ("native",)),
              Technology("Apache HTTP Server", "Web server", "2.4", ("header",), ("native",))]
    external = [Technology("jquery", "Other", "3.6.0", ("whatweb JQuery",), ("whatweb",)),
                Technology("Apache HTTP Server", "Other", "2.4.52", ("whatweb",), ("whatweb",)),
                Technology("Ubuntu", "Other", "", ("whatweb",), ("whatweb",))]
    merged = {t.name: t for t in merge_technologies(native, external)}
    assert merged["jQuery"].version == "3.6.0"
    assert merged["jQuery"].category == "JavaScript library"  # native category kept
    assert merged["jQuery"].sources == ("native", "whatweb")
    assert merged["Apache HTTP Server"].version == "2.4.52"  # more specific version
    assert merged["Ubuntu"].category == "Other"


def test_merge_takes_category_from_later_source_if_first_is_other() -> None:
    merged = merge_technologies([Technology("X", "Other")], [Technology("x", "CMS", "1")])
    assert merged == [Technology("X", "CMS", "1")]


class FakeScanner:
    name = "fake"

    def __init__(self, result: list[Technology] | None = None, *, fail: bool = False) -> None:
        self.result = result or []
        self.fail = fail
        self.urls: list[str] = []

    async def scan(self, url: str) -> list[Technology]:
        self.urls.append(url)
        if self.fail:
            raise ModuleError("exit code 1")
        return self.result


async def test_fingerprint_native_only() -> None:
    result = await fingerprint(response("<title>T</title>", ("server", "nginx")))
    assert names(result.technologies) == {"nginx": ""}
    assert result.title == "T" and result.notes == ()


async def test_fingerprint_with_external_scanner() -> None:
    scanner = FakeScanner([Technology("PHP", "Other", "8.1.2", sources=("whatweb",))])
    result = await fingerprint(response("", ("x-powered-by", "PHP")), external=scanner)
    assert scanner.urls == ["http://203.0.113.10/"]
    php = next(t for t in result.technologies if t.name == "PHP")
    assert php.version == "8.1.2" and php.sources == ("native", "whatweb")


async def test_fingerprint_survives_external_failure(caplog: pytest.LogCaptureFixture) -> None:
    result = await fingerprint(response("", ("server", "nginx")), external=FakeScanner(fail=True))
    assert names(result.technologies) == {"nginx": ""}
    assert result.notes == ("fake failed: exit code 1; native rules only",)
    assert "using native fingerprints only" in caplog.text
