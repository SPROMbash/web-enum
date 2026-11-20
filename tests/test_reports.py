"""Markdown and JSON reports, escaping of untrusted content, atomic writing."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from web_enum.models import (
    DiscoveredPath,
    Finding,
    Form,
    FormField,
    ModuleStatus,
    Report,
    Severity,
    Technology,
)
from web_enum.report import markdown as md
from web_enum.report.json_report import SCHEMA, render_json, report_to_dict
from web_enum.report.markdown import esc, render_markdown
from web_enum.report.writer import atomic_write, report_basename, write_reports

FINDINGS = (
    Finding("sensitive-git-head", "Git repository exposed (.git/HEAD)", Severity.HIGH, "content",
            "http://box.htb:8080/.git/HEAD", "HTTP 200, 21 bytes, starts with: 'ref: refs/'",
            "Block access to .git/.", ("https://example.org/git",)),
    Finding("csp-missing", "Content-Security-Policy header missing", Severity.LOW, "headers",
            "http://box.htb:8080/", "No Content-Security-Policy header", "Define a CSP."),
)


def make_report(**changes: object) -> Report:
    report = Report(
        target="http://box.htb:8080/", final_url="http://box.htb:8080/login", status=200,
        title="Acme Login", generated="2026-11-20T12:00:00+00:00", tool_version="0.1.0",
        authorization="in scope (box.htb)", partial=False,
        limits="10 concurrent, 20 req/s, budget 5000 requests", requests_sent=239,
        modules=(ModuleStatus("fingerprint", "ok", 0.4),
                 ModuleStatus("headers", "ok", 0.1),
                 ModuleStatus("discovery", "ok", 11.8, notes=("ffuf failed: x",)),
                 ModuleStatus("forms", "skipped", message="skipped (--skip)")),
        findings=FINDINGS,
        technologies=(Technology("Apache HTTP Server", "Web server", "2.4.52",
                                 ("header server: Apache/2.4.52",), ("native", "whatweb")),),
        paths=(DiscoveredPath("http://box.htb:8080/admin", 301, 0,
                              redirect="http://box.htb:8080/admin/", source="ffuf"),),
        forms=(Form("http://box.htb:8080/login", "http://box.htb:8080/login", "POST",
                    fields=(FormField("user", "text"), FormField("pass", "password"))),),
        passed_checks=("CORS does not reflect arbitrary origins",),
        discovery_engine="ffuf", wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt",
        calibration="random paths answer 404 (275 bytes)",
    )
    return replace(report, **changes)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def test_json_is_plain_data_with_schema() -> None:
    data = json.loads(render_json(make_report()))
    assert data["schema"] == SCHEMA
    assert data["summary"] == {"high": 1, "medium": 0, "low": 1, "info": 0}
    assert data["findings"][0]["severity"] == "high"  # enum -> string
    assert data["findings"][0]["references"] == ["https://example.org/git"]  # tuple -> list
    assert data["forms"][0]["has_password"] is True
    assert data["forms"][0]["has_file_upload"] is False
    assert data["modules"][2]["notes"] == ["ffuf failed: x"]
    assert data["partial"] is False and data["requests_sent"] == 239


def test_json_keeps_unicode_readable() -> None:
    assert "Señal" in render_json(make_report(title="Señal"))


def test_report_to_dict_roundtrip_keys() -> None:
    data = report_to_dict(make_report())
    assert list(data)[:3] == ["schema", "summary", "target"]


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def test_markdown_structure() -> None:
    text = render_markdown(make_report())
    for heading in ("# web-enum report", "## Summary", "## Findings", "## Technologies",
                    "## Discovered content", "## Forms", "## Checks passed", "## Modules"):
        assert heading in text
    assert "| 1 | 0 | 1 | 0 |" in text  # summary row
    assert text.index("Git repository exposed") < text.index("Content-Security-Policy header")
    assert "### 1. 🔴 HIGH — Git repository exposed (.git/HEAD)" in text
    assert "- **References:** https://example.org/git" in text
    assert "authorised" in text and "PARTIAL" not in text
    assert "| discovery | ok | 11.8s | ffuf failed: x |" in text
    assert "| forms | skipped | 0.0s | skipped (--skip) |" in text
    assert "pass (password)" in text


def test_markdown_partial_banner() -> None:
    assert "**PARTIAL REPORT**" in render_markdown(make_report(partial=True))


def test_markdown_empty_sections() -> None:
    text = render_markdown(make_report(findings=(), technologies=(), paths=(), forms=(),
                                       passed_checks=(), discovery_engine="", title=""))
    assert "No findings." in text and "None detected." in text
    assert "No content discovered." in text and "No forms found." in text
    assert "## Checks passed" not in text and "**Engine:**" not in text
    assert "| Title | — |" in text


def test_markdown_caps_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(md, "MAX_PATHS", 2)
    paths = tuple(DiscoveredPath(f"http://box.htb/p{i}", 200, 1) for i in range(5))
    text = render_markdown(make_report(paths=paths))
    assert "…and 3 more (see the JSON report)." in text
    assert "p4" not in text


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("<img src=x onerror=alert(1)>", "&lt;img src=x onerror=alert(1)&gt;"),
        ("[click](javascript:alert(1))", "\\[click\\](javascript:alert(1))"),
        ("a|b", "a\\|b"),
        ("line1\nline2", "line1 line2"),
        ("**bold** _it_ `code` # h", "\\*\\*bold\\*\\* \\_it\\_ \\`code\\` \\# h"),
        ("C:\\path", "C:\\\\path"),
    ],
)
def test_escaping_untrusted_text(raw: str, expected: str) -> None:
    assert esc(raw) == expected


def test_hostile_page_title_is_inert() -> None:
    text = render_markdown(make_report(title="<script>alert(1)</script> | ## evil"))
    assert "<script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt; \\| \\#\\# evil" in text


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("target", "generated", "expected"),
    [
        ("http://box.htb:8080/", "2026-11-20T12:00:00+00:00", "box.htb-8080-20261120-120000"),
        ("https://example.com/", "2026-11-20T12:00:00+00:00", "example.com-20261120-120000"),
        ("http://[2001:db8::1]/", "2026-11-20T12:00:00+00:00", "2001_db8_1-20261120-120000"),
        ("http://box.htb/", "not a date", "box.htb-report"),
        ("http://box.htb:99999/", "2026-11-20T12:00:00+00:00", "box.htb-20261120-120000"),
    ],
)
def test_report_basename(target: str, generated: str, expected: str) -> None:
    assert report_basename(make_report(target=target, generated=generated)) == expected


def test_write_reports(tmp_path: Path) -> None:
    out = tmp_path / "reports" / "nested"
    paths = write_reports(make_report(), out, ["md", "json"])
    assert [p.name for p in paths] == ["box.htb-8080-20261120-120000.md",
                                       "box.htb-8080-20261120-120000.json"]
    assert json.loads(paths[1].read_text(encoding="utf-8"))["schema"] == SCHEMA
    assert sorted(p.name for p in out.iterdir()) == sorted(p.name for p in paths)  # no temp files


def test_partial_reports_are_named_as_such(tmp_path: Path) -> None:
    [path] = write_reports(make_report(partial=True), tmp_path, ["json"])
    assert path.name.endswith("-partial.json")


def test_atomic_write_leaves_nothing_on_failure(tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "r.md"
    target.write_text("old complete report", encoding="utf-8")

    def boom(src: str, dst: str) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("web_enum.report.writer.os.replace", boom)
    with pytest.raises(OSError, match="disk full"):
        atomic_write(target, "new report")
    assert target.read_text(encoding="utf-8") == "old complete report"  # untouched
    assert [p.name for p in tmp_path.iterdir()] == ["r.md"]  # temp file cleaned up
