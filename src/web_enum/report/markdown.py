"""Markdown report: prioritised findings first, details after.

Everything that comes from the target (titles, evidence, URLs, header values)
is untrusted. :func:`esc` neutralises Markdown and HTML syntax in it, so a page
titled ``<img src=x onerror=alert(1)>`` or a link ``[x](javascript:...)`` is
shown as text, never rendered, when the report is opened in a Markdown viewer.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from web_enum.models import Finding, Report, Severity

_ESCAPE = str.maketrans({
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_", "[": "\\[", "]": "\\]",
    "<": "&lt;", ">": "&gt;", "|": "\\|", "#": "\\#",
    "\n": " ", "\r": " ", "\t": " ",
})
_BADGE = {Severity.HIGH: "🔴 HIGH", Severity.MEDIUM: "🟠 MEDIUM", Severity.LOW: "🟡 LOW",
          Severity.INFO: "🔵 INFO"}
MAX_PATHS = 500


def esc(text: object) -> str:
    """Make untrusted text inert in Markdown (and in the HTML a viewer renders)."""
    return str(text).translate(_ESCAPE).strip()


def _table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(esc(cell) for cell in row) + " |" for row in rows]
    return lines


def _section_findings(findings: Sequence[Finding]) -> list[str]:
    out = ["## Findings", ""]
    if not findings:
        return out + ["No findings.", ""]
    out += _table(("#", "Severity", "Finding", "URL"),
                  ((i, f.severity.value.upper(), f.title, f.url)
                   for i, f in enumerate(findings, 1)))
    out.append("")
    for i, f in enumerate(findings, 1):
        out += [
            f"### {i}. {_BADGE[f.severity]} — {esc(f.title)}",
            "",
            f"- **URL:** {esc(f.url)}",
            f"- **Category:** {esc(f.category)} (id: {esc(f.id)})",
            f"- **Evidence:** {esc(f.evidence)}",
            f"- **Recommendation:** {esc(f.recommendation)}",
        ]
        if f.references:
            out.append("- **References:** " + ", ".join(esc(r) for r in f.references))
        out.append("")
    return out


def render_markdown(report: Report) -> str:
    counts = report.severity_counts()
    out = [f"# web-enum report — {esc(report.target)}", ""]
    if report.partial:
        out += ["> **PARTIAL REPORT**: the scan was interrupted; modules marked "
                "*interrupted* did not finish.", ""]
    out += [
        "> Generated for an **authorised** assessment. It describes weaknesses of the "
        "target: store it securely and share it only with the system owner.",
        "",
    ]
    out += _table(("", ""), (
        ("Target", report.target),
        ("Final URL", f"{report.final_url} (HTTP {report.status})"),
        ("Title", report.title or "—"),
        ("Generated", report.generated),
        ("Authorised because", report.authorization),
        ("Limits", report.limits),
        ("Requests sent", report.requests_sent),
        ("Tool", f"web-enum {report.tool_version}"),
    ))
    out += ["", "## Summary", ""]
    out += _table(("High", "Medium", "Low", "Info"),
                  [(counts["high"], counts["medium"], counts["low"], counts["info"])])
    out.append("")
    out += _section_findings(report.findings)

    out += ["## Technologies", ""]
    if report.technologies:
        out += _table(("Category", "Technology", "Version", "Sources", "Evidence"),
                      ((t.category, t.name, t.version or "—", ", ".join(t.sources),
                        "; ".join(t.evidence)[:200]) for t in report.technologies))
    else:
        out.append("None detected.")
    out.append("")

    out += ["## Discovered content", ""]
    if report.discovery_engine:
        out += [f"- **Engine:** {esc(report.discovery_engine)}",
                f"- **Wordlist:** {esc(report.wordlist)}",
                f"- **Soft-404 calibration:** {esc(report.calibration or '—')}", ""]
    if report.paths:
        shown = report.paths[:MAX_PATHS]
        out += _table(("Status", "URL", "Size", "Redirect", "Source"),
                      ((p.status, p.url, p.length, p.redirect or "—", p.source) for p in shown))
        if len(report.paths) > MAX_PATHS:
            out += ["", f"…and {len(report.paths) - MAX_PATHS} more (see the JSON report)."]
    else:
        out.append("No content discovered.")
    out.append("")

    out += ["## Forms", ""]
    if report.forms:
        out += _table(("Page", "Method", "Action", "Fields"),
                      ((f.page, f.method, f.action,
                        ", ".join(f"{x.name or '?'} ({x.type})" for x in f.fields))
                       for f in report.forms))
    else:
        out.append("No forms found.")
    out.append("")

    if report.passed_checks:
        out += ["## Checks passed", ""] + [f"- {esc(c)}" for c in report.passed_checks] + [""]

    out += ["## Modules", ""]
    out += _table(("Module", "Status", "Duration", "Details"),
                  ((m.name, m.status, f"{m.duration:.1f}s",
                    "; ".join(filter(None, (m.message, *m.notes))) or "—")
                   for m in report.modules))
    out.append("")
    return "\n".join(out)
