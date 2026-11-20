"""Write reports atomically.

Each file is written to a temporary file in the same directory and then moved
into place with ``os.replace`` (atomic on POSIX and Windows): a crash or a
Ctrl+C never leaves a half-written report that looks complete.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from web_enum.models import Report
from web_enum.report.json_report import render_json
from web_enum.report.markdown import render_markdown

RENDERERS = {"md": render_markdown, "json": render_json}
_UNSAFE = re.compile(r"[^A-Za-z0-9.-]+")


def report_basename(report: Report) -> str:
    """'box.htb-8080-20261120-120000' (safe on every filesystem)."""
    parts = urlsplit(report.target)
    host = _UNSAFE.sub("_", parts.hostname or "target").strip("_") or "target"
    try:
        port = parts.port
    except ValueError:
        port = None
    try:
        stamp = datetime.fromisoformat(report.generated).strftime("%Y%m%d-%H%M%S")
    except ValueError:
        stamp = "report"
    return f"{host}-{port}-{stamp}" if port else f"{host}-{stamp}"


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_reports(report: Report, output_dir: Path, formats: Sequence[str]) -> list[Path]:
    base = report_basename(report) + ("-partial" if report.partial else "")
    paths = []
    for fmt in formats:
        path = output_dir / f"{base}.{fmt}"
        atomic_write(path, RENDERERS[fmt](report))
        paths.append(path)
    return paths
