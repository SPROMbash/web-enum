"""JSON report: the whole Report as plain data, with a schema identifier.

``schema`` lets other tools (a dashboard, a diff between two scans, the
htb-writeups notes) check which format they are reading before parsing it.
Enums become their string values, tuples become lists.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from enum import Enum
from typing import Any

from web_enum.models import Report

SCHEMA = "web-enum/report@1"


def report_to_dict(report: Report) -> dict[str, Any]:
    data = asdict(report)
    plain = {key: _plain(value) for key, value in data.items()}
    for form, original in zip(plain["forms"], report.forms, strict=True):
        form["has_password"] = original.has_password
        form["has_file_upload"] = original.has_file_upload
    return {"schema": SCHEMA, "summary": report.severity_counts(), **plain}


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def render_json(report: Report) -> str:
    return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n"
