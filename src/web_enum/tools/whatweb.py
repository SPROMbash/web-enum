"""whatweb backend (Kali / Parrot): ~1800 fingerprinting plugins.

Run in its stealthiest mode: aggression level 1 (one request, no plugin-driven
extra requests), redirects not followed (we hand it the final same-origin URL),
honest User-Agent, our timeouts. Its single request goes through the shared
:class:`RateLimiter`, so it counts toward concurrency, rate and budget.

Output: ``--log-json`` to a private temporary file. whatweb's JSON is not fully
standard across versions (some write a trailing ``{}`` element or a trailing
comma), so parsing is tolerant, and every field is type-checked: it is
external input.

Mapped to our model: one :class:`Technology` per plugin, except plugins that
describe the response rather than a technology (Title, IP, Country, cookies,
security headers...), which the other modules already cover.
"""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from web_enum.errors import ModuleError
from web_enum.log import get_logger
from web_enum.models import Technology
from web_enum.ratelimit import RateLimiter
from web_enum.tools.process import ProcessRunner, run_process

log = get_logger(__name__)

# Plugins that are not technologies (or are reported better by other modules).
SKIP_PLUGINS = frozenset({
    "Country", "IP", "Title", "HTTPServer", "RedirectLocation", "UncommonHeaders",
    "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security", "Cookies", "HttpOnly",
    "Email", "Script", "Meta-Author", "Meta-Refresh-Redirect", "PasswordField", "Frame",
    "HTML5", "X-UA-Compatible", "Content-Language", "Allow", "Via-Proxy", "X-Powered-By",
    "Access-Control-Allow-Methods", "Content-Security-Policy", "Open-Graph-Protocol",
    "Object", "probably",
})
# whatweb plugin name -> our rule name, so both engines merge into one entry.
ALIASES = {
    "apache": "Apache HTTP Server",
    "microsoft-iis": "Microsoft IIS",
    "jquery": "jQuery",
    "wordpress": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "php": "PHP",
    "nginx": "nginx",
    "bootstrap": "Bootstrap",
    "apache-tomcat": "Apache Tomcat",
    "tomcat": "Apache Tomcat",
    "jenkins": "Jenkins",
    "phpmyadmin": "phpMyAdmin",
    "roundcube": "Roundcube",
    "grafana": "Grafana",
    "werkzeug": "Werkzeug",
    "python": "Python",
    "asp_net": "ASP.NET",
    "litespeed": "LiteSpeed",
    "jetty": "Jetty",
    "django": "Django",
    "laravel": "Laravel",
    "cloudflare": "Cloudflare",
    "varnish": "Varnish",
    "moodle": "Moodle",
    "gitlab": "GitLab",
    "gitea": "Gitea",
}
_TRAILING_COMMA = re.compile(r",\s*([\]}])")


class WhatWeb:
    name = "whatweb"

    def __init__(
        self,
        path: str,
        *,
        limiter: RateLimiter,
        user_agent: str,
        timeout: float,
        headers: Mapping[str, str] | None = None,
        runner: ProcessRunner = run_process,
    ) -> None:
        self.path = path
        self.limiter = limiter
        self.user_agent = user_agent
        self.timeout = timeout
        self.headers = dict(headers or {})
        self.runner = runner

    def argv(self, url: str, log_file: Path) -> list[str]:
        seconds = str(max(1, round(self.timeout)))
        argv = [
            self.path,
            "--color=never",
            "--no-errors",
            "--aggression=1",
            "--follow-redirect=never",
            f"--user-agent={self.user_agent}",
            f"--open-timeout={seconds}",
            f"--read-timeout={seconds}",
            f"--log-json={log_file}",
        ]
        argv += [f"--header={name}:{value}" for name, value in self.headers.items()]
        argv.append(url)  # last, after all options
        return argv

    async def scan(self, url: str) -> list[Technology]:
        with tempfile.TemporaryDirectory(prefix="web-enum-whatweb-") as tmp:
            log_file = Path(tmp) / "whatweb.json"
            async with self.limiter:  # its one request counts like ours
                result = await self.runner(self.argv(url, log_file),
                                           timeout=self.timeout * 4 + 30)
            text = log_file.read_text(encoding="utf-8", errors="replace") \
                if log_file.is_file() else ""
        if not text.strip():
            raise ModuleError(f"whatweb produced no output ({result.last_error_line()})")
        technologies = parse_whatweb_json(text)
        log.debug("whatweb: %d technologies", len(technologies))
        return technologies


def parse_whatweb_json(text: str) -> list[Technology]:
    data = _load_lenient(text)
    entries = data if isinstance(data, list) else [data]
    found: dict[str, Technology] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("plugins"), dict):
            continue  # e.g. the trailing {} some versions write
        for plugin, details in entry["plugins"].items():
            if not isinstance(plugin, str) or plugin in SKIP_PLUGINS:
                continue
            tech = _technology(plugin, details if isinstance(details, dict) else {})
            found.setdefault(tech.name.lower(), tech)
    return list(found.values())


def _load_lenient(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_TRAILING_COMMA.sub(r"\1", text.strip()))
    except json.JSONDecodeError as exc:
        raise ModuleError(f"whatweb output is not valid JSON: {exc}") from None


def _technology(plugin: str, details: dict[str, Any]) -> Technology:
    versions = _strings(details.get("version"))
    evidence = [f"whatweb {plugin}"]
    for key in ("string", "os", "module"):
        values = _strings(details.get(key))
        if values:
            evidence.append(f"whatweb {plugin} {key}: {', '.join(values)[:100]}")
    name = ALIASES.get(plugin.lower(), plugin)
    return Technology(
        name=name,
        category="Other",  # whatweb has no categories; merging keeps the native one
        version=versions[0] if versions else "",
        evidence=tuple(evidence),
        sources=("whatweb",),
    )


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if isinstance(v, (str, int, float))][:5]
    if isinstance(value, (str, int, float)):
        return [str(value)]
    return []
