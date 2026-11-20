"""The discovery module: choose an engine and run the whole pipeline.

Pipeline (each step keeps what it found even if a later one fails):

1. **seeds**: robots.txt and sitemap.xml paths;
2. **calibration**: the soft-404 profile;
3. **sensitive files**: ~30 known paths, verified by content;
4. **wordlist engine**: native, ffuf or feroxbuster, filtered by our criteria;
5. **seed paths**: requested natively and filtered the same way;
6. **directory listings**: detected in responses web-enum already has; other
   discovered directories (e.g. '/admin' -> '/admin/', or anything found by an
   external tool) are fetched to check, up to MAX_LISTING_CHECKS.

Running out of budget at any step stops the pipeline and marks the result
truncated; everything found so far is kept.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from web_enum.config import Config
from web_enum.discovery.external import ExternalEngine
from web_enum.discovery.native import (
    DiscoveryJob,
    EngineResult,
    NativeEngine,
    check_url,
    is_directory,
    is_listing,
)
from web_enum.discovery.seeds import collect_seeds
from web_enum.discovery.sensitive import probe_sensitive
from web_enum.discovery.soft404 import NotFoundProfile, make_probe, probe_paths
from web_enum.discovery.wordlist import Wordlist
from web_enum.errors import BudgetExhaustedError, ModuleError, ToolNotFoundError
from web_enum.http import HttpClient
from web_enum.log import get_logger
from web_enum.models import DiscoveredPath, Finding, Severity
from web_enum.target import Target
from web_enum.tools.feroxbuster import FeroxbusterEngine
from web_enum.tools.ffuf import FfufEngine
from web_enum.tools.process import ProcessRunner, find_tool, run_process

log = get_logger(__name__)

MAX_LISTING_CHECKS = 20
EXTERNAL_ENGINES: dict[str, type[ExternalEngine]] = {
    "ffuf": FfufEngine,
    "feroxbuster": FeroxbusterEngine,
}
_ADMIN = re.compile(
    r"/(admin|administrator|adminpanel|admin-panel|login|signin|dashboard|panel|console|"
    r"manager|cpanel|webadmin|backend|phpmyadmin|pma|adminer|wp-admin|wp-login\.php|"
    r"jenkins|grafana|kibana|host-manager|jmx-console|web-console)(/|\.php)?$",
    re.IGNORECASE,
)
Engine = NativeEngine | ExternalEngine
ToolFinder = Callable[[str, Mapping[str, str]], "str | None"]


@dataclass
class DiscoveryResult:
    engine: str
    wordlist: str
    words: int
    profile: str = ""
    paths: list[DiscoveredPath] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    truncated: bool = False


# --------------------------------------------------------------------------- #
# Engine selection
# --------------------------------------------------------------------------- #
def choose_engine(
    setting: str, tool_paths: Mapping[str, str], find: ToolFinder = find_tool
) -> tuple[str, str | None]:
    """(engine name, binary path). 'auto' prefers ffuf, then feroxbuster, then native."""
    if setting == "native":
        return "native", None
    if setting in EXTERNAL_ENGINES:
        path = find(setting, tool_paths)
        if path is None:
            raise ToolNotFoundError(
                f"tools.discovery is '{setting}' but {setting} was not found. Install it "
                f"(sudo apt install {setting}), set tools.paths.{setting}, or use 'auto'."
            )
        return setting, path
    for name in EXTERNAL_ENGINES:
        path = find(name, tool_paths)
        if path is not None:
            return name, path
    return "native", None


def build_engine(
    name: str, path: str | None, *, http: HttpClient, target: Target, config: Config,
    headers: Mapping[str, str] | None = None, runner: ProcessRunner = run_process,
) -> Engine:
    if name == "native" or path is None:
        return NativeEngine(http, concurrency=config.limits.concurrency)
    return EXTERNAL_ENGINES[name](
        path, target=target, limiter=http.limiter, user_agent=config.http.user_agent,
        timeout=config.http.timeout, headers=headers, runner=runner,
    )


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
async def calibrate(http: HttpClient, target: Target, config: Config) -> NotFoundProfile:
    probes = []
    for path in probe_paths(config.discovery.soft404_probes, config.discovery.extensions):
        try:
            response = await http.fetch(target.join(path))
        except BudgetExhaustedError:
            raise
        except ModuleError as exc:
            log.debug("calibration probe %s failed: %s", path, exc)
            continue
        probes.append(make_probe(path, response))
    profile = NotFoundProfile(probes)
    log.info("Soft-404 calibration: %s", profile.describe())
    return profile


async def run_discovery(
    http: HttpClient, target: Target, config: Config, engine: Engine, wordlist: Wordlist,
) -> DiscoveryResult:
    result = DiscoveryResult(engine=engine.name, wordlist=wordlist.source,
                             words=len(wordlist.words))
    if wordlist.rejected:
        result.notes.append(f"{wordlist.rejected} unsafe wordlist entries skipped")
    collected = EngineResult()
    try:
        seeds = await collect_seeds(http, target)
        result.notes.extend(seeds.notes)

        profile = await calibrate(http, target, config)
        result.profile = profile.describe()

        sensitive, notes = await probe_sensitive(http, target, profile)
        result.findings.extend(sensitive)
        result.notes.extend(notes)

        job = DiscoveryJob(
            base_url=target.base, words=wordlist.words, extensions=config.discovery.extensions,
            status_codes=config.discovery.status_codes,
            recursion_depth=config.discovery.recursion_depth, profile=profile,
        )
        try:
            collected = await engine.run(job)
        except ModuleError as exc:  # external tool failed: say so, keep the rest
            log.warning("%s failed: %s", engine.name, exc)
            result.notes.append(f"{engine.name} failed: {exc}")
        result.notes.extend(collected.notes)
        result.truncated = collected.truncated

        known = {p.url for p in collected.paths}
        for url, source in seeds.paths.items():
            if url not in known and url.startswith(target.base) and not collected.truncated:
                await check_url(http, url, url[len(target.base):], job, collected,
                                source=source)

        await _check_listings(http, collected)
    except BudgetExhaustedError:
        result.truncated = True
        result.notes.append("request budget exhausted: discovery stopped early")

    result.paths = sorted({p.url: p for p in collected.paths}.values(), key=lambda p: p.url)
    result.findings.extend(_path_findings(result.paths, collected.listings))
    return result


async def _check_listings(http: HttpClient, collected: EngineResult) -> None:
    """Fetch discovered directories not fetched yet (e.g. found as '/admin' -> '/admin/')."""
    fetched = {p.url for p in collected.paths if p.source not in EXTERNAL_ENGINES}
    pending = []
    for path in collected.paths:
        url = path.url if path.url.endswith("/") else path.url + "/"
        if is_directory(path) and url not in fetched and url not in pending:
            pending.append(url)
    for url in pending[:MAX_LISTING_CHECKS]:
        try:
            response = await http.fetch(url)
        except BudgetExhaustedError:
            raise
        except ModuleError:
            continue
        if is_listing(response):
            collected.listings.append(url)


def _path_findings(paths: list[DiscoveredPath], listings: list[str]) -> list[Finding]:
    findings = [
        Finding(
            id="directory-listing", title="Directory listing enabled", severity=Severity.MEDIUM,
            category="content", url=url, evidence="Auto-generated index page (Index of /...)",
            recommendation="Disable automatic indexes (Apache: Options -Indexes; nginx: "
                           "autoindex off) so file names are not exposed.",
        )
        for url in sorted(set(listings))
    ]
    admin = [p for p in paths if _ADMIN.search(p.url) or p.status == 401]
    if admin:
        findings.append(Finding(
            id="admin-interfaces", title="Login / administration interfaces found",
            severity=Severity.INFO, category="content", url=admin[0].url,
            evidence="; ".join(f"{p.status} {p.url}" for p in admin[:15]),
            recommendation="Restrict administration interfaces (VPN, IP allow-list) and make "
                           "sure they require strong authentication.",
        ))
    return findings
