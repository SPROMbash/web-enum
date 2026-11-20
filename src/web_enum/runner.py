"""Scan orchestration: plan, run the modules, consolidate and prioritise.

* :func:`plan_scan` decides *before any request* what will run: modules
  (config, ``--only``, ``--skip``), engines (whatweb, ffuf / feroxbuster /
  native) and the wordlist. A tool explicitly requested but missing is an error
  here, not halfway through a scan. ``--dry-run`` prints this plan.
* :func:`run_scan` fetches the main page (no answer -> TargetUnreachableError),
  then runs fingerprint, headers and discovery concurrently (sharing one rate
  limiter, so limits hold for the scan as a whole) and forms after discovery,
  because it analyses the pages discovery found. Every module is isolated: a
  failure is recorded in its status and the others carry on.
* Results land in :class:`ScanState` as each module finishes, so a Ctrl+C can
  still produce a report: finished modules keep their results, running ones
  are marked ``interrupted``.
* :func:`build_report` merges everything and sorts findings by severity.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from web_enum import __version__
from web_enum.analyzers.fingerprint import FingerprintResult, fingerprint
from web_enum.analyzers.forms import FormsResult, run_forms
from web_enum.analyzers.headers import HeaderAnalysis, run_headers
from web_enum.config import MODULE_NAMES, Config
from web_enum.discovery.run import DiscoveryResult, build_engine, choose_engine, run_discovery
from web_enum.discovery.wordlist import Wordlist, load_wordlist, resolve_wordlist
from web_enum.errors import ConfigError, ModuleError, TargetUnreachableError, ToolNotFoundError
from web_enum.http import HttpClient, HttpResponse, make_async_client, make_limiter
from web_enum.log import get_logger
from web_enum.models import Finding, ModuleStatus, Report
from web_enum.ratelimit import RateLimiter
from web_enum.target import Target
from web_enum.tools.process import ProcessRunner, find_tool, run_process
from web_enum.tools.whatweb import WhatWeb

log = get_logger(__name__)

ToolFinder = Callable[[str, Mapping[str, str]], "str | None"]


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ScanPlan:
    modules: tuple[str, ...]  # modules that will run, in MODULE_NAMES order
    skipped: dict[str, str]  # module -> reason
    whatweb: str | None = None  # whatweb binary, if it will be used
    discovery_engine: str = ""
    discovery_tool: str | None = None
    wordlist: Wordlist | None = None  # loaded at planning time: a bad file fails before any request


def parse_modules(text: str | None, option: str) -> set[str] | None:
    if text is None:
        return None
    names = {n.strip().lower() for n in text.split(",") if n.strip()}
    unknown = names - set(MODULE_NAMES)
    if unknown or not names:
        raise ConfigError(
            f"{option}: unknown module(s) {', '.join(sorted(unknown)) or '(none given)'}. "
            f"Known: {', '.join(MODULE_NAMES)}"
        )
    return names


def plan_scan(
    config: Config, *, only: set[str] | None = None, skip: set[str] | None = None,
    find: ToolFinder = find_tool,
) -> ScanPlan:
    modules: list[str] = []
    skipped: dict[str, str] = {}
    for name in MODULE_NAMES:
        if only is not None and name not in only:
            skipped[name] = "not selected (--only)"
        elif skip and name in skip:
            skipped[name] = "skipped (--skip)"
        elif only is None and not config.modules[name]:
            skipped[name] = "disabled in config (modules)"
        else:
            modules.append(name)
    if not modules:
        raise ConfigError("No module left to run with the current options and configuration.")

    whatweb: str | None = None
    if "fingerprint" in modules and config.tools.fingerprint != "native":
        whatweb = find("whatweb", config.tools.paths)
        if whatweb is None and config.tools.fingerprint == "whatweb":
            raise ToolNotFoundError(
                "tools.fingerprint is 'whatweb' but whatweb was not found. Install it "
                "(sudo apt install whatweb), set tools.paths.whatweb, or use 'auto'."
            )

    engine, tool, wordlist = "", None, None
    if "discovery" in modules:
        engine, tool = choose_engine(config.tools.discovery, config.tools.paths, find)
        wordlist = load_wordlist(resolve_wordlist(config.discovery.wordlist,
                                                  config.discovery.wordlist_candidates))
    return ScanPlan(tuple(modules), skipped, whatweb, engine, tool, wordlist)


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
@dataclass
class ScanState:
    started: float = field(default_factory=time.monotonic)
    main: HttpResponse | None = None
    statuses: dict[str, ModuleStatus] = field(default_factory=dict)
    running: set[str] = field(default_factory=set)
    fingerprint: FingerprintResult | None = None
    headers: HeaderAnalysis | None = None
    discovery: DiscoveryResult | None = None
    forms: FormsResult | None = None
    limiter: RateLimiter | None = None

    @property
    def requests_sent(self) -> int:
        return self.limiter.used if self.limiter is not None else 0


async def _module(
    state: ScanState, name: str, work: Callable[[], Awaitable[Any]],
    store: Callable[[Any], None],
) -> None:
    """Run one module in isolation; record its status. Cancellation propagates."""
    state.running.add(name)
    start = time.monotonic()
    log.info("Module %s: started", name)
    try:
        result = await work()
    except ModuleError as exc:
        log.warning("Module %s failed: %s", name, exc)
        state.statuses[name] = ModuleStatus(name, "error", time.monotonic() - start, str(exc))
    except Exception as exc:  # a bug in one module must not kill the scan
        log.debug("Module %s crashed", name, exc_info=True)
        log.error("Module %s: unexpected %s: %s", name, type(exc).__name__, exc)
        state.statuses[name] = ModuleStatus(
            name, "error", time.monotonic() - start, f"unexpected {type(exc).__name__}: {exc}")
    else:
        store(result)
        notes = tuple(getattr(result, "notes", ()))
        state.statuses[name] = ModuleStatus(name, "ok", time.monotonic() - start, notes=notes)
        log.info("Module %s: done in %.1fs", name, time.monotonic() - start)
    finally:
        state.running.discard(name)


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #
async def run_scan(
    target: Target, config: Config, plan: ScanPlan, state: ScanState, *,
    headers: Mapping[str, str] | None = None, client: httpx.AsyncClient | None = None,
    runner: ProcessRunner = run_process, limiter: RateLimiter | None = None,
) -> None:
    async with contextlib.AsyncExitStack() as stack:
        if client is None:
            client = await stack.enter_async_context(make_async_client(config, headers))
        active_limiter = limiter or make_limiter(config)
        state.limiter = active_limiter
        http = HttpClient.from_config(client, active_limiter, target, config)

        try:
            main = await http.fetch(target.url, follow_redirects=True)
        except ModuleError as exc:
            raise TargetUnreachableError(f"{target.url} did not answer: {exc}") from None
        state.main = main
        log.info("Target answered %d (%s)%s", main.status, main.url,
                 f", redirect to {main.blocked_redirect} not followed"
                 if main.blocked_redirect else "")

        def keep(attr: str) -> Callable[[Any], None]:
            return lambda result: setattr(state, attr, result)

        async def fingerprint_module() -> FingerprintResult:
            external = None
            if plan.whatweb is not None:
                external = WhatWeb(plan.whatweb, limiter=active_limiter,
                                   user_agent=config.http.user_agent,
                                   timeout=config.http.timeout, headers=headers, runner=runner)
            return await fingerprint(main, external=external)

        async def discovery_module() -> DiscoveryResult:
            if plan.wordlist is None:
                raise ModuleError("no wordlist in the scan plan")
            engine = build_engine(plan.discovery_engine, plan.discovery_tool, http=http,
                                  target=target, config=config, headers=headers, runner=runner)
            return await run_discovery(http, target, config, engine, plan.wordlist)

        async def forms_module() -> FormsResult:
            found = state.discovery.paths if state.discovery is not None else []
            return await run_forms(http, target, main, found, max_pages=config.forms.max_pages)

        async def discovery_then_forms() -> None:
            if "discovery" in plan.modules:
                await _module(state, "discovery", discovery_module, keep("discovery"))
            if "forms" in plan.modules:
                await _module(state, "forms", forms_module, keep("forms"))

        work: list[Awaitable[None]] = []
        if "fingerprint" in plan.modules:
            work.append(_module(state, "fingerprint", fingerprint_module, keep("fingerprint")))
        if "headers" in plan.modules:
            work.append(_module(state, "headers", lambda: run_headers(http, target, main),
                                keep("headers")))
        work.append(discovery_then_forms())
        await asyncio.gather(*work)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def prioritise(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """De-duplicate (same id + URL) and sort: severity, then category, then title."""
    unique = {(f.id, f.url): f for f in findings}
    return tuple(sorted(unique.values(),
                        key=lambda f: (f.severity.rank, f.category, f.title, f.url)))


def limits_summary(config: Config) -> str:
    lim = config.limits
    return (f"{lim.concurrency} concurrent, {lim.rate:g} req/s, budget {lim.max_requests} "
            "requests")


def build_report(
    target: Target, config: Config, plan: ScanPlan, state: ScanState, *,
    authorization: str, partial: bool = False, now: datetime | None = None,
) -> Report:
    statuses = []
    for name in MODULE_NAMES:
        if name in state.statuses:
            statuses.append(state.statuses[name])
        elif name in plan.skipped:
            statuses.append(ModuleStatus(name, "skipped", message=plan.skipped[name]))
        elif partial:
            statuses.append(ModuleStatus(name, "interrupted",
                                         message="interrupted before finishing"))
        else:
            statuses.append(ModuleStatus(name, "skipped", message="not run"))

    findings: list[Finding] = []
    if state.headers is not None:
        findings.extend(state.headers.findings)
    if state.discovery is not None:
        findings.extend(state.discovery.findings)
    if state.forms is not None:
        findings.extend(state.forms.findings)

    main = state.main
    fp = state.fingerprint
    disc = state.discovery
    return Report(
        target=target.url,
        final_url=main.url if main is not None else target.url,
        status=main.status if main is not None else 0,
        title=fp.title if fp is not None else "",
        generated=(now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        tool_version=__version__,
        authorization=authorization,
        partial=partial,
        limits=limits_summary(config),
        requests_sent=state.requests_sent,
        modules=tuple(statuses),
        findings=prioritise(findings),
        technologies=fp.technologies if fp is not None else (),
        paths=tuple(disc.paths) if disc is not None else (),
        forms=tuple(state.forms.forms) if state.forms is not None else (),
        passed_checks=tuple(state.headers.passed) if state.headers is not None else (),
        discovery_engine=disc.engine if disc is not None else "",
        wordlist=disc.wordlist if disc is not None else "",
        calibration=disc.profile if disc is not None else "",
    )
