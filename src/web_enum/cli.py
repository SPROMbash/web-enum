"""Command-line interface.

Commands:

* ``scan URL``  — enumerate an AUTHORISED web target;
* ``tools``     — which Kali / Parrot tools and wordlists are available;
* ``config``    — the effective configuration and where it comes from.

The ethical gate runs before anything else (even ``--dry-run``): the target's
host must be in ``scope`` or the user must pass ``--authorized``. Options are a
configuration layer validated like the YAML. Every expected failure is a
``WebEnumError`` turned into a message and an exit code by :func:`_guard`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
import yaml

from web_enum import __version__
from web_enum.config import Config, load_config
from web_enum.discovery.run import choose_engine
from web_enum.discovery.sensitive import default_sensitive_rules
from web_enum.discovery.wordlist import BUNDLED, expand, resolve_wordlist
from web_enum.errors import WebEnumError
from web_enum.http import parse_header
from web_enum.log import add_file_handler, get_logger, setup_logging
from web_enum.models import Report
from web_enum.report.writer import write_reports
from web_enum.runner import (
    ScanPlan,
    ScanState,
    build_report,
    limits_summary,
    parse_modules,
    plan_scan,
    run_scan,
)
from web_enum.target import Target, authorize, parse_target
from web_enum.tools.process import find_tool

log = get_logger(__name__)

ETHICS = (
    "Use only against targets you are AUTHORISED to test (your labs, HTB) or public "
    "information. It detects and documents; it never exploits."
)
EXIT_CODES = ("Exit codes: 0 ok, 1 unexpected error, 2 invalid input/config, 3 required tool "
              "missing, 4 target not authorised, 5 target unreachable, 130 interrupted.")

app = typer.Typer(
    help=f"Web enumeration for authorised targets.\n\n{ETHICS}\n\n{EXIT_CODES}",
    add_completion=False,
    no_args_is_help=True,
)


class Format(str, Enum):
    md = "md"
    json = "json"
    both = "both"


class EngineChoice(str, Enum):
    auto = "auto"
    ffuf = "ffuf"
    feroxbuster = "feroxbuster"
    native = "native"


ConfigOpt = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="YAML config (default: ~/.config/web-enum/config.yaml)."),
]
INSTALL_HINT = {"whatweb": "sudo apt install whatweb", "ffuf": "sudo apt install ffuf",
                "feroxbuster": "sudo apt install feroxbuster"}


def _version(value: bool) -> None:
    if value:
        typer.echo(f"web-enum {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version, is_eager=True, help="Show version and exit."),
    ] = None,
) -> None:
    """Web enumeration for authorised targets."""


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
@app.command()
def scan(
    url: Annotated[str, typer.Argument(
        help="Target URL, e.g. http://10.10.11.42 or box.htb:8080.")],
    authorized: Annotated[bool, typer.Option(
        "--authorized", help="I am authorised to test this target (if it is not in 'scope').")
    ] = False,
    only: Annotated[str | None, typer.Option(
        "--only", help="Run only these modules: fingerprint,headers,discovery,forms.")] = None,
    skip: Annotated[str | None, typer.Option("--skip", help="Skip these modules.")] = None,
    wordlist: Annotated[str | None, typer.Option(
        "--wordlist", "-w", help="Wordlist file (default: SecLists/dirb if installed).")] = None,
    extensions: Annotated[str | None, typer.Option(
        "--extensions", "-x", help="Extensions to try, e.g. php,txt,bak.")] = None,
    engine: Annotated[EngineChoice | None, typer.Option(
        "--engine", "-e", help="Discovery engine (default from config: auto).")] = None,
    depth: Annotated[int | None, typer.Option(
        "--depth", "-d", help="Recursion depth into found directories (0-5).")] = None,
    concurrency: Annotated[int | None, typer.Option(
        "--concurrency", "-t", help="Simultaneous requests (1-100).")] = None,
    rate: Annotated[float | None, typer.Option("--rate", help="Max requests per second.")] = None,
    max_requests: Annotated[int | None, typer.Option(
        "--max-requests", help="Request budget for the whole scan.")] = None,
    header: Annotated[list[str] | None, typer.Option(
        "--header", "-H", help="Extra header 'Name: value' (repeatable), e.g. a session cookie.")
    ] = None,
    verify_tls: Annotated[bool, typer.Option(
        "--verify-tls", help="Verify TLS certificates (off by default: labs use self-signed).")
    ] = False,
    config_path: ConfigOpt = None,
    output_dir: Annotated[Path | None, typer.Option(
        "--output-dir", "-o", help="Folder for reports and web-enum.log.")] = None,
    fmt: Annotated[Format, typer.Option("--format", "-f", help="Report format.")] = Format.both,
    dry_run: Annotated[bool, typer.Option(
        "--dry-run", help="Show the plan and exit; send no requests.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug output.")] = False,
) -> None:
    """Enumerate an AUTHORISED web target: technologies, content, headers and forms.

    The target must be in 'scope' (config) or you must pass --authorized.
    """
    overrides = _overrides(
        wordlist=wordlist, extensions=extensions, engine=engine, depth=depth,
        concurrency=concurrency, rate=rate, max_requests=max_requests,
        verify_tls=verify_tls, output_dir=output_dir,
    )
    _guard(lambda: _scan(url, authorized, only, skip, header or [], config_path, overrides,
                         fmt, dry_run, verbose), verbose=verbose)


def _overrides(
    *, wordlist: str | None, extensions: str | None, engine: EngineChoice | None,
    depth: int | None, concurrency: int | None, rate: float | None, max_requests: int | None,
    verify_tls: bool, output_dir: Path | None,
) -> dict[str, Any]:
    """Command-line options as a config layer (only the options actually given)."""
    out: dict[str, Any] = {}

    def put(section: str, key: str, value: Any) -> None:
        if value is not None:
            out.setdefault(section, {})[key] = value

    put("discovery", "wordlist", wordlist)
    if extensions is not None:
        put("discovery", "extensions", [e for e in extensions.split(",") if e.strip()])
    put("discovery", "recursion_depth", depth)
    put("tools", "discovery", engine.value if engine else None)
    put("limits", "concurrency", concurrency)
    put("limits", "rate", rate)
    put("limits", "max_requests", max_requests)
    if verify_tls:
        put("http", "verify_tls", True)
    if output_dir is not None:
        out["output_dir"] = str(output_dir)
    return out


def _scan(
    url: str, authorized: bool, only: str | None, skip: str | None, raw_headers: list[str],
    config_path: Path | None, overrides: dict[str, Any], fmt: Format, dry_run: bool,
    verbose: bool,
) -> None:
    headers = dict(parse_header(h) for h in raw_headers)
    secrets = [v for v in headers.values() if v]
    setup_logging("DEBUG" if verbose else "INFO", secrets=secrets)

    cfg = load_config(config_path, overrides=overrides or None)
    if not verbose:
        setup_logging(cfg.log_level, secrets=secrets)
    target = parse_target(url)
    authorization = authorize(target, cfg.scope, authorized_flag=authorized)  # exit 4 if not
    plan = plan_scan(cfg, only=parse_modules(only, "--only"),
                     skip=parse_modules(skip, "--skip"), find=find_tool)
    formats = ["md", "json"] if fmt is Format.both else [fmt.value]

    if dry_run:
        _print_plan(target, cfg, plan, authorization, formats)
        return

    add_file_handler(cfg.output_dir / "web-enum.log", secrets=secrets)
    log.info("web-enum %s: %s (%s)", __version__, target.url, authorization)
    log.info("Limits: %s", limits_summary(cfg))

    state = ScanState()
    partial = False
    try:
        asyncio.run(run_scan(target, cfg, plan, state, headers=headers))
    except KeyboardInterrupt:
        partial = True
        log.warning("Interrupted: writing a PARTIAL report with what finished.")

    report = build_report(target, cfg, plan, state, authorization=authorization,
                          partial=partial)
    paths = write_reports(report, cfg.output_dir, formats)
    _print_summary(report, paths)
    if partial:
        raise typer.Exit(130)


def estimate_requests(cfg: Config, plan: ScanPlan) -> int:
    """Rough request count for --dry-run (recursion and redirects not included)."""
    total = 1  # main page
    if "headers" in plan.modules:
        total += 1
    if "fingerprint" in plan.modules and plan.whatweb:
        total += 1
    if "discovery" in plan.modules and plan.wordlist is not None:
        total += 2 + cfg.discovery.soft404_probes + len(default_sensitive_rules())
        total += len(expand(plan.wordlist.words, cfg.discovery.extensions))
    if "forms" in plan.modules:
        total += cfg.forms.max_pages - 1
    return total


def _print_plan(target: Target, cfg: Config, plan: ScanPlan, authorization: str,
                formats: list[str]) -> None:
    echo = typer.echo
    estimate = estimate_requests(cfg, plan)
    echo("DRY RUN: no request will be sent.\n")
    echo(f"  Target       {target.url}  (discovery base: {target.base})")
    echo(f"  Authorised   {authorization}")
    echo(f"  Limits       {limits_summary(cfg)}")
    budget_note = "" if estimate <= cfg.limits.max_requests else "  -> exceeds the budget: " \
        "discovery will be cut"
    echo(f"  Estimate     ~{estimate} requests{budget_note}")
    echo(f"  Reports      {cfg.output_dir} ({', '.join(formats)})\n")
    details = {
        "fingerprint": "native rules" + (f" + whatweb ({plan.whatweb})" if plan.whatweb
                                         else " (whatweb not used)"),
        "headers": "security headers, cookies, CORS (1 probe request)",
        "forms": f"up to {cfg.forms.max_pages} pages, never submitted",
    }
    if plan.wordlist is not None:
        engine = plan.discovery_engine + (f" ({plan.discovery_tool})" if plan.discovery_tool
                                          else "")
        exts = ", ".join(cfg.discovery.extensions) or "none"
        details["discovery"] = (f"{engine}; wordlist {plan.wordlist.source} "
                                f"({len(plan.wordlist.words)} words); extensions {exts}; "
                                f"depth {cfg.discovery.recursion_depth}")
    for name in ("fingerprint", "headers", "discovery", "forms"):
        if name in plan.modules:
            echo(f"  [RUN ] {name:<12} {details[name]}")
        else:
            echo(f"  [skip] {name:<12} {plan.skipped.get(name, '')}")


def _print_summary(report: Report, paths: list[Path]) -> None:
    counts = report.severity_counts()
    log.info("Findings: %d high, %d medium, %d low, %d info (%d requests)", counts["high"],
             counts["medium"], counts["low"], counts["info"], report.requests_sent)
    for finding in report.findings:
        if finding.severity.value in ("high", "medium"):
            log.warning("  [%s] %s - %s", finding.severity.value.upper(), finding.title,
                        finding.url)
    for module in report.modules:
        if module.status in ("error", "interrupted"):
            log.warning("Module %s: %s %s", module.name, module.status, module.message)
    for path in paths:
        log.info("Report: %s", path)


# --------------------------------------------------------------------------- #
# tools
# --------------------------------------------------------------------------- #
@app.command("tools")
def list_tools(config_path: ConfigOpt = None) -> None:
    """Show which Kali / Parrot tools and wordlists web-enum can use."""
    _guard(lambda: _list_tools(config_path), verbose=False)


def _list_tools(config_path: Path | None) -> None:
    cfg = load_config(config_path)
    echo = typer.echo
    echo(f"{'TOOL':<13} {'STATUS':<8} PATH")
    for name in ("whatweb", "ffuf", "feroxbuster"):
        path = find_tool(name, cfg.tools.paths)
        status = "found" if path else "missing"
        echo(f"{name:<13} {status:<8} {path or '-  (' + INSTALL_HINT[name] + ')'}")
    engine, _ = choose_engine("auto", cfg.tools.paths, find_tool)
    echo(f"\nDiscovery engine with 'auto': {engine} (configured: {cfg.tools.discovery})")
    wordlist = resolve_wordlist("auto", cfg.discovery.wordlist_candidates)
    if wordlist == BUNDLED:
        wordlist = "bundled list (install seclists for better coverage)"
    echo(f"Wordlist with 'auto':         {wordlist}")


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
@app.command("config")
def show_config(config_path: ConfigOpt = None) -> None:
    """Show the effective configuration and where it was loaded from."""
    _guard(lambda: _show_config(config_path), verbose=False)


def _show_config(config_path: Path | None) -> None:
    cfg = load_config(config_path)
    typer.echo("# Loaded from: " + " <- ".join(cfg.origins))
    typer.echo(yaml.safe_dump(config_as_dict(cfg), sort_keys=False, allow_unicode=True), nl=False)


def config_as_dict(cfg: Config) -> dict[str, Any]:
    """Plain, YAML-friendly view of the configuration (paths and tuples converted)."""
    data = asdict(cfg)
    data.pop("origins")
    data["output_dir"] = str(cfg.output_dir)
    return {key: _plain(value) for key, value in data.items()}


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


# --------------------------------------------------------------------------- #
# Shared machinery
# --------------------------------------------------------------------------- #
def _guard(action: Callable[[], None], *, verbose: bool) -> None:
    """Run a command body, mapping expected errors to exit codes."""
    setup_logging("DEBUG" if verbose else "INFO")
    try:
        action()
    except typer.Exit:
        raise  # deliberate exit codes; typer.Exit IS an Exception, so re-raise it first
    except WebEnumError as exc:
        log.error("%s", exc)
        raise typer.Exit(exc.exit_code) from None
    except KeyboardInterrupt:
        log.error("Interrupted by user.")
        raise typer.Exit(130) from None
    except Exception as exc:
        log.debug("Unexpected error", exc_info=True)
        log.error("Unexpected error: %s: %s (re-run with -v for details)", type(exc).__name__, exc)
        raise typer.Exit(1) from None
