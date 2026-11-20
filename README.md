# web-enum

Web enumeration for **authorised** targets. Give it a URL and it fingerprints the
technologies, discovers content with wordlists, analyses security headers,
cookies, CORS and HTML forms, and writes a **prioritised** report in Markdown and
JSON. Built for Kali / Parrot: it drives **whatweb**, **ffuf** and
**feroxbuster** when they are installed and falls back to its own Python engine
when they are not.

```bash
web-enum scan http://10.10.11.42 --authorized --dry-run   # see the plan, send nothing
web-enum scan http://10.10.11.42 --authorized -x php,txt  # full scan
web-enum tools                                            # which Kali tools it found
```

> [!IMPORTANT]
> **Ethical scope.** Use web-enum only against targets you are **authorised to
> test**: your own labs, Hack The Box / TryHackMe machines, or a client's systems
> under a signed engagement. It is a **detection and documentation** tool: it
> never exploits, never submits forms, never brute-forces credentials, never
> tries to evade defences and never causes denial of service. The target is
> always given explicitly and must be authorised (see [Safeguards](#safeguards)).

---

## Contents

- [What it does](#what-it-does)
- [Safeguards](#safeguards)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [How a scan works](#how-a-scan-works)
- [Findings and severity](#findings-and-severity)
- [Reports](#reports)
- [Exit codes](#exit-codes)
- [Development](#development)
- [Architecture](#architecture)
- [Verification status](#verification-status)
- [What this project demonstrates](#what-this-project-demonstrates)
- [License](#license)

## What it does

| Module | What it checks | Engine |
|---|---|---|
| **fingerprint** | Web servers, languages, frameworks, CMS, panels (Tomcat, Jenkins, Grafana, phpMyAdmin...), JS libraries, **with versions** | 44 YAML rules on the page it already has + **whatweb** (`--aggression=1`) |
| **headers** | HTTPS / HSTS, CSP weaknesses, clickjacking, `nosniff`, Referrer/Permissions-Policy, version disclosure, cookie flags, CORS reflection | Python, plus one CORS probe request |
| **discovery** | Files and directories from a wordlist, `robots.txt` / `sitemap.xml` paths, 33 sensitive files (`.git`, `.env`, backups, SQL dumps, keys...) **verified by content**, directory listings, admin panels | **ffuf** or **feroxbuster** or native Python |
| **forms** | Passwords over HTTP or in URLs, cross-origin actions, POST forms without anti-CSRF tokens, file uploads | Python (forms are parsed, **never submitted**) |

Two things make the results trustworthy:

- **Soft-404 calibration.** Before discovery, random paths that cannot exist are
  requested to learn what "not found" looks like on this server (status, size,
  word/line counts, whether it reflects the path, whether everything redirects to
  /login). The same criterion filters results from every engine — word and line
  counts are recomputed the way ffuf and feroxbuster count them.
- **Content verification.** A sensitive file is reported only if its body proves
  it: `.git/HEAD` must start with `ref:`, `backup.zip` must start with `PK\x03\x04`,
  `.env` must contain `KEY=value` lines. Status codes lie; content does not.

## Safeguards

Enforced in code, each one with tests:

| Safeguard | How |
|---|---|
| **Explicit authorisation** | The target host must match `scope` in your config (hostname incl. subdomains, IP or CIDR such as `10.10.10.0/24`) or you pass `--authorized`. Otherwise: exit code 4, no request sent, nothing written. Checked even before `--dry-run`. DNS is never resolved to decide: authorising an IP does not authorise a name pointing to it. |
| **Never leaves the target** | Every request is checked against the target's origin (scheme + host + port) in the HTTP engine itself. Off-site links, redirects, sitemap entries and form actions are reported, never followed. |
| **Never attacks** | Forms are never submitted; no payloads, no credential brute force, no WAF evasion (honest User-Agent, no IP/UA rotation, no bypass headers). |
| **Never floods** | One limiter for the whole scan: concurrency, requests/second and a request **budget**. `Retry-After` honoured; a `429` halves the global rate. External tools get the same limits *and* a time cap of `budget / rate` seconds, so even recursion cannot exceed the budget. |
| **Safe with hostile targets** | Bodies capped after decompression (gzip bombs), standard-library parsers, no XXE in sitemaps, target text escaped in Markdown reports (a page titled `<script>` stays text). |
| **Secrets stay secret** | Values of `-H` headers (cookies, tokens) are masked as `***` in the console and the log file. External tools always get argv lists, never a shell. |

## Installation

Python 3.10+. Designed for **Kali Linux / Parrot OS**; also runs on any OS with
the native engine.

```bash
# recommended: the Kali tools web-enum can drive (all optional)
sudo apt install ffuf feroxbuster whatweb seclists

# web-enum itself, as an isolated CLI tool
pipx install git+https://github.com/SPROMbash/web-enum.git
web-enum tools        # check what it found

# for development
git clone https://github.com/SPROMbash/web-enum.git && cd web-enum
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# What would run? (no request sent)
web-enum scan http://10.10.11.42 --authorized --dry-run

# HTB box, extensions, recursion one level deep
web-enum scan http://10.10.11.42 --authorized -x php,txt,bak -d 1

# Authenticated scan with a session cookie, slow and gentle
web-enum scan https://lab.local/app/ -H "Cookie: PHPSESSID=..." -t 5 --rate 5

# Only headers and forms, JSON only
web-enum scan https://lab.local --only headers,forms -f json

# Force an engine and a wordlist
web-enum scan http://box.htb:8080 --authorized -e feroxbuster \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

| Option | Description |
|---|---|
| `--authorized` | You are authorised to test this target (if it is not in `scope`). |
| `--only`, `--skip` | Modules: `fingerprint,headers,discovery,forms`. |
| `-w, --wordlist` | Wordlist (default: SecLists `common.txt`, then dirb, then the bundled list). |
| `-x, --extensions` | Extensions to append, e.g. `php,txt,bak`. |
| `-e, --engine` | `auto` (ffuf > feroxbuster > native), `ffuf`, `feroxbuster`, `native`. |
| `-d, --depth` | Recursion into discovered directories (0-5, default 0). |
| `-t, --concurrency` | Simultaneous requests (1-100, default 10). |
| `--rate` | Requests per second (default 20). |
| `--max-requests` | Request budget for the whole scan (default 5000). |
| `-H, --header` | Extra header, repeatable (`-H "Cookie: ..."`). Masked in logs. |
| `--verify-tls` | Verify certificates (off by default: labs use self-signed ones). |
| `-o, --output-dir` | Reports and `web-enum.log` (default `reports/`). |
| `-f, --format` | `md`, `json` or `both` (default). |
| `--dry-run` | Print the plan, the request estimate and exit. |
| `-v, --verbose` | Debug output. |

**Ctrl+C** stops the scan and still writes a report named `*-partial.*`, with the
modules that finished and the others marked *interrupted*.

## Configuration

Your file (`--config`, or `~/.config/web-enum/config.yaml`) is merged over the
bundled [`default_config.yaml`](src/web_enum/data/default_config.yaml); command-line
options are merged over both and validated the same way. Unknown keys are
errors, so typos never pass silently. `web-enum config` shows the result.

```yaml
# ~/.config/web-enum/config.yaml
scope:                       # targets you are authorised to test
  - 10.10.10.0/23            # HTB lab range
  - lab.local                # and its subdomains
limits: {concurrency: 10, rate: 20, max_requests: 5000}
tools:
  discovery: auto            # auto | ffuf | feroxbuster | native
  fingerprint: auto          # auto | whatweb | native
discovery:
  extensions: [php, txt]
  recursion_depth: 1
modules: {forms: true}
```

Detection logic is data, not code: technology fingerprints live in
[`tech_rules.yaml`](src/web_enum/data/tech_rules.yaml) and sensitive files in
[`sensitive_paths.yaml`](src/web_enum/data/sensitive_paths.yaml).

## How a scan works

```text
plan (no request yet): modules, engines, wordlist  ── --dry-run stops here
  │
main page ── no answer → exit 5
  │
  ├─ fingerprint  native rules on the main page + whatweb ──────────┐
  ├─ headers      main page + 1 CORS probe ─────────────────────────┤  one shared
  └─ discovery    robots/sitemap → soft-404 calibration →           │  rate limiter
                  sensitive files → ffuf/feroxbuster/native →       │  and budget
                  directory listings                                │
                    └─ forms  main page + discovered HTML pages ────┘
  │
report: findings de-duplicated and sorted by severity → .md + .json
```

Modules are isolated: if one fails (or an external tool crashes), its status says
why and the rest of the scan carries on.

## Findings and severity

| Severity | Meaning | Examples |
|---|---|---|
| **high** | Direct exposure that can lead to compromise | exposed `.git` / `.env` / backups / SQL dump / private key, password sent over HTTP or in a URL, CORS reflecting any origin with credentials |
| **medium** | Weakness that commonly enables an attack | directory listing, session cookie without `HttpOnly`/`Secure`, CORS reflection, `phpinfo()`, Apache `server-status` |
| **low** | Missing hardening or information disclosure | no CSP / clickjacking protection / `nosniff`, version in `Server`, POST form without CSRF token |
| **info** | Useful observations | admin/login panels, file upload forms, missing Referrer-Policy |

Every finding has an id, the URL, the **evidence** and a concrete
**recommendation**.

## Reports

`reports/<host>[-<port>]-<timestamp>.md` and `.json`:

- header: target, final URL, title, **why the scan was authorised**, limits in
  force, number of requests;
- summary by severity, then the prioritised findings table and their details;
- technologies (version, evidence, which engine saw them), discovered content
  (engine, wordlist, calibration), forms, checks the target passed, and the
  status of every module.

The JSON carries `"schema": "web-enum/report@1"` for tooling. Reports describe a
target's weaknesses: store them securely (`reports/` is git-ignored).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Report written (findings or not) |
| 1 | Unexpected error (details with `-v`) |
| 2 | Invalid URL, option, configuration or wordlist |
| 3 | A tool explicitly requested (e.g. `--engine ffuf`) is not installed |
| 4 | Target not authorised (not in `scope`, no `--authorized`) |
| 5 | Target unreachable |
| 130 | Interrupted with Ctrl+C (a partial report is written) |

## Development

```bash
pytest                                 # 467 tests, no network, no Kali tools needed
pytest --cov=web_enum --cov-branch     # 99% line + branch coverage
mypy                                   # strict typing, checked as Linux
ruff check src tests                   # lint
python -m build && twine check dist/*  # build and validate (never uploaded)
```

**No test touches the network or runs a Kali tool.** HTTP goes through
[respx](https://lundberg.github.io/respx/) (an unmocked request fails the test)
with a small fake web server; the process runner is injected, so "ffuf" and
"whatweb" are replaced by doubles that write realistic JSON output; the clock
and `sleep` are injected, so rate limits and back-off are asserted exactly and
cost no time. Security-relevant checks were also mutation-tested (break the
code, see the test fail).

## Architecture

```text
src/web_enum/
├── cli.py              Typer commands, ethical gate, options as a config layer
├── config.py           YAML layers -> strictly validated frozen dataclasses
├── target.py           URL normalisation, same-origin boundary, scope (host/IP/CIDR)
├── runner.py           plan, concurrent isolated modules, partial state, prioritisation
├── http.py             shared httpx client, origin check per request, retries, body cap
├── ratelimit.py        concurrency + rate + budget, back-pressure
├── models.py           Finding, Severity, Technology, DiscoveredPath, Form, Report
├── analyzers/          fingerprint · headers · forms (pure functions over responses)
├── discovery/          wordlist · soft404 · seeds · sensitive · native · external · run
├── tools/              process (safe subprocess) · whatweb · ffuf · feroxbuster
├── report/             markdown (escaped) · json_report · writer (atomic)
└── data/               default_config · tech_rules · sensitive_paths · wordlist
```

## Verification status

Being explicit about what has and has not been verified:

- ✅ The whole tool against a **real HTTP server** (a local site with an exposed
  `.git`, a backup, a directory listing, a hidden robots.txt path and HTML
  forms): every expected finding, at the configured rate.
- ✅ All logic with 467 hermetic tests (99% coverage).
- ⚠️ **whatweb, ffuf and feroxbuster themselves** have not been run yet: their
  integration is tested with realistic output fixtures, but their exact option
  names and JSON formats must be confirmed on Kali (to do: one scan per engine
  against an HTB box, adjusting parsers/fixtures if needed).
- ⚠️ A real Ctrl+C is simulated in tests (same `KeyboardInterrupt`) but not yet
  pressed on a live scan.

## What this project demonstrates

- **Offensive tooling with guardrails by design:** authorisation gate, origin
  boundary enforced in the HTTP layer, request budget that also binds external
  tools, read-only analysis.
- **Async Python:** `asyncio` + `httpx`, a worker pool, concurrent isolated
  modules sharing one rate limiter, cancellation that keeps partial results.
- **Integrating CLI tools safely:** argv lists, timeouts that kill, injectable
  process runner, tolerant and type-checked parsing of their output.
- **Accuracy over noise:** soft-404 calibration shared across engines, content
  verification, false-positive tests (a hardened site must yield zero findings).
- **Testability:** dependency injection (clock, sleep, process runner), HTTP
  mocked with respx, a fake web server, mutation-tested safeguards.
- **Clean packaging:** `pyproject.toml` (hatchling), `src/` layout, typed
  (`py.typed`), console entry point, PyPI-ready metadata.

## License

[MIT](LICENSE) © 2026 SpromBash
