"""Load and validate the YAML configuration.

Layers: bundled ``data/default_config.yaml`` <- user file (``--config`` or
``$XDG_CONFIG_HOME/web-enum/config.yaml``). Mappings are merged recursively,
lists are replaced. The result is a tree of frozen dataclasses: after loading,
nothing in the program can modify the configuration by accident.

Validation is strict: unknown keys are rejected (a typo such as ``concurency``
would otherwise be silently ignored) and every error names the exact key.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from web_enum import __version__
from web_enum.errors import ConfigError, InvalidTargetError
from web_enum.target import normalize_scope_entry

APP_DIR_NAME = "web-enum"
CONFIG_FILE_NAME = "config.yaml"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
MODULE_NAMES = ("fingerprint", "headers", "discovery", "forms")
TOOL_NAMES = ("ffuf", "feroxbuster", "whatweb")
DISCOVERY_BACKENDS = ("auto", "ffuf", "feroxbuster", "native")
FINGERPRINT_BACKENDS = ("auto", "whatweb", "native")

_EXTENSION_RE = re.compile(r"^[a-z0-9]{1,10}$")
_TOP_KEYS = (
    "output_dir", "log_level", "scope", "http", "limits", "modules", "tools", "discovery",
    "forms",
)


@dataclass(frozen=True)
class HttpSettings:
    timeout: float
    max_retries: int
    max_retry_wait: float
    verify_tls: bool
    max_body_kb: int
    user_agent: str


@dataclass(frozen=True)
class LimitSettings:
    concurrency: int
    rate: float
    max_requests: int


@dataclass(frozen=True)
class ToolSettings:
    discovery: str
    fingerprint: str
    paths: dict[str, str]


@dataclass(frozen=True)
class DiscoverySettings:
    wordlist: str
    wordlist_candidates: tuple[str, ...]
    extensions: tuple[str, ...]
    status_codes: tuple[int, ...]
    recursion_depth: int
    soft404_probes: int


@dataclass(frozen=True)
class FormSettings:
    max_pages: int


@dataclass(frozen=True)
class Config:
    output_dir: Path
    log_level: str
    scope: tuple[str, ...]
    http: HttpSettings
    limits: LimitSettings
    modules: dict[str, bool]
    tools: ToolSettings
    discovery: DiscoverySettings
    forms: FormSettings
    origins: tuple[str, ...]

    @property
    def enabled_modules(self) -> tuple[str, ...]:
        return tuple(name for name in MODULE_NAMES if self.modules[name])


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def user_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_DIR_NAME / CONFIG_FILE_NAME


def load_config(
    path: Path | None = None, *, search_user_config: bool = True,
    overrides: dict[str, Any] | None = None,
) -> Config:
    """Bundled defaults <- user file <- ``overrides`` (command-line options).

    Overrides go through exactly the same validation as the YAML, so
    ``--concurrency 500`` fails with the same message as ``concurrency: 500``.
    """
    raw = _parse_yaml(_bundled_text(), "<bundled defaults>")
    origins = ["<bundled defaults>"]

    user_file: Path | None = None
    if path is not None:
        user_file = path.expanduser()
        if not user_file.is_file():
            raise ConfigError(f"Config file not found: {user_file}")
    elif search_user_config and user_config_path().is_file():
        user_file = user_config_path()

    if user_file is not None:
        raw = deep_merge(raw, _parse_yaml(user_file.read_text(encoding="utf-8"), str(user_file)))
        origins.append(str(user_file))

    if overrides:
        raw = deep_merge(raw, overrides)
        origins.append("command line")

    return _build(raw, tuple(origins))


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge ``override`` into ``base``: mappings recursively, anything else replaced."""
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _bundled_text() -> str:
    return (
        resources.files("web_enum")
        .joinpath("data")
        .joinpath("default_config.yaml")
        .read_text(encoding="utf-8")
    )


def _parse_yaml(text: str, origin: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)  # safe_load: never builds arbitrary Python objects
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {origin}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{origin}: top level must be a mapping")
    return data


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def _build(raw: dict[str, Any], origins: tuple[str, ...]) -> Config:
    _check_keys(raw, _TOP_KEYS, "")

    log_level = _str(raw, "log_level", "").upper()
    if log_level not in LOG_LEVELS:
        raise ConfigError(f"'log_level' must be one of {', '.join(LOG_LEVELS)}")

    scope = tuple(
        dict.fromkeys(_scope_entry(e) for e in _str_list(raw, "scope", "") if e.strip())
    )

    h = _section(raw, "http", "")
    _check_keys(h, ("timeout", "max_retries", "max_retry_wait", "verify_tls", "max_body_kb",
                    "user_agent"), "http")
    http = HttpSettings(
        timeout=_number(h, "timeout", "http", minimum=1),
        max_retries=_int(h, "max_retries", "http", minimum=0),
        max_retry_wait=_number(h, "max_retry_wait", "http", minimum=0),
        verify_tls=_bool(h, "verify_tls", "http"),
        max_body_kb=_int(h, "max_body_kb", "http", minimum=16),
        user_agent=_str(h, "user_agent", "http").replace("{version}", __version__),
    )

    li = _section(raw, "limits", "")
    _check_keys(li, ("concurrency", "rate", "max_requests"), "limits")
    limits = LimitSettings(
        concurrency=_int(li, "concurrency", "limits", minimum=1, maximum=100),
        rate=_number(li, "rate", "limits", minimum=0.1),
        max_requests=_int(li, "max_requests", "limits", minimum=1),
    )

    mo = _section(raw, "modules", "")
    _check_keys(mo, MODULE_NAMES, "modules")
    modules = {name: _bool(mo, name, "modules") for name in MODULE_NAMES}

    t = _section(raw, "tools", "")
    _check_keys(t, ("discovery", "fingerprint", "paths"), "tools")
    paths_raw = _section(t, "paths", "tools")
    _check_keys(paths_raw, TOOL_NAMES, "tools.paths")
    tools = ToolSettings(
        discovery=_choice(t, "discovery", "tools", DISCOVERY_BACKENDS),
        fingerprint=_choice(t, "fingerprint", "tools", FINGERPRINT_BACKENDS),
        paths={name: _str(paths_raw, name, "tools.paths") for name in paths_raw},
    )

    d = _section(raw, "discovery", "")
    _check_keys(d, ("wordlist", "wordlist_candidates", "extensions", "status_codes",
                    "recursion_depth", "soft404_probes"), "discovery")
    discovery = DiscoverySettings(
        wordlist=_str(d, "wordlist", "discovery"),
        wordlist_candidates=tuple(_str_list(d, "wordlist_candidates", "discovery")),
        extensions=tuple(_extension(e) for e in _str_list(d, "extensions", "discovery")),
        status_codes=_status_codes(d),
        recursion_depth=_int(d, "recursion_depth", "discovery", minimum=0, maximum=5),
        soft404_probes=_int(d, "soft404_probes", "discovery", minimum=1, maximum=10),
    )

    f = _section(raw, "forms", "")
    _check_keys(f, ("max_pages",), "forms")
    forms = FormSettings(max_pages=_int(f, "max_pages", "forms", minimum=1))

    return Config(
        output_dir=Path(_str(raw, "output_dir", "")).expanduser(),
        log_level=log_level,
        scope=scope,
        http=http,
        limits=limits,
        modules=modules,
        tools=tools,
        discovery=discovery,
        forms=forms,
        origins=origins,
    )


def _scope_entry(value: str) -> str:
    try:
        return normalize_scope_entry(value)
    except InvalidTargetError as exc:
        raise ConfigError(f"'scope': {exc}") from None


def _extension(value: str) -> str:
    ext = value.strip().lstrip(".").lower()
    if not _EXTENSION_RE.match(ext):
        raise ConfigError(f"'discovery.extensions': '{value}' is not a valid extension")
    return ext


def _status_codes(d: dict[str, Any]) -> tuple[int, ...]:
    value = _get(d, "status_codes", "discovery")
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(c, int) and not isinstance(c, bool) and 100 <= c <= 599
                   for c in value)
    ):
        raise ConfigError("'discovery.status_codes' must be a non-empty list of HTTP codes")
    return tuple(sorted(set(value)))


# Generic helpers -------------------------------------------------------------
def _name(where: str, key: str) -> str:
    return f"{where}.{key}" if where else key


def _check_keys(mapping: dict[str, Any], allowed: tuple[str, ...], where: str) -> None:
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise ConfigError(
            f"Unknown key(s) in '{where or 'config'}': {', '.join(map(str, unknown))}. "
            f"Allowed: {', '.join(allowed)}"
        )


def _get(mapping: dict[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        raise ConfigError(f"Missing required key '{_name(where, key)}'")
    return mapping[key]


def _section(mapping: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    value = _get(mapping, key, where)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"'{_name(where, key)}' must be a mapping")
    return value


def _str(mapping: dict[str, Any], key: str, where: str) -> str:
    value = _get(mapping, key, where)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"'{_name(where, key)}' must be a non-empty string")
    return value.strip()


def _str_list(mapping: dict[str, Any], key: str, where: str) -> list[str]:
    value = _get(mapping, key, where)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{_name(where, key)}' must be a list of strings")
    return value


def _bool(mapping: dict[str, Any], key: str, where: str) -> bool:
    value = _get(mapping, key, where)
    if not isinstance(value, bool):
        raise ConfigError(f"'{_name(where, key)}' must be true or false")
    return value


def _number(mapping: dict[str, Any], key: str, where: str, *, minimum: float) -> float:
    value = _get(mapping, key, where)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"'{_name(where, key)}' must be a number")
    if value < minimum:
        raise ConfigError(f"'{_name(where, key)}' must be >= {minimum:g}")
    return float(value)


def _int(
    mapping: dict[str, Any], key: str, where: str, *, minimum: int, maximum: int | None = None
) -> int:
    value = _get(mapping, key, where)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"'{_name(where, key)}' must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        bounds = f">= {minimum}" if maximum is None else f"between {minimum} and {maximum}"
        raise ConfigError(f"'{_name(where, key)}' must be {bounds}")
    return value


def _choice(mapping: dict[str, Any], key: str, where: str, options: tuple[str, ...]) -> str:
    value = _str(mapping, key, where).lower()
    if value not in options:
        raise ConfigError(f"'{_name(where, key)}' must be one of {', '.join(options)}")
    return value
