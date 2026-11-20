"""Configuration: bundled defaults, user overrides, strict validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import WriteConfig
from web_enum import __version__
from web_enum.config import MODULE_NAMES, deep_merge, load_config, user_config_path
from web_enum.errors import ConfigError


def test_bundled_defaults_are_valid_and_conservative() -> None:
    cfg = load_config(search_user_config=False)
    assert cfg.origins == ("<bundled defaults>",)
    assert cfg.scope == ()  # nothing is authorised by default
    assert cfg.limits.concurrency == 10
    assert cfg.limits.rate == 20
    assert cfg.limits.max_requests == 5000
    assert cfg.enabled_modules == MODULE_NAMES
    assert cfg.tools.discovery == "auto"
    assert cfg.discovery.wordlist == "auto"
    assert cfg.discovery.recursion_depth == 0
    assert 404 not in cfg.discovery.status_codes
    assert __version__ in cfg.http.user_agent and "{version}" not in cfg.http.user_agent


def test_user_file_overrides_only_given_keys(write_config: WriteConfig) -> None:
    path = write_config(
        "scope: [lab.local, 10.10.10.0/24]\n"
        "limits: {concurrency: 3}\n"
        "modules: {forms: false}\n"
        "tools: {discovery: FFUF, paths: {ffuf: /opt/ffuf}}\n"
        "discovery: {extensions: [.PHP, txt]}\n"
    )
    cfg = load_config(path)
    assert cfg.origins == ("<bundled defaults>", str(path))
    assert cfg.scope == ("lab.local", "10.10.10.0/24")
    assert cfg.limits.concurrency == 3
    assert cfg.limits.rate == 20  # untouched default survives the merge
    assert cfg.enabled_modules == ("fingerprint", "headers", "discovery")
    assert cfg.tools.discovery == "ffuf"
    assert cfg.tools.fingerprint == "auto"
    assert cfg.tools.paths == {"ffuf": "/opt/ffuf"}
    assert cfg.discovery.extensions == ("php", "txt")


def test_user_config_found_in_xdg_dir(tmp_path: Path) -> None:
    path = user_config_path()
    assert path == tmp_path / "xdg" / "web-enum" / "config.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("log_level: debug\n", encoding="utf-8")
    cfg = load_config()
    assert cfg.log_level == "DEBUG"
    assert cfg.origins[-1] == str(path)
    # ...and ignored when explicitly asked not to look for it.
    assert load_config(search_user_config=False).log_level == "INFO"


def test_command_line_overrides_win_and_are_validated(write_config: WriteConfig) -> None:
    path = write_config("limits: {rate: 5, concurrency: 3}\n")
    cfg = load_config(path, overrides={"limits": {"rate": 50}})
    assert cfg.limits.rate == 50 and cfg.limits.concurrency == 3
    assert cfg.origins == ("<bundled defaults>", str(path), "command line")
    with pytest.raises(ConfigError, match="'limits.concurrency' must be between 1 and 100"):
        load_config(overrides={"limits": {"concurrency": 500}})


def test_empty_user_file_keeps_defaults(write_config: WriteConfig) -> None:
    assert load_config(write_config("")).limits.concurrency == 10


def test_missing_config_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_deep_merge_recurses_into_mappings_and_replaces_lists() -> None:
    base = {"a": {"b": 1, "c": {"d": 2}}, "l": [1, 2]}
    merged = deep_merge(base, {"a": {"c": {"e": 3}}, "l": [9]})
    assert merged == {"a": {"b": 1, "c": {"d": 2, "e": 3}}, "l": [9]}
    assert base == {"a": {"b": 1, "c": {"d": 2}}, "l": [1, 2]}  # input untouched


@pytest.mark.parametrize(
    ("yaml_text", "message"),
    [
        ("- not a mapping\n", "top level must be a mapping"),
        ("limits: {concurrency: [\n", "Invalid YAML"),
        ("concurency: 5\n", r"Unknown key\(s\) in 'config': concurency"),
        ("limits: {concurency: 5}\n", r"Unknown key\(s\) in 'limits'"),
        ("log_level: LOUD\n", "'log_level' must be one of"),
        ("limits: {concurrency: 0}\n", "'limits.concurrency' must be between 1 and 100"),
        ("limits: {concurrency: 500}\n", "between 1 and 100"),
        ("limits: {concurrency: 2.5}\n", "'limits.concurrency' must be an integer"),
        ("limits: {rate: 0}\n", "'limits.rate' must be >= 0.1"),
        ("limits: {rate: fast}\n", "'limits.rate' must be a number"),
        ("http: {verify_tls: 'yes'}\n", "'http.verify_tls' must be true or false"),
        ("http: {timeout: true}\n", "'http.timeout' must be a number"),
        ("http: {user_agent: ''}\n", "'http.user_agent' must be a non-empty string"),
        ("http: 5\n", "'http' must be a mapping"),
        ("modules: {exploit: true}\n", r"Unknown key\(s\) in 'modules': exploit"),
        ("tools: {discovery: gobuster}\n", "'tools.discovery' must be one of"),
        ("tools: {paths: {nmap: /usr/bin/nmap}}\n", r"Unknown key\(s\) in 'tools.paths'"),
        ("scope: lab.local\n", "'scope' must be a list of strings"),
        ("discovery: {extensions: ['p h p']}\n", "not a valid extension"),
        ("discovery: {status_codes: []}\n", "non-empty list of HTTP codes"),
        ("discovery: {status_codes: [200, 999]}\n", "non-empty list of HTTP codes"),
        ("discovery: {recursion_depth: 9}\n", "between 0 and 5"),
        ("forms: {max_pages: 0}\n", "'forms.max_pages' must be >= 1"),
    ],
)
def test_invalid_values_name_the_key(
    write_config: WriteConfig, yaml_text: str, message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(write_config(yaml_text))


def test_scope_entries_normalised_and_deduplicated(write_config: WriteConfig) -> None:
    cfg = load_config(
        write_config("scope: ['*.Lab.Local', lab.local, 'http://box.htb:8080/', 10.10.10.9/24]\n")
    )
    assert cfg.scope == ("lab.local", "box.htb", "10.10.10.0/24")


def test_invalid_scope_entry_is_a_config_error(write_config: WriteConfig) -> None:
    with pytest.raises(ConfigError, match="'scope': Invalid scope entry '10.0.0.0/40'"):
        load_config(write_config("scope: [10.0.0.0/40]\n"))


def test_null_lists_mean_empty(write_config: WriteConfig) -> None:
    cfg = load_config(write_config("scope: null\ndiscovery: {extensions: null}\n"))
    assert cfg.scope == ()
    assert cfg.discovery.extensions == ()


def test_missing_required_key_after_merge(write_config: WriteConfig) -> None:
    # Setting a section to null removes it entirely; its required keys are then missing.
    with pytest.raises(ConfigError, match="Missing required key 'limits.concurrency'"):
        load_config(write_config("limits: null\n"))


def test_status_codes_are_deduplicated_and_sorted(write_config: WriteConfig) -> None:
    cfg = load_config(write_config("discovery: {status_codes: [403, 200, 200]}\n"))
    assert cfg.discovery.status_codes == (200, 403)


def test_config_is_immutable() -> None:
    cfg = load_config(search_user_config=False)
    with pytest.raises(AttributeError):
        cfg.limits.rate = 1000  # type: ignore[misc]
