"""Target parsing, same-origin boundary and the scope gate."""

from __future__ import annotations

import pytest

from web_enum.errors import InvalidTargetError, ScopeError
from web_enum.target import (
    Target,
    authorize,
    is_ip,
    normalize_host,
    normalize_scope_entry,
    parse_target,
    scope_match,
)


# --------------------------------------------------------------------------- #
# parse_target
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("text", "url", "base"),
    [
        ("10.10.11.42", "http://10.10.11.42/", "http://10.10.11.42/"),
        ("http://Box.HTB", "http://box.htb/", "http://box.htb/"),
        ("box.htb:8080", "http://box.htb:8080/", "http://box.htb:8080/"),
        ("https://example.com:443/", "https://example.com/", "https://example.com/"),
        ("http://example.com:80/app", "http://example.com/app", "http://example.com/app/"),
        ("https://example.com/app/", "https://example.com/app/", "https://example.com/app/"),
        (
            "https://example.com/app/login.php",
            "https://example.com/app/login.php",
            "https://example.com/app/",
        ),
        ("http://example.com/page#top", "http://example.com/page", "http://example.com/page/"),
        ("  http://example.com.  ", "http://example.com/", "http://example.com/"),
        ("http://[2001:db8::1]:8443/", "http://[2001:db8::1]:8443/", "http://[2001:db8::1]:8443/"),
        ("http://bücher.example", "http://xn--bcher-kva.example/", "http://xn--bcher-kva.example/"),
    ],
)
def test_parse_target_normalises(text: str, url: str, base: str) -> None:
    target = parse_target(text)
    assert target.url == url
    assert target.base == base


def test_target_fields() -> None:
    target = parse_target("HTTPS://Example.com:8443/a/b.php")
    assert target == Target("https", "example.com", 8443, "/a/b.php", "/a/")
    assert target.origin == "https://example.com:8443"
    assert not target.is_ip
    assert parse_target("192.0.2.10").is_ip


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "Empty target"),
        ("   ", "Empty target"),
        ("ftp://example.com", "Unsupported scheme 'ftp'"),
        ("file:///etc/passwd", "Unsupported scheme 'file'"),
        ("http://admin:secret@example.com/", "Credentials in the URL"),
        ("http://example.com/search?q=1", "query string"),
        ("http://", "No host"),
        ("http://example.com:99999/", "Invalid URL"),
        ("http://exa mple.com/", "Invalid hostname"),
        ("http://-bad-.com/", "Invalid hostname"),
        ("http://" + "a" * 64 + ".com/", "Invalid hostname"),
    ],
)
def test_parse_target_rejects(text: str, message: str) -> None:
    with pytest.raises(InvalidTargetError, match=message):
        parse_target(text)


def test_join_is_relative_to_base_directory() -> None:
    target = parse_target("http://example.com/app/login.php")
    assert target.join("admin/") == "http://example.com/app/admin/"
    assert target.join(".git/HEAD") == "http://example.com/app/.git/HEAD"
    assert target.join("/robots.txt") == "http://example.com/robots.txt"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("/admin", True),
        ("backup.zip", True),
        ("http://example.com:80/x", True),
        ("HTTP://EXAMPLE.COM/x", True),
        ("https://example.com/x", False),  # other scheme
        ("http://example.com:8080/x", False),  # other port
        ("http://sub.example.com/x", False),  # subdomain is another origin
        ("http://evil.test/x", False),
        ("//evil.test/x", False),  # protocol-relative link
        ("javascript:alert(1)", False),
        ("mailto:admin@example.com", False),
    ],
)
def test_same_origin_boundary(url: str, expected: bool) -> None:
    assert parse_target("http://example.com/app/").same_origin(url) is expected


# --------------------------------------------------------------------------- #
# hosts and scope entries
# --------------------------------------------------------------------------- #
def test_normalize_host() -> None:
    assert normalize_host("Box.HTB.") == "box.htb"
    assert normalize_host("[2001:DB8::1]") == "2001:db8::1"
    assert normalize_host("localhost") == "localhost"
    assert is_ip("10.10.11.42") and is_ip("::1") and not is_ip("box.htb")


@pytest.mark.parametrize(
    ("entry", "normalised"),
    [
        ("Lab.Local", "lab.local"),
        ("*.lab.local", "lab.local"),
        ("https://lab.local:8443/app", "lab.local"),
        ("box.htb:8080", "box.htb"),
        ("10.10.11.42", "10.10.11.42"),
        ("10.10.10.7/24", "10.10.10.0/24"),  # host bits dropped
        ("2001:db8::/32", "2001:db8::/32"),
        ("2001:DB8::1", "2001:db8::1"),
    ],
)
def test_normalize_scope_entry(entry: str, normalised: str) -> None:
    assert normalize_scope_entry(entry) == normalised


@pytest.mark.parametrize("entry", ["10.10.10.0/99", "lab/local", "*.", "https://", "bad host"])
def test_normalize_scope_entry_rejects(entry: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_scope_entry(entry)


SCOPE = ("lab.local", "10.10.10.0/24", "10.10.11.42", "2001:db8::/32")


@pytest.mark.parametrize(
    ("host", "entry"),
    [
        ("lab.local", "lab.local"),
        ("app.lab.local", "lab.local"),
        ("deep.app.LAB.local", "lab.local"),
        ("10.10.10.200", "10.10.10.0/24"),
        ("10.10.11.42", "10.10.11.42"),
        ("2001:db8::5", "2001:db8::/32"),
        # Look-alikes that must NOT match:
        ("evillab.local", None),  # suffix without a dot boundary
        ("lab.local.evil.test", None),  # scope name as a prefix
        ("10.10.11.43", None),
        ("10.10.12.1", None),
        ("box.htb", None),  # a name is never matched against IP entries (no DNS)
    ],
)
def test_scope_match(host: str, entry: str | None) -> None:
    assert scope_match(host, SCOPE) == entry


def test_ip_entry_does_not_authorise_hostname_pointing_to_it() -> None:
    assert scope_match("box.htb", ("10.10.11.42",)) is None


# --------------------------------------------------------------------------- #
# authorize: the ethical gate
# --------------------------------------------------------------------------- #
def test_authorize_in_scope() -> None:
    reason = authorize(parse_target("http://10.10.10.5"), SCOPE, authorized_flag=False)
    assert reason == "in scope (10.10.10.0/24)"


def test_authorize_with_flag() -> None:
    reason = authorize(parse_target("http://box.htb"), (), authorized_flag=True)
    assert reason == "--authorized given by the user"


def test_scope_wins_over_flag_in_the_reason() -> None:
    reason = authorize(parse_target("http://lab.local"), SCOPE, authorized_flag=True)
    assert reason == "in scope (lab.local)"


def test_authorize_refuses_out_of_scope() -> None:
    with pytest.raises(ScopeError, match="'box.htb' is not in your authorised scope") as info:
        authorize(parse_target("http://box.htb"), SCOPE, authorized_flag=False)
    assert info.value.exit_code == 4


def test_empty_scope_refuses_by_default() -> None:
    with pytest.raises(ScopeError):
        authorize(parse_target("http://192.0.2.1"), (), authorized_flag=False)
