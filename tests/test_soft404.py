"""Soft-404 calibration and matching."""

from __future__ import annotations

import pytest

from web_enum.discovery.soft404 import (
    NotFoundProfile,
    Probe,
    count_words_lines,
    make_probe,
    probe_paths,
)
from web_enum.http import HttpResponse

SOFT = b"<html>\n<p>Page not found here</p>\n</html>"


def probe(path: str, status: int = 200, body: bytes = SOFT, length: int | None = None,
          location: str | None = None) -> Probe:
    return Probe(path, status, body, len(body) if length is None else length, location)


def native_counts(body: bytes) -> tuple[int, int]:
    return count_words_lines(body, "native")


def test_count_words_lines_per_engine() -> None:
    body = b"a  b\tc\nd\n"
    assert count_words_lines(body, "native") == (4, 2)
    assert count_words_lines(body, "feroxbuster") == (4, 2)
    assert count_words_lines(body, "ffuf") == (3, 3)  # Go split on " " and "\n"


def test_probe_paths_are_random_and_varied() -> None:
    first, second = probe_paths(4, ["php"]), probe_paths(4, ["php"])
    assert len(first) == 4 and first != second
    assert first[2].endswith(".php") and first[3].endswith("/")
    assert len({len(p) for p in first}) == 4  # different lengths reveal path reflection
    assert probe_paths(3, [])[2].endswith(".html")


def test_404_is_always_not_found() -> None:
    assert NotFoundProfile([]).is_not_found(path="x", status=404, length=1, words=1, lines=1)


def test_same_structure_is_not_found_real_page_is_found() -> None:
    profile = NotFoundProfile([probe("abcdefghij")])
    words, lines = native_counts(SOFT)
    assert profile.is_not_found(path="admin", status=200, length=999, words=words, lines=lines)
    assert not profile.is_not_found(path="admin", status=200, length=2311, words=402, lines=61)
    assert not profile.is_not_found(path="admin", status=403, length=len(SOFT), words=words,
                                    lines=lines)  # other status: different answer


def test_reflected_path_detected_and_used() -> None:
    def page(path: str) -> bytes:
        return f"No such page: /{path}, sorry pal".encode()

    a, b = "abcdefghij", "abcdefghijklmnopqr"
    profile = NotFoundProfile([probe(a, body=page(a)), probe(b, body=page(b))])
    assert profile.reflects_path
    candidate = "backup-2024-final-version"
    body = page(candidate)
    # words differ? no - same structure; but also check pure length logic with odd counts:
    assert profile.is_not_found(path=candidate, status=200, length=len(body), words=99,
                                lines=99)
    assert not profile.is_not_found(path=candidate, status=200, length=len(body) + 50,
                                    words=99, lines=99)


def test_no_reflection_when_lengths_constant() -> None:
    assert not NotFoundProfile([probe("abc"), probe("abcdefgh")]).reflects_path


def test_constant_redirect_is_not_found_but_directory_redirect_is_found() -> None:
    profile = NotFoundProfile([probe("abcdefghij", status=302, location="/login")])
    assert profile.is_not_found(path="admin", status=302, length=0, words=0, lines=0,
                                location="http://example.com/login")
    assert not profile.is_not_found(path="admin", status=302, length=0, words=0, lines=0,
                                    location="http://example.com/admin/")


def test_redirect_template_with_path() -> None:
    # server that adds a slash to ANY path: indistinguishable, so treated as not found
    profile = NotFoundProfile([probe("abcdefghij", status=301, location="/{path}/")])
    assert profile.is_not_found(path="admin", status=301, length=0, words=0, lines=0,
                                location="/admin/")


def test_engine_flavor_used_for_counts() -> None:
    body = b"Not  found\n"  # double space: ffuf counts 3 words, native 2
    profile = NotFoundProfile([probe("abcdefghij", body=body, length=500)])
    assert profile.is_not_found(path="x", status=200, length=1, words=3, lines=2, flavor="ffuf")
    assert not profile.is_not_found(path="x", status=200, length=1, words=3, lines=2)


def test_make_probe_uses_content_length_when_truncated() -> None:
    response = HttpResponse("http://example.com/abc", 200, (("content-length", "50000"),),
                            b"x" * 100, truncated=True)
    assert make_probe("abc", response).length == 50000
    bogus = HttpResponse("http://example.com/abc", 200, (("content-length", "lots"),),
                         b"x" * 100, truncated=True)
    assert make_probe("abc", bogus).length == 100


def test_make_probe_location_template() -> None:
    response = HttpResponse("http://example.com/abcdef", 301,
                            (("location", "http://example.com/abcdef/"),), b"")
    assert make_probe("abcdef", response).location_template == "/{path}/"


def test_matches_response() -> None:
    profile = NotFoundProfile([probe("abcdefghij")])
    soft = HttpResponse("http://example.com/admin", 200, (), SOFT)
    real = HttpResponse("http://example.com/admin", 200, (), b"<h1>Admin</h1> login form here")
    assert profile.matches_response("admin", soft)
    assert not profile.matches_response("admin", real)


@pytest.mark.parametrize(
    ("probes", "text"),
    [([], "no calibration"),
     ([probe("abc", status=404, body=b"nf")], "random paths answer 404 (2 bytes)")],
)
def test_describe(probes: list[Probe], text: str) -> None:
    assert NotFoundProfile(probes).describe() == text


def test_describe_reflection() -> None:
    profile = NotFoundProfile([probe("ab", body=b"x/ab"), probe("abcd", body=b"x/abcd")])
    assert profile.describe().endswith(", reflects the path")
    assert profile.statuses == {200}
