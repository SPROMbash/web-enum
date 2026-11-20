"""Wordlists: resolution, sanitising, expansion."""

from __future__ import annotations

from pathlib import Path

import pytest

from web_enum.discovery import wordlist as wl
from web_enum.discovery.wordlist import BUNDLED, expand, load_wordlist, resolve_wordlist, sanitize
from web_enum.errors import ConfigError


def test_auto_picks_first_existing_candidate(tmp_path: Path) -> None:
    second = tmp_path / "common.txt"
    second.write_text("admin\n", encoding="utf-8")
    assert resolve_wordlist("auto", [str(tmp_path / "missing.txt"), str(second)]) == str(second)


def test_auto_falls_back_to_bundled(tmp_path: Path) -> None:
    assert resolve_wordlist("auto", [str(tmp_path / "nope.txt")]) == BUNDLED


def test_explicit_wordlist_is_used(tmp_path: Path) -> None:
    mine = tmp_path / "mine.txt"
    mine.write_text("x\n", encoding="utf-8")
    assert resolve_wordlist(str(mine), ["/usr/share/wordlists/dirb/common.txt"]) == str(mine)


def test_explicit_wordlist_must_exist(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="Wordlist not found"):
        resolve_wordlist(str(tmp_path / "missing.txt"), [])


def test_bundled_wordlist_loads_clean() -> None:
    words = load_wordlist(BUNDLED)
    assert words.source == BUNDLED
    assert len(words.words) > 150 and words.rejected == 0
    assert "admin" in words.words and "api/v1" in words.words
    assert len(set(words.words)) == len(words.words)


def test_load_sanitises_and_deduplicates(tmp_path: Path) -> None:
    path = tmp_path / "list.txt"
    path.write_text(
        "# comment\n\nadmin\n/admin\n  login.php  \n../../etc/passwd\nhttp://evil.test/x\n"
        "a b\nq?x=1\nfrag#1\nback\\slash\n//double\napi/../../x\n.git/HEAD\n",
        encoding="utf-8",
    )
    words = load_wordlist(str(path))
    # '//double' -> 'double': leading slashes are stripped, so it can no longer form a
    # protocol-relative URL ('//host/...'); harmless, kept.
    assert words.words == ("admin", "login.php", "double", ".git/HEAD")
    assert words.rejected == 7


def test_load_rejects_empty_and_unreadable(tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="no usable entries"):
        load_wordlist(str(empty))
    with pytest.raises(ConfigError, match="Cannot read wordlist"):
        load_wordlist(str(tmp_path))  # a directory


def test_max_words_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wl, "MAX_WORDS", 3)
    path = tmp_path / "big.txt"
    path.write_text("\n".join(f"w{i}" for i in range(10)), encoding="utf-8")
    assert load_wordlist(str(path)).words == ("w0", "w1", "w2")


@pytest.mark.parametrize(
    ("entry", "expected"),
    [("admin", "admin"), ("/admin/", "admin/"), ("a/b.php", "a/b.php"), ("..", None),
     ("x\x01y", None), ("", None), ("/", None)],
)
def test_sanitize(entry: str, expected: str | None) -> None:
    assert sanitize(entry) == expected


def test_expand_with_extensions() -> None:
    assert expand(["admin", "login.php", "images/", "api/v1", "admin"], ["php", "bak"]) == [
        "admin", "admin.php", "admin.bak", "login.php", "images/", "api/v1", "api/v1.php",
        "api/v1.bak",
    ]
    assert expand(["a"], []) == ["a"]
