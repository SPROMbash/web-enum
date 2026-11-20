"""Wordlists: choose, load, sanitise, expand with extensions.

``wordlist: auto`` picks the first existing candidate (SecLists / dirb paths on
Kali and Parrot), falling back to the small list bundled with the package.

Every entry is sanitised: comments and blanks dropped, leading '/' removed,
anything that could escape the base directory ('..', absolute URLs, '//') or
inject request syntax (spaces, '?', '#') is rejected. Duplicates are removed
keeping the original order (wordlists are usually sorted by usefulness).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from web_enum.errors import ConfigError

BUNDLED = "<bundled>"
MAX_WORDS = 500_000  # protects memory against a wrong file (e.g. rockyou passed by mistake)


@dataclass(frozen=True)
class Wordlist:
    source: str  # file path, or BUNDLED
    words: tuple[str, ...]
    rejected: int = 0


def expand(words: Sequence[str], extensions: Sequence[str]) -> list[str]:
    """Words plus word.ext for every extension (not for directories or words with one).

    Same rule as ffuf's -e and feroxbuster's -x, so request estimates match.
    """
    out: list[str] = []
    for word in words:
        out.append(word)
        last = word.rsplit("/", 1)[-1]
        if extensions and last and "." not in last:
            out.extend(f"{word}.{ext}" for ext in extensions)
    return list(dict.fromkeys(out))


def resolve_wordlist(setting: str, candidates: Iterable[str]) -> str:
    """Path to use (or BUNDLED). An explicit path must exist."""
    if setting != "auto":
        path = Path(setting).expanduser()
        if not path.is_file():
            raise ConfigError(f"Wordlist not found: {path}")
        return str(path)
    for candidate in candidates:
        if Path(candidate).expanduser().is_file():
            return str(Path(candidate).expanduser())
    return BUNDLED


def load_wordlist(source: str) -> Wordlist:
    if source == BUNDLED:
        text = (resources.files("web_enum").joinpath("data").joinpath("wordlist.txt")
                .read_text(encoding="utf-8"))
    else:
        try:
            text = Path(source).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ConfigError(f"Cannot read wordlist {source}: {exc}") from None
    words: list[str] = []
    rejected = 0
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        word = sanitize(entry)
        if word is None:
            rejected += 1
            continue
        words.append(word)
        if len(words) >= MAX_WORDS:
            break
    unique = tuple(dict.fromkeys(words))
    if not unique:
        raise ConfigError(f"Wordlist {source} has no usable entries")
    return Wordlist(source=source, words=unique, rejected=rejected)


def sanitize(entry: str) -> str | None:
    """Clean one wordlist entry, or None if it must not be requested."""
    word = entry.lstrip("/")
    if not word or "://" in word or "//" in word:
        return None
    if any(c in word for c in " \t?#\\") or any(ord(c) < 32 for c in word):
        return None
    if any(part == ".." for part in word.split("/")):
        return None
    return word
