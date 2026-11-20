"""Soft-404 calibration: learn what "not found" looks like on this server.

Many servers answer 200 (or a redirect to /login) for paths that do not exist.
Without calibration a wordlist run would "find" every word. Before discovery we
request a few random paths that cannot exist and remember the responses:

* status + word/line counts: a soft-404 page has the same structure for any
  path, even when it echoes the path back (the path is just one more word);
* length, including servers that *reflect* the path: if probes of different
  lengths differ in length by exactly the path difference, the expected length
  of a candidate is computed rather than compared literally;
* redirects: a constant Location (everything -> /login) marks redirects to it
  as "not found".

Word and line counts depend on who counts: ffuf splits words on single spaces,
feroxbuster on any whitespace. The profile keeps the probe bodies and computes
the signature with the same rules as the engine whose results it is judging, so
one criterion serves all engines.
"""

from __future__ import annotations

import secrets
import string
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from web_enum.http import HttpResponse

FLAVORS = ("native", "ffuf", "feroxbuster")
_ALPHABET = string.ascii_lowercase + string.digits


def count_words_lines(body: bytes, flavor: str) -> tuple[int, int]:
    """Words and lines as each engine counts them."""
    if flavor == "ffuf":  # Go: len(strings.Split(body, " ")), len(strings.Split(body, "\n"))
        return len(body.split(b" ")), len(body.split(b"\n"))
    # native and feroxbuster (Rust): split_whitespace().count(), lines().count()
    return len(body.split()), len(body.splitlines())


def random_token(length: int) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def probe_paths(count: int, extensions: Sequence[str]) -> list[str]:
    """Random paths of different lengths and shapes (plain, with extension, directory)."""
    ext = (extensions or ["html"])[0]
    shapes = [random_token(10), random_token(18), f"{random_token(12)}.{ext}",
              f"{random_token(14)}/", random_token(22), f"{random_token(9)}.php",
              f"{random_token(16)}.bak", random_token(26), f"{random_token(11)}.txt",
              f"{random_token(13)}/"]
    return shapes[:count]


@dataclass(frozen=True)
class Probe:
    path: str
    status: int
    body: bytes
    length: int  # full length (Content-Length when the body was truncated)
    location_template: str | None  # Location with the probe path replaced by {path}


def _location_template(response: HttpResponse, path: str) -> str | None:
    location = response.location
    if location is None:
        return None
    return urlsplit(location).path.replace(path.rstrip("/"), "{path}")


def make_probe(path: str, response: HttpResponse) -> Probe:
    length = len(response.body)
    if response.truncated:
        declared = response.header("content-length") or ""
        length = int(declared) if declared.isdigit() else length
    return Probe(path, response.status, response.body, length,
                 _location_template(response, path))


class NotFoundProfile:
    """What this server answers for paths that do not exist."""

    def __init__(self, probes: Sequence[Probe]) -> None:
        self.probes = tuple(probes)
        self.reflects_path = self._detect_reflection()

    def _detect_reflection(self) -> bool:
        by_status: dict[int, list[Probe]] = {}
        for probe in self.probes:
            by_status.setdefault(probe.status, []).append(probe)
        for group in by_status.values():
            for a in group:
                for b in group:
                    diff_path = len(b.path) - len(a.path)
                    if diff_path and b.length - a.length == diff_path:
                        return True
        return False

    @property
    def statuses(self) -> set[int]:
        return {p.status for p in self.probes}

    def describe(self) -> str:
        if not self.probes:
            return "no calibration"
        parts = sorted({f"{p.status} ({p.length} bytes)" for p in self.probes})
        reflect = ", reflects the path" if self.reflects_path else ""
        return f"random paths answer {', '.join(parts)}{reflect}"

    def is_not_found(
        self, *, path: str, status: int, length: int, words: int, lines: int,
        location: str | None = None, flavor: str = "native",
    ) -> bool:
        """True if this response looks like the server's "not found" answer."""
        if status == 404:
            return True
        for probe in self.probes:
            if probe.status != status:
                continue
            if probe.location_template is not None and location is not None:
                candidate = urlsplit(location).path.replace(path.rstrip("/"), "{path}")
                if candidate == probe.location_template:
                    return True
                continue
            p_words, p_lines = count_words_lines(probe.body, flavor)
            if (words, lines) == (p_words, p_lines):
                return True
            expected = probe.length + (len(path) - len(probe.path) if self.reflects_path else 0)
            if abs(length - expected) <= 2:
                return True
        return False

    def matches_response(self, path: str, response: HttpResponse) -> bool:
        words, lines = count_words_lines(response.body, "native")
        return self.is_not_found(path=path, status=response.status, length=len(response.body),
                                 words=words, lines=lines, location=response.location)
