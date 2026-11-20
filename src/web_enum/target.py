"""The target URL and the authorisation (scope) gate.

* :func:`parse_target` turns what the user typed into a canonical :class:`Target`
  (scheme, host, port, base path). Anything ambiguous is rejected instead of
  guessed, because the target defines what the tool is allowed to touch.
* :meth:`Target.same_origin` is the boundary every module respects: the tool
  never requests a URL on another scheme / host / port (links, redirects,
  sitemap entries, form actions pointing elsewhere are reported, not followed).
* :func:`authorize` is the ethical gate: the host must match an entry of the
  configured ``scope`` (hostname, IP or CIDR) or the user must pass
  ``--authorized``. DNS is never resolved to decide: names and IPs are matched
  as written, so authorising ``10.10.11.42`` does not authorise ``box.htb``
  even if it points there. Explicit beats clever.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from web_enum.errors import InvalidTargetError, ScopeError

DEFAULT_PORTS = {"http": 80, "https": 443}
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass(frozen=True)
class Target:
    """A canonical http(s) target.

    ``url`` is the exact page the user asked for (analysed for headers, forms and
    technologies); ``base`` is the directory content discovery starts from.
    """

    scheme: str
    host: str
    port: int
    path: str
    base_path: str

    @property
    def is_ip(self) -> bool:
        return is_ip(self.host)

    @property
    def origin(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host  # IPv6 literal
        if self.port == DEFAULT_PORTS[self.scheme]:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{self.port}"

    @property
    def url(self) -> str:
        return self.origin + self.path

    @property
    def base(self) -> str:
        return self.origin + self.base_path

    def join(self, path: str) -> str:
        """Absolute URL for ``path`` relative to the base directory."""
        return urljoin(self.base, path)

    def same_origin(self, url: str) -> bool:
        """True if ``url`` (absolute or relative to the base) stays on this origin."""
        try:
            other = parse_target(urljoin(self.base, url))
        except InvalidTargetError:
            return False
        return (other.scheme, other.host, other.port) == (self.scheme, self.host, self.port)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_target(text: str) -> Target:
    """Parse and normalise a target URL.

    A bare host (``10.10.11.42``, ``box.htb:8080``) gets ``http://``: that is how
    lab targets are usually written, and https must be asked for explicitly.
    """
    raw = text.strip()
    if not raw:
        raise InvalidTargetError("Empty target URL")
    if "://" not in raw:
        raw = "http://" + raw

    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetError(f"Invalid URL '{text}': {exc}") from None

    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise InvalidTargetError(f"Unsupported scheme '{scheme}' in '{text}': use http or https")
    if parts.username is not None or parts.password is not None:
        raise InvalidTargetError(
            "Credentials in the URL are not accepted (they would end up in logs and "
            "reports): use --header 'Authorization: ...' instead"
        )
    if parts.query:
        raise InvalidTargetError(
            f"'{text}' has a query string: give the page or directory URL without '?...'"
        )
    if not parts.hostname:
        raise InvalidTargetError(f"No host in '{text}'")

    host = normalize_host(parts.hostname)
    path = parts.path or "/"  # with a host, urlsplit's path is '' or starts with '/'
    return Target(
        scheme=scheme,
        host=host,
        port=port if port is not None else DEFAULT_PORTS[scheme],
        path=path,
        base_path=_base_path(path),
    )


def _base_path(path: str) -> str:
    """Directory of ``path``: '/app' -> '/app/', '/app/login.php' -> '/app/'."""
    if path.endswith("/"):
        return path
    head, _, last = path.rpartition("/")
    if "." in last:  # looks like a file
        return head + "/"
    return path + "/"


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def normalize_host(host: str) -> str:
    """Lower-case hostname (IDNA-encoded) or canonical IP; raises if invalid."""
    value = host.strip().strip("[]").rstrip(".").lower()
    if is_ip(value):
        return str(ipaddress.ip_address(value))
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        raise InvalidTargetError(f"Invalid hostname '{host}'") from None
    labels = ascii_host.split(".")
    if not ascii_host or len(ascii_host) > 253 or not all(_LABEL_RE.match(lb) for lb in labels):
        raise InvalidTargetError(f"Invalid hostname '{host}'")
    return ascii_host


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
def normalize_scope_entry(entry: str) -> str:
    """Canonical form of a scope entry: hostname, IP or CIDR network.

    Accepts a URL too (``https://lab.local:8443/app`` -> ``lab.local``) and a
    leading ``*.`` (hostnames already include their subdomains).
    """
    value = entry.strip()
    if "/" in value and "://" not in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            raise InvalidTargetError(f"Invalid scope entry '{entry}'") from None
    if "://" in value:
        value = urlsplit(value).hostname or ""
    elif value.count(":") == 1:  # host:port (an IPv6 literal has several colons)
        value = value.split(":", 1)[0]
    if value.startswith("*."):
        value = value[2:]
    if not value:
        raise InvalidTargetError(f"Invalid scope entry '{entry}'")
    return normalize_host(value)


def scope_match(host: str, scope: tuple[str, ...]) -> str | None:
    """Return the scope entry that covers ``host``, or None."""
    host = normalize_host(host)
    if is_ip(host):
        address = ipaddress.ip_address(host)
        for entry in scope:
            if "/" in entry:
                if address in ipaddress.ip_network(entry):
                    return entry
            elif entry == host:
                return entry
        return None
    for entry in scope:
        if "/" in entry or is_ip(entry):
            continue
        if host == entry or host.endswith("." + entry):
            return entry
    return None


def authorize(target: Target, scope: tuple[str, ...], *, authorized_flag: bool) -> str:
    """The ethical gate. Returns why the scan is allowed, or raises ScopeError."""
    entry = scope_match(target.host, scope)
    if entry is not None:
        return f"in scope ({entry})"
    if authorized_flag:
        return "--authorized given by the user"
    raise ScopeError(
        f"'{target.host}' is not in your authorised scope. web-enum only scans targets "
        "you are authorised to test: add it to 'scope' in your config "
        "(hostname, IP or CIDR), or pass --authorized if you ARE authorised."
    )
