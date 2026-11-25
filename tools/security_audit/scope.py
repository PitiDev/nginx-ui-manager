"""Scope control: load and validate the authorized target list.

The scanner only ever touches hosts that appear in `authorized_domains.txt`.
This module is deliberately strict: a single malformed line aborts the run,
because silently skipping a typo is how scans drift out of scope.
"""

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path


class ScopeError(Exception):
    """Raised when the authorized target list is missing, empty or invalid."""


# RFC 1123 label: 1-63 chars, alnum + hyphen, not starting/ending with hyphen.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*\.?$")


@dataclass(frozen=True)
class Target:
    host: str               # lower-cased hostname or IPv4 literal
    port: int = 443         # HTTPS port
    custom_port: bool = False

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}" if self.custom_port else self.host

    @property
    def https_base(self) -> str:
        return f"https://{self.label}"

    @property
    def http_base(self) -> str:
        # The plain-HTTP check only makes sense on the standard port pair.
        return f"http://{self.host}"


def _parse_line(raw: str, lineno: int) -> Target:
    value = raw.strip()

    if "://" in value:
        raise ScopeError(
            f"line {lineno}: '{value}' looks like a URL. List bare hostnames only "
            f"(e.g. 'www.example.com'), without scheme or path."
        )
    if "/" in value:
        raise ScopeError(f"line {lineno}: '{value}' contains '/'. Paths and CIDR ranges are not allowed.")
    if "*" in value:
        raise ScopeError(f"line {lineno}: '{value}' contains a wildcard. List each host explicitly.")

    host, port, custom = value, 443, False
    if value.count(":") == 1:
        host, port_str = value.split(":")
        if not port_str.isdigit() or not 1 <= int(port_str) <= 65535:
            raise ScopeError(f"line {lineno}: invalid port in '{value}'.")
        port, custom = int(port_str), int(port_str) != 443
    elif ":" in value:
        raise ScopeError(f"line {lineno}: IPv6 literals are not supported: '{value}'.")

    host = host.lower().rstrip(".")
    try:
        ipaddress.IPv4Address(host)
        return Target(host, port, custom)
    except ValueError:
        pass

    if len(host) > 253 or not _HOSTNAME_RE.match(host):
        raise ScopeError(f"line {lineno}: '{value}' is not a valid hostname.")
    return Target(host, port, custom)


MAX_TARGETS = 500


def parse_host(value: str) -> Target:
    """Validate a single host entry (same rules as a line in the list file)."""
    return _parse_line(value.strip(), 1)


def parse_targets(text: str, source: str = "authorized_domains.txt", allow_empty: bool = False) -> list[Target]:
    """Parse the authorized list text. Blank lines and `#` comments are ignored."""
    targets: list[Target] = []
    seen: set[Target] = set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        target = _parse_line(line, lineno)
        if target not in seen:
            seen.add(target)
            targets.append(target)

    if len(targets) > MAX_TARGETS:
        raise ScopeError(f"{len(targets)} hosts listed; the limit is {MAX_TARGETS} per scan.")
    if not targets and not allow_empty:
        raise ScopeError(
            f"Authorized domain list is empty: {source}\n"
            f"Add at least one organization-owned hostname (uncommented) before scanning."
        )
    return targets


def load_targets(path: Path) -> list[Target]:
    """Read and validate the authorized list file."""
    if not path.is_file():
        raise ScopeError(
            f"Authorized domain list not found: {path}\n"
            f"Create it with one organization-owned hostname per line."
        )
    return parse_targets(path.read_text(encoding="utf-8"), source=str(path))
