"""Host and port parsing for Nessus plugin findings.

This module provides functions to parse host:port combinations from
plugin data (database and reference files), supporting IPv4, IPv6 (bracketed),
and hostname formats.
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING, Any, Optional


if TYPE_CHECKING:
    from .workflow_mapper import WorkflowMapper


# ====== Scan overview helpers ======
_HNAME_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

def split_host_port(token: str) -> tuple[Optional[str], Optional[str]]:
    """Split a host:port token into separate components.

    Accepts multiple formats:
      - [IPv6]:port (bracketed IPv6 with port)
      - [IPv6] (bracketed IPv6 without port)
      - IPv4:port
      - hostname:port
      - bare IPv6
      - bare IPv4
      - bare hostname

    Args:
        token: Host:port string to parse

    Returns:
        Tuple of (host, port) where port may be None if not specified
    """
    token = token.strip()
    if not token:
        return None, None
    if token.startswith("["):
        match = re.match(r"^\[(.+?)\](?::(\d+))?$", token)
        if match:
            return match.group(1), (match.group(2) if match.group(2) else None)
    if token.count(":") >= 2 and not re.search(r"]:\d+$", token):
        return token, None
    if ":" in token:
        host, port = token.rsplit(":", 1)
        if port.isdigit():
            return host, port
    return token, None


def parse_hosts_ports(lines: list[str]) -> tuple[list[str], str]:
    """Parse lines into hosts and ports.

    Args:
        lines: Lines containing host:port tokens

    Returns:
        Tuple of (unique_hosts_list, comma_separated_ports_string)
    """
    hosts = []
    ports = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        tokens = re.split(r"[\s,]+", line)
        for token in tokens:
            host, port = split_host_port(token)
            if not host:
                continue
            hosts.append(host)
            if port:
                ports.add(port)
    hosts = list(dict.fromkeys(hosts))
    ports_str = (
        ",".join(sorted(ports, key=lambda x: int(x))) if ports else ""
    )
    return hosts, ports_str

def is_hostname(s: str) -> bool:
    """Check if a string is a valid hostname.

    Args:
        s: String to validate

    Returns:
        True if valid hostname (max 253 chars, valid format)
    """
    return bool(_HNAME_RE.match(s)) and len(s) <= 253


def is_ipv4(s: str) -> bool:
    """Check if a string is a valid IPv4 address.

    Args:
        s: String to validate

    Returns:
        True if valid IPv4 address
    """
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def is_ipv6(s: str) -> bool:
    """Check if a string is a valid IPv6 address.

    Args:
        s: String to validate

    Returns:
        True if valid IPv6 address
    """
    try:
        ipaddress.IPv6Address(s)
        return True
    except Exception:
        return False


def detect_host_type(host: str) -> str:
    """Detect host type from address string.

    Uses existing validation functions (is_ipv4, is_ipv6) to classify hosts.

    Args:
        host: Host address string (IP or hostname)

    Returns:
        One of 'ipv4', 'ipv6', 'hostname'

    Examples:
        >>> detect_host_type("192.168.1.1")
        'ipv4'
        >>> detect_host_type("2001:db8::1")
        'ipv6'
        >>> detect_host_type("example.com")
        'hostname'
    """
    if is_ipv4(host):
        return 'ipv4'
    if is_ipv6(host):
        return 'ipv6'
    return 'hostname'


def is_valid_token(
    token: str,
) -> tuple[bool, Optional[str], Optional[str]]:
    """Validate a host:port token and extract components.

    Args:
        token: Token to validate (host or host:port)

    Returns:
        Tuple of (is_valid, host, port) where host and port are None if invalid
    """
    token = token.strip()
    if not token:
        return False, None, None

    if token.startswith("["):
        match = re.match(r"^\[(.+?)\](?::(\d+))?$", token)
        if match and is_ipv6(match.group(1)):
            port = match.group(2)
            if port is None:
                return True, match.group(1), None
            if port.isdigit() and 1 <= int(port) <= 65535:
                return True, match.group(1), port
        return False, None, None

    if token.count(":") >= 2 and not re.search(r"]:\d+$", token):
        return (is_ipv6(token), token if is_ipv6(token) else None, None)

    if ":" in token:
        host, port = token.rsplit(":", 1)
        if (
            port.isdigit()
            and 1 <= int(port) <= 65535
            and (is_hostname(host) or is_ipv4(host))
        ):
            return True, host, port
        return False, None, None

    if is_hostname(token) or is_ipv4(token) or is_ipv6(token):
        return True, token, None

    return False, None, None


# ====== Compare hosts/ports across filtered files ======
def normalize_combos(
    hosts: list[str],
    ports_set: set[str],
    combos_map: dict[str, set[str]],
    had_explicit: bool,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Normalize host-port combinations for comparison.

    Args:
        hosts: List of hosts
        ports_set: Set of all ports
        combos_map: Mapping of hosts to their specific ports
        had_explicit: Whether explicit port combinations were found

    Returns:
        Normalized tuple of (host, ports_tuple) combinations
    """
    if had_explicit and combos_map:
        items = []
        for host in hosts:
            host_ports = combos_map.get(host, set())
            items.append((host, tuple(sorted(host_ports, key=lambda x: int(x)))))
        return tuple(items)
    assumed = tuple(
        sorted(
            (host, tuple(sorted(ports_set, key=lambda x: int(x))))
            for host in hosts
        )
    )
    return assumed


# ====== Superset / coverage analysis across filtered files ======
def build_item_set(
    hosts: list[str],
    ports_set: set[str],
    combos_map: dict[str, set[str]],
    had_explicit: bool,
) -> set[str]:
    """Build a set of atomic items for inclusion checks.

    Items are either:
      - 'host:port' when explicit port combinations exist
      - 'host' when no ports are specified

    Args:
        hosts: List of hosts
        ports_set: Set of all ports
        combos_map: Mapping of hosts to their specific ports
        had_explicit: Whether explicit port combinations were found

    Returns:
        Set of 'host' or 'host:port' strings
    """
    items = set()
    if had_explicit:
        any_ports = any(bool(v) for v in combos_map.values())
        if any_ports:
            for host in hosts:
                host_ports = combos_map.get(host, set())
                if host_ports:
                    for port in host_ports:
                        items.add(f"{host}:{port}")
                else:
                    # Host present but no explicit ports - treat as bare host
                    items.add(host)
        else:
            # Defensive: had_explicit True but no ports recorded
            for host in hosts:
                items.add(host)
    else:
        # No explicit combos; interpret as Cartesian product or bare hosts
        if ports_set:
            for host in hosts:
                for port in ports_set:
                    items.add(f"{host}:{port}")
        else:
            for host in hosts:
                items.add(host)
    return items


def extract_plugin_id_from_filename(name_or_path) -> Optional[str]:
    """
    Extract Nessus plugin ID from filename.

    Handles both regular filenames (12345.txt) and review-complete
    prefixed files (REVIEW_COMPLETE-12345.txt, review-complete-12345.txt).

    Args:
        name_or_path: Filename string or Path object

    Returns:
        Plugin ID string if found, None otherwise

    Examples:
        >>> extract_plugin_id_from_filename("12345.txt")
        "12345"
        >>> extract_plugin_id_from_filename("REVIEW_COMPLETE-12345.txt")
        "12345"
        >>> extract_plugin_id_from_filename("vulnerability-name-12345.txt")
        "12345"
    """
    # Handle both Path and str
    if hasattr(name_or_path, 'name'):
        name = name_or_path.name
    else:
        name = str(name_or_path)

    # Extract leading numeric plugin ID
    match = re.match(r"^(\d+)", name)
    return match.group(1) if match else None


def group_findings_by_workflow(files: list[tuple[Any, Any]], workflow_mapper: "WorkflowMapper") -> dict[str, list[tuple[Any, Any]]]:
    """
    Group files by their workflow name.

    Args:
        files: List of (Finding, Plugin) tuples from database query
        workflow_mapper: WorkflowMapper instance

    Returns:
        Dict mapping workflow_name -> list of (Finding, Plugin) tuples
        Files without workflows are excluded.

    Example:
        >>> # With database tuples:
        >>> files = [(Finding(...), Plugin(...)), ...]
        >>> groups = group_findings_by_workflow(files, mapper)
        >>> groups
        {"SMB Signing Not Required": [(Finding(...), Plugin(...)), ...], ...}
    """
    from collections import defaultdict

    groups = defaultdict(list)

    for plugin_file, plugin in files:
        # Get plugin ID from database record instead of filename parsing
        plugin_id = str(plugin.plugin_id)
        workflow = workflow_mapper.get_workflow(plugin_id)
        if workflow:
            groups[workflow.workflow_name].append((plugin_file, plugin))

    return dict(groups)