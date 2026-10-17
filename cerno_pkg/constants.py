"""Centralized application constants and configuration.

This module contains all constants used throughout the cerno application,
including paths, URL templates, protocol lists, and NSE profiles for security
testing tools integration.
"""

import os
import re
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import CernoConfig


# ========== Application paths and prefixes ==========
_results_root_cache: Optional[Path] = None


def get_results_root(config: Optional["CernoConfig"] = None) -> Path:
    """Get results root directory from config (lazy-loaded with caching).

    Args:
        config: Optional config to use. If None, loads config.

    Returns:
        Path to results root directory
    """
    global _results_root_cache

    if _results_root_cache is None:
        if config is None:
            from .config import load_config
            config = load_config()

        if config.results_root:
            _results_root_cache = Path(config.results_root).expanduser()
        else:
            _results_root_cache = Path.home() / ".cerno" / "artifacts"

    return _results_root_cache


def reset_results_root_cache() -> None:
    """Reset cached results root (for testing)."""
    global _results_root_cache
    _results_root_cache = None

SCANS_ROOT: Path = Path.home() / ".cerno" / "scans"
"""Root directory for scan exports (plugin host lists)."""

REVIEW_PREFIX: str = "REVIEW_COMPLETE-"
"""Prefix added to filenames that have been reviewed."""

REVIEW_STATE_UNREVIEWED: str = "unreviewed"
"""Finding not yet reviewed (default on import)."""

REVIEW_STATE_IN_PROGRESS: str = "in_progress"
"""Finding review started but not finished."""

REVIEW_STATE_DONE: str = "done"
"""Finding review finished."""

REVIEW_STATES: tuple[str, ...] = (
    REVIEW_STATE_UNREVIEWED,
    REVIEW_STATE_IN_PROGRESS,
    REVIEW_STATE_DONE,
)
"""Valid values for ``findings.review_state`` (mirrors the schema CHECK constraint)."""

REVIEW_TRANSITIONS: dict[str, tuple[str, ...]] = {
    REVIEW_STATE_UNREVIEWED: (REVIEW_STATE_IN_PROGRESS,),
    REVIEW_STATE_IN_PROGRESS: (REVIEW_STATE_DONE,),
    REVIEW_STATE_DONE: (REVIEW_STATE_UNREVIEWED,),
}
"""Allowed review-state transitions (current state -> permitted next states).

Workflow: unreviewed -> in_progress -> done, and done -> unreviewed to reset.
Enforced by ``Finding.transition_review_state()`` for both the TUI and MCP.
"""

REVIEW_STATE_LABELS: dict[str, str] = {
    REVIEW_STATE_UNREVIEWED: "Unreviewed",
    REVIEW_STATE_IN_PROGRESS: "In Progress",
    REVIEW_STATE_DONE: "Done",
}
"""Display labels for review states (shown to users as the finding's "status")."""

REVIEW_STATE_STYLES: dict[str, str] = {
    REVIEW_STATE_UNREVIEWED: "cyan",
    REVIEW_STATE_IN_PROGRESS: "blue",
    REVIEW_STATE_DONE: "magenta",
}
"""Rich styles for review states. Deliberately avoids the severity palette
(red/yellow/green) so progress is never mistaken for risk."""

REVIEW_STATE_ICONS: dict[str, str] = {
    REVIEW_STATE_UNREVIEWED: "○",
    REVIEW_STATE_IN_PROGRESS: "◐",
    REVIEW_STATE_DONE: "✓",
}
"""Compact status indicators: ○ Unreviewed, ◐ In Progress, ✓ Done (Done list rows)."""

REVIEW_MOVE_LABELS: dict[str, str] = {
    REVIEW_STATE_IN_PROGRESS: "Move to In Progress",
    REVIEW_STATE_DONE: "Move to Done",
    REVIEW_STATE_UNREVIEWED: "Move back to Unreviewed",
}
"""[M] action labels keyed by *target* status (past tense: replace "Move" with "Moved")."""


# ========== Plugin details configuration ==========
PLUGIN_DETAILS_BASE: str = "https://www.tenable.com/plugins/nessus/"
"""Base URL for Tenable plugin detail pages."""


# ========== NetExec protocol support ==========
NETEXEC_PROTOCOLS: list[str] = [
    "mssql",
    "smb",
    "ftp",
    "ldap",
    "nfs",
    "rdp",
    "ssh",
    "vnc",
    "winrm",
    "wmi",
]
"""Supported protocols for NetExec/CrackMapExec tool integration."""


# ========== NSE (Nmap Scripting Engine) profiles ==========
NSE_PROFILES: list[tuple[str, str, list[str], bool]] = [
    ("Crypto", "Check SSL/TLS cipher suites and certificates", ["ssl-enum-ciphers", "ssl-cert", "ssl-date"], False),
    ("SSH", "Enumerate SSH algorithms and authentication methods", ["ssh2-enum-algos", "ssh-auth-methods"], False),
    ("SMB", "Check SMB security modes and signing", ["smb-security-mode", "smb2-security-mode"], False),
    ("SNMP", "Enumerate SNMP information (requires UDP)", ["snmp*"], True),
    ("IPMI", "Check IPMI version information (requires UDP)", ["ipmi-version"], True),
]
"""NSE profile definitions: (name, description, script_list, needs_udp)."""


# ========== Severity color mapping ==========
# Format: severity_level -> (rich_color_name, ansi_color_code)
# This is the single source of truth for severity colors across the app
SEVERITY_COLORS: dict[str, tuple[str, str]] = {
    "critical": ("red", "\u001b[31m"),
    "high": ("yellow", "\u001b[33m"),
    "medium": ("blue", "\u001b[34m"),
    "low": ("green", "\u001b[32m"),
    "info": ("cyan", "\u001b[36m"),
    "default": ("magenta", "\u001b[35m"),
}
"""Severity level to color mapping for Rich and ANSI outputs."""


# ========== File processing limits ==========
MAX_FILE_BYTES: int = 2_000_000
"""Maximum file size in bytes to process (2MB limit for safety)."""

DEFAULT_TOP_PORTS: int = 5
"""Default number of top ports to display in summaries."""

SAMPLE_THRESHOLD: int = 5
"""Threshold for triggering host sampling in tool workflows."""

VISIBLE_GROUPS: int = 5
"""Number of comparison groups to display before pagination."""


# ========== Process timeouts ==========
PROCESS_TERMINATE_TIMEOUT: int = 3
"""Timeout in seconds when waiting for subprocess termination."""


# ========== Search and parsing configuration ==========
SEARCH_WINDOW_SIZE: int = 800
"""Character window size around CVE matches when searching plugin pages."""

MIN_TERM_LENGTH: int = 2
"""Minimum length for search terms when extracting CVEs."""


# ========== Validation patterns ==========
HNAME_RE: re.Pattern[str] = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
"""Regex pattern for validating hostname format."""


# ========== Validation functions ==========
def validate_results_root(path: Path) -> tuple[bool, str]:
    """Validate that RESULTS_ROOT is writable.

    Args:
        path: Path to validate for writability

    Returns:
        Tuple of (is_valid, error_message). error_message is empty string if valid.
    """
    # Check if path exists
    if not path.exists():
        # Try to create it
        try:
            path.mkdir(parents=True, exist_ok=True)
            return True, ""
        except (PermissionError, OSError) as e:
            return False, f"Cannot create results directory {path}: {e}"

    # Path exists, check if it's a directory
    if not path.is_dir():
        return False, f"Results path {path} exists but is not a directory"

    # Check if writable
    if not os.access(path, os.W_OK):
        return False, f"Results directory {path} is not writable"

    return True, ""
