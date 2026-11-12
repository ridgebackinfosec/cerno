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
"""Per-scan working directories (only http_urls.txt is written here, when web services exist)."""

REVIEW_PREFIX: str = "REVIEW_COMPLETE-"
"""Legacy filename prefix from before review state moved to the database (unused)."""

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
"""Compact status indicators for the findings-list Status column and its legend.

✓ Done is reachable in that list via the [D] Done-only filter, so all three
are rendered -- see ``render._status_legend``.
"""

REVIEW_MOVE_LABELS: dict[str, str] = {
    REVIEW_STATE_IN_PROGRESS: "Move to In Progress",
    REVIEW_STATE_DONE: "Move to Done",
    REVIEW_STATE_UNREVIEWED: "Move back to Unreviewed",
}
"""[M] action labels keyed by *target* status (past tense: replace "Move" with "Moved")."""

# Verification verdicts (truth, distinct from review state). Mirrors the
# verdict_types lookup table seeded in database.py.
VERDICT_LABELS: dict[str, str] = {
    "confirmed": "Confirmed",
    "false_positive": "False Positive",
    "unable": "Unable to Verify",
}
"""Display labels for verification verdicts."""

VERDICT_STYLES: dict[str, str] = {
    "confirmed": "bold red",
    "false_positive": "green",
    "unable": "yellow",
}
"""Rich styles for verdicts (Confirmed = risk red, False Positive = cleared green)."""

VERDICT_ICONS: dict[str, str] = {
    "confirmed": "✓",
    "false_positive": "✗",
    "unable": "?",
}
"""Compact verdict indicators: ✓ Confirmed, ✗ False Positive, ? Unable."""


# ========== Plugin details configuration ==========
PLUGIN_DETAILS_BASE: str = "https://www.tenable.com/plugins/nessus/"
"""Base URL for Tenable plugin detail pages."""

NUCLEI_TEMPLATE_URL_BASE: str = "https://cloud.projectdiscovery.io/public/"
"""Base URL for the public nuclei template viewer.

Keyed on the bare template id, so it works without knowing the template's path.
Used as the fallback when a result carries no usable ``template`` path.
"""

NUCLEI_TEMPLATE_REPO_BASE: str = (
    "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
)
"""Base URL for a template's source in the nuclei-templates repository.

Preferred over :data:`NUCLEI_TEMPLATE_URL_BASE` because it shows the operator
the matcher logic that actually fired. It needs the result's ``template`` path
(e.g. ``http/cves/2021/CVE-2021-44228.yaml``), which cannot be derived from a
template id, hence the two bases. ``blob/`` is GitHub's canonical form for a
file; ``tree/`` also resolves but redirects here.
"""

NUCLEI_RESPONSE_SIZE_READ: int = 10_485_760
"""``-rsr``: max response bytes nuclei reads (10 MiB)."""

NUCLEI_RESPONSE_SIZE_SAVE: int = 1_048_576
"""``-rss``: max response bytes nuclei stores in its output (1 MiB).

Cerno's importer discards ``request``/``response`` entirely, so this only
bounds the size of the ``-je``/``-me`` artifacts the operator keeps.
"""

BURP_KB_BASE: str = "https://portswigger.net/kb/issues/"
"""Base URL for PortSwigger's issue-definition knowledge base.

Keyed on the 8-digit hex type index, with no slug: PortSwigger publishes
``.../kb/issues/00200300_cross-site-scripting-reflected`` but the bare
``.../kb/issues/00200300`` resolves to the same page. That is why the hex type
index -- not the decimal ``type`` the XML stores -- is Burp's ``plugin_ref``:
it makes the details URL derivable from the id alone, exactly like the other
two sources.
"""

BURP_REQUEST_MAX_BYTES: int = 4096
"""Max decoded request bytes kept per Burp issue instance."""

BURP_RESPONSE_MAX_BYTES: int = 4096
"""Max decoded response bytes kept per Burp issue instance.

Burp stores full HTTP exchanges; a single response can be megabytes. The whole
exchange lands in one ``finding_affected_hosts.plugin_output`` cell, which the
finding panel and the Claude assistant context both render in full.
"""

BURP_MAX_INSTANCES_RENDERED: int = 10
"""Max Burp issue instances rendered into one host:port's ``plugin_output``.

One issue type routinely fires on dozens of parameters of the same host:port,
and ``finding_affected_hosts`` is UNIQUE per ``(finding_id, host_id,
port_number)`` -- so every one of those instances merges into a single cell.
Without this cap the per-instance byte caps alone still leave the panel
unreadable. Instances beyond the cap are summarised by a trailing count.
"""


# ========== Finding sources (multi-source plugin identity) ==========
SOURCE_NESSUS: str = "nessus"
SOURCE_NUCLEI: str = "nuclei"
SOURCE_BURP: str = "burp"
SOURCE_OPERATOR: str = "operator"
"""Findings the tester wrote by hand in the review TUI.

One of two sources that are *created* rather than imported, which is why
neither has a parser or importer module -- :mod:`cerno_pkg.authored_findings`
writes both directly. Everything downstream treats them like any other source.
"""

SOURCE_AGENT: str = "agent"
"""Findings an MCP client created, i.e. ones an agent asserted.

Split from :data:`SOURCE_OPERATOR` so the channel that wrote a hand-authored
finding stays visible after the fact: a finding the tester verified by hand is
a different claim from one an agent produced, and on an engagement that
difference carries evidentiary weight. The namespace records the *creator*
only -- editing an ``agent:`` finding in the TUI leaves it ``agent:``.
"""

AUTHORED_SOURCES: frozenset[str] = frozenset({SOURCE_OPERATOR, SOURCE_AGENT})
"""Sources whose findings are hand-authored rather than parsed from a scan.

The single definition every "can this be edited?" test uses, so the two
channels cannot drift apart: forgetting one value in a two-way ``or`` would
leave a finding that no interface can correct. Contrast the scanner sources,
whose rows are a record of what a tool reported and are deliberately immutable.
"""

AUTHORED_SCAN_NAMES: dict[str, str] = {
    SOURCE_OPERATOR: "Operator",
    SOURCE_AGENT: "Agent",
}
"""The scan each authored source collects its findings into, per source.

``findings`` needs a ``scan_id`` and a hand-authored finding belongs to no
scanner run, so one scan per source holds them all. Keeping them out of the
scanner scans preserves the invariant ``cross_scan`` relies on -- that a scan
has a single source -- so ``cerno scan compare`` keeps working on the scans
around them. Comparing the two authored scans *with each other* is refused for
the same reason it refuses Nessus against nuclei: their plugin ids are
namespaced apart, so they share none and a diff would report every finding on
both sides as unique to its scan.

One scan per source per *database*, created on first use, which means each
accumulates across engagements. The findings list's ``[F]`` name filter narrows
it, and ``cerno scan delete Operator`` / ``cerno scan delete Agent`` clears it.
"""

SOURCE_UNKNOWN: str = "unknown"
"""Source of an id carrying no recognised namespace prefix.

Deliberately *not* a valid source: it has no ``finding_sources`` row and no
``SOURCE_IDS`` entry, so :func:`parsing.plugin_source_id` raises on it and
nothing can be written to the database under it. Read paths treat it as "no
known source" and render a finding without a details link rather than
fabricating one.
"""

SOURCE_IDS: dict[str, int] = {
    SOURCE_NESSUS: 1,
    SOURCE_NUCLEI: 2,
    SOURCE_BURP: 3,
    SOURCE_OPERATOR: 4,
    SOURCE_AGENT: 5,
}
"""``finding_sources.source_id`` per source name.

Mirrors the ``finding_sources`` rows in ``database.LOOKUP_SEEDS``.
"""

PLUGIN_ID_PREFIXES: dict[str, str] = {
    SOURCE_NESSUS: "nessus:",
    SOURCE_NUCLEI: "nuclei:",
    SOURCE_BURP: "burp:",
    SOURCE_OPERATOR: "operator:",
    SOURCE_AGENT: "agent:",
}
"""Namespace prefix applied to ``plugins.plugin_id`` per source.

*Every* source is namespaced, Nessus included (``'nessus:57608'``). No source
is the default, so a bare token is not a valid plugin id anywhere: it has no
source, and :func:`parsing.plugin_source` reports :data:`SOURCE_UNKNOWN` for
it rather than guessing.

The uniformity is what makes a new source cheap — it needs a prefix here and a
``finding_sources`` row, and nothing else has to learn about it. It also keeps
the global ``plugins`` table collision-free: a nuclei template literally named
``57608`` cannot occupy the same key as Nessus plugin 57608.
"""

PLUGIN_ID_LABELS: dict[str, str] = {
    SOURCE_NESSUS: "Nessus Plugin ID",
    SOURCE_NUCLEI: "Nuclei Template ID",
    SOURCE_BURP: "Burp Issue Type",
    SOURCE_OPERATOR: "Operator Finding ID",
    SOURCE_AGENT: "Agent Finding ID",
}
"""Label for the identifier row in the finding panel, per source."""

PLUGIN_URL_TEMPLATES: dict[str, str] = {
    SOURCE_NESSUS: PLUGIN_DETAILS_BASE + "{ref}",
    SOURCE_NUCLEI: NUCLEI_TEMPLATE_URL_BASE + "{ref}",
    SOURCE_BURP: BURP_KB_BASE + "{ref}",
}
"""Details-page template per source, keyed on the source-native ``{ref}``.

A source absent from this map has no known details page, and callers must
render no link rather than fabricate one. Every source in
:data:`AUTHORED_SOURCES` is such a source by nature: a hand-written finding has
nothing to link to unless its author supplied a reference URL, which is stored
in ``plugins.plugin_url`` and preferred by :func:`parsing.plugin_details_url`
over any template.

Burp is a partial case: the template is right for a real issue type, but an
extension-generated issue carries a :data:`BURP_GENERIC_TYPES` ref with a name
slug appended and has no knowledge-base page at all. The importer stores
``plugin_url=None`` for those, and that is not enough on its own --
:func:`parsing.plugin_details_url` falls back to this template when no URL was
stored -- so :func:`parsing.plugin_details_url` special-cases a slugged Burp
ref. See :data:`BURP_GENERIC_TYPES`.
"""

BURP_GENERIC_TYPES: frozenset[str] = frozenset({"00000000", "08000000"})
"""Burp type indexes that do not identify a specific issue type.

``0x08000000`` is the type every Burp *extension*-generated issue reports, and
``0x00000000`` is the unset value. Both are shared by unrelated issues, so using
one as a ``plugin_id`` would merge, say, two different extensions' findings onto
a single ``plugins`` row under whichever name was imported first. The importer
appends a slug of the issue name for these (``burp:08000000-jwt-none-algorithm``)
and records no details URL, since PortSwigger publishes no page for them.
"""


# ========== Hand-authored findings ==========
AUTHORED_TITLE_MAX_CHARS: int = 200
"""Cap on a hand-authored finding's title.

``plugins.plugin_name`` has no length constraint, but the title is rendered
into a table cell and a panel header; a runaway title from an MCP client
pasting tool output would push every column off screen.
"""

AUTHORED_DESCRIPTION_MAX_CHARS: int = 20_000
"""Cap on a hand-authored finding's description.

Stored once per affected host, like every other source's evidence, so the cost
is multiplied by the host count. Generous enough for a written-up finding and
small enough that a pasted scan log is refused rather than silently stored.
"""


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
    (
        "Crypto",
        "Check SSL/TLS cipher suites and certificates",
        ["ssl-enum-ciphers", "ssl-cert", "ssl-date"],
        False,
    ),
    (
        "SSH",
        "Enumerate SSH algorithms and authentication methods",
        ["ssh2-enum-algos", "ssh-auth-methods"],
        False,
    ),
    (
        "SMB",
        "Check SMB security modes and signing",
        ["smb-security-mode", "smb2-security-mode"],
        False,
    ),
    ("SNMP", "Enumerate SNMP information (requires UDP)", ["snmp*"], True),
    ("IPMI", "Check IPMI version information (requires UDP)", ["ipmi-version"], True),
]
"""NSE profile definitions: (name, description, script_list, needs_udp)."""


# ========== Severity color mapping ==========
# Format: severity_level -> (rich_color_name, ansi_color_code)
# Used by ansi.colorize_severity_label() and render.severity_style(). Only the Rich
# name is read; ANSI codes are derived from it via the color_scheme remap. A few
# tables in render.py/cerno.py still define their own severity colors.
SEVERITY_COLORS: dict[str, tuple[str, str]] = {
    "critical": ("red", "\u001b[31m"),
    "high": ("yellow", "\u001b[33m"),
    "medium": ("blue", "\u001b[34m"),
    "low": ("green", "\u001b[32m"),
    "info": ("cyan", "\u001b[36m"),
    "default": ("magenta", "\u001b[35m"),
}
"""Severity level to color mapping for Rich and ANSI outputs."""

# ========== Terminal background color schemes ==========
COLOR_SCHEMES: tuple[str, ...] = ("light", "dark")
"""Valid values for the ``color_scheme`` config key (default: light)."""

LIGHT_BG_COLOR_MAP: dict[str, str] = {
    "yellow": "dark_orange3",
    "bright_yellow": "dark_orange3",
    "cyan": "turquoise4",
    "bright_cyan": "turquoise4",
    "green": "green4",
    "bright_green": "green4",
    "magenta": "dark_magenta",
    "bright_magenta": "dark_magenta",
    "red": "red3",
    "bright_red": "red3",
    "blue": "blue3",
    "bright_blue": "blue3",
    "white": "default",
    "bright_white": "default",
}
"""Named color -> darker 256-color variant readable on a white background.

Applied to every Rich style string (``ansi.remap_style``) and ANSI code
(``ansi.initialize_colors``) when ``color_scheme`` is ``light``. The dark scheme
uses the named colors unchanged."""


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
    """Validate that the results root (get_results_root()) is writable.

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
