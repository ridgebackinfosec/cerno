"""Rich-based table and UI rendering for the cerno TUI.

This module provides functions to render tables, paginated content, action
menus, and comparison results using the Rich library for terminal UI.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, List, Optional, Union, TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from .ansi import C, colorize_severity_label, fmt_action, info, warn, get_console, style_if_enabled
from .constants import SEVERITY_COLORS
from .fs import default_page_size, pretty_severity_label
from .logging_setup import log_timing

if TYPE_CHECKING:
    from .models import Finding, Plugin

_console_global = get_console()


def print_action_menu(actions: list[tuple[str, str]]) -> None:
    """Print action menu with Rich Text formatting.

    Args:
        actions: List of (key, description) tuples.
                Examples: [("V", "View file"), ("B", "Back")]
    """
    action_text = Text()
    for i, (key, desc) in enumerate(actions):
        if i > 0:
            action_text.append(" / ", style=None)
        action_text.append(f"[{key}] ", style=style_if_enabled("cyan"))
        action_text.append(desc, style=None)

    _console_global.print("[cyan]>>[/cyan] ", end="")
    _console_global.print(action_text)


# ===================================================================
# Rendering Helpers (Tables, Panels, Prompts)
# ===================================================================


def menu_pager(text: str, page_size: Optional[int] = None) -> None:
    """Interactive pager with keyboard navigation for multi-page text.

    Uses [N] Next / [P] Prev / [B] Back navigation, mirroring the
    file-selection menu UX. Auto-exits without prompts for single-page text.

    Args:
        text: Text content to page through (newline-separated)
        page_size: Number of lines per page (default: auto from terminal)
    """
    lines = text.splitlines()
    if not lines:
        return
    page_items = page_size or default_page_size()
    total_pages = max(1, math.ceil(len(lines) / page_items))

    if total_pages == 1:
        print(f"\nPage 1/1 — lines 1-{len(lines)} of {len(lines)}")
        print("─" * 80)
        print("\n".join(lines))
        print("─" * 80)
        return

    page_index = 0
    while True:
        start = page_index * page_items
        end = start + page_items
        chunk = lines[start:end]
        print(
            f"\nPage {page_index+1}/{total_pages} — "
            f"lines {start+1}-{min(end, len(lines))} of {len(lines)}"
        )
        print("─" * 80)
        print("\n".join(chunk))
        print("─" * 80)
        print_action_menu([("N", "Next page"), ("P", "Prev page"), ("B", "Back")])
        try:
            answer = Prompt.ask("Action", default="").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            return
        if answer in ("b", "back", "q", "x"):
            return
        if answer in ("n", "next"):
            if page_index + 1 < total_pages:
                page_index += 1
            else:
                warn("Already at last page.")
            continue
        if answer in ("p", "prev", "previous"):
            if page_index > 0:
                page_index -= 1
            else:
                warn("Already at first page.")
            continue
        if answer == "":
            return
        warn("Use N (next), P (prev), or B (back).")


def render_scan_table(scans: list[Path]) -> None:
    """Render a table of available scan directories.

    Args:
        scans: List of scan directory paths to display
    """
    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    table.add_column("#", justify="right", no_wrap=True, max_width=5)
    table.add_column("Scan", overflow="fold")
    for i, scan_dir in enumerate(scans, 1):
        table.add_row(str(i), scan_dir.name)
    _console_global.print(table)


def render_severity_table(
    severities: list[Path],
    msf_summary: Optional[tuple[int, int, int, int]] = None,
    workflow_summary: Optional[tuple[int, int, int, int]] = None,
    scan_id: Optional[int] = None,
) -> None:
    """Render a table of severity levels with review progress percentages.

    Database-only mode: scan_id is required for database queries.

    Args:
        severities: List of severity directory paths
        msf_summary: Optional tuple of (index, unreviewed, reviewed, total)
            for Metasploit modules row
        workflow_summary: Optional tuple of (index, unreviewed, reviewed, total)
            for Workflow Mapped row
        scan_id: Scan ID for database queries (required)
    """
    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    table.add_column("#", justify="right", no_wrap=True, max_width=5)
    table.add_column("Severity", no_wrap=True, max_width=20)
    # Headers indicate percent (cells contain N (P%))
    table.add_column("Unreviewed (%)", justify="right", no_wrap=True, max_width=15)
    table.add_column("Reviewed (%)", justify="right", no_wrap=True, max_width=14)
    table.add_column("Total", justify="right", no_wrap=True, max_width=8)

    if scan_id is None:
        # scan_id should always be provided in DB-only mode, but handle gracefully
        from .ansi import warn
        warn("scan_id not provided - cannot render severity table")
        return

    for i, severity_dir in enumerate(severities, 1):
        unreviewed, reviewed, total = count_severity_findings(severity_dir, scan_id=scan_id)
        label = pretty_severity_label(severity_dir.name)
        table.add_row(
            str(i),
            severity_cell(label),
            unreviewed_cell(unreviewed, total),
            reviewed_cell(reviewed, total),
            total_cell(total),
        )

    if msf_summary:
        index, unreviewed, reviewed, total = msf_summary
        table.add_row(
            str(index),
            severity_cell("Metasploit Module"),
            unreviewed_cell(unreviewed, total),
            reviewed_cell(reviewed, total),
            total_cell(total),
        )

    if workflow_summary:
        index, unreviewed, reviewed, total = workflow_summary
        table.add_row(
            str(index),
            severity_cell("Workflow Mapped"),
            unreviewed_cell(unreviewed, total),
            reviewed_cell(reviewed, total),
            total_cell(total),
        )

    _console_global.print(table)


def render_finding_list_table(
    display: list[tuple[Any, Any]],
    sort_mode: str,
    get_counts_for: Any,
    row_offset: int = 0,
    show_severity: bool = False,
) -> None:
    """Render a paginated file list table with plugin info from database.

    Args:
        display: List of (Finding, Plugin) tuples to display on this page
        sort_mode: Current sort mode ("hosts", "name", or "plugin_id")
        get_counts_for: Function to get (host_count, ports_str) for a Finding object
        row_offset: Starting row number for pagination
        show_severity: Whether to show severity column (for MSF mode)
    """

    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    table.add_column("#", justify="right", no_wrap=True, max_width=5)
    table.add_column("Plugin ID", justify="right", no_wrap=True, max_width=10)
    table.add_column("Name", overflow="fold")
    # Always show host count column
    table.add_column("Hosts", justify="right", no_wrap=True, max_width=8)
    if show_severity:
        table.add_column("Severity", justify="left", no_wrap=True, max_width=15)

    for i, (plugin_file, plugin) in enumerate(display, 1):
        row_number = row_offset + i

        # Use plugin data directly from database
        plugin_id_str = str(plugin.plugin_id)
        plugin_name = plugin.plugin_name or "Unknown"

        row_data = [str(row_number), plugin_id_str, plugin_name]

        # Always retrieve and show host count from database
        host_count, _ports_str = get_counts_for(plugin_file)
        row_data.append(str(host_count))

        if show_severity:
            # Get severity from plugin metadata
            # Schema v5+: severity_label computed from severity_int
            from .nessus_import import severity_label_from_int
            label = severity_label_from_int(plugin.severity_int)
            sev_dir_format = f"{plugin.severity_int}_{label}"
            sev_label = pretty_severity_label(sev_dir_format)
            sev_colored = severity_cell(sev_label)
            row_data.append(sev_colored)

        table.add_row(*row_data)

    _console_global.print(table)


def render_compare_tables(
    parsed: list[tuple[Union[Path, str], list[str], set[str], dict[str, set[str]], bool]],
    host_intersection: set[str],
    host_union: set[str],
    port_intersection: set[str],
    port_union: set[str],
    same_hosts: bool,
    same_ports: bool,
    same_combos: bool,
    groups_sorted: list[list[str]],
) -> None:
    """Render comparison results showing host/port analysis across files.

    Args:
        parsed: List of (file_or_display_name, hosts, ports, combos, had_explicit) tuples
        host_intersection: Set of hosts common to all files
        host_union: Set of all hosts across all files
        port_intersection: Set of ports common to all files
        port_union: Set of all ports across all files
        same_hosts: Whether all files have identical host sets
        same_ports: Whether all files have identical port sets
        same_combos: Whether all files have identical host:port combinations
        groups_sorted: List of filename groups with identical combinations
    """
    summary = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False
    )
    summary.add_column("Aspect", max_width=20)
    summary.add_column("Equal Across Files", justify="center", no_wrap=True, max_width=20)
    summary.add_column("Intersection Size", justify="right", no_wrap=True, max_width=18)
    summary.add_column("Union Size", justify="right", no_wrap=True, max_width=12)
    summary.add_row(
        "Hosts",
        "✅" if same_hosts else "❌",
        str(len(host_intersection)),
        str(len(host_union)),
    )
    summary.add_row(
        "Ports",
        "✅" if same_ports else "❌",
        str(len(port_intersection)),
        str(len(port_union)),
    )
    summary.add_row("Host:Port Combos", "✅" if same_combos else "❌", "-", "-")
    _console_global.print(summary)

    files_table = Table(
        title="Filtered Files",
        box=box.SIMPLE,
        show_lines=False,
        pad_edge=False
    )
    files_table.add_column("#", justify="right", no_wrap=True, max_width=5)
    files_table.add_column("File", overflow="fold")
    files_table.add_column("Hosts", justify="right", no_wrap=True, max_width=8)
    files_table.add_column("Ports", justify="right", no_wrap=True, max_width=8)
    files_table.add_column(
        "Explicit combos?", justify="center", no_wrap=True, max_width=16
    )

    for i, (file_path, hosts, ports_set, combos, had_explicit) in enumerate(
        parsed, 1
    ):
        files_table.add_row(
            str(i),
            file_path if isinstance(file_path, str) else file_path.name,
            str(len(hosts)),
            str(len(ports_set)),
            "Yes" if had_explicit else "No",
        )

    _console_global.print(files_table)

    if len(groups_sorted) > 1:
        groups_table = Table(
            title="Identical Host:Port Groups",
            box=box.SIMPLE,
            show_lines=False,
            pad_edge=False
        )
        groups_table.add_column("#", justify="right", no_wrap=True, max_width=5)
        groups_table.add_column("Count", justify="right", no_wrap=True, max_width=12)
        groups_table.add_column("Findings (sample)", overflow="fold")
        for i, names in enumerate(groups_sorted, 1):
            sample = "\n".join(names[:8])
            if len(names) > 8:
                sample += f"\n... (+{len(names)-8} more - press [D] to view details)"
            groups_table.add_row(str(i), str(len(names)), sample)
        _console_global.print(groups_table)

        # Offer details view for large groups
        if any(len(names) > 8 for names in groups_sorted):
            from rich.prompt import Prompt
            try:
                detail_choice = Prompt.ask(
                    "\nPress [D] for full group details, or [Enter] to continue",
                    default=""
                ).strip().lower()

                if detail_choice == "d":
                    # Display full group details using pager
                    full_text = ""
                    for i, names in enumerate(groups_sorted, 1):
                        full_text += f"\nGroup #{i} ({len(names)} findings):\n"
                        full_text += "\n".join(f"  - {name}" for name in names)
                        full_text += "\n"

                    from .fs import menu_pager
                    menu_pager(full_text)
            except KeyboardInterrupt:
                pass
    else:
        info("\nAll filtered files fall into a single identical group.")


@log_timing
def render_actions_footer(
    *,
    group_applied: bool,
    candidates_count: int,
    sort_mode: str,
    can_next: bool,
    can_prev: bool,
) -> None:
    """Render action footer with responsive layout based on terminal width.

    Uses two-column grid for wide terminals (≥100 chars) and single-column
    layout for narrow terminals (<100 chars) to prevent wrapping.

    Args:
        group_applied: Whether a group filter is currently active
        candidates_count: Number of files matching current filter
        sort_mode: Current sort mode ("plugin_id", "hosts", or "name")
        can_next: Whether next page is available
        can_prev: Whether previous page is available
    """
    from .ansi import get_terminal_width

    # Row 1: Navigation basics + filtering controls
    left_row1 = join_actions_texts(
        [
            key_text("Enter", "Open first match"),
            key_text("B", "Back"),
            key_text("?", "Help"),
        ]
    )
    # Determine sort label for display
    sort_label = {
        "plugin_id": "Plugin ID",
        "hosts": "Hosts",
        "name": "Name"
    }.get(sort_mode, "Name")

    right_row1 = join_actions_texts(
        [
            key_text("F", "Filter"),
            key_text("C", "Clear filter"),
            key_text("O", f"Sort: {sort_label}"),
        ]
    )

    # Row 2: Analysis + pagination
    left_row2 = join_actions_texts(
        [
            key_text("R", "Reviewed"),
            key_text("H", "Compare"),
            key_text("I", "Superset"),
        ]
    )
    right_items_row2 = [
        key_text("N", "Next page", enabled=can_next),
        key_text("P", "Prev page", enabled=can_prev),
    ]
    if group_applied:
        right_items_row2.append(key_text("X", "Clear group"))
    right_row2 = join_actions_texts(right_items_row2)

    # Row 3: Bulk operations
    left_row3 = join_actions_texts(
        [
            key_text("E", f"CVEs ({candidates_count})"),
            key_text("M", f"Mark reviewed ({candidates_count})"),
        ]
    )
    right_row3 = Text()  # Empty for now, reserved for future actions

    # Detect terminal width for responsive layout
    term_width = get_terminal_width()

    if term_width >= 100:
        # Wide terminal: use 2-column grid layout
        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(ratio=1)
        grid.add_column(ratio=1)
        grid.add_row(left_row1, right_row1)
        grid.add_row(left_row2, right_row2)
        grid.add_row(left_row3, right_row3)
        _console_global.print(grid)
    else:
        # Narrow terminal: single-column layout to prevent wrapping
        _console_global.print(left_row1)
        _console_global.print(right_row1)
        _console_global.print(left_row2)
        _console_global.print(right_row2)
        _console_global.print(left_row3)
        if right_row3.plain:  # Only print if not empty
            _console_global.print(right_row3)


def show_actions_help(
    *,
    group_applied: bool,
    candidates_count: int,
    sort_mode: str,
    can_next: bool,
    can_prev: bool,
) -> None:
    """Render a categorized help panel for main/MSF file lists.

    Args:
        group_applied: Whether a group filter is currently active
        candidates_count: Number of files matching current filter
        sort_mode: Current sort mode ("hosts" or "name")
        can_next: Whether next page is available
        can_prev: Whether previous page is available
    """
    table = Table.grid(padding=(0, 1))
    table.add_row(
        Text("Navigation", style="bold"),
        key_text("Enter", "Open first match"),
        key_text("N", "Next page", enabled=can_next),
        key_text("P", "Prev page", enabled=can_prev),
        key_text("B", "Back"),
    )
    table.add_row(
        Text("Filtering", style="bold"),
        key_text("F", "Filter - Set a filter to narrow down file list"),
        key_text("C", "Clear filter - Remove active filter"),
    )
    table.add_row(
        Text("Sorting", style="bold"),
        key_text(
            "O",
            f"Sort: {'Hosts' if sort_mode=='hosts' else 'Name'} - Toggle between host count and name sorting",
        ),
    )
    table.add_row(
        Text("Bulk review", style="bold"),
        key_text(
            "M",
            f"Mark reviewed ({candidates_count}) - Mark all filtered files as REVIEW_COMPLETE",
        ),
    )
    table.add_row(
        Text("Analysis", style="bold"),
        key_text("H", "Compare - Find files with identical host:port combinations"),
        key_text("I", "Superset - Find files where one is a subset of another"),
        key_text("E", f"CVEs ({candidates_count}) - Extract CVEs for all filtered files"),
    )
    if group_applied:
        table.add_row(
            Text("Groups", style="bold"), key_text("X", "Clear group filter")
        )
    panel = Panel(table, title="Actions", border_style=style_if_enabled("cyan"))
    _console_global.print(panel)


def show_reviewed_help() -> None:
    """Render help panel for completed findings view."""
    table = Table.grid(padding=(0, 1))
    table.add_column(style=style_if_enabled("cyan"), no_wrap=True)
    table.add_column()

    table.add_row("Purpose", "View findings marked as completed during review")
    table.add_row("Undo", "Press [U] to restore findings to pending state")
    table.add_row("Filter", "Press [F] to filter by plugin name")
    table.add_row("", "")
    table.add_row("Note", "This is a management view - select findings in main list to work with them")

    panel = Panel(
        table,
        title="[bold cyan]Completed Findings Help[/]",
        border_style=style_if_enabled("cyan")
    )
    _console_global.print(panel)


def key_text(key: str, label: str, *, enabled: bool = True) -> Text:
    """Format a keyboard shortcut with label for action menus.

    Args:
        key: Keyboard key to press
        label: Description of the action
        enabled: Whether the action is currently available

    Returns:
        Formatted Text object with cyan key and dimmed/normal label
    """
    text = Text()
    text.append(f"[{key}] ", style=style_if_enabled("cyan"))
    text.append(label, style=None if enabled else style_if_enabled("dim"))
    if not enabled:
        text.stylize(style_if_enabled("dim"))
    return text


def join_actions_texts(items: list[Text]) -> Text:
    """Join multiple action Text items with "/" separators.

    Args:
        items: List of Text objects to join

    Returns:
        Combined Text object with separators
    """
    output = Text()
    for i, item in enumerate(items):
        if i:
            output.append(" / ", style=style_if_enabled("dim"))
        output.append(item)
    return output


def count_severity_findings(
    directory: Path,
    scan_id: int
) -> tuple[int, int, int]:
    """Count unreviewed, reviewed, and total files in a severity directory.

    Database-only mode: queries the database for review state tracking.

    Args:
        directory: Severity directory path
        scan_id: Scan ID for database queries (required)

    Returns:
        Tuple of (unreviewed_count, reviewed_count, total_count)
    """
    from .models import Finding
    severity_dir_name = directory.name
    return Finding.count_by_scan_severity(scan_id, severity_dir_name)


def severity_cell(label: str) -> Any:
    """Format a severity label cell with color styling.

    Args:
        label: Severity level label

    Returns:
        Styled Text object for table cell
    """
    text = Text(label)
    text.stylize("bold")
    text.stylize(severity_style(label))
    return text


def unreviewed_cell(count: int, total: int) -> Any:
    """Format an unreviewed count cell with percentage and color.

    Args:
        count: Number of unreviewed files
        total: Total number of files

    Returns:
        Styled Text object showing count and percentage
    """
    percentage = 0
    if total:
        percentage = round((count / total) * 100)
    text = Text(f"{count} ({percentage}%)")
    if count == 0:
        text.stylize(style_if_enabled("green"))
    elif count <= 10:
        text.stylize(style_if_enabled("yellow"))
    else:
        text.stylize(style_if_enabled("red"))
    return text


def reviewed_cell(count: int, total: int) -> Any:
    """Format a reviewed count cell with percentage.

    Args:
        count: Number of reviewed files
        total: Total number of files

    Returns:
        Styled Text object showing count and percentage
    """
    percentage = 0
    if total:
        percentage = round((count / total) * 100)
    text = Text(f"{count} ({percentage}%)")
    text.stylize(style_if_enabled("magenta"))
    return text


def total_cell(count: int) -> Any:
    """Format a total count cell in bold.

    Args:
        count: Total count to display

    Returns:
        Bold Text object
    """
    text = Text(str(count))
    text.stylize("bold")
    return text


def severity_style(label: str) -> str:
    """Map a severity label to a color style.

    Uses centralized SEVERITY_COLORS mapping from constants.py.
    Respects the no_color configuration setting by returning
    empty string (no styling) when color output is disabled.

    Args:
        label: Severity level label

    Returns:
        Color style name for Rich styling (or empty string if colors disabled)
    """
    from .ansi import get_no_color

    # If colors are disabled, return empty string (no styling)
    if get_no_color():
        return ""

    normalized_label = label.strip().lower()

    # Look up color from centralized mapping
    for severity_key, (rich_color, _) in SEVERITY_COLORS.items():
        if severity_key in normalized_label:
            return rich_color

    # Default fallback
    return SEVERITY_COLORS["default"][0]


# ===================================================================
# Finding Display Formatters (moved from cerno.py)
# ===================================================================


def _file_raw_payload_text(finding: "Finding") -> str:
    """
    Get raw file content from database (all host:port lines).

    Args:
        finding: Finding database object

    Returns:
        File content as UTF-8 string (one host:port per line)
    """
    # Get all host:port lines from database
    lines = finding.get_all_host_port_lines()
    content = "\n".join(lines)
    if lines:
        content += "\n"  # Add trailing newline
    return content


def _file_raw_paged_text(finding: "Finding", plugin: "Plugin") -> str:
    """
    Prepare raw file content for paged viewing with metadata from database.

    Args:
        finding: Finding database object
        plugin: Plugin metadata object

    Returns:
        Formatted string with file info and content
    """
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"

    # Get content from database
    content = _file_raw_payload_text(finding)
    size_bytes = len(content.encode('utf-8'))

    lines = [f"Showing: {display_name} ({size_bytes} bytes from database)"]
    lines.append(content)
    return "\n".join(lines)


def page_text(text: str) -> None:
    """
    Send text through a pager if possible; otherwise print.

    Args:
        text: Text content to display
    """
    with _console_global.pager(styles=True):
        _console_global.print(text, end="" if text.endswith("\n") else "\n")


def _grouped_payload_text(finding: "Finding") -> str:
    """
    Generate grouped host:port text for copying/viewing from database.

    Args:
        finding: Finding database object

    Returns:
        Formatted string with host:port,port,... lines
    """
    # Get all host:port lines from database
    lines = finding.get_all_host_port_lines()

    # Group ports by host
    from collections import defaultdict
    host_ports = defaultdict(list)

    for line in lines:
        if ":" in line:
            # Handle IPv6 with brackets: [host]:port
            if line.startswith("["):
                # IPv6 format: [2001:db8::1]:80
                host_end = line.index("]")
                host = line[1:host_end]  # Remove brackets
                port = line[host_end+2:]  # Skip ']:'
            else:
                # IPv4 or hostname: host:port
                host, port = line.rsplit(":", 1)
            host_ports[host].append(port)
        else:
            # No port
            host_ports[line].append(None)

    # Format output: host:port1,port2,port3 or just host if no ports
    out = []
    for host in host_ports.keys():
        ports = [p for p in host_ports[host] if p is not None]
        if ports:
            # Sort ports numerically
            sorted_ports = sorted(set(ports), key=lambda x: int(x))
            out.append(f"{host}:{','.join(sorted_ports)}")
        else:
            out.append(host)

    return "\n".join(out) + ("\n" if out else "")


def _grouped_paged_text(finding: "Finding", plugin: "Plugin") -> str:
    """
    Prepare grouped host:port content for paged viewing from database.

    Args:
        finding: Finding database object
        plugin: Plugin metadata object

    Returns:
        Formatted string with header and grouped content
    """
    body = _grouped_payload_text(finding)
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
    return f"Grouped view: {display_name}\n{body}"


def _hosts_only_payload_text(finding: "Finding") -> str:
    """
    Extract only hosts (IPs or FQDNs) without port information from database.

    Args:
        finding: Finding database object

    Returns:
        One host per line
    """
    # Get unique hosts from database (already sorted: IPs first, then hostnames)
    hosts, _ports_str = finding.get_hosts_and_ports()
    return "\n".join(hosts) + ("\n" if hosts else "")


def _hosts_only_paged_text(finding: "Finding", plugin: "Plugin") -> str:
    """
    Prepare hosts-only content for paged viewing from database.

    Args:
        finding: Finding database object
        plugin: Plugin metadata object

    Returns:
        Formatted string with header and host list
    """
    body = _hosts_only_payload_text(finding)
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
    return f"Hosts-only view: {display_name}\n{body}"


def _build_plugin_output_details(
    finding: "Finding",
    plugin: "Plugin"
) -> Optional[str]:
    """Build formatted text for plugin output details display.

    Shows plugin_output data for each affected host:port combination.
    If multiple hosts have the same output, shows all separately (no deduplication).

    Args:
        finding: Finding database object
        plugin: Plugin metadata object

    Returns:
        Formatted string for display via menu_pager(), or None if no outputs
    """
    from .database import get_connection

    # Get all plugin outputs from database
    with get_connection() as conn:
        outputs = finding.get_plugin_outputs_by_host(conn)

    if not outputs:
        return None

    # Filter out entries with no plugin_output (None or empty)
    outputs_with_data = [
        (host, port, output) for (host, port, output) in outputs
        if output is not None and output.strip()
    ]

    if not outputs_with_data:
        return None

    # Build formatted output
    lines = []
    lines.append(f"Finding Details: {plugin.plugin_name} (Plugin {plugin.plugin_id})")
    lines.append("=" * 80)
    lines.append(f"Severity: {plugin.severity_label}")
    lines.append(f"Total hosts with output: {len(outputs_with_data)}")
    lines.append("")

    # Display each host:port's plugin output
    for idx, (host, port, output) in enumerate(outputs_with_data, 1):
        # Format host:port
        if port is not None:
            host_display = f"{host}:{port}"
        else:
            host_display = host

        lines.append(f"[{idx}/{len(outputs_with_data)}] Host: {host_display}")
        lines.append("-" * 80)
        lines.append(output)
        lines.append("")  # Blank line between entries

    return "\n".join(lines)


def _display_finding_preview(
    plugin: "Plugin",
    finding: "Finding",
    sev_dir: Optional[Path],
    chosen: Path,
) -> None:
    """Display finding preview panel with metadata (database-only).

    Args:
        plugin: Plugin metadata object
        finding: Finding database object (required)
        sev_dir: Severity directory path
        chosen: File path (for URL extraction)
    """
    import re

    # Get hosts and ports from database
    hosts, ports_str = finding.get_hosts_and_ports()

    # Build Rich Panel preview
    content = Text()

    # Check for Metasploit module from plugin metadata
    is_msf = plugin.has_metasploit

    # Nessus Plugin ID
    content.append("Nessus Plugin ID: ", style=style_if_enabled("cyan"))
    content.append(f"{plugin.plugin_id}\n", style=style_if_enabled("yellow"))

    # Severity
    content.append("Severity: ", style=style_if_enabled("cyan"))
    sev_label = pretty_severity_label(sev_dir.name) if sev_dir else f"{plugin.severity_int}_{plugin.severity_label or 'Unknown'}"
    content.append(f"{sev_label}\n", style=severity_style(sev_label))

    # Plugin Details (URL)
    plugin_url = None
    # Import _plugin_details_line from parsing module if needed
    # For now, we'll skip this feature until Phase 5 when we move _plugin_details_line
    # pd_line = _plugin_details_line(chosen)
    # if pd_line:
    #     try:
    #         match = re.search(r"(https?://[^\s)\]\}>,;]+)", pd_line)
    #         plugin_url = match.group(1) if match else None
    #         if plugin_url:
    #             content.append("Plugin Details: ", style=style_if_enabled("cyan"))
    #             content.append(f"{plugin_url}\n", style=style_if_enabled("blue underline"))
    #     except Exception:
    #         pass

    # Unique hosts
    content.append("Unique hosts: ", style=style_if_enabled("cyan"))
    content.append(f"{len(hosts)}\n", style=style_if_enabled("yellow"))

    # Example host
    if hosts:
        content.append("Example host: ", style=style_if_enabled("cyan"))
        content.append(f"{hosts[0]}\n", style=style_if_enabled("yellow"))

    # Ports detected
    if ports_str:
        content.append("Ports detected: ", style=style_if_enabled("cyan"))
        content.append(f"{ports_str}", style=style_if_enabled("yellow"))

    # Create panel with plugin name as title and MSF indicator in subtitle
    subtitle = None
    if is_msf:
        subtitle = "⚡ Metasploit module available"

    panel = Panel(
        content,
        title=f"[bold cyan]{plugin.plugin_name}[/]",
        subtitle=subtitle,
        subtitle_align="center",
        title_align="center",
        border_style=style_if_enabled("cyan")
    )

    _console_global.print()  # Blank line before panel
    _console_global.print(panel)


# ===================================================================
# CVE Display Functions (moved from cerno.py)
# ===================================================================


def bulk_extract_cves_for_plugins(plugins: List[tuple[int, str]]) -> None:
    """
    Display CVEs for multiple plugins from database (read-only, no web scraping).

    Queries the database for CVEs associated with each plugin and displays
    a consolidated list organized by plugin.

    Args:
        plugins: List of (plugin_id, plugin_name) tuples
    """
    from .models import Plugin
    from .database import get_connection
    from .ansi import header, info

    header("CVE Information for Filtered Findings")
    info(f"Displaying CVEs from {len(plugins)} finding(s)...\n")

    results = {}  # plugin_name -> list of CVEs

    # Query database (instant, no progress bar needed)
    with get_connection() as conn:
        for plugin_id, plugin_name in plugins:
            try:
                plugin = Plugin.get_by_id(plugin_id, conn=conn)
                if plugin and plugin.cves:
                    results[plugin_name] = plugin.cves
            except Exception:
                # Silently skip failed queries
                pass

    # Display results
    _display_bulk_cve_results(results)


def bulk_extract_cves_for_findings(files: List[Path]) -> None:
    """
    Display CVEs for multiple plugin findings from database (read-only, no web scraping).

    Queries the database for CVEs associated with each plugin file and displays
    a consolidated list organized by plugin.

    Args:
        files: List of plugin file paths to display CVEs for
    """
    from .models import Plugin
    from .database import get_connection
    from .parsing import extract_plugin_id_from_filename
    from .ansi import header, info

    header("CVE Information for Filtered Findings")
    info(f"Displaying CVEs from {len(files)} file(s)...\n")

    results = {}  # plugin_name -> list of CVEs

    # Query database (instant, no progress bar needed)
    with get_connection() as conn:
        for file_path in files:
            plugin_id = extract_plugin_id_from_filename(file_path)
            if not plugin_id:
                continue

            try:
                plugin = Plugin.get_by_id(int(plugin_id), conn=conn)
                if plugin and plugin.cves:
                    results[file_path.name] = plugin.cves
            except Exception:
                # Silently skip failed queries
                pass

    # Display results
    _display_bulk_cve_results(results)


def _display_bulk_cve_results(results: dict[str, list[str]]) -> None:
    """Display CVE extraction results with preview and smart format selection.

    Shows CVE count preview before asking for format choice.
    Auto-selects combined format for 1-2 findings, separated for 3+.

    Args:
        results: Dictionary mapping plugin name/filename to list of CVEs
    """
    from rich.prompt import Prompt
    from .ansi import info, warn

    # Display results
    if results:
        # Count total findings and unique CVEs
        total_findings = len(results)
        all_cves = set()
        for cves in results.values():
            all_cves.update(cves)
        total_unique_cves = len(all_cves)

        # Show preview before asking for format
        info(f"\nFound {total_unique_cves} unique CVE(s) across {total_findings} finding(s)")

        # Smart default: 1-2 findings → combined, 3+ → separated
        default_format = "c" if total_findings <= 2 else "s"
        default_label = "Combined" if default_format == "c" else "Separated"

        # Ask user for display format with smart default
        print_action_menu([
            ("S", "Separated (by finding)"),
            ("C", "Combined (all unique CVEs)"),
            ("", f"[Enter] for {default_label}")
        ])
        try:
            format_choice = Prompt.ask(
                "Choose format",
                default=default_format
            ).lower()
        except KeyboardInterrupt:
            return

        if format_choice in ("c", "combined"):
            # Combined list: all unique CVEs across all findings
            info(f"\nAll unique CVEs ({total_unique_cves}):\n")
            for cve in sorted(all_cves):
                info(f"  {cve}")
        else:
            # Separated by file (default)
            info(f"\nCVEs by finding ({total_findings}):\n")
            for plugin_name, cves in sorted(results.items()):
                info(f"{plugin_name}:")
                for cve in cves:
                    info(f"  {cve}")
                _console_global.print()  # Blank line between plugins
    else:
        warn("No CVEs found for any of the filtered findings.")

    try:
        Prompt.ask("\nPress Enter to continue", default="")
    except KeyboardInterrupt:
        pass


def _color_unreviewed(count: int) -> str:
    """
    Colorize unreviewed file count based on severity.

    Args:
        count: Number of unreviewed findings

    Returns:
        ANSI-colored string
    """
    from .ansi import C

    if count == 0:
        return f"{C.GREEN}{count}{C.RESET}"
    if count <= 10:
        return f"{C.YELLOW}{count}{C.RESET}"
    return f"{C.RED}{count}{C.RESET}"
