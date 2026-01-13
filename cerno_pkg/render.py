"""Rich-based table and UI rendering for the cerno TUI.

This module provides functions to render tables, paginated content, action
menus, and comparison results using the Rich library for terminal UI.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, List, Optional, Union, TYPE_CHECKING

from rich import box
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from contextlib import contextmanager
import time

from .ansi import info, warn, header, get_console, style_if_enabled
from .constants import SEVERITY_COLORS
from .fs import default_page_size, pretty_severity_label
from .logging_setup import log_timing

if TYPE_CHECKING:
    from .models import Finding, Plugin

_console_global = get_console()


@contextmanager
def show_progress(message: str, threshold_seconds: float = 0.5):
    """Context manager to show progress spinner for long-running operations.

    Only displays spinner if operation takes longer than threshold.

    Args:
        message: Message to display (e.g., "Loading findings...")
        threshold_seconds: Minimum duration before showing spinner (default: 0.5s)

    Example:
        >>> with show_progress("Loading 755 findings..."):
        ...     findings = Finding.get_by_scan_with_plugin(scan_id)
    """
    start_time = time.time()

    try:
        yield  # Execute the wrapped code first
    finally:
        elapsed = time.time() - start_time
        # Note: This displays after the operation, not during
        # For true async progress, we'd need threading which adds complexity
        # For now, this serves as timing feedback for slow operations
        if elapsed >= threshold_seconds:
            # Show elapsed time for operations that exceeded threshold
            _console_global.print(f"[dim]({elapsed:.1f}s)[/dim]")


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


def render_empty_state(context: str, filter_text: str = "") -> None:
    """Render helpful empty state message based on context.

    Args:
        context: Context identifier for empty state type
            - "filter_mismatch": No findings match current filter
            - "no_severity": No findings at this severity level
            - "all_completed": All findings marked as completed
            - "no_findings": No findings in scan at all
        filter_text: Current filter string (if applicable)
    """
    if context == "filter_mismatch":
        if filter_text:
            info(f'\nNo findings match your current filter: "{filter_text}"')
        else:
            info("\nNo findings match the current filter.")
        info("")
        info("Suggestions:")
        info("  • Press [C] to clear filter and see all findings")
        info("  • Press [F] to adjust your search term")
        info("  • Try broader terms like 'http' or 'ssl'")
        info("")

    elif context == "no_severity":
        info("\nNo findings at this severity level.")
        info("")
        info("This may mean:")
        info("  • The scan found no issues of this severity")
        info("  • All findings of this severity have been filtered out")
        info("")
        info("Press [B] to return to severity menu.")
        info("")

    elif context == "all_completed":
        from .ansi import ok
        ok("\n✓ All findings marked as completed!")
        info("")
        info("Next steps:")
        info("  • Press [R] to view completed findings")
        info("  • Press [U] from the reviewed list to undo completion")
        info("  • Press [B] to return to severity menu")
        info("")

    elif context == "no_findings":
        warn("\nNo findings in this scan.")
        info("")
        info("This could mean:")
        info("  • The .nessus file contained no vulnerability findings")
        info("  • Import process encountered issues")
        info("")


def render_pagination_indicator(
    current_page: int,
    total_pages: int,
    total_items: int
) -> str:
    """Generate pagination indicator with visual progress bar.

    Args:
        current_page: Current page number (0-indexed)
        total_pages: Total number of pages
        total_items: Total number of items across all pages

    Returns:
        Formatted pagination string with progress bar

    Examples:
        >>> render_pagination_indicator(0, 5, 125)
        '[████░░░░░░] Page 1/5 (125 total)'
        >>> render_pagination_indicator(2, 5, 125)
        '[██████░░░░] Page 3/5 (125 total)'
    """
    if total_pages <= 1:
        return f"Page 1/1 ({total_items} total)"

    # Calculate progress bar
    progress = (current_page + 1) / total_pages
    bar_width = 10
    filled = int(progress * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    # Bold page numbers for emphasis
    page_display = f"**{current_page + 1}/{total_pages}**"

    return f"[{bar}] Page {page_display} ({total_items} total)"


def render_scan_context_header(scan: Any, scan_id: int) -> None:
    """Render compact scan context header with metadata and progress.

    Args:
        scan: Scan database object
        scan_id: Scan ID for database queries

    Displays scan overview including:
    - Scan name and file
    - Import timestamp
    - Total findings count
    - Review progress (unreviewed/reviewed/completed)

    Layout adapts to terminal width (single line vs multi-line).
    """
    from .ansi import get_terminal_width, style_if_enabled
    from .database import get_connection
    from datetime import datetime

    # Query database for finding counts by review state
    with get_connection() as conn:
        cursor = conn.execute("""
            SELECT
                SUM(CASE WHEN review_state = 'pending' THEN 1 ELSE 0 END) as unreviewed,
                SUM(CASE WHEN review_state = 'reviewed' THEN 1 ELSE 0 END) as reviewed,
                SUM(CASE WHEN review_state = 'completed' THEN 1 ELSE 0 END) as completed,
                COUNT(*) as total
            FROM findings
            WHERE scan_id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        unreviewed_count = row[0] if row else 0
        reviewed_count = row[1] if row else 0
        completed_count = row[2] if row else 0
        total_count = row[3] if row else 0

    # Format timestamp as relative time if recent, otherwise date
    if scan.imported_at:
        try:
            if isinstance(scan.imported_at, str):
                imported_dt = datetime.fromisoformat(scan.imported_at.replace('Z', '+00:00'))
            else:
                imported_dt = scan.imported_at

            now = datetime.now(imported_dt.tzinfo) if imported_dt.tzinfo else datetime.now()
            delta = now - imported_dt
            delta_seconds = delta.total_seconds()

            if delta_seconds < 3600:  # Less than 1 hour
                minutes = int(delta_seconds / 60)
                time_ago = f"{minutes} min ago" if minutes != 1 else "1 min ago"
            elif delta_seconds < 86400:  # Less than 1 day
                hours = int(delta_seconds / 3600)
                time_ago = f"{hours} hour{'s' if hours != 1 else ''} ago"
            elif delta_seconds < 604800:  # Less than 1 week
                days = int(delta_seconds / 86400)
                time_ago = f"{days} day{'s' if days != 1 else ''} ago"
            else:
                time_ago = imported_dt.strftime("%Y-%m-%d")
        except Exception:
            time_ago = "unknown"
    else:
        time_ago = "unknown"

    # Detect terminal width for responsive layout
    term_width = get_terminal_width()

    # Build header text
    scan_name = scan.scan_name or "Unknown"
    nessus_file = scan.nessus_file_path or "unknown.nessus"

    if term_width >= 120:
        # Wide terminal: single line
        header_text = Text()
        header_text.append("Scan: ", style=style_if_enabled("bold"))
        header_text.append(f"{scan_name}", style=style_if_enabled("cyan"))
        header_text.append(" | ", style=style_if_enabled("dim"))
        header_text.append(f"File: {nessus_file}", style=None)
        header_text.append(" | ", style=style_if_enabled("dim"))
        header_text.append(f"Imported: {time_ago}", style=None)
        header_text.append(" | ", style=style_if_enabled("dim"))
        header_text.append(f"Total: {total_count} plugins", style=style_if_enabled("bold"))
        header_text.append(" | ", style=style_if_enabled("dim"))
        header_text.append(f"Unreviewed: {unreviewed_count}", style=style_if_enabled("cyan"))
        header_text.append(" | ", style=style_if_enabled("dim"))
        header_text.append(f"Reviewed: {reviewed_count}", style=style_if_enabled("yellow"))
        header_text.append(" | ", style=style_if_enabled("dim"))
        header_text.append(f"Completed: {completed_count}", style=style_if_enabled("green"))

        _console_global.print(header_text)
    else:
        # Narrow/medium terminal: multi-line layout
        line1 = Text()
        line1.append("Scan: ", style=style_if_enabled("bold"))
        line1.append(f"{scan_name}", style=style_if_enabled("cyan"))
        line1.append(" | ", style=style_if_enabled("dim"))
        line1.append(f"Imported: {time_ago}", style=None)

        line2 = Text()
        line2.append(f"Total: {total_count} plugins", style=style_if_enabled("bold"))
        line2.append(" | ", style=style_if_enabled("dim"))
        line2.append(f"Unreviewed: {unreviewed_count}", style=style_if_enabled("cyan"))
        line2.append(" | ", style=style_if_enabled("dim"))
        line2.append(f"Reviewed: {reviewed_count}", style=style_if_enabled("yellow"))
        line2.append(" | ", style=style_if_enabled("dim"))
        line2.append(f"Completed: {completed_count}", style=style_if_enabled("green"))

        _console_global.print(line1)
        _console_global.print(line2)

    # Separator line
    _console_global.print("─" * min(term_width, 80))


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
        show_severity: Deprecated - severity column is now always shown
    """

    table = Table(
        title=None, box=box.SIMPLE, show_lines=False, pad_edge=False,
        row_styles=["", "dim"]
    )
    table.add_column("#", justify="right", no_wrap=True, max_width=5)
    table.add_column("Plugin ID", justify="right", no_wrap=True, max_width=10)
    table.add_column("Severity", justify="left", no_wrap=True, max_width=10)
    table.add_column("Name", overflow="fold")
    # Always show host count column
    table.add_column("Hosts", justify="right", no_wrap=True, max_width=8)

    for i, (plugin_file, plugin) in enumerate(display, 1):
        row_number = row_offset + i

        # Use plugin data directly from database
        plugin_id_str = str(plugin.plugin_id)
        plugin_name = plugin.plugin_name or "Unknown"

        # Get severity from plugin metadata
        from .nessus_import import severity_label_from_int
        from .ansi import get_terminal_width
        label = severity_label_from_int(plugin.severity_int)

        # Adaptive severity labels based on terminal width
        term_width = get_terminal_width()

        if term_width >= 120:
            # Wide terminal: full labels
            sev_display = label  # "Critical", "High", "Medium", "Low", "Info"
        elif term_width >= 80:
            # Medium terminal: abbreviated labels (current default)
            sev_display = {
                "Critical": "Crit",
                "High": "High",
                "Medium": "Med",
                "Low": "Low",
                "Info": "Info"
            }.get(label, label)
        else:
            # Narrow terminal: single-character indicators
            sev_display = {
                "Critical": "C",
                "High": "H",
                "Medium": "M",
                "Low": "L",
                "Info": "I"
            }.get(label, label[0] if label else "?")

        # Color-code the severity label using severity_cell
        sev_colored = severity_cell(sev_display)

        row_data = [str(row_number), plugin_id_str, sev_colored, plugin_name]

        # Always retrieve and show host count from database
        host_count, _ports_str = get_counts_for(plugin_file)
        row_data.append(str(host_count))

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
    # Display explanatory context before results
    num_groups = len(groups_sorted)
    if num_groups > 1:
        header(f"Found {num_groups} groups with identical host:port combinations")
        info("")
        info("What this means: Findings in the same group affect the exact same systems.")
        info("You might want to review them together or choose one as representative.")
        info("")
    else:
        header("Comparison Results - All findings in single group")
        info("")
        info("What this means: All filtered findings affect identical host:port combinations.")
        info("")

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
                sample += f"\n\n[bold yellow]Showing 8 of {len(names)} findings - Press [D] to view all[/]"
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
            key_text("S", f"Sort: {sort_label}"),
        ]
    )

    # Row 2: Analysis + pagination
    left_row2 = join_actions_texts(
        [
            key_text("R", "Reviewed"),
            key_text("H", "Compare"),
            key_text("O", "Overlapping"),
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


def render_tool_availability_table(include_unavailable: bool = True) -> None:
    """Render a table showing availability and version info for all registered tools.

    Displays each tool's installation status (✅ available, ❌ not found) and
    version information if available. Automatically adapts when new tools are
    added to the tool registry.

    Args:
        include_unavailable: If True, shows all tools regardless of availability.
                           If False, only shows available tools.

    Example output:
        Tool         Status  Version/Details
        ─────────────────────────────────────────
        nmap         ✅      v7.92
        netexec      ✅      v1.2.1
        metasploit   ✅      Available (web-based)
        custom       ✅      Available (user-defined)
    """
    import shutil
    from .tool_registry import get_available_tools
    from .ops import get_tool_version

    # Get all registered tools
    all_tools = get_available_tools(check_requirements=False)

    # Build table data
    table_rows = []
    for tool in all_tools:
        # Check if tool is available
        if tool.requires:
            # Tool has binary requirements - check if any are available
            is_available = any(shutil.which(cmd) for cmd in tool.requires)
            if is_available:
                # Get version info
                version = get_tool_version(tool.name, tool.requires)
                if version:
                    details = f"v{version}"
                else:
                    details = "Available"
            else:
                details = "Not found in PATH"
        else:
            # Tool has no binary requirements (user-defined)
            is_available = True
            if tool.id == "custom":
                details = "Available (user-defined)"
            else:
                details = "Available"

        # Add row to table data
        if include_unavailable or is_available:
            status_icon = "✅" if is_available else "❌"
            table_rows.append((tool.name, status_icon, details, is_available))

    # Create Rich table
    table = Table(
        title="Tool Availability",
        box=box.SIMPLE,
        show_lines=False,
        pad_edge=False,
    )

    # Add columns with styling
    table.add_column("Tool", style=style_if_enabled("cyan"), no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True, max_width=10)
    table.add_column("Version/Details", overflow="fold")

    # Populate rows
    for tool_name, status_icon, details, is_available in table_rows:
        # Style details based on availability
        if is_available:
            details_text = Text(details)
            details_text.stylize(style_if_enabled("green"))
        else:
            details_text = Text(details)
            details_text.stylize(style_if_enabled("red"))

        table.add_row(tool_name, status_icon, details_text)

    # Print table
    _console_global.print(table)


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
            "S",
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
        key_text("O", "Overlapping - Find findings that cover all affected systems of another finding"),
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

    Uses neutral cyan color for progress tracking (not risk indication).
    Reserve red/yellow/green for severity labels only.

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
    # Use neutral cyan color for progress metrics (not risk colors)
    text.stylize(style_if_enabled("cyan"))
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


def file_raw_payload_text(finding: "Finding") -> str:
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


def file_raw_paged_text(finding: "Finding", plugin: "Plugin") -> str:
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
    content = file_raw_payload_text(finding)
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


def grouped_payload_text(finding: "Finding") -> str:
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


def grouped_paged_text(finding: "Finding", plugin: "Plugin") -> str:
    """
    Prepare grouped host:port content for paged viewing from database.

    Args:
        finding: Finding database object
        plugin: Plugin metadata object

    Returns:
        Formatted string with header and grouped content
    """
    body = grouped_payload_text(finding)
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
    return f"Grouped view: {display_name}\n{body}"


def hosts_only_payload_text(finding: "Finding") -> str:
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


def hosts_only_paged_text(finding: "Finding", plugin: "Plugin") -> str:
    """
    Prepare hosts-only content for paged viewing from database.

    Args:
        finding: Finding database object
        plugin: Plugin metadata object

    Returns:
        Formatted string with header and host list
    """
    body = hosts_only_payload_text(finding)
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
    return f"Hosts-only view: {display_name}\n{body}"


def build_plugin_output_details(
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


def display_finding_preview(
    plugin: "Plugin",
    finding: "Finding",
    sev_dir: Optional[Path],
    chosen: Path,
    workflow_mapper: Optional[Any] = None,
) -> None:
    """Display finding preview panel with metadata (database-only).

    Args:
        plugin: Plugin metadata object
        finding: Finding database object (required)
        sev_dir: Severity directory path
        chosen: File path (for URL extraction)
        workflow_mapper: Optional workflow mapper to check for workflow availability
    """

    # Get hosts from database
    hosts, _ = finding.get_hosts_and_ports()

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

    # Get port distribution from database
    port_distribution = finding.get_port_distribution()

    # Unique hosts with port summary
    content.append("Unique hosts: ", style=style_if_enabled("cyan"))
    if port_distribution and len(port_distribution) > 0:
        port_list = ", ".join(sorted(port_distribution.keys(), key=lambda x: int(x)))
        content.append(f"{len(hosts)} across {len(port_distribution)} port(s) ({port_list})\n", style=style_if_enabled("yellow"))
    else:
        content.append(f"{len(hosts)}\n", style=style_if_enabled("yellow"))

    # Port distribution details (if multiple ports)
    if port_distribution and len(port_distribution) > 1:
        content.append("Distribution: ", style=style_if_enabled("cyan"))
        dist_parts = []
        for port in sorted(port_distribution.keys(), key=lambda x: int(x)):
            count = port_distribution[port]
            dist_parts.append(f"{count} host{'s' if count != 1 else ''} on port {port}")
        content.append(", ".join(dist_parts) + "\n", style=style_if_enabled("yellow"))

    # Example host (with port if available)
    if hosts:
        content.append("Example: ", style=style_if_enabled("cyan"))
        # Show example host with first port if available
        if port_distribution:
            first_port = sorted(port_distribution.keys(), key=lambda x: int(x))[0]
            content.append(f"{hosts[0]}:{first_port}\n", style=style_if_enabled("yellow"))
        else:
            content.append(f"{hosts[0]}\n", style=style_if_enabled("yellow"))

    # Create panel with plugin name as title and indicators in subtitle
    subtitle_parts = []

    # Add Metasploit badge (if available)
    if is_msf:
        if plugin.metasploit_names and len(plugin.metasploit_names) > 0:
            # Show count if multiple modules, otherwise show first module name
            if len(plugin.metasploit_names) > 1:
                msf_text = f"⚡ Metasploit ({len(plugin.metasploit_names)} modules)"
            else:
                msf_module = plugin.metasploit_names[0]
                # Truncate long module names to 40 chars
                if len(msf_module) > 40:
                    msf_module = msf_module[:37] + "..."
                msf_text = f"⚡ Metasploit: {msf_module}"
            subtitle_parts.append(msf_text)
        else:
            subtitle_parts.append("⚡ Metasploit")

    # Add Workflow badge (if available)
    if workflow_mapper and plugin:
        workflow = workflow_mapper.get_workflow(str(plugin.plugin_id))
        if workflow:
            workflow_name = workflow.workflow_name
            # Truncate long workflow names to 40 chars
            if len(workflow_name) > 40:
                workflow_name = workflow_name[:37] + "..."
            subtitle_parts.append(f"📋 Workflow: {workflow_name}")

    subtitle = " | ".join(subtitle_parts) if subtitle_parts else None

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
    display_bulk_cve_results(results)


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
    display_bulk_cve_results(results)


def display_bulk_cve_results(results: dict[str, list[str]]) -> None:
    """Display CVE extraction results with preview and smart format selection.

    Shows CVE count preview before asking for format choice.
    Auto-selects combined format for 1-2 findings, separated for 3+.

    Args:
        results: Dictionary mapping plugin name/filename to list of CVEs
    """
    from rich.prompt import Prompt
    # Display results
    if results:
        # Count total findings and unique CVEs
        total_findings = len(results)
        all_cves = set()
        for cves in results.values():
            all_cves.update(cves)
        total_unique_cves = len(all_cves)

        # Show enhanced preview with CVE distribution
        info(f"\nFound {total_unique_cves} unique CVE(s) across {total_findings} finding(s):")

        # Show CVE count per finding (limit to first 10 findings for readability)
        findings_to_show = list(results.items())[:10]
        for plugin_name, cves in findings_to_show:
            # Truncate long plugin names
            display_name = plugin_name if len(plugin_name) <= 60 else plugin_name[:57] + "..."
            info(f"  {display_name}: {len(cves)} CVE(s)")

        if len(results) > 10:
            remaining = len(results) - 10
            info(f"  ... and {remaining} more finding(s)")

        # Smart default: 1-2 findings → combined, 3+ → separated
        default_format = "c" if total_findings <= 2 else "s"
        default_label = "Combined" if default_format == "c" else "Separated"

        # Ask user for display format with smart default
        info("")  # Blank line for spacing
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


def color_unreviewed(count: int) -> str:
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
