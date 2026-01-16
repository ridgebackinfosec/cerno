#!/usr/bin/env python3
"""
Cerno - Modern CLI for Nessus finding host review and security tool orchestration.

This tool provides an interactive TUI for reviewing Nessus finding exports,
running security tools (nmap, netexec, metasploit), and tracking progress.
"""

# --- import path shim (supports both `python cerno.py` and `python -m cerno`) ---
import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from cerno_pkg import (
    # version
    __version__,
    # ops
    root_or_sudo_available,
    # parsing
    group_findings_by_workflow,
    # constants
    get_results_root,
    DEFAULT_TOP_PORTS,
    # ansi / labels
    header,
    ok,
    warn,
    err,
    info,
    fmt_action,
    style_if_enabled,
    # render
    render_severity_table,
    render_finding_list_table,
    render_actions_footer,
    severity_cell,
    pretty_severity_label,
    default_page_size,
    print_action_menu,
    # fs
    process_single_finding,
    # session
    save_session,
    load_session,
    delete_session,
    show_scan_summary,
    # workflow_mapper
    WorkflowMapper,
    # analysis
    natural_key,
    # tui
    parse_severity_selection,
    SeveritySelection,
    handle_finding_list_actions,
    # banner
    display_banner,
)

# === Standard library imports ===
import math
import types
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from cerno_pkg.config import CernoConfig

# === Third-party imports ===
import typer
from typer import Exit
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.traceback import install as rich_tb_install

# Create a console for the interactive flow (configured with no_color setting)
from cerno_pkg.ansi import get_console, get_terminal_width
_console_global = get_console()

# Install pretty tracebacks, but suppress for Typer/Click exit exceptions
rich_tb_install(show_locals=False, suppress=["typer", "click"])

# === Configuration context ===
import contextvars
from typing import Optional as Opt

_config_context: contextvars.ContextVar[Opt['CernoConfig']] = contextvars.ContextVar('config', default=None)

def get_current_config():
    """Get config from context or load fresh."""
    from cerno_pkg import load_config
    config = _config_context.get()
    if config is None:
        config = load_config()
    return config


# === CLI functions start here ===
# All helper functions have been moved to cerno_pkg modules



# === Main application logic ===


def browse_workflow_groups(
    scan: Any,  # Scan object
    workflow_groups: Dict[str, List[Tuple[Any, Any]]],
    args: types.SimpleNamespace,
    use_sudo: bool,
    skipped_total: List[str],
    reviewed_total: List[str],
    completed_total: List[str],
    workflow_mapper,
    config: Optional["CernoConfig"] = None,
    session_start_time: Optional[Any] = None,
) -> None:
    """
    Browse workflow groups and findings within selected workflow.

    Displays a menu of workflow names with file counts, allows selection,
    then shows findings for that workflow.

    Args:
        scan: Scan database object
        workflow_groups: Dict mapping workflow_name -> list of (Finding, Plugin) tuples
        args: Command-line arguments
        use_sudo: Whether sudo is available
        skipped_total: List of skipped filenames
        reviewed_total: List of reviewed filenames
        completed_total: List of completed filenames
        workflow_mapper: WorkflowMapper instance
    """
    # Load config if not provided (defensive programming)
    if config is None:
        from cerno_pkg.config import load_config
        config = load_config()

    scan_dir = Path(scan.export_root) / scan.scan_name
    if not workflow_groups:
        warn("No findings with mapped workflows found.")
        return

    while True:
        # Build table of workflows
        from cerno_pkg import breadcrumb
        bc = breadcrumb(scan_dir.name, "Workflow Mapped Findings")
        header(bc if bc else "Workflow Mapped Findings - Select Workflow")

        table = Table(title="Workflows", box=box.SIMPLE)
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Workflow Name", style="bold")
        table.add_column("Unreviewed", justify="right")
        table.add_column("Reviewed", justify="right")
        table.add_column("Total", justify="right")

        workflow_list = sorted(workflow_groups.items(), key=lambda x: len(x[1]), reverse=True)

        for idx, (workflow_name, files) in enumerate(workflow_list, start=1):
            total = len(files)
            # Use database review_state instead of filename checking
            reviewed = sum(1 for (pf, _p) in files if pf.review_state == "completed")
            unreviewed = total - reviewed

            table.add_row(
                str(idx),
                workflow_name,
                str(unreviewed),
                str(reviewed),
                str(total),
            )

        _console_global.print(table)
        print_action_menu([("B", "Back")])

        try:
            ans = Prompt.ask("Choose workflow").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted â€” returning to severity menu.")
            return

        if ans in ("b", "back", "q"):
            return

        if not ans.isdigit() or not (1 <= int(ans) <= len(workflow_list)):
            warn(f"Invalid choice. Please enter 1-{len(workflow_list)} or [B]ack.")
            continue

        # Get selected workflow
        workflow_idx = int(ans) - 1
        workflow_name, workflow_files = workflow_list[workflow_idx]

        # Extract plugin IDs from database records instead of filenames
        plugin_ids = []
        for _finding, plugin in workflow_files:
            plugin_ids.append(plugin.plugin_id)

        # Browse findings for this workflow using database query filtered by plugin IDs
        browse_file_list(
            scan,
            None,  # No specific severity dir (workflow may span multiple severities)
            None,  # No severity filter
            f"Workflow: {workflow_name}",
            args,
            use_sudo,
            skipped_total,
            reviewed_total,
            completed_total,
            is_msf_mode=True,  # Show severity labels
            workflow_mapper=workflow_mapper,
            plugin_ids_filter=plugin_ids if plugin_ids else None,
            config=config,
            session_start_time=session_start_time,
        )

        # Refresh workflow files from database to get updated review_state values
        # This ensures the statistics display shows current counts after marking files reviewed
        from cerno_pkg.models import Finding
        refreshed_files = Finding.get_by_scan_with_plugin(
            scan_id=scan.scan_id,
            plugin_ids=plugin_ids if plugin_ids else None,
        )
        workflow_groups[workflow_name] = refreshed_files


# === Unified file list browser ===



def browse_file_list(
    scan: Any,  # Scan object
    sev_dir: Optional[Path],
    severity_dir_filter: Optional[str],
    severity_label: str,
    args: types.SimpleNamespace,
    use_sudo: bool,
    skipped_total: List[str],
    reviewed_total: List[str],
    completed_total: List[str],
    is_msf_mode: bool = False,
    workflow_mapper: Optional[WorkflowMapper] = None,
    has_metasploit_filter: Optional[bool] = None,
    plugin_ids_filter: Optional[list[int]] = None,
    severity_dirs_filter: Optional[list[str]] = None,
    config: Optional["CernoConfig"] = None,
    session_start_time: Optional[Any] = None,
) -> None:
    """
    Browse and interact with file list (unified for severity and MSF modes).

    Args:
        scan: Scan database object
        sev_dir: Severity directory for file operations (optional, derived if needed)
        severity_dir_filter: Severity directory filter for database query (e.g., "3_High")
        severity_label: Display label for the severity
        workflow_mapper: Optional workflow mapper for plugin workflows
        args: Command-line arguments
        use_sudo: Whether sudo is available
        skipped_total: List to track skipped findings
        reviewed_total: List to track reviewed findings
        completed_total: List to track completed findings
        is_msf_mode: If True, display severity labels in reviewed list
        has_metasploit_filter: Optional filter for metasploit plugins
        plugin_ids_filter: Optional list of specific plugin IDs to include
    """
    from cerno_pkg.models import Finding

    # Load config if not provided (defensive programming)
    if config is None:
        from cerno_pkg.config import load_config
        config = load_config()

    file_filter = ""
    reviewed_filter = ""
    group_filter: Optional[Tuple[int, set, str]] = None
    # Default sort: severity for mixed views (Critical at top), plugin_id for single severity
    sort_mode = "plugin_id" if severity_dir_filter is not None else "severity"

    # Use config value if set, otherwise calculate based on terminal
    page_size = config.default_page_size if config.default_page_size is not None else default_page_size()

    # Validate page size
    if page_size <= 0:
        warn(f"Invalid page size {page_size} in config, using default")
        page_size = default_page_size()

    page_idx = 0
    first_iteration = True  # Track first iteration for startup hint

    # Derive scan_dir from scan object
    scan_dir = Path(scan.export_root) / scan.scan_name

    def get_counts_for(finding: "Finding") -> Tuple[int, str]:
        """Get host/port counts from database via v_finding_stats view.

        Args:
            finding: Finding database object

        Returns:
            Tuple of (host_count, ports_string) - computed from v_finding_stats view
        """
        # Query v_finding_stats view for computed host/port counts
        from cerno_pkg.database import query_one, get_connection
        with get_connection() as conn:
            row = query_one(
                conn,
                "SELECT host_count, port_count FROM v_finding_stats WHERE finding_id = ?",
                (finding.finding_id,)
            )
            if row:
                return (row["host_count"] or 0, "")
            return (0, "")

    while True:
        # Query database for findings with plugin info
        all_records = Finding.get_by_scan_with_plugin(
            scan_id=scan.scan_id,
            severity_dir=severity_dir_filter,
            severity_dirs=severity_dirs_filter,
            has_metasploit=has_metasploit_filter,
            plugin_ids=plugin_ids_filter,
        )

        # Separate reviewed and unreviewed based on review_state from database
        reviewed = [
            (pf, p) for (pf, p) in all_records if pf.review_state == "completed"
        ]
        unreviewed = [
            (pf, p) for (pf, p) in all_records if pf.review_state != "completed"
        ]

        # Apply file filter (plugin name search)
        candidates = [
            (pf, p)
            for (pf, p) in unreviewed
            if (file_filter.lower() in p.plugin_name.lower())
            and (group_filter is None or f"Plugin {p.plugin_id}: {p.plugin_name}" in group_filter[1])
        ]

        # Apply sorting
        if sort_mode == "severity":
            # Sort by severity descending (Critical first), then by plugin name
            display = sorted(
                candidates,
                key=lambda record: (-record[1].severity_int, natural_key(record[1].plugin_name)),
            )
        elif sort_mode == "hosts":
            display = sorted(
                candidates,
                key=lambda record: (-get_counts_for(record[0])[0], natural_key(record[1].plugin_name)),
            )
        elif sort_mode == "plugin_id":
            # Sort by plugin ID (numeric ascending)
            display = sorted(candidates, key=lambda record: record[1].plugin_id)
        else:  # name
            display = sorted(candidates, key=lambda record: natural_key(record[1].plugin_name))

        total_pages = (
            max(1, math.ceil(len(display) / page_size)) if page_size > 0 else 1
        )
        if page_idx >= total_pages:
            page_idx = total_pages - 1

        start = page_idx * page_size
        end = start + page_size
        page_items = display[start:end]

        try:
            from cerno_pkg import breadcrumb

            filter_info = f"filtered: '{file_filter}'" if file_filter else "Findings"
            bc = breadcrumb(scan_dir.name, severity_label, filter_info)
            header(bc if bc else f"Severity: {severity_label}")

            # Show startup hint on first iteration
            if first_iteration:
                from rich.text import Text
                hint = Text()
                hint.append("Welcome to Cerno Review", style="bold cyan")
                hint.append(" | Press ", style="dim")
                hint.append("[?]", style="bold yellow")
                hint.append(" for help", style="dim")
                _console_global.print(hint)

                # Terminal width warning for narrow terminals
                term_width = get_terminal_width()
                if term_width < 80:
                    warn(f"Note: Terminal width is {term_width} chars (recommended: 100+). Some layouts may wrap.")

                _console_global.print()  # Blank line for spacing
                first_iteration = False

            # Build status line components
            from rich.text import Text

            status_parts = []

            # Unreviewed count
            status_parts.append(f"Unreviewed findings ({len(unreviewed)})")

            # File filter with visual indicator if active
            if file_filter:
                filter_text = Text()
                filter_text.append("[FILTER] ", style="bold cyan")
                filter_text.append(f"Name: '{file_filter}'", style="bold yellow")
                status_parts.append(filter_text)
            else:
                status_parts.append("Filter: '*'")

            # Group filter with bold visual indicator
            if group_filter:
                # Enhanced group filter with description (backward compatible)
                group_desc = group_filter[2] if len(group_filter) > 2 else f"{len(group_filter[1])} findings"
                group_text = Text()
                group_text.append("[ACTIVE FILTER] ", style="bold cyan")
                group_text.append(f"Group #{group_filter[0]}: {group_desc} ({len(group_filter[1])})", style="bold yellow")
                status_parts.append(group_text)

            sort_label = {
                "severity": "Severity ↓",
                "plugin_id": "Plugin ID ↑",
                "hosts": "Host count ↓",
                "name": "Name A↑Z"
            }.get(sort_mode, "Severity ↓")

            # Show next sort mode indicator
            next_sort_mode = {
                "severity": "Plugin ID ↑",
                "plugin_id": "Name A↑Z",
                "name": "Host count ↓",
                "hosts": "Severity ↓"
            }.get(sort_mode, "Plugin ID ↑")

            status_parts.append(f"Sort: {sort_label} (next: {next_sort_mode})")

            # Enhanced pagination indicator with progress bar
            from cerno_pkg.render import render_pagination_indicator
            page_indicator = render_pagination_indicator(page_idx, total_pages, len(display))
            status_parts.append(page_indicator)

            # Session time indicator
            if session_start_time:
                from datetime import datetime
                elapsed = datetime.now() - session_start_time
                elapsed_seconds = int(elapsed.total_seconds())
                hours, remainder = divmod(elapsed_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)

                if hours > 0:
                    session_time_str = f"{hours}h {minutes}m"
                else:
                    session_time_str = f"{minutes}m {seconds}s"

                # Build session stats string
                session_stats = f"Session: {session_time_str}"
                if reviewed_total or completed_total or skipped_total:
                    session_stats += f" | R:{len(reviewed_total)} C:{len(completed_total)} S:{len(skipped_total)}"
                status_parts.append(session_stats)

            # Responsive layout based on terminal width
            term_width = get_terminal_width()

            # Helper to join status parts (handles both str and Text objects)
            def join_status_parts(parts, separator=" | "):
                """Join status parts, handling both strings and Rich Text objects."""
                if not parts:
                    return ""
                result = Text()
                for i, part in enumerate(parts):
                    if i > 0:
                        result.append(separator)
                    if isinstance(part, Text):
                        result.append(part)
                    else:
                        result.append(str(part))
                return result

            if term_width >= 120:
                # Wide terminal: single line with separators
                status = join_status_parts(status_parts)
                _console_global.print(status)
            elif term_width >= 80:
                # Medium terminal: two lines
                status_line1 = join_status_parts(status_parts[:2])
                status_line2 = join_status_parts(status_parts[2:])
                _console_global.print(status_line1)
                _console_global.print(status_line2)
            else:
                # Narrow terminal: multi-line (one per part)
                for part in status_parts:
                    if isinstance(part, Text):
                        _console_global.print(part)
                    else:
                        _console_global.print(str(part))

            # Render table or empty state message
            if not display:
                from cerno_pkg.render import render_empty_state
                # Determine context for empty state
                if file_filter:
                    render_empty_state("filter_mismatch", file_filter)
                elif all_records and len(all_records) == len(reviewed):
                    render_empty_state("all_completed")
                elif not all_records:
                    render_empty_state("no_severity")
                # Don't render table if no findings
            else:
                render_finding_list_table(
                    page_items, sort_mode, get_counts_for, row_offset=start,
                    show_severity=is_msf_mode
                )

                # Add hint on first page if more results exist
                can_next = page_idx + 1 < total_pages
                can_prev = page_idx > 0
                if page_idx == 0 and can_next:
                    remaining = len(display) - page_size
                    info(f"→ {remaining} more finding{'s' if remaining != 1 else ''} available (press N for next page)")

            # Always render footer with available actions
            can_next = page_idx + 1 < total_pages
            can_prev = page_idx > 0
            render_actions_footer(
                group_applied=bool(group_filter),
                candidates_count=len(candidates),
                sort_mode=sort_mode,
                can_next=can_next,
                can_prev=can_prev,
            )

            ans = Prompt.ask("Choose a file number, or action").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted â€” returning to severity menu.")
            break

        # Handle actions
        action_result = handle_finding_list_actions(
            ans,
            candidates,
            page_items,
            display,
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
            total_pages,
            reviewed,
            None,  # sev_map no longer used
            get_counts_for,
        )

        (
            action_type,
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
        ) = action_result

        if action_type == "back":
            break
        elif action_type == "help":
            continue
        elif action_type == "mark_all":
            # Always require confirmation for bulk operations
            from cerno_pkg.fs import mark_review_complete
            from rich.prompt import Confirm

            try:
                confirm_msg = f"Mark all {len(candidates)} findings as review complete?"
                confirmed = Confirm.ask(confirm_msg, default=False)
            except KeyboardInterrupt:
                warn("\nInterrupted â€” cancelling bulk operation.")
                continue

            if not confirmed:
                info("Bulk operation cancelled.")
                continue

            # Proceed with bulk marking
            marked = 0
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=_console_global,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "Marking findings as review complete...", total=len(candidates)
                )
                for finding, plugin in candidates:
                    if mark_review_complete(finding):
                        marked += 1
                        display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
                        completed_total.append(display_name)
                    progress.advance(task)
            ok(f"Summary: {marked} marked, {len(candidates)-marked} skipped.")
            continue
        elif action_type == "file_selected":
            # Determine which record was selected
            if ans == "":
                chosen_record = page_items[0]
            else:
                global_idx = int(ans) - 1
                chosen_record = display[global_idx]

            # Extract plugin info from record
            finding, plugin = chosen_record

            # Create synthetic path for legacy code that still uses chosen.name
            # In database-only mode, construct a name from plugin ID
            synthetic_name = f"{plugin.plugin_id}_{plugin.plugin_name.replace(' ', '_').replace('/', '_')}.txt"
            chosen_path = Path(synthetic_name)

            # Get severity directory from plugin metadata
            if is_msf_mode:
                # Construct severity directory name from plugin severity
                sev_label = plugin.severity_label or f"Severity_{plugin.severity_int}"
                chosen_sev_dir = scan_dir / f"{plugin.severity_int}_{sev_label}"
            else:
                chosen_sev_dir = sev_dir

            # Process the file
            process_single_finding(
                chosen_path,
                plugin,
                finding,
                scan_dir,
                chosen_sev_dir,
                args,
                use_sudo,
                skipped_total,
                reviewed_total,
                completed_total,
                show_severity=is_msf_mode,
                workflow_mapper=workflow_mapper,
            )
        elif action_type is None:
            continue


# === Main application logic ===


def show_session_statistics(
    session_start_time,
    reviewed_total: list[str],
    completed_total: list[str],
    skipped_total: list[str],
    scan_dir: Path,
    scan_id: Optional[int] = None,
) -> None:
    """
    Display rich session statistics at the end of a review session.

    Args:
        session_start_time: Datetime when session started
        reviewed_total: List of reviewed (not marked complete) findings
        completed_total: List of marked complete findings
        skipped_total: List of skipped (empty) findings
        scan_dir: Scan directory for severity analysis
        scan_id: Optional scan ID for database queries
    """
    from datetime import datetime
    from rich.table import Table

    console = get_console()

    # Calculate session duration
    session_end_time = datetime.now()
    duration = session_end_time - session_start_time
    hours, remainder = divmod(int(duration.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    duration_str = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"

    header("Session Statistics")

    # Overall stats table
    from cerno_pkg.ansi import style_if_enabled
    overall_table = Table(show_header=True, header_style=style_if_enabled("bold cyan"))
    overall_table.add_column("Metric", style=style_if_enabled("cyan"))
    overall_table.add_column("Count", justify="right", style=style_if_enabled("yellow"))

    overall_table.add_row("Session Duration", duration_str)
    overall_table.add_row("Findings Reviewed (not marked)", str(len(reviewed_total)))
    overall_table.add_row("Findings Marked Complete", str(len(completed_total)))
    overall_table.add_row("Findings Skipped (empty)", str(len(skipped_total)))
    overall_table.add_row("Total Findings Processed", str(len(reviewed_total) + len(completed_total) + len(skipped_total)))

    console.print(overall_table)
    _console_global.print()

    # Per-severity breakdown (for completed findings only)
    if completed_total:
        severity_counts = {}

        # Use database if available, otherwise fall back to filesystem
        if scan_id is not None:
            from cerno_pkg.database import db_transaction, query_all

            # Query database for completed findings grouped by severity
            with db_transaction() as conn:
                rows = query_all(
                    conn,
                    """
                    SELECT p.severity_label, COUNT(*) as count
                    FROM findings f
                    JOIN v_plugins_with_severity p ON f.plugin_id = p.plugin_id
                    WHERE f.scan_id = ? AND f.review_state = 'completed'
                    GROUP BY p.severity_label
                    """,
                    (scan_id,)
                )
                for row in rows:
                    sev_label = pretty_severity_label(row[0])
                    severity_counts[sev_label] = row[1]
        else:
            # Fallback to filesystem walk
            for sev_dir in scan_dir.iterdir():
                if not sev_dir.is_dir():
                    continue
                sev_label = pretty_severity_label(sev_dir.name)
                count = sum(1 for name in completed_total if any(
                    (sev_dir / fname).exists() or (sev_dir / f"REVIEW_COMPLETE-{fname}").exists()
                    for fname in [name, name.replace("REVIEW_COMPLETE-", "")]
                ))
                if count > 0:
                    severity_counts[sev_label] = count

        if severity_counts:
            sev_table = Table(show_header=True, header_style=style_if_enabled("bold cyan"))
            sev_table.add_column("Severity Level", style=style_if_enabled("cyan"))
            sev_table.add_column("Completed Count", justify="right", style=style_if_enabled("yellow"))

            for sev_label in sorted(severity_counts.keys()):
                sev_col = severity_cell(sev_label)
                sev_table.add_row(sev_col, str(severity_counts[sev_label]))



def main(args: types.SimpleNamespace) -> None:
    """
    Main application entry point for interactive review mode.

    Args:
        args: Command-line arguments namespace containing:
            - export_root (Optional[Path]): DEPRECATED. Path to export directory.
              Review mode now requires database. Use 'cerno import' first.
            - no_tools (bool): Skip tool execution workflow if True.
            - custom_workflows (Optional[Path]): Custom workflow YAML to supplement defaults.
            - custom_workflows_only (Optional[Path]): Use only this workflow YAML.

    Note:
        The --export-root flag has been deprecated for review mode. All review
        operations now use the database for improved performance and feature support
        including workflow mapping, Metasploit module detection, and session tracking.
    """
    # Load configuration
    config = get_current_config()

    # Validate results root is writable before proceeding
    from cerno_pkg import validate_results_root
    results_root = get_results_root()
    is_valid, error_msg = validate_results_root(results_root)
    if not is_valid:
        err(f"Results directory validation failed: {error_msg}")
        warn(f"Please ensure {results_root} is writable or update results_root in config")
        raise Exit(1)

    # Track session start time
    from datetime import datetime
    session_start_time = datetime.now()

    # Initialize variables for scan selection (used later for session tracking)
    scan_id: int = 0  # Will be set when user selects a scan
    scan_dir: Optional[Path] = None  # Will be set when user selects a scan

    # Initialize workflow mapper
    custom_workflows = getattr(args, 'custom_workflows', None)
    custom_workflows_only = getattr(args, 'custom_workflows_only', None)

    # Check config for custom workflows if CLI args not provided
    if not custom_workflows and not custom_workflows_only and config.custom_workflows_path:
        custom_workflows = Path(config.custom_workflows_path)

    if custom_workflows_only:
        # Replace mode: Use ONLY custom YAML
        with _console_global.status("[bold green]Loading custom workflows..."):
            workflow_mapper = WorkflowMapper(yaml_path=custom_workflows_only)
        if workflow_mapper.count() > 0:
            _console_global.print(f"Loaded {workflow_mapper.count()} custom workflow(s) from {custom_workflows_only} (defaults disabled)")
        else:
            warn(f"No workflows loaded from {custom_workflows_only}")
    else:
        # Default or supplement mode
        with _console_global.status("[bold green]Loading workflows..."):
            workflow_mapper = WorkflowMapper()  # Load defaults
            default_count = workflow_mapper.count()

        if custom_workflows:
            # Supplement mode: Load custom YAML in addition to defaults
            # Determine source: CLI argument or config
            source = "CLI argument" if getattr(args, 'custom_workflows', None) else "config"
            with _console_global.status("[bold green]Loading additional custom workflows..."):
                additional_count = workflow_mapper.load_additional_workflows(custom_workflows)
            if additional_count > 0:
                _console_global.print(f"Loaded {default_count} default + {additional_count} custom workflow(s) from {custom_workflows} ({source})")
            else:
                warn(f"No additional workflows loaded from {custom_workflows}")
            _console_global.print(f"Total: {workflow_mapper.count()} workflow(s) available")
        elif default_count > 0:
            _console_global.print(f"Loaded {default_count} default workflow(s)\n")

    use_sudo = root_or_sudo_available()
    if not use_sudo:
        warn(
            "Not running as root and no 'sudo' found — "
            "some scan types (e.g., UDP) may fail."
        )

    # Tool availability check (unless --no-tools enabled)
    if not args.no_tools:
        from cerno_pkg.render import render_tool_availability_table
        render_tool_availability_table(include_unavailable=True)
        _console_global.print()  # Add spacing

        # If --check flag used, exit after displaying checks
        if getattr(args, 'check', False):
            raise Exit(0)

    export_root = Path(args.export_root) if args.export_root else None
    if export_root and not export_root.exists():
        err(f"Export root not found: {export_root}")
        raise Exit(1)

    # if export_root:
    #     ok(f"Using export root: {export_root.resolve()}")
    if args.no_tools:
        info("(no-tools mode: tool prompts disabled for this session)")

    reviewed_total: List[str] = []
    completed_total: List[str] = []
    skipped_total: List[str] = []

    # If no export_root specified, use database scan selection
    if export_root is None:
        from cerno_pkg.models import Scan, Finding
        from datetime import datetime

        # Outer loop for scan selection
        # Wrapped in try/finally to ensure session is saved on ALL exit paths
        try:
            while True:
                # Save previous scan's session before loading next scan menu
                # This handles the case where user reviews multiple scans (presses 'b' to go back)
                if scan_id != 0:
                    save_session(
                        scan_id,
                        session_start_time,
                        reviewed_count=len(reviewed_total),
                        completed_count=len(completed_total),
                        skipped_count=len(skipped_total),
                    )

                    # Show statistics if work was done
                    if reviewed_total or completed_total or skipped_total:
                        if scan_dir is not None:
                            show_session_statistics(
                                session_start_time,
                                reviewed_total,
                                completed_total,
                                skipped_total,
                                scan_dir,
                                scan_id=scan_id,
                            )

                    delete_session(scan_id)

                    # Reset tracking for next scan
                    scan_id = 0
                    scan_dir = None
                    reviewed_total = []
                    completed_total = []
                    skipped_total = []

                # Get all scans from database
                try:
                    with _console_global.status("[bold green]Loading scans from database..."):
                        all_scans = Scan.get_all()
                except Exception as e:
                    err(f"Failed to query scans from database: {e}")
                    return

                if not all_scans:
                    # First-time user - show guided tour
                    from cerno_pkg.onboarding import show_guided_tour

                    show_guided_tour()
                    # After tour, show import instructions
                    info("\nTo get started, import a Nessus scan:")
                    info("  cerno import nessus /path/to/scan.nessus\n")
                    return

                # Display scan selection menu
                header("Available Scans")
                from rich.table import Table
                from rich import box
                from cerno_pkg.ansi import style_if_enabled

                scan_table = Table(show_header=True, header_style=style_if_enabled("bold cyan"), box=box.SIMPLE)
                scan_table.add_column("#", style=style_if_enabled("cyan"), justify="right")
                scan_table.add_column("Scan Name", style=style_if_enabled("yellow"))
                scan_table.add_column("Last Reviewed", style=style_if_enabled("magenta"))

                for idx, scan in enumerate(all_scans, 1):
                    last_reviewed = "never"
                    if scan.last_reviewed_at:
                        try:
                            dt = datetime.fromisoformat(scan.last_reviewed_at)
                            now = datetime.now()
                            delta = now - dt
                            if delta.days == 0:
                                if delta.seconds < 3600:
                                    mins = delta.seconds // 60
                                    last_reviewed = f"{mins} min{'s' if mins != 1 else ''} ago"
                                else:
                                    hours = delta.seconds // 3600
                                    last_reviewed = f"{hours} hour{'s' if hours != 1 else ''} ago"
                            elif delta.days == 1:
                                last_reviewed = "yesterday"
                            elif delta.days < 7:
                                last_reviewed = f"{delta.days} days ago"
                            else:
                                last_reviewed = dt.strftime("%Y-%m-%d")
                        except Exception:
                            last_reviewed = scan.last_reviewed_at[:10]  # Just date

                    scan_table.add_row(str(idx), scan.scan_name, last_reviewed)

                _console_global.print(scan_table)
                print_action_menu([("Q", "Quit")])

                try:
                    ans = Prompt.ask("Choose scan").strip().lower()
                except KeyboardInterrupt:
                    warn("\nInterrupted — exiting.")
                    return

                if ans in ("x", "exit", "q", "quit"):
                    return

                if not ans.isdigit() or not (1 <= int(ans) <= len(all_scans)):
                    warn(f"Invalid choice. Please enter 1-{len(all_scans)} or [Q]uit.")
                    continue  # Back to scan selection

                selected_scan = all_scans[int(ans) - 1]
                export_root = Path(selected_scan.export_root)
                scan_dir = export_root / selected_scan.scan_name

                # Note: scan_dir is a Path object used for display (scan_dir.name) only
                # In database-only mode, the directory doesn't need to exist

                # Type narrowing: ensure scan_id is not None
                if selected_scan.scan_id is None:
                    warn("Invalid scan - missing scan_id")
                    continue

                scan_id: int = selected_scan.scan_id
                ok(f"Selected: {selected_scan.scan_name}")

                # Check for existing session
                previous_session = load_session(scan_id)
                if previous_session:
                    from datetime import datetime
                    session_date = datetime.fromisoformat(previous_session.session_start)
                    header("Previous Session Found")
                    info(f"Session started: {session_date.strftime('%Y-%m-%d %H:%M:%S')}")
                    info(f"Reviewed: {previous_session.reviewed_count} findings")
                    info(f"Completed: {previous_session.completed_count} findings")
                    info(f"Skipped: {previous_session.skipped_count} findings")
                    try:
                        resume = Confirm.ask("Resume this session?", default=True)
                    except KeyboardInterrupt:
                        warn("\nInterrupted — exiting.")
                        return

                    if resume:
                        # Session start time is restored; file tracking continues from database
                        session_start_time = session_date
                        ok("Session resumed.")
                    else:
                        # Start fresh session - end the old one
                        delete_session(scan_id)
                        ok("Starting fresh session.")
                else:
                    # No previous session - start fresh
                    pass

                # Overview immediately after selecting scan
                # Use config value if set, otherwise use DEFAULT_TOP_PORTS
                top_ports = config.top_ports_count if config.top_ports_count is not None else DEFAULT_TOP_PORTS

                # Validate range
                if top_ports <= 0:
                    warn(f"Invalid top_ports_count {top_ports} in config, using default {DEFAULT_TOP_PORTS}")
                    top_ports = DEFAULT_TOP_PORTS
                elif top_ports > 100:
                    warn(f"top_ports_count {top_ports} is very large, capping at 100")
                    top_ports = 100

                show_scan_summary(scan_dir, top_ports_n=top_ports, scan_id=scan_id)

                # Show workflow guidance for first-time or returning users
                from cerno_pkg.onboarding import show_workflow_guidance
                show_workflow_guidance(scan_name=scan.scan_name, scan_id=scan_id)

                # Host filter state (persists across severity loop iterations)
                host_filter: Optional[str] = None  # Active host filter (IP/hostname)
                host_filter_plugin_ids: Optional[list[int]] = None  # Cached plugin IDs for filter

                # Severity loop (inner loop)
                while True:
                    from cerno_pkg import breadcrumb
                    bc = breadcrumb(scan_dir.name, "Choose severity")
                    header(bc if bc else f"Scan: {scan_dir.name} — choose severity")

                    # Get severity directories from database (database-only mode)
                    # Apply host filter if active
                    severity_dir_names = Finding.get_severity_dirs_for_scan(
                        scan_id, plugin_ids=host_filter_plugin_ids
                    )
                    if not severity_dir_names:
                        warn("No severity directories in this scan.")
                        break

                    # Create virtual Path objects for compatibility with existing render code
                    # Database returns pre-sorted (DESC), so no additional sorting needed
                    severities = [scan_dir / sev_name for sev_name in severity_dir_names]

                    # Metasploit Module virtual group (menu counts) - query from database
                    # Apply host filter if active
                    msf_files = Finding.get_by_scan_with_plugin(
                        scan_id=scan_id,
                        has_metasploit=True,
                        plugin_ids=host_filter_plugin_ids
                    )

                    has_msf = len(msf_files) > 0
                    msf_total = len(msf_files)
                    msf_reviewed = sum(
                        1
                        for (pf, _p) in msf_files
                        if pf.review_state == "completed"
                    )
                    msf_unrev = msf_total - msf_reviewed

                    msf_summary = (
                        (msf_unrev, msf_reviewed, msf_total)
                        if has_msf
                        else None
                    )

                    # Workflow Mapped virtual group (menu counts) - query from database
                    # Apply host filter if active (intersect workflow plugins with host filter)
                    workflow_plugin_ids = workflow_mapper.get_all_plugin_ids()
                    if workflow_plugin_ids:
                        workflow_plugin_ids_int = [int(pid) for pid in workflow_plugin_ids if pid.isdigit()]
                        # If host filter is active, intersect with host filter plugin IDs
                        if host_filter_plugin_ids is not None:
                            workflow_plugin_ids_int = [
                                pid for pid in workflow_plugin_ids_int
                                if pid in host_filter_plugin_ids
                            ]
                        if workflow_plugin_ids_int:
                            workflow_files = Finding.get_by_scan_with_plugin(
                                scan_id=scan_id,
                                plugin_ids=workflow_plugin_ids_int
                            )
                        else:
                            workflow_files = []
                    else:
                        workflow_files = []

                    has_workflows = len(workflow_files) > 0
                    workflow_total = len(workflow_files)
                    workflow_reviewed = sum(
                        1
                        for (pf, _p) in workflow_files
                        if pf.review_state == "completed"
                    )
                    workflow_unrev = workflow_total - workflow_reviewed

                    workflow_summary = (
                        (workflow_unrev, workflow_reviewed, workflow_total)
                        if has_workflows
                        else None
                    )

                    render_severity_table(
                        severities,
                        msf_summary=msf_summary,
                        workflow_summary=workflow_summary,
                        scan_id=scan_id,
                        plugin_ids=host_filter_plugin_ids
                    )

                    # Show host filter status if active
                    if host_filter:
                        info(f"Filtering by host: {host_filter}")

                    # Show action menu with appropriate options
                    if host_filter:
                        print_action_menu([("H", "Host search"), ("C", "Clear filter"), ("B", "Back")])
                    else:
                        print_action_menu([("H", "Host search"), ("B", "Back")])

                    # Dynamic tip message based on available special filters
                    if has_msf and has_workflows:
                        info("Tip: Use numbers (1-5), M, W, or combine (e.g., 1-3,M)")
                    elif has_msf:
                        info("Tip: Use numbers (1-5), M, or combine (e.g., 1-3,M)")
                    elif has_workflows:
                        info("Tip: Use numbers (1-5), W, or combine (e.g., 1-3,W)")
                    else:
                        info("Tip: Multi-select is supported (e.g., 1-3 or 1,3,5)")

                    try:
                        ans = Prompt.ask("Choose").strip().lower()
                    except KeyboardInterrupt:
                        warn("\nInterrupted — returning to scan menu.")
                        break

                    if ans in ("b", "back"):
                        break
                    elif ans == "q":
                        return
                    elif ans in ("h", "host"):
                        # Host search flow
                        from cerno_pkg.models import Host

                        host_input = Prompt.ask("Enter IP address or hostname").strip()
                        if not host_input:
                            warn("No host entered.")
                            continue

                        # Strip brackets from IPv6 if present (e.g., [::1] -> ::1)
                        if host_input.startswith("[") and host_input.endswith("]"):
                            host_input = host_input[1:-1]

                        # Query plugin IDs for this host in current scan
                        plugin_ids = Host.get_plugin_ids_for_scan(
                            host_address=host_input,
                            scan_id=scan_id,
                            partial_match=True
                        )

                        if not plugin_ids:
                            warn(f"No findings found for host: {host_input}")
                            continue

                        # Set filter state
                        host_filter = host_input
                        host_filter_plugin_ids = plugin_ids
                        ok(f"Found {len(plugin_ids)} finding(s) for host '{host_input}'")
                        continue

                    elif ans in ("c", "clear") and host_filter:
                        # Clear host filter
                        host_filter = None
                        host_filter_plugin_ids = None
                        ok("Host filter cleared.")
                        continue

                    # Parse selection (supports ranges, comma-separated, and M/W letters)
                    selection = parse_severity_selection(ans, len(severities))

                    if selection is None:
                        warn("Invalid choice. Use numbers (1-5), M, W, or combine (e.g., 1-3,M).")
                        continue

                    # Validate special filter selections against availability
                    if selection.msf_selected and not has_msf:
                        warn("No Metasploit modules available for this scan.")
                        continue
                    if selection.workflow_selected and not has_workflows:
                        warn("No workflow-mapped findings available for this scan.")
                        continue

                    # Map new selection fields to existing variable names for minimal downstream changes
                    severity_indices = selection.severity_indices
                    msf_in_selection = selection.msf_selected
                    workflow_in_selection = selection.workflow_selected

                    # === Multiple severities selected (or mix of severities + MSF) ===
                    if len(severity_indices) > 1 or (len(severity_indices) >= 1 and msf_in_selection):
                        selected_sev_dirs = [severities[idx - 1] for idx in severity_indices]

                        # Build combined label
                        sev_labels = [pretty_severity_label(sev.name) for sev in selected_sev_dirs]
                        if msf_in_selection:
                            sev_labels.append("Metasploit Module")

                        combined_label = " + ".join(sev_labels)

                        # For multi-severity selection, pass list of severity directories to filter
                        severity_dir_names = [sev.name for sev in selected_sev_dirs]
                        # Build label with host filter if active
                        label = combined_label
                        if host_filter:
                            label = f"{combined_label} (Host: {host_filter})"
                        browse_file_list(
                            selected_scan,
                            selected_sev_dirs[0] if selected_sev_dirs else None,
                            None,  # Single severity filter not used for multi-severity
                            label,
                            args,
                            use_sudo,
                            skipped_total,
                            reviewed_total,
                            completed_total,
                            is_msf_mode=True,  # Show severity labels for each file
                            workflow_mapper=workflow_mapper,
                            severity_dirs_filter=severity_dir_names,
                            plugin_ids_filter=host_filter_plugin_ids,
                            config=config,
                            session_start_time=session_start_time,
                        )

                    # === Single severity selected (normal or MSF only) ===
                    elif len(severity_indices) == 1:
                        choice_idx = severity_indices[0]
                        sev_dir = severities[choice_idx - 1]

                        # Use severity directory name as filter (e.g., "3_High")
                        severity_dir_filter = sev_dir.name

                        # Build label with host filter if active
                        label = pretty_severity_label(sev_dir.name)
                        if host_filter:
                            label = f"{label} (Host: {host_filter})"

                        browse_file_list(
                            selected_scan,
                            sev_dir,
                            severity_dir_filter,
                            label,
                            args,
                            use_sudo,
                            skipped_total,
                            reviewed_total,
                            completed_total,
                            is_msf_mode=False,
                            workflow_mapper=workflow_mapper,
                            plugin_ids_filter=host_filter_plugin_ids,
                            config=config,
                            session_start_time=session_start_time,
                        )

                    # === Metasploit Module only ===
                    elif msf_in_selection:
                        # Build label with host filter if active
                        label = "Metasploit Module"
                        if host_filter:
                            label = f"{label} (Host: {host_filter})"

                        # Query database for metasploit plugins across all severities
                        browse_file_list(
                            selected_scan,
                            None,  # No single severity dir
                            None,  # No severity filter
                            label,
                            args,
                            use_sudo,
                            skipped_total,
                            reviewed_total,
                            completed_total,
                            is_msf_mode=True,
                            workflow_mapper=workflow_mapper,
                            has_metasploit_filter=True,
                            plugin_ids_filter=host_filter_plugin_ids,
                            config=config,
                            session_start_time=session_start_time,
                        )

                    # === Workflow Mapped only ===
                    elif workflow_in_selection:
                        # Group findings by workflow name using database records
                        # Note: workflow_files is already filtered by host_filter_plugin_ids
                        workflow_groups = group_findings_by_workflow(workflow_files, workflow_mapper)

                        browse_workflow_groups(
                            selected_scan,
                            workflow_groups,
                            args,
                            use_sudo,
                            skipped_total,
                            reviewed_total,
                            completed_total,
                            workflow_mapper,
                            config=config,
                            session_start_time=session_start_time,
                        )

                # End of severity loop - continue to scan selection loop
                # (User pressed 'b' or 'q' from severity menu)

        finally:
            # Always save session on exit (handles early exits via q, Ctrl+C, or errors)
            # Only save if scan was actually selected (scan_id != 0)
            if scan_id != 0:
                save_session(
                    scan_id,
                    session_start_time,
                    reviewed_count=len(reviewed_total),
                    completed_count=len(completed_total),
                    skipped_count=len(skipped_total),
                )

                # Session summary with rich statistics (only if work was done)
                if reviewed_total or completed_total or skipped_total:
                    # Type guard: scan_dir must be defined if any work was done
                    if scan_dir is not None:
                        show_session_statistics(
                            session_start_time,
                            reviewed_total,
                            completed_total,
                            skipped_total,
                            scan_dir,
                            scan_id=scan_id,
                        )

                # Always end session (mark session_end timestamp in database)
                delete_session(scan_id)

    _console_global.print() # Empty line
    ok("Now run \"cerno review\" to start reviewing findings.")


# === Typer CLI ===
# Main app + sub-apps (import, scan, config)

app = typer.Typer(
    help="cerno — faster review & tooling runner for vulnerability scans",
    add_completion=True,
)
_console = _console_global

# Sub-applications
import_app = typer.Typer(
    help="Import data from various sources into cerno"
)

scan_app = typer.Typer(
    help="Scan management - list and delete imported scans"
)

config_app = typer.Typer(
    help="Configuration management - view and modify settings"
)

workflow_app = typer.Typer(
    help="Workflow management - list and view available workflows"
)

# Register sub-apps with main app
app.add_typer(import_app, name="import")
app.add_typer(scan_app, name="scan")
app.add_typer(config_app, name="config")
app.add_typer(workflow_app, name="workflow")


# Version callback for --version flag
def version_callback(value: bool):
    """Print version and exit."""
    if value:
        print(f"cerno {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    )
):
    """cerno CLI - faster review & tooling runner for vulnerability scans."""
    # Load configuration (auto-creates with defaults if missing)
    from cerno_pkg import load_config, initialize_colors
    from cerno_pkg.logging_setup import init_logger
    from cerno_pkg.database import initialize_database

    config = load_config()

    # Initialize systems with config
    init_logger(config)
    initialize_colors(config)

    # Initialize database AFTER logger is ready (prevents logging bleed during import)
    initialize_database()

    # Store config in context for access by commands
    _config_context.set(config)


@app.command(help="Interactive review of findings.")
def review(
    export_root: Optional[Path] = typer.Option(
        None, "--export-root", "-r", help="DEPRECATED: Scan root (use 'cerno import' instead)."
    ),
    no_tools: bool = typer.Option(
        False, "--no-tools", help="Disable tool prompts (review-only)."
    ),
    custom_workflows: Optional[Path] = typer.Option(
        None,
        "--custom-workflows",
        "-w",
        help="Custom workflow YAML to supplement defaults (custom overrides on conflict).",
    ),
    custom_workflows_only: Optional[Path] = typer.Option(
        None,
        "--custom-workflows-only",
        help="Use ONLY this workflow YAML (ignores default workflows).",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress promotional banner display."
    ),
    check: bool = typer.Option(
        False, "--check", help="Check tool availability and exit (no review)."
    ),
) -> None:
    """
    Run interactive review mode with database-driven workflow.

    This command requires scans to be imported into the database first.
    Use 'cerno import' to import scans before reviewing.

    Note: The --export-root flag has been deprecated. All review operations
    now require database mode for improved performance and features like
    workflow mapping, Metasploit module detection, and session tracking.

    Usage:
        cerno review              # Select from imported scans
        cerno import scan.nessus  # Import scan first if needed
    """
    # Display promotional banner (unless suppressed)
    if not quiet:
        display_banner()
        _console_global.print()  # Add spacing after banner

    # Validate: can't use both flags
    if custom_workflows and custom_workflows_only:
        err("Cannot use both --custom-workflows and --custom-workflows-only")
        raise typer.Exit(1)

    args = types.SimpleNamespace(
        export_root=export_root,
        no_tools=no_tools,
        custom_workflows=custom_workflows,
        custom_workflows_only=custom_workflows_only,
        check=check,
    )
    try:
        main(args)
    except KeyboardInterrupt:
        warn("\nInterrupted — goodbye.")


def show_nessus_tool_suggestions(nessus_file: Path) -> None:
    """
    Display suggested tool commands after import export completes.

    Args:
        nessus_file: Path to the original .nessus file
    """
    header("Suggested Tool Commands")
    info("\nYour .nessus file can ALSO be used as the input for these tools:\n")

    # eyewitness command
    info(fmt_action("1. eyewitness (screenshot and report tool | https://github.com/RedSiege/EyeWitness):"))
    eyewitness_cmd = f"eyewitness -x {nessus_file} -d ~/eyewitness_report --results 500 --user-agent \"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0\" --timeout 30"
    info(f"   {eyewitness_cmd}\n")

    # gowitness command
    info(fmt_action("2. gowitness (screenshot and report tool | https://github.com/sensepost/gowitness):"))
    gowitness_cmd = f"gowitness scan nessus -f {nessus_file} --chrome-user-agent \"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\" --write-db -t 20"
    info(f"   {gowitness_cmd}\n")

    # msfconsole db_import command
    # info(fmt_action("3. msfconsole (Metasploit import):"))
    # msfconsole_cmd = f"msfconsole -q -x \"db_import {nessus_file} ; hosts; services; vulns; exit\""
    # info(f"   {msfconsole_cmd}\n")

    info("Tip: Copy these commands to run them in your terminal.\n")


# === Import Sub-App Commands ===
# Grouped under 'cerno import'

@import_app.command(name="nessus", help="Import .nessus file and populate database with findings")
def import_scan(
    nessus: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a .nessus file"
    ),
) -> None:
    """
    Import .nessus file and export finding host lists to organized directory.

    Auto-detects scan name from .nessus file and exports to ~/.cerno/scans/<scan_name>.
    """
    from cerno_pkg.nessus_import import import_nessus_file, extract_scan_name_from_nessus
    from cerno_pkg.constants import SCANS_ROOT

    # Always extract scan name from .nessus file for consistency with database
    scan_name = extract_scan_name_from_nessus(nessus)

    # Determine output directory (always use SCANS_ROOT/<scan_name>)
    out_dir = SCANS_ROOT / scan_name
    info(f"Using scan name: {scan_name}")
    # info(f"Findings location: {out_dir}")

    # Check for duplicate imports
    from cerno_pkg.database import compute_file_hash
    from cerno_pkg.models import Scan

    new_file_hash = compute_file_hash(nessus)
    existing_scan = Scan.get_by_name(scan_name)

    if existing_scan:
        # Check if it's the identical file
        if existing_scan.nessus_file_hash == new_file_hash:
            ok(f"Scan '{scan_name}' already imported (identical file). Skipping.")
            raise typer.Exit(0)

        # Different file, same name - prompt user
        warn(f"A scan named '{scan_name}' already exists.")
        if existing_scan.created_at:
            warn(f"Existing: imported on {existing_scan.created_at}")
        warn(f"New file: {nessus.name}")
        _console_global.print()

        choices = [
            "1. Overwrite existing scan",
            "2. Import with new name (add suffix)",
            "3. Cancel import"
        ]
        for choice in choices:
            _console_global.print(f"  {choice}")

        ans = Prompt.ask("\nChoice", default="3").strip()

        if ans == "1":
            info("Overwriting existing scan...")
        elif ans == "2":
            # Find unique suffix
            counter = 2
            new_scan_name = f"{scan_name}_{counter}"
            while Scan.get_by_name(new_scan_name):
                counter += 1
                new_scan_name = f"{scan_name}_{counter}"

            scan_name = new_scan_name
            out_dir = out_dir.parent / scan_name
            info(f"Importing as: {scan_name}")
        else:
            info("Import cancelled.")
            raise typer.Exit(0)

    # Run export
    header("Importing scan to database")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Wrap import with progress spinner
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task(f"Importing {nessus.name}...", total=None)
            result = import_nessus_file(
                nessus_file=nessus,
                output_dir=out_dir,
                scan_name=scan_name,
                include_ports=True
            )

        ok(f"Import complete: {result.plugins_exported} findings")

        # Display severity breakdown
        if result.severities:
            from rich.table import Table
            from rich import box
            from cerno_pkg.render import severity_cell
            from cerno_pkg.nessus_import import severity_label_from_int

            _console_global.print()  # Blank line before table
            info("Severity Breakdown:")
            from cerno_pkg.ansi import style_if_enabled
            sev_table = Table(show_header=True, header_style=style_if_enabled("bold cyan"), box=box.SIMPLE)
            sev_table.add_column("Severity", style=style_if_enabled("cyan"))
            sev_table.add_column("Plugins", justify="right", style=style_if_enabled("yellow"))

            # Sort by severity (highest first: 4->0)
            for sev_int in sorted(result.severities.keys(), reverse=True):
                count = result.severities[sev_int]
                if count > 0:  # Only show non-zero severities
                    sev_label = severity_label_from_int(sev_int)
                    sev_table.add_row(severity_cell(sev_label), str(count))

            _console_global.print(sev_table)
        
    except Exception as e:
        err(f"Export failed: {e}")
        raise typer.Exit(1)

    # Show suggested tool commands
    _console_global.print()  # Blank line for spacing
    show_nessus_tool_suggestions(nessus)


# === Scan Sub-App Commands ===
# Grouped under 'cerno scan'

@scan_app.command(name="list", help="List all imported scans with statistics and review progress")
def list_scans() -> None:
    """Display all scans in the database with finding counts and severity breakdown."""
    from cerno_pkg.models import Scan
    from rich.table import Table

    scans = Scan.get_all_with_stats()

    if not scans:
        info("No scans found in database.")
        info("Tip: Use 'cerno import nessus <scan.nessus>' to import a scan")
        return

    from cerno_pkg.ansi import style_if_enabled

    # Create summary table
    table = Table(title="Imported Scans", show_header=True, header_style=style_if_enabled("bold cyan"))
    table.add_column("Scan Name", style=style_if_enabled("yellow"), no_wrap=True)
    table.add_column("Total Unique Hosts", justify="right", style=style_if_enabled("bright_cyan"))
    table.add_column("Total Findings", justify="right")
    table.add_column("Critical", justify="right", style=style_if_enabled("red"))
    table.add_column("High", justify="right", style=style_if_enabled("bright_red"))
    table.add_column("Medium", justify="right", style=style_if_enabled("yellow"))
    table.add_column("Low", justify="right", style=style_if_enabled("cyan"))
    table.add_column("Info", justify="right", style=style_if_enabled("dim"))
    table.add_column("Reviewed", justify="right", style=style_if_enabled("green"))
    table.add_column("Last Reviewed", style=style_if_enabled("dim"))

    for scan in scans:
        # Format last reviewed date
        last_reviewed = scan["last_reviewed_at"]
        if last_reviewed:
            # Parse ISO format and display as date only
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(last_reviewed)
                last_reviewed = dt.strftime("%Y-%m-%d")
            except Exception:
                pass
        else:
            last_reviewed = "Never"

        table.add_row(
            scan["scan_name"],
            str(scan["unique_hosts"] or 0),
            str(scan["total_findings"] or 0),
            str(scan["critical_count"] or 0),
            str(scan["high_count"] or 0),
            str(scan["medium_count"] or 0),
            str(scan["low_count"] or 0),
            str(scan["info_count"] or 0),
            str(scan["reviewed_count"] or 0),
            last_reviewed
        )

    _console_global.print(table)
    _console_global.print()  # Blank line
    info(f"Total scans: {len(scans)}")
    info("Use 'cerno review' to start reviewing a scan")


@scan_app.command(name="delete", help="Delete a scan and all associated data from database")
def delete_scan(
    scan_name: str = typer.Argument(..., help="Name of scan to delete")
) -> None:
    """Delete a scan and all associated data from the database.

    This will permanently remove:
    - The scan entry
    - All findings for this scan
    - All host:port data
    - All review sessions
    - All tool execution records and artifacts

    This action cannot be undone!
    """
    from cerno_pkg.models import Scan

    # Check if scan exists
    scan = Scan.get_by_name(scan_name)
    if not scan:
        err(f"Scan not found: {scan_name}")
        info("Use 'cerno list' to see available scans")
        raise typer.Exit(1)

    # Confirm deletion
    warn(f"You are about to delete scan: {scan_name}")
    warn("This will permanently delete ALL associated data:")
    warn("  - Findings")
    warn("  - Host:port combinations")
    warn("  - Review sessions")
    warn("  - Tool executions and artifacts")
    _console_global.print()  # Blank line

    try:
        response = Prompt.ask("Type the scan name to confirm deletion").strip()
    except KeyboardInterrupt:
        _console_global.print()  # Newline after ^C
        info("Deletion cancelled")
        raise typer.Exit(0)

    if response != scan_name:
        err("Scan name does not match. Deletion cancelled.")
        raise typer.Exit(1)

    # Delete scan
    if Scan.delete_by_name(scan_name):
        ok(f"Scan deleted: {scan_name}")
    else:
        err(f"Failed to delete scan: {scan_name}")
        raise typer.Exit(1)


# === Config Sub-App Commands ===
# Grouped under 'cerno config'

@config_app.command(name="reset", help="Reset configuration file to defaults")
def config_reset() -> None:
    """Reset config file at ~/.cerno/config.yaml to defaults."""
    from cerno_pkg import create_example_config, get_config_path
    import shutil

    config_path = get_config_path()

    # Backup existing if present
    if config_path.exists():
        backup_path = config_path.with_suffix(".yaml.backup")
        shutil.copy(config_path, backup_path)
        info(f"Backed up existing config to {backup_path}")

    if create_example_config():
        ok(f"Reset config to defaults at {config_path}")
        info("Edit this file to customize your preferences")
    else:
        err("Failed to reset config file")
        raise typer.Exit(1)


@config_app.command(name="show", help="Display current configuration with all settings and paths")
def config_show() -> None:
    """Display current configuration (merged from file and defaults)."""
    from cerno_pkg import load_config, get_config_path, CernoConfig, DEFAULT_TOP_PORTS
    from rich.table import Table

    config_path = get_config_path()
    config = load_config()

    header("Current Configuration")
    info(f"Config file: {config_path}")
    _console_global.print()

    # Create table with Description column
    table = Table(title="Configuration Values", show_header=True, header_style=style_if_enabled("bold cyan"))
    table.add_column("Setting", style=style_if_enabled("cyan"), no_wrap=True)
    table.add_column("Value", style=style_if_enabled("yellow"))
    table.add_column("Description", style=style_if_enabled("dim white"))
    table.add_column("Status", style=style_if_enabled("green"))

    # Get defaults for comparison
    defaults = CernoConfig()

    # Collect all rows for sorting
    rows = []

    # Paths
    rows.append(("results_root", config.results_root or str(get_results_root()),
                config.results_root == defaults.results_root, "Directory for tool output"))

    # Display preferences
    rows.append(("default_page_size", config.default_page_size or "auto",
                config.default_page_size == defaults.default_page_size, "Items per page in lists"))
    rows.append(("top_ports_count", config.top_ports_count or DEFAULT_TOP_PORTS,
                config.top_ports_count == defaults.top_ports_count, "Top ports to show"))

    # Behavior
    rows.append(("custom_workflows_path", config.custom_workflows_path or "(not set)",
                config.custom_workflows_path == defaults.custom_workflows_path, "Path to custom workflows YAML"))

    # Network

    # Tool defaults
    rows.append(("default_tool", config.default_tool or "(not set)",
                config.default_tool == defaults.default_tool, "Pre-select: nmap/netexec/custom"))
    rows.append(("default_netexec_protocol", config.default_netexec_protocol or "smb",
                config.default_netexec_protocol == defaults.default_netexec_protocol, "Default: smb/ssh/ftp/etc"))
    rows.append(("nmap_default_profile", config.nmap_default_profile or "(not set)",
                config.nmap_default_profile == defaults.nmap_default_profile, "NSE profile name"))

    # Logging
    rows.append(("log_path", config.log_path or str(Path.home() / ".cerno" / "cerno.log"),
                config.log_path == defaults.log_path, "Log file location"))
    rows.append(("debug_logging", config.debug_logging,
                config.debug_logging == defaults.debug_logging, "Enable DEBUG logs"))

    # Display
    rows.append(("no_color", config.no_color,
                config.no_color == defaults.no_color, "Disable ANSI colors"))
    rows.append(("term_override", config.term_override or "(not set)",
                config.term_override == defaults.term_override, "Force terminal type"))

    # NetExec integration
    rows.append(("nxc_workspace_path", config.nxc_workspace_path or "~/.nxc/workspaces/default/",
                config.nxc_workspace_path == defaults.nxc_workspace_path, "NetExec workspace directory"))
    rows.append(("nxc_enrichment_enabled", config.nxc_enrichment_enabled,
                config.nxc_enrichment_enabled == defaults.nxc_enrichment_enabled, "Show NetExec context in findings"))

    # Sort rows alphabetically by setting name (first element of tuple)
    rows.sort(key=lambda row: row[0])

    # Add sorted rows to table
    for key, value, is_default, description in rows:
        status = "Default" if is_default else "Configured"
        value_str = str(value) if value is not None else "None"
        table.add_row(key, value_str, description, status)

    _console.print(table)
    _console_global.print()
    info(f"Edit config: {config_path}")
    info("Change values: cerno config set <key> <value>")
    info("Reset to defaults: cerno config reset")


@config_app.command(name="get", help="Retrieve value of a specific configuration key")
def config_get(
    key: str = typer.Argument(..., help="Config key to retrieve")
) -> None:
    """Get and display a specific configuration value."""
    from cerno_pkg import load_config

    config = load_config()

    # Map key to config attribute
    if not hasattr(config, key):
        err(f"Unknown config key: {key}")
        info("Available keys: results_root, default_page_size, top_ports_count, custom_workflows_path,")
        info("                default_tool, default_netexec_protocol, nmap_default_profile,")
        info("                log_path, debug_logging, no_color, term_override")
        raise typer.Exit(1)

    value = getattr(config, key)
    if value is None:
        info(f"{key} is not set (using default)")
    else:
        _console_global.print(value)


@config_app.command(name="set", help="Update value of a specific configuration key")
def config_set(
    key: str = typer.Argument(..., help="Config key to set"),
    value: str = typer.Argument(..., help="Value to set")
) -> None:
    """Set a configuration value in ~/.cerno/config.yaml."""
    from cerno_pkg import load_config, save_config, get_config_path

    config = load_config()

    # Validate key
    if not hasattr(config, key):
        err(f"Unknown config key: {key}")
        info("Available keys: results_root, default_page_size, top_ports_count, custom_workflows_path,")
        info("                default_tool, default_netexec_protocol, nmap_default_profile,")
        info("                log_path, debug_logging, no_color, term_override")
        raise typer.Exit(1)

    # Type conversion based on key
    try:
        if key in ["default_page_size", "top_ports_count"]:
            typed_value = int(value)
        elif key in ["no_color", "debug_logging"]:
            typed_value = value.lower() in ("true", "1", "yes", "on")
        else:
            typed_value = value

        setattr(config, key, typed_value)

        if save_config(config):
            ok(f"Set {key} = {typed_value}")
            info(f"Config saved to {get_config_path()}")
        else:
            err("Failed to save config")
            raise typer.Exit(1)
    except ValueError as e:
        err(f"Invalid value for {key}: {e}")
        raise typer.Exit(1)


# ===== Workflow Commands =====

@workflow_app.command(name="list", help="List all available workflows from bundled and custom YAML files")
def workflow_list(
    custom_workflows: Optional[Path] = typer.Option(
        None, "--custom-workflows", "-w", help="Path to custom workflows YAML file"
    ),
) -> None:
    """Display all available workflows with plugin IDs and descriptions."""
    from cerno_pkg.workflow_mapper import WorkflowMapper
    from rich.table import Table
    from rich.console import Console

    console = Console()

    # Initialize workflow mapper (loads bundled workflows)
    workflow_mapper = WorkflowMapper()

    # Load custom workflows if provided
    if custom_workflows:
        if not custom_workflows.exists():
            err(f"Custom workflows file not found: {custom_workflows}")
            raise typer.Exit(1)
        try:
            count = workflow_mapper.load_additional_workflows(custom_workflows)
            info(f"Loaded {count} custom workflow(s) from {custom_workflows}")
        except Exception as e:
            err(f"Failed to load custom workflows: {e}")
            raise typer.Exit(1)

    # Get all workflows
    all_workflows = workflow_mapper.get_all_workflows()

    if not all_workflows:
        warn("No workflows found")
        return

    # Build Rich table
    table = Table(title="[bold cyan]Available Workflows[/]", show_header=True, header_style="bold magenta")
    table.add_column("Plugin ID(s)", style="cyan", no_wrap=True)
    table.add_column("Workflow Name", style="yellow")
    table.add_column("Description", style="dim")

    for workflow in all_workflows:
        plugin_ids = workflow.get("plugin_id", "")
        workflow_name = workflow.get("workflow_name", "")
        description = workflow.get("description", "")

        # Truncate long descriptions
        if len(description) > 80:
            description = description[:77] + "..."

        table.add_row(plugin_ids, workflow_name, description)

    console.print()
    console.print(table)
    console.print()
    info(f"Total workflows: {len(all_workflows)}")


if __name__ == "__main__":
    app()