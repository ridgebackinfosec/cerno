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
    review_count_cells,
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
    filter_finding_candidates,
    handle_finding_list_actions,
    ask_claude_multiline,
    # banner
    display_banner,
)

# === Standard library imports ===
import math
import types
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from cerno_pkg.config import CernoConfig
    from cerno_pkg.workflow_mapper import Workflow

# === Third-party imports ===
import typer
from typer import Exit
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.traceback import install as rich_tb_install

# Create a console for the interactive flow (configured with no_color setting)
from cerno_pkg.ansi import get_console, get_terminal_width, safe_text
from cerno_pkg.models import count_review_states
from cerno_pkg.constants import (
    REVIEW_STATE_DONE,
    REVIEW_STATE_IN_PROGRESS,
    REVIEW_STATE_LABELS,
    REVIEW_STATE_STYLES,
    REVIEW_STATE_UNREVIEWED,
)

_console_global = get_console()

# Install pretty tracebacks, hiding Typer's internal frames (including the
# Click it vendors as of 0.26) so CLI exit exceptions don't dump framework
# noise. Rich treats a *string* suppress entry as a filesystem path, not a
# module name, so these must be module objects to resolve at all.
_TB_SUPPRESS = [typer]
rich_tb_install(show_locals=False, suppress=_TB_SUPPRESS)

# === Configuration context ===
import contextvars
from typing import Optional as Opt

_config_context: contextvars.ContextVar[Opt["CernoConfig"]] = contextvars.ContextVar(
    "config", default=None
)


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


def browse_claude_chat(
    finding: Any,
    plugin: Any,
    hosts: list[str],
    workflow: Optional["Workflow"] = None,
) -> None:
    """Interactive Claude Assistant chat panel for a finding.

    Opens a persistent chat overlay for the given finding. Loads prior conversation
    history from SQLite, displays it, and enters an input loop.

    Args:
        finding: Finding database object
        plugin: Plugin database object
        hosts: List of affected host strings for context
        workflow: Optional Workflow object containing verification steps and references
    """
    from cerno_pkg.database import get_connection
    from cerno_pkg import claude_assistant
    from cerno_pkg.models import ClaudeConversationTurn
    from cerno_pkg.render import render_claude_panel
    from rich.prompt import Prompt

    finding_id = finding.finding_id
    if finding_id is None:
        warn("Finding has no ID — cannot open Claude Assistant.")
        return

    # Track whether the assistant notice has been shown this session (per-call local state)
    notice_shown = False

    with get_connection() as conn:
        turns = ClaudeConversationTurn.get_by_finding(conn, finding_id)
        is_resumed = bool(turns)

        # Show assistant notice once per call (not stored in DB)
        if not notice_shown:
            from cerno_pkg.claude_assistant import ASSISTANT_NOTICE

            _console_global.print(ASSISTANT_NOTICE)
            notice_shown = True

        while True:
            # Render the full panel (clears and redraws on each iteration)
            render_claude_panel(turns, is_resumed=is_resumed)

            try:
                raw = ask_claude_multiline()
            except KeyboardInterrupt:
                break

            if not raw:
                continue

            # Clear history
            if raw.strip() == "/clear":
                from rich.prompt import Confirm

                if Confirm.ask(
                    "Clear conversation history for this finding?", default=False
                ):
                    cleared = ClaudeConversationTurn.clear(conn, finding_id)
                    turns = []
                    is_resumed = False
                    ok(f"Cleared {cleared} turn(s).")
                continue

            # Report brief shortcut
            if raw.lower() in claude_assistant.REPORT_BRIEF_TRIGGERS:
                raw = claude_assistant.REPORT_BRIEF_QUERY

            # Send to Claude
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[cyan]Asking Claude...[/cyan]"),
                TimeElapsedColumn(),
                console=_console_global,
                transient=True,
            ) as progress:
                progress.add_task("", total=None)
                response = claude_assistant.run_exchange(
                    conn=conn,
                    finding_id=finding_id,
                    plugin=plugin,
                    finding=finding,
                    hosts=hosts,
                    question=raw,
                    workflow=workflow,
                )

            # Reload turns after exchange (includes new user+assistant turn)
            turns = ClaudeConversationTurn.get_by_finding(conn, finding_id)
            is_resumed = bool(turns)


def browse_claude_chat_aggregate(
    context_key: str,
    scope_description: str,
    scan_names: list[str],
    findings_with_plugins: list[Any],
) -> None:
    """Interactive Claude Assistant chat for an aggregate scope.

    Used at severity-menu level (all findings in scan) and findings-list level
    (all findings in current filter/severity selection). Conversation history is
    persisted in SQLite keyed by context_key.

    Args:
        context_key: Deterministic string identifying the conversation scope
        scope_description: Human-readable scope label shown to the user
        scan_names: Display names of the selected scan(s)
        findings_with_plugins: List of (Finding, Plugin) tuples in scope
    """
    from cerno_pkg.database import get_connection
    from cerno_pkg import claude_assistant
    from cerno_pkg.models import ClaudeAggregateConversationTurn
    from cerno_pkg.render import render_claude_panel
    from rich.prompt import Prompt

    with get_connection() as conn:
        turns = ClaudeAggregateConversationTurn.get_by_context(conn, context_key)
        is_resumed = bool(turns)

        from cerno_pkg.claude_assistant import ASSISTANT_NOTICE

        _console_global.print(ASSISTANT_NOTICE)
        _console_global.print(f"[dim]Scope: {safe_text(scope_description)}[/dim]")

        while True:
            render_claude_panel(turns, is_resumed=is_resumed)

            try:
                raw = ask_claude_multiline()
            except KeyboardInterrupt:
                break

            if not raw:
                continue

            if raw.strip() == "/clear":
                from rich.prompt import Confirm

                if Confirm.ask(
                    "Clear conversation history for this scope?", default=False
                ):
                    cleared = ClaudeAggregateConversationTurn.clear(conn, context_key)
                    turns = []
                    is_resumed = False
                    ok(f"Cleared {cleared} turn(s).")
                continue

            # Report brief shortcut
            if raw.lower() in claude_assistant.REPORT_BRIEF_TRIGGERS:
                raw = claude_assistant.REPORT_BRIEF_QUERY

            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[cyan]Asking Claude...[/cyan]"),
                TimeElapsedColumn(),
                console=_console_global,
                transient=True,
            ) as progress:
                progress.add_task("", total=None)
                response = claude_assistant.run_aggregate_exchange(
                    conn=conn,
                    context_key=context_key,
                    scope_description=scope_description,
                    scan_names=scan_names,
                    findings_with_plugins=findings_with_plugins,
                    question=raw,
                )

            turns = ClaudeAggregateConversationTurn.get_by_context(conn, context_key)
            is_resumed = bool(turns)


def browse_workflow_groups(
    scan: Any,  # Scan object (primary scan)
    workflow_groups: Dict[str, List[Tuple[Any, Any]]],
    args: types.SimpleNamespace,
    use_sudo: bool,
    in_progress_total: List[str],
    done_total: List[str],
    workflow_mapper,
    config: Optional["CernoConfig"] = None,
    session_start_time: Optional[Any] = None,
    scan_label: Optional[str] = None,
    scans: Optional[List[Any]] = None,
) -> None:
    """
    Browse workflow groups and findings within selected workflow.

    Displays a menu of workflow names with Unreviewed / In Progress / Done
    counts, allows selection, then shows findings for that workflow.

    Args:
        scan: Primary Scan database object
        workflow_groups: Dict mapping workflow_name -> list of (Finding, Plugin) tuples
        args: Command-line arguments
        use_sudo: Whether sudo is available
        in_progress_total: List of findings viewed but not marked done
        done_total: List of findings marked done
        workflow_mapper: WorkflowMapper instance
        config: Optional config (loaded if omitted)
        session_start_time: Review session start, used for end-of-session statistics
        scan_label: Optional display label override (used for multi-scan breadcrumbs)
        scans: Optional full list of selected Scan objects for multi-scan support
    """
    # Load config if not provided (defensive programming)
    if config is None:
        from cerno_pkg.config import load_config

        config = load_config()

    scan_dir = Path(scan.export_root) / scan.scan_name
    _wf_label = scan_label if scan_label else scan_dir.name
    if not workflow_groups:
        warn("No findings with mapped workflows found.")
        return

    while True:
        # Build table of workflows
        from cerno_pkg import breadcrumb

        bc = breadcrumb(_wf_label, "Workflow Mapped Findings")
        header(bc if bc else "Workflow Mapped Findings - Select Workflow")

        table = Table(title="Workflows", box=box.SIMPLE)
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Workflow Name", style="bold")
        for state in (
            REVIEW_STATE_UNREVIEWED,
            REVIEW_STATE_IN_PROGRESS,
            REVIEW_STATE_DONE,
        ):
            table.add_column(f"{REVIEW_STATE_LABELS[state]} (%)", justify="right")
        table.add_column("Total", justify="right")

        workflow_list = sorted(
            workflow_groups.items(), key=lambda x: len(x[1]), reverse=True
        )

        for idx, (workflow_name, files) in enumerate(workflow_list, start=1):
            counts = count_review_states(pf for (pf, _p) in files)
            table.add_row(str(idx), workflow_name, *review_count_cells(counts))

        _console_global.print(table)
        print_action_menu([("B", "Back")])

        try:
            ans = Prompt.ask("Choose workflow").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to severity menu.")
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
        all_scans = scans if scans else [scan]
        browse_file_list(
            all_scans,
            None,  # No specific severity dir (workflow may span multiple severities)
            None,  # No severity filter
            f"Workflow: {workflow_name}",
            args,
            use_sudo,
            in_progress_total,
            done_total,
            is_msf_mode=True,  # Show severity labels
            workflow_mapper=workflow_mapper,
            plugin_ids_filter=plugin_ids if plugin_ids else None,
            config=config,
            session_start_time=session_start_time,
        )

        # Refresh workflow files from database to get updated review_state values
        # This ensures the statistics display shows current counts after moving findings between statuses
        from cerno_pkg.models import Finding

        all_scan_ids = [s.scan_id for s in all_scans if s.scan_id is not None]
        if len(all_scan_ids) > 1:
            refreshed_files, _ = Finding.get_by_scan_ids_merged(
                scan_ids=all_scan_ids,
                plugin_ids=plugin_ids if plugin_ids else None,
            )
        else:
            refreshed_files = Finding.get_by_scan_with_plugin(
                scan_id=scan.scan_id,
                plugin_ids=plugin_ids if plugin_ids else None,
            )
        workflow_groups[workflow_name] = refreshed_files


# === Unified file list browser ===


def browse_file_list(
    scans: list[Any],  # List of Scan objects (single-scan: [scan])
    sev_dir: Optional[Path],
    severity_dir_filter: Optional[str],
    severity_label: str,
    args: types.SimpleNamespace,
    use_sudo: bool,
    in_progress_total: List[str],
    done_total: List[str],
    is_msf_mode: bool = False,
    workflow_mapper: Optional[WorkflowMapper] = None,
    has_metasploit_filter: Optional[bool] = None,
    plugin_ids_filter: Optional[list[int]] = None,
    severity_dirs_filter: Optional[list[str]] = None,
    config: Optional["CernoConfig"] = None,
    session_start_time: Optional[Any] = None,
) -> None:
    """
    Browse and interact with the findings list (unified for severity and MSF modes).

    Args:
        scans: List of Scan database objects (single-scan: pass [scan])
        sev_dir: Severity display path, used for the preview and tool output paths
        severity_dir_filter: Severity directory filter for database query (e.g., "3_High")
        severity_label: Display label for the severity
        workflow_mapper: Optional workflow mapper for plugin workflows
        args: Command-line arguments
        use_sudo: Whether sudo is available
        in_progress_total: List to track findings viewed but not marked done
        done_total: List to track findings marked done
        is_msf_mode: If True, display severity labels in the Done list
        has_metasploit_filter: Optional filter for metasploit plugins
        plugin_ids_filter: Optional list of specific plugin IDs to include
        severity_dirs_filter: Optional list of severity filters for a multi-severity view
        config: Optional config (loaded if omitted)
        session_start_time: Review session start, used for end-of-session statistics
    """
    from cerno_pkg.models import Finding

    # Load config if not provided (defensive programming)
    if config is None:
        from cerno_pkg.config import load_config

        config = load_config()

    # Resolve proxy state (CLI override takes precedence over config)
    _proxy_active = config.proxychains_enabled
    if getattr(args, "proxy", False):
        _proxy_active = True
    elif getattr(args, "no_proxy", False):
        _proxy_active = False

    file_filter = ""
    reviewed_filter = ""
    group_filter: Optional[Tuple[int, set, str]] = None
    status_filter: Optional[str] = None  # [I] toggle: None = all open statuses
    # Default sort: severity for mixed views (Critical at top), plugin_id for single severity
    sort_mode = "plugin_id" if severity_dir_filter is not None else "severity"

    # Use config value if set, otherwise calculate based on terminal
    page_size = (
        config.default_page_size
        if config.default_page_size is not None
        else default_page_size()
    )

    # Validate page size
    if page_size <= 0:
        warn(f"Invalid page size {page_size} in config, using default")
        page_size = default_page_size()

    page_idx = 0
    first_iteration = True  # Track first iteration for startup hint

    # Derive scan variables from scans list
    primary_scan = scans[0]
    scan_id = primary_scan.scan_id
    is_multi_scan = len(scans) > 1
    scan_ids = [s.scan_id for s in scans]
    scan_names = [s.scan_name for s in scans]
    scan_dir = Path(primary_scan.export_root) / primary_scan.scan_name

    # Claude availability check (once per browse session)
    from cerno_pkg.claude_assistant import check_claude_available, claude_enabled

    claude_installed = check_claude_available()
    has_claude = claude_enabled(config)

    def get_counts_for(finding: "Finding") -> Tuple[int, str]:
        """Get host/port counts from database.

        In multi-scan mode, counts distinct hosts across all finding_ids for this plugin.

        Args:
            finding: Finding database object

        Returns:
            Tuple of (host_count, ports_string)
        """
        from cerno_pkg.database import query_one, get_connection

        with get_connection() as conn:
            if is_multi_scan and all_instances:
                all_fids = [
                    f.finding_id
                    for f in all_instances.get(finding.plugin_id, [])
                    if f.finding_id is not None
                ]
            else:
                all_fids = (
                    [finding.finding_id] if finding.finding_id is not None else []
                )

            if not all_fids:
                return (0, "")

            placeholders = ",".join("?" * len(all_fids))
            row = query_one(
                conn,
                f"SELECT COUNT(DISTINCT host_id) FROM finding_affected_hosts WHERE finding_id IN ({placeholders})",
                tuple(all_fids),
            )
            return (row[0] if row else 0, "")

    # Initialize multi-scan tracking variables (updated each loop iteration)
    all_instances: dict[int, list["Finding"]] = {}
    scan_labels: Optional[dict[int, str]] = None

    while True:
        # Query database for findings with plugin info
        if is_multi_scan:
            all_records, all_instances = Finding.get_by_scan_ids_merged(
                scan_ids=scan_ids,
                severity_dir=severity_dir_filter,
                severity_dirs=severity_dirs_filter,
                has_metasploit=has_metasploit_filter,
                plugin_ids=plugin_ids_filter,
            )
            # Build scan label strings: "All N" or "M of N"
            total_scans = len(scans)
            scan_labels = {
                pid: (
                    f"All {total_scans}"
                    if len(findings) == total_scans
                    else f"{len(findings)} of {total_scans}"
                )
                for pid, findings in all_instances.items()
            }
        else:
            all_records = Finding.get_by_scan_with_plugin(
                scan_id=scan_id,
                severity_dir=severity_dir_filter,
                severity_dirs=severity_dirs_filter,
                has_metasploit=has_metasploit_filter,
                plugin_ids=plugin_ids_filter,
            )
            all_instances = {}
            scan_labels = None

        # Separate reviewed and unreviewed based on review_state from database
        reviewed = [
            (pf, p) for (pf, p) in all_records if pf.review_state == REVIEW_STATE_DONE
        ]
        unreviewed = [
            (pf, p) for (pf, p) in all_records if pf.review_state != REVIEW_STATE_DONE
        ]

        # Apply name, group, and status filters
        candidates = filter_finding_candidates(
            unreviewed, file_filter, group_filter, status_filter
        )

        # Unique CVE count across all filtered candidates
        unique_cve_count = len({cve for _, p in candidates if p.cves for cve in p.cves})

        # Unique host count across all filtered candidates (single DB query)
        if candidates:
            if is_multi_scan and all_instances:
                all_fids = [
                    f.finding_id
                    for pf, _ in candidates
                    for f in all_instances.get(pf.plugin_id, [])
                    if f.finding_id is not None
                ]
            else:
                all_fids = [
                    pf.finding_id for pf, _ in candidates if pf.finding_id is not None
                ]

            if all_fids:
                from cerno_pkg.database import query_one, get_connection

                placeholders = ",".join("?" * len(all_fids))
                with get_connection() as conn:
                    row = query_one(
                        conn,
                        f"SELECT COUNT(DISTINCT host_id) FROM finding_affected_hosts WHERE finding_id IN ({placeholders})",
                        tuple(all_fids),
                    )
                unique_host_count = row[0] if row else 0
            else:
                unique_host_count = 0
        else:
            unique_cve_count = 0
            unique_host_count = 0

        # Apply sorting
        if sort_mode == "severity":
            # Sort by severity descending (Critical first), then by plugin name
            display = sorted(
                candidates,
                key=lambda record: (
                    -record[1].severity_int,
                    natural_key(record[1].plugin_name),
                ),
            )
        elif sort_mode == "hosts":
            display = sorted(
                candidates,
                key=lambda record: (
                    -get_counts_for(record[0])[0],
                    natural_key(record[1].plugin_name),
                ),
            )
        elif sort_mode == "plugin_id":
            # Sort by plugin ID (numeric ascending)
            display = sorted(candidates, key=lambda record: record[1].plugin_id)
        else:  # name
            display = sorted(
                candidates, key=lambda record: natural_key(record[1].plugin_name)
            )

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

            if is_multi_scan:
                _names = [s.scan_name for s in scans]
                _scan_label = (
                    f"{_names[0]} + {_names[1]}"
                    if len(_names) == 2
                    else f"{len(_names)} scans"
                )
            else:
                _scan_label = scan_dir.name
            filter_info = f"filtered: '{file_filter}'" if file_filter else "Findings"
            if status_filter:
                filter_info += f" ({REVIEW_STATE_LABELS[status_filter]} only)"
            bc = breadcrumb(_scan_label, severity_label, filter_info)
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
                    warn(
                        f"Note: Terminal width is {term_width} chars (recommended: 100+). Some layouts may wrap."
                    )

                _console_global.print()  # Blank line for spacing
                first_iteration = False

            # Build status line components
            from rich.text import Text

            status_parts: list[str | Text] = []

            # Open (not Done) counts by status
            open_unrev, open_in_prog, _done, _total = count_review_states(
                pf for (pf, _p) in unreviewed
            )
            open_text = Text()
            open_text.append(
                f"{REVIEW_STATE_LABELS[REVIEW_STATE_UNREVIEWED]} {open_unrev}",
                style=style_if_enabled(REVIEW_STATE_STYLES[REVIEW_STATE_UNREVIEWED]),
            )
            open_text.append(" · ")
            open_text.append(
                f"{REVIEW_STATE_LABELS[REVIEW_STATE_IN_PROGRESS]} {open_in_prog}",
                style=style_if_enabled(REVIEW_STATE_STYLES[REVIEW_STATE_IN_PROGRESS]),
            )
            status_parts.append(open_text)

            # File filter with visual indicator if active
            if file_filter:
                filter_text = Text()
                filter_text.append("[FILTER] ", style="bold cyan")
                filter_text.append(f"Name: '{file_filter}'", style="bold yellow")
                status_parts.append(filter_text)
            else:
                status_parts.append("Filter: '*'")

            # Status filter ([I] toggle)
            if status_filter:
                status_text = Text()
                status_text.append("[FILTER] ", style="bold cyan")
                status_text.append(
                    f"Status: {REVIEW_STATE_LABELS[status_filter]}",
                    style=style_if_enabled(
                        f"bold {REVIEW_STATE_STYLES[status_filter]}"
                    ),
                )
                status_parts.append(status_text)

            # Group filter with bold visual indicator
            if group_filter:
                # group_filter is (index, labels, description)
                group_desc = (
                    group_filter[2]
                    if len(group_filter) > 2
                    else f"{len(group_filter[1])} findings"
                )
                group_text = Text()
                group_text.append("[ACTIVE FILTER] ", style="bold cyan")
                group_text.append(
                    f"Group #{group_filter[0]}: {group_desc} ({len(group_filter[1])})",
                    style="bold yellow",
                )
                status_parts.append(group_text)

            sort_label = {
                "severity": "Severity ↓",
                "plugin_id": "Plugin ID ↑",
                "hosts": "Host count ↓",
                "name": "Name A↑Z",
            }.get(sort_mode, "Severity ↓")

            # Show next sort mode indicator
            next_sort_mode = {
                "severity": "Plugin ID ↑",
                "plugin_id": "Name A↑Z",
                "name": "Host count ↓",
                "hosts": "Severity ↓",
            }.get(sort_mode, "Plugin ID ↑")

            status_parts.append(f"Sort: {sort_label} (next: {next_sort_mode})")

            # Enhanced pagination indicator with progress bar
            from cerno_pkg.render import render_pagination_indicator

            page_indicator = render_pagination_indicator(
                page_idx, total_pages, len(display)
            )
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
                if in_progress_total or done_total:
                    session_stats += f" (+{len(in_progress_total)} In Progress, +{len(done_total)} Done)"
                status_parts.append(session_stats)

            # Proxy badge
            if _proxy_active:
                proxy_badge = Text()
                proxy_badge.append("[PROXY ENABLED]", style="bold magenta")
                status_parts.insert(0, proxy_badge)

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
                elif status_filter and unreviewed:
                    render_empty_state(
                        "status_mismatch", REVIEW_STATE_LABELS[status_filter]
                    )
                elif all_records and len(all_records) == len(reviewed):
                    render_empty_state("all_completed")
                elif not all_records:
                    render_empty_state("no_severity")
                # Don't render table if no findings
            else:
                # Query Claude chat history for ✦ indicator (per-page, lightweight)
                chat_history_ids: frozenset[int] = frozenset()
                try:
                    from cerno_pkg.models import ClaudeConversationTurn
                    from cerno_pkg.database import get_connection

                    page_finding_ids = [
                        f.finding_id for f, _ in page_items if f.finding_id is not None
                    ]
                    if page_finding_ids:
                        with get_connection() as _chat_conn:
                            chat_history_ids = frozenset(
                                ClaudeConversationTurn.finding_has_history(
                                    _chat_conn, page_finding_ids
                                )
                            )
                except Exception:
                    pass  # Non-critical: indicator simply won't show on error

                render_finding_list_table(
                    page_items,
                    sort_mode,
                    get_counts_for,
                    row_offset=start,
                    show_severity=is_msf_mode,
                    scan_labels=scan_labels,
                    chat_history_finding_ids=chat_history_ids,
                )

                # Add hint on first page if more results exist
                can_next = page_idx + 1 < total_pages
                can_prev = page_idx > 0
                if page_idx == 0 and can_next:
                    remaining = len(display) - page_size
                    info(
                        f"→ {remaining} more finding{'s' if remaining != 1 else ''} available (press N for next page)"
                    )

            # Always render footer with available actions
            can_next = page_idx + 1 < total_pages
            can_prev = page_idx > 0
            render_actions_footer(
                group_applied=bool(group_filter),
                candidates_count=len(candidates),
                unique_cve_count=unique_cve_count,
                unique_host_count=unique_host_count,
                sort_mode=sort_mode,
                can_next=can_next,
                can_prev=can_prev,
                has_claude=has_claude,
                claude_installed=claude_installed,
                status_filter_active=status_filter is not None,
            )

            ans = Prompt.ask("Choose a finding number, or action").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning to severity menu.")
            break

        # Handle host view (intercept before generic action handler)
        if ans == "v":
            if not candidates:
                warn("No findings match the current filter.")
                continue
            from cerno_pkg.database import get_connection
            from cerno_pkg.render import (
                _collect_aggregate_host_ports,
                aggregate_grouped_payload_text,
                aggregate_grouped_paged_text,
                aggregate_hosts_only_payload_text,
                aggregate_hosts_only_paged_text,
                aggregate_raw_payload_text,
                aggregate_raw_paged_text,
                menu_pager,
                print_action_menu,
            )
            from cerno_pkg.tools import copy_to_clipboard
            from rich.prompt import Confirm

            scope_parts = [f"Severity: {severity_label}"]
            if file_filter:
                scope_parts.append(f"filter: {file_filter}")
            if status_filter:
                scope_parts.append(f"status: {REVIEW_STATE_LABELS[status_filter]}")
            if group_filter:
                _, _, group_desc = group_filter
                scope_parts.append(f"group: {group_desc}")
            scope_label = " | ".join(scope_parts)

            with get_connection() as _v_conn:
                host_ports, sorted_hosts = _collect_aggregate_host_ports(
                    candidates, _v_conn
                )

            if not sorted_hosts:
                warn("No host data available for current findings.")
                continue

            text = aggregate_grouped_paged_text(host_ports, sorted_hosts, scope_label)
            payload = aggregate_grouped_payload_text(host_ports, sorted_hosts)
            menu_pager(text)

            print_action_menu(
                [
                    ("C", "Copy to clipboard"),
                    ("F", "Change format"),
                    ("B", "Back"),
                ]
            )
            try:
                post_choice = Prompt.ask("Action", default="b").strip().lower()
            except KeyboardInterrupt:
                continue

            if post_choice in ("c", "copy"):
                ok_flag, detail = copy_to_clipboard(payload)
                if ok_flag:
                    ok("Copied to clipboard.")
                else:
                    warn(f"{detail} Printing below for manual copy:")
                    _console_global.print(payload)

            elif post_choice in ("f", "format"):
                print_action_menu(
                    [
                        ("R", "Raw"),
                        ("H", "Hosts only"),
                        ("G", "Grouped (current)"),
                    ]
                )
                try:
                    fmt = Prompt.ask("Choose format", default="g").strip().lower()
                except KeyboardInterrupt:
                    continue

                if fmt in ("r", "raw"):
                    text = aggregate_raw_paged_text(
                        host_ports, sorted_hosts, scope_label
                    )
                    payload = aggregate_raw_payload_text(host_ports, sorted_hosts)
                elif fmt in ("h", "hosts", "hosts-only"):
                    text = aggregate_hosts_only_paged_text(sorted_hosts, scope_label)
                    payload = aggregate_hosts_only_payload_text(sorted_hosts)
                else:
                    continue

                if text and payload:
                    menu_pager(text)
                    try:
                        if Confirm.ask("Copy to clipboard?", default=True):
                            ok_flag, detail = copy_to_clipboard(payload)
                            if ok_flag:
                                ok("Copied to clipboard.")
                            else:
                                warn(f"{detail}")
                    except KeyboardInterrupt:
                        pass

            continue

        # Toggle In Progress-only status filter (intercept before generic action handler)
        if ans == "i":
            if status_filter is None:
                status_filter = REVIEW_STATE_IN_PROGRESS
                ok(f"Showing {REVIEW_STATE_LABELS[status_filter]} findings only.")
            else:
                status_filter = None
                ok("Showing all statuses.")
            page_idx = 0
            continue

        # Handle Claude aggregate chat (intercept before generic action handler)
        if ans == "a":
            if not has_claude and claude_installed:
                from cerno_pkg.claude_assistant import ensure_enabled

                if ensure_enabled(config):
                    has_claude = True
            if has_claude:
                import hashlib

                scope_parts = [f"Severity: {severity_label}"]
                if file_filter:
                    scope_parts.append(f"filter: {file_filter}")
                if status_filter:
                    scope_parts.append(f"status: {REVIEW_STATE_LABELS[status_filter]}")
                if group_filter:
                    _, _, group_desc = group_filter
                    scope_parts.append(f"group: {group_desc}")
                scope_desc = " | ".join(scope_parts)
                scan_ids_str = ",".join(str(sid) for sid in sorted(scan_ids))
                scope_hash = hashlib.md5(scope_desc.encode()).hexdigest()[:8]
                context_key = f"findings_list:{scan_ids_str}:{scope_hash}"
                browse_claude_chat_aggregate(
                    context_key=context_key,
                    scope_description=scope_desc,
                    scan_names=scan_names,
                    findings_with_plugins=candidates,
                )
            elif not claude_installed:
                warn(
                    "Claude Assistant is not available. Install the claude CLI to use this feature."
                )
            continue

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
            unique_cve_count=unique_cve_count,
            unique_host_count=unique_host_count,
            status_filter_active=status_filter is not None,
        )

        (
            action_type,
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
        ) = action_result

        if ans == "c":
            status_filter = (
                None  # [C] clears the status filter along with the name filter
            )

        if action_type == "back":
            break
        elif action_type == "help":
            continue
        elif action_type == "mark_all":
            # Bulk move: each filtered finding moves to its next status
            from cerno_pkg.fs import move_review_state
            from rich.prompt import Confirm

            to_start = sum(
                1 for (f, _p) in candidates if f.review_state == REVIEW_STATE_UNREVIEWED
            )
            to_finish = sum(
                1
                for (f, _p) in candidates
                if f.review_state == REVIEW_STATE_IN_PROGRESS
            )

            try:
                confirm_msg = (
                    f"Move {len(candidates)} findings to their next status? "
                    f"{to_start} → In Progress, {to_finish} → Done"
                )
                confirmed = Confirm.ask(confirm_msg, default=False)
            except KeyboardInterrupt:
                warn("\nInterrupted — cancelling bulk operation.")
                continue

            if not confirmed:
                info("Bulk operation cancelled.")
                continue

            started = finished = 0
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=_console_global,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "Moving findings to next status...", total=len(candidates)
                )
                for finding, plugin in candidates:
                    new_state = move_review_state(finding, plugin, quiet=True)
                    if new_state is not None:
                        display_name = (
                            f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
                        )
                        if new_state == REVIEW_STATE_DONE:
                            finished += 1
                            done_total.append(display_name)
                        else:
                            started += 1
                            in_progress_total.append(display_name)
                        # Sync other scan instances in multi-scan mode
                        if is_multi_scan:
                            for other_f in all_instances.get(plugin.plugin_id, []):
                                if other_f.finding_id != finding.finding_id:
                                    other_f.update_review_state(new_state)
                    progress.advance(task)
            ok(f"Moved {started} to In Progress, {finished} to Done.")
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
                in_progress_total,
                done_total,
                show_severity=is_msf_mode,
                workflow_mapper=workflow_mapper,
                use_proxy=_proxy_active,
            )

            # In multi-scan mode, broadcast review state changes to all other instances
            if is_multi_scan and all_instances:
                from cerno_pkg.database import query_one, get_connection

                with get_connection() as conn:
                    state_row = query_one(
                        conn,
                        "SELECT review_state FROM findings WHERE finding_id = ?",
                        (finding.finding_id,),
                    )
                if state_row:
                    new_state = state_row["review_state"]
                    for other_f in all_instances.get(finding.plugin_id, []):
                        if other_f.finding_id != finding.finding_id:
                            other_f.update_review_state(new_state)

        elif action_type is None:
            continue


# === Main application logic ===


def show_session_statistics(
    session_start_time,
    in_progress_total: list[str],
    done_total: list[str],
    scan_dir: Path,
    scan_id: Optional[int] = None,
    scan_ids: Optional[list[int]] = None,
) -> None:
    """
    Display rich session statistics at the end of a review session.

    Args:
        session_start_time: Datetime when session started
        in_progress_total: List of findings viewed but not marked done
        done_total: List of findings marked done
        scan_dir: Scan directory (only used by the legacy no-scan_id fallback)
        scan_id: Optional scan ID for database queries
        scan_ids: Optional list of scan IDs for multi-scan queries (overrides scan_id)
    """
    from datetime import datetime
    from rich.table import Table

    console = get_console()

    # Calculate session duration
    session_end_time = datetime.now()
    duration = session_end_time - session_start_time
    hours, remainder = divmod(int(duration.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    duration_str = (
        f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"
    )

    header("Session Statistics")

    # Overall stats table
    from cerno_pkg.ansi import style_if_enabled

    overall_table = Table(show_header=True, header_style=style_if_enabled("bold cyan"))
    overall_table.add_column("Metric", style=style_if_enabled("cyan"))
    overall_table.add_column("Count", justify="right", style=style_if_enabled("yellow"))

    overall_table.add_row("Session Duration", duration_str)
    overall_table.add_row("Moved to In Progress", str(len(in_progress_total)))
    overall_table.add_row("Moved to Done", str(len(done_total)))
    overall_table.add_row(
        "Total status changes", str(len(in_progress_total) + len(done_total))
    )

    console.print(overall_table)
    _console_global.print()

    # Per-severity breakdown (for completed findings only)
    if done_total:
        severity_counts = {}

        # Database query (multi-scan or single-scan). The filesystem branch below
        # is a legacy fallback, only reached when no scan_id is passed.
        if scan_ids and len(scan_ids) > 1:
            from cerno_pkg.database import db_transaction, query_all

            with db_transaction() as conn:
                placeholders = ",".join("?" * len(scan_ids))
                rows = query_all(
                    conn,
                    f"""
                    SELECT p.severity_label, COUNT(DISTINCT f.plugin_id) as count
                    FROM findings f
                    JOIN v_plugins_with_severity p ON f.plugin_id = p.plugin_id
                    WHERE f.scan_id IN ({placeholders}) AND f.review_state = 'done'
                    GROUP BY p.severity_label
                    """,
                    tuple(scan_ids),
                )
                for row in rows:
                    sev_label = pretty_severity_label(row[0])
                    severity_counts[sev_label] = row[1]
        elif scan_id is not None:
            from cerno_pkg.database import db_transaction, query_all

            # Query database for completed findings grouped by severity
            with db_transaction() as conn:
                rows = query_all(
                    conn,
                    """
                    SELECT p.severity_label, COUNT(*) as count
                    FROM findings f
                    JOIN v_plugins_with_severity p ON f.plugin_id = p.plugin_id
                    WHERE f.scan_id = ? AND f.review_state = 'done'
                    GROUP BY p.severity_label
                    """,
                    (scan_id,),
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
                count = sum(
                    1
                    for name in done_total
                    if any(
                        (sev_dir / fname).exists()
                        or (sev_dir / f"REVIEW_COMPLETE-{fname}").exists()
                        for fname in [name, name.replace("REVIEW_COMPLETE-", "")]
                    )
                )
                if count > 0:
                    severity_counts[sev_label] = count

        if severity_counts:
            sev_table = Table(
                show_header=True, header_style=style_if_enabled("bold cyan")
            )
            sev_table.add_column("Severity Level", style=style_if_enabled("cyan"))
            sev_table.add_column(
                "Done",
                justify="right",
                style=style_if_enabled(REVIEW_STATE_STYLES[REVIEW_STATE_DONE]),
            )

            sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            for sev_label in sorted(
                severity_counts, key=lambda lbl: (sev_order.get(lbl, 99), lbl)
            ):
                sev_col = severity_cell(sev_label)
                sev_table.add_row(sev_col, str(severity_counts[sev_label]))

            # Counts cover every Done finding in the scan(s), not just this session.
            console.print("Done by severity (all sessions):")
            console.print(sev_table)
            _console_global.print()


def main(args: types.SimpleNamespace) -> None:
    """
    Main application entry point for interactive review mode.

    Args:
        args: Command-line arguments namespace containing:
            - export_root (Optional[Path]): DEPRECATED and ignored. When set, the
              review is skipped and only a 'cerno review' reminder is printed.
            - no_tools (bool): Skip tool execution workflow if True.
            - custom_workflows (Optional[Path]): Custom workflow YAML to supplement defaults.
            - custom_workflows_only (Optional[Path]): Use only this workflow YAML.
            - check (bool): Print the tool availability table and exit.
            - proxy / no_proxy (bool): Force proxychains4 routing on/off for this session.
    """
    # Load configuration
    config = get_current_config()

    # Validate results root is writable before proceeding
    from cerno_pkg import validate_results_root

    results_root = get_results_root()
    is_valid, error_msg = validate_results_root(results_root)
    if not is_valid:
        err(f"Results directory validation failed: {error_msg}")
        warn(
            f"Please ensure {results_root} is writable or update results_root in config"
        )
        raise Exit(1)

    # Track session start time
    from datetime import datetime

    session_start_time = datetime.now()

    # Initialize variables for scan selection (used later for session tracking)
    scan_id: int = 0  # Will be set when user selects a scan
    scan_dir: Optional[Path] = None  # Will be set when user selects a scan

    # Initialize workflow mapper
    custom_workflows = getattr(args, "custom_workflows", None)
    custom_workflows_only = getattr(args, "custom_workflows_only", None)

    # Check config for custom workflows if CLI args not provided
    if (
        not custom_workflows
        and not custom_workflows_only
        and config.custom_workflows_path
    ):
        custom_workflows = Path(config.custom_workflows_path)

    if custom_workflows_only:
        # Replace mode: Use ONLY custom YAML
        with _console_global.status("[bold green]Loading custom workflows..."):
            workflow_mapper = WorkflowMapper(yaml_path=custom_workflows_only)
        if workflow_mapper.count() > 0:
            _console_global.print(
                f"Loaded {workflow_mapper.count()} custom workflow(s) from {custom_workflows_only} (defaults disabled)"
            )
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
            source = (
                "CLI argument" if getattr(args, "custom_workflows", None) else "config"
            )
            with _console_global.status(
                "[bold green]Loading additional custom workflows..."
            ):
                additional_count = workflow_mapper.load_additional_workflows(
                    custom_workflows
                )
            if additional_count > 0:
                _console_global.print(
                    f"Loaded {default_count} default + {additional_count} custom workflow(s) from {custom_workflows} ({source})"
                )
            else:
                warn(f"No additional workflows loaded from {custom_workflows}")
            _console_global.print(
                f"Total: {workflow_mapper.count()} workflow(s) available"
            )
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
        if getattr(args, "check", False):
            raise Exit(0)

    export_root = Path(args.export_root) if args.export_root else None
    if export_root and not export_root.exists():
        err(f"Export root not found: {export_root}")
        raise Exit(1)

    # if export_root:
    #     ok(f"Using export root: {export_root.resolve()}")
    if args.no_tools:
        info("(no-tools mode: tool prompts disabled for this session)")

    in_progress_total: List[str] = []
    done_total: List[str] = []

    # If no export_root specified, use database scan selection
    if export_root is None:
        from cerno_pkg.models import Scan, Finding
        from datetime import datetime

        def _additional_scan_ids(scans: list[Scan]) -> Optional[list[int]]:
            """Return secondary scan IDs for a multi-scan selection (None for single scan)."""
            ids = [s.scan_id for s in scans[1:] if s.scan_id is not None]
            return ids or None

        selected_scans: list[Scan] = []
        # Carried across iterations of the scan-selection loop below: the
        # previous scan's session is saved at the top of the next pass, after
        # this has been populated from that selection.
        all_scan_ids: list[int] = []

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
                        in_progress_count=len(in_progress_total),
                        done_count=len(done_total),
                        additional_scan_ids=_additional_scan_ids(selected_scans),
                    )

                    # Show statistics if work was done
                    if in_progress_total or done_total:
                        if scan_dir is not None:
                            show_session_statistics(
                                session_start_time,
                                in_progress_total,
                                done_total,
                                scan_dir,
                                scan_id=scan_id,
                                scan_ids=(
                                    all_scan_ids if len(all_scan_ids) > 1 else None
                                ),
                            )

                    delete_session(scan_id)

                    # Reset tracking for next scan
                    scan_id = 0
                    scan_dir = None
                    in_progress_total = []
                    done_total = []

                # Get all scans from database
                try:
                    with _console_global.status(
                        "[bold green]Loading scans from database..."
                    ):
                        all_scans = Scan.get_all()
                except Exception as e:
                    err(f"Failed to query scans from database: {e}")
                    info(
                        "If the database is corrupted, try: rm ~/.cerno/cerno.db && cerno import nessus <file>"
                    )
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

                scan_table = Table(
                    show_header=True,
                    header_style=style_if_enabled("bold cyan"),
                    box=box.SIMPLE,
                )
                scan_table.add_column(
                    "#", style=style_if_enabled("cyan"), justify="right"
                )
                scan_table.add_column("Scan Name", style=style_if_enabled("yellow"))
                scan_table.add_column(
                    "Last Reviewed", style=style_if_enabled("magenta")
                )

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
                                    last_reviewed = (
                                        f"{mins} min{'s' if mins != 1 else ''} ago"
                                    )
                                else:
                                    hours = delta.seconds // 3600
                                    last_reviewed = (
                                        f"{hours} hour{'s' if hours != 1 else ''} ago"
                                    )
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
                    ans = Prompt.ask(
                        "Choose scan(s) (e.g. 1  or  1-3  or  1,3,5)"
                    ).strip()
                except KeyboardInterrupt:
                    warn("\nInterrupted — exiting.")
                    return

                if ans in ("x", "exit", "q", "quit"):
                    return

                from cerno_pkg.tui import parse_scan_selection

                indices = parse_scan_selection(ans, len(all_scans))
                if indices is None:
                    warn(
                        f"Invalid choice. Enter 1-{len(all_scans)}, a range like 1-3, or [Q]uit."
                    )
                    continue

                selected_scans = [all_scans[i - 1] for i in indices]
                selected_scan = selected_scans[0]  # Primary scan for backward compat
                export_root = Path(selected_scan.export_root)
                scan_dir = export_root / selected_scan.scan_name

                # Note: scan_dir is a Path object used for display (scan_dir.name) only
                # In database-only mode, the directory doesn't need to exist

                # Type narrowing: ensure scan_id is not None
                if selected_scan.scan_id is None:
                    warn("Invalid scan - missing scan_id")
                    continue

                scan_id = selected_scan.scan_id
                all_scan_ids = [
                    s.scan_id for s in selected_scans if s.scan_id is not None
                ]
                if len(selected_scans) > 1:
                    names = ", ".join(s.scan_name for s in selected_scans)
                    ok(f"Selected: {names}")
                else:
                    ok(f"Selected: {selected_scan.scan_name}")

                # Check for existing session
                previous_session = load_session(scan_id)
                if previous_session:
                    from datetime import datetime

                    session_date = datetime.fromisoformat(
                        previous_session.session_start
                    )
                    header("Previous Session Found")
                    info(
                        f"Session started: {session_date.strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    info(f"In Progress: {previous_session.in_progress_count} findings")
                    info(f"Done: {previous_session.done_count} findings")
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
                top_ports = (
                    config.top_ports_count
                    if config.top_ports_count is not None
                    else DEFAULT_TOP_PORTS
                )

                # Validate range
                if top_ports <= 0:
                    warn(
                        f"Invalid top_ports_count {top_ports} in config, using default {DEFAULT_TOP_PORTS}"
                    )
                    top_ports = DEFAULT_TOP_PORTS
                elif top_ports > 100:
                    warn(f"top_ports_count {top_ports} is very large, capping at 100")
                    top_ports = 100

                show_scan_summary(
                    scan_dir,
                    top_ports_n=top_ports,
                    scan_id=scan_id,
                    scan_ids=all_scan_ids if len(all_scan_ids) > 1 else None,
                    scan_names=(
                        [s.scan_name for s in selected_scans]
                        if len(selected_scans) > 1
                        else None
                    ),
                )

                # Show workflow guidance for first-time or returning users
                from cerno_pkg.onboarding import show_workflow_guidance

                show_workflow_guidance(
                    scan_name=selected_scan.scan_name,
                    scan_id=scan_id,
                    scan_ids=all_scan_ids if len(all_scan_ids) > 1 else None,
                    scan_names=(
                        [s.scan_name for s in selected_scans]
                        if len(selected_scans) > 1
                        else None
                    ),
                )

                # Host filter state (persists across severity loop iterations)
                host_filter: Optional[str] = None  # Active host filter (IP/hostname)
                host_filter_plugin_ids: Optional[list[int]] = (
                    None  # Cached plugin IDs for filter
                )

                # Claude availability (computed once per scan selection)
                from cerno_pkg.claude_assistant import (
                    check_claude_available as _check_claude,
                )
                from cerno_pkg.claude_assistant import claude_enabled as _claude_enabled

                _claude_installed_sev = _check_claude()
                _has_claude_sev = _claude_enabled(config)

                # Build multi-scan display label for breadcrumb/header
                if len(selected_scans) > 1:
                    _label_names = [s.scan_name for s in selected_scans]
                    if len(_label_names) == 2:
                        _scan_label = f"{_label_names[0]} + {_label_names[1]}"
                    else:
                        _scan_label = f"{len(_label_names)} scans"
                else:
                    _scan_label = scan_dir.name

                # Severity loop (inner loop)
                while True:
                    from cerno_pkg import breadcrumb

                    bc = breadcrumb(_scan_label, "Choose severity")
                    header(bc if bc else f"Scan: {_scan_label} — choose severity")

                    # Get severity directories from database (database-only mode)
                    # Apply host filter if active
                    severity_dir_names = Finding.get_severity_dirs_for_scan(
                        scan_id,
                        plugin_ids=host_filter_plugin_ids,
                        scan_ids=all_scan_ids if len(all_scan_ids) > 1 else None,
                    )
                    if not severity_dir_names:
                        warn("No severity directories in this scan.")
                        break

                    # Create virtual Path objects for compatibility with existing render code
                    # Database returns pre-sorted (DESC), so no additional sorting needed
                    severities = [
                        scan_dir / sev_name for sev_name in severity_dir_names
                    ]

                    # Metasploit Module virtual group (menu counts) - query from database
                    # Apply host filter if active
                    if len(all_scan_ids) > 1:
                        msf_files, _ = Finding.get_by_scan_ids_merged(
                            scan_ids=all_scan_ids,
                            has_metasploit=True,
                            plugin_ids=host_filter_plugin_ids,
                        )
                    else:
                        msf_files = Finding.get_by_scan_with_plugin(
                            scan_id=scan_id,
                            has_metasploit=True,
                            plugin_ids=host_filter_plugin_ids,
                        )

                    has_msf = len(msf_files) > 0
                    msf_summary = (
                        count_review_states(pf for (pf, _p) in msf_files)
                        if has_msf
                        else None
                    )

                    # Workflow Mapped virtual group (menu counts) - query from database
                    # Apply host filter if active (intersect workflow plugins with host filter)
                    workflow_plugin_ids = workflow_mapper.get_all_plugin_ids()
                    if workflow_plugin_ids:
                        workflow_plugin_ids_int = [
                            int(pid) for pid in workflow_plugin_ids if pid.isdigit()
                        ]
                        # If host filter is active, intersect with host filter plugin IDs
                        if host_filter_plugin_ids is not None:
                            workflow_plugin_ids_int = [
                                pid
                                for pid in workflow_plugin_ids_int
                                if pid in host_filter_plugin_ids
                            ]
                        if workflow_plugin_ids_int:
                            if len(all_scan_ids) > 1:
                                workflow_files, _ = Finding.get_by_scan_ids_merged(
                                    scan_ids=all_scan_ids,
                                    plugin_ids=workflow_plugin_ids_int,
                                )
                            else:
                                workflow_files = Finding.get_by_scan_with_plugin(
                                    scan_id=scan_id, plugin_ids=workflow_plugin_ids_int
                                )
                        else:
                            workflow_files = []
                    else:
                        workflow_files = []

                    has_workflows = len(workflow_files) > 0
                    workflow_summary = (
                        count_review_states(pf for (pf, _p) in workflow_files)
                        if has_workflows
                        else None
                    )

                    render_severity_table(
                        severities,
                        msf_summary=msf_summary,
                        workflow_summary=workflow_summary,
                        scan_id=scan_id,
                        plugin_ids=host_filter_plugin_ids,
                        scan_ids=all_scan_ids if len(all_scan_ids) > 1 else None,
                    )

                    # Show host filter status if active
                    if host_filter:
                        info(f"Filtering by host: {host_filter}")

                    # Show action menu with appropriate options
                    _sev_menu_items: list[tuple[str, str]] = [("H", "Host search")]
                    if host_filter:
                        _sev_menu_items.append(("C", "Clear filter"))
                    if _has_claude_sev:
                        _sev_menu_items.append(("A", "Ask Claude"))
                    elif _claude_installed_sev:
                        _sev_menu_items.append(("A", "Ask Claude (enable…)"))
                    _sev_menu_items.append(("B", "Back"))
                    print_action_menu(_sev_menu_items)

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

                        # Query plugin IDs for this host across all selected scans
                        plugin_ids = Host.get_plugin_ids_for_scan(
                            ip_address=host_input,
                            scan_id=scan_id,
                            partial_match=True,
                            scan_ids=all_scan_ids if len(all_scan_ids) > 1 else None,
                        )

                        if not plugin_ids:
                            warn(f"No findings found for host: {host_input}")
                            continue

                        # Set filter state
                        host_filter = host_input
                        host_filter_plugin_ids = plugin_ids
                        ok(
                            f"Found {len(plugin_ids)} finding(s) for host '{host_input}'"
                        )
                        continue

                    elif ans in ("c", "clear") and host_filter:
                        # Clear host filter
                        host_filter = None
                        host_filter_plugin_ids = None
                        ok("Host filter cleared.")
                        continue

                    elif ans == "a":
                        if not _has_claude_sev and _claude_installed_sev:
                            from cerno_pkg.claude_assistant import ensure_enabled

                            if ensure_enabled(config):
                                _has_claude_sev = True
                        if _has_claude_sev:
                            # Build aggregate context from all findings in the current scan scope
                            _sev_scan_names = [s.scan_name for s in selected_scans]
                            _sev_scope = "All findings — " + ", ".join(_sev_scan_names)
                            if host_filter:
                                _sev_scope += f" (host filter: {host_filter})"
                            _sev_scan_ids_str = ",".join(
                                str(sid) for sid in sorted(all_scan_ids)
                            )
                            _host_suffix = f":{host_filter}" if host_filter else ""
                            _sev_context_key = (
                                f"sev_menu:{_sev_scan_ids_str}{_host_suffix}"
                            )
                            # Fetch all findings for context (no severity filter)
                            if len(all_scan_ids) > 1:
                                _sev_findings, _ = Finding.get_by_scan_ids_merged(
                                    scan_ids=all_scan_ids,
                                    plugin_ids=host_filter_plugin_ids,
                                )
                            else:
                                _sev_findings = Finding.get_by_scan_with_plugin(
                                    scan_id=scan_id,
                                    plugin_ids=host_filter_plugin_ids,
                                )
                            browse_claude_chat_aggregate(
                                context_key=_sev_context_key,
                                scope_description=_sev_scope,
                                scan_names=_sev_scan_names,
                                findings_with_plugins=_sev_findings,
                            )
                        elif not _claude_installed_sev:
                            warn(
                                "Claude Assistant is not available. Install the claude CLI to use this feature."
                            )
                        continue

                    # Parse selection (supports ranges, comma-separated, and M/W letters)
                    selection = parse_severity_selection(ans, len(severities))

                    if selection is None:
                        warn(
                            "Invalid choice. Use numbers (1-5), M, W, or combine (e.g., 1-3,M)."
                        )
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
                    if len(severity_indices) > 1 or (
                        len(severity_indices) >= 1 and msf_in_selection
                    ):
                        selected_sev_dirs = [
                            severities[idx - 1] for idx in severity_indices
                        ]

                        # Build combined label
                        sev_labels = [
                            pretty_severity_label(sev.name) for sev in selected_sev_dirs
                        ]
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
                            selected_scans,
                            selected_sev_dirs[0] if selected_sev_dirs else None,
                            None,  # Single severity filter not used for multi-severity
                            label,
                            args,
                            use_sudo,
                            in_progress_total,
                            done_total,
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
                            selected_scans,
                            sev_dir,
                            severity_dir_filter,
                            label,
                            args,
                            use_sudo,
                            in_progress_total,
                            done_total,
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
                            selected_scans,
                            None,  # No single severity dir
                            None,  # No severity filter
                            label,
                            args,
                            use_sudo,
                            in_progress_total,
                            done_total,
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
                        workflow_groups = group_findings_by_workflow(
                            workflow_files, workflow_mapper
                        )

                        browse_workflow_groups(
                            selected_scan,
                            workflow_groups,
                            args,
                            use_sudo,
                            in_progress_total,
                            done_total,
                            workflow_mapper,
                            config=config,
                            session_start_time=session_start_time,
                            scan_label=_scan_label,
                            scans=selected_scans,
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
                    in_progress_count=len(in_progress_total),
                    done_count=len(done_total),
                    additional_scan_ids=_additional_scan_ids(selected_scans),
                )

                # Session summary with rich statistics (only if work was done)
                if in_progress_total or done_total:
                    # Type guard: scan_dir must be defined if any work was done
                    if scan_dir is not None:
                        show_session_statistics(
                            session_start_time,
                            in_progress_total,
                            done_total,
                            scan_dir,
                            scan_id=scan_id,
                            scan_ids=all_scan_ids if len(all_scan_ids) > 1 else None,
                        )

                # Always end session (mark session_end timestamp in database)
                delete_session(scan_id)

    _console_global.print()  # Empty line
    ok('Now run "cerno review" to start reviewing findings.')


# === Typer CLI ===
# Main app + sub-apps (import, scan, config, workflow, creds)

app = typer.Typer(
    help="cerno — faster review & tooling runner for vulnerability scans",
    add_completion=True,
)
_console = _console_global

# Sub-applications
import_app = typer.Typer(help="Import data from various sources into cerno")

scan_app = typer.Typer(
    help="Scan management - list, delete and compare scans, and show host history"
)

config_app = typer.Typer(help="Configuration management - view and modify settings")

workflow_app = typer.Typer(help="Workflow management - list available workflows")

creds_app = typer.Typer(
    help="NetExec credential inspection - list refs and reveal cleartext (local)"
)

# Register sub-apps with main app
app.add_typer(import_app, name="import")
app.add_typer(scan_app, name="scan")
app.add_typer(config_app, name="config")
app.add_typer(workflow_app, name="workflow")
app.add_typer(creds_app, name="creds")


def _repo_root() -> Path:
    """Return the Cerno repository root for this checkout."""
    start = Path(__file__).resolve().parent
    for candidate in (start, *start.parents):
        if (
            (candidate / "pyproject.toml").is_file()
            and (candidate / "cerno.py").is_file()
            and (candidate / "cerno_pkg").is_dir()
        ):
            return candidate

    return start


def _demo_assets_dir() -> Path:
    """Return the repository demo assets directory."""
    assets_dir = _repo_root() / "docs" / "demo"
    if assets_dir.exists():
        return assets_dir

    from importlib import resources

    package_assets = resources.files("cerno_pkg").joinpath("demo")
    package_assets_path = Path(str(package_assets))
    if package_assets.is_dir() and package_assets_path.exists():
        return package_assets_path

    raise FileNotFoundError(
        "Demo assets were not found. Expected docs/demo under the Cerno repository "
        "root or packaged assets under cerno_pkg/demo."
    )


def _import_demo_nessus(nessus_file: Path, overwrite: bool = False) -> tuple[str, bool]:
    """Import a bundled demo Nessus file without post-import tool suggestions."""
    from cerno_pkg.constants import SCANS_ROOT
    from cerno_pkg.database import compute_file_hash
    from cerno_pkg.models import Scan
    from cerno_pkg.nessus_import import (
        extract_scan_name_from_nessus,
        import_nessus_file,
    )

    scan_name = extract_scan_name_from_nessus(nessus_file)
    out_dir = SCANS_ROOT / scan_name
    new_file_hash = compute_file_hash(nessus_file)
    existing_scan = Scan.get_by_name(scan_name)

    if existing_scan:
        if existing_scan.nessus_file_hash == new_file_hash:
            info(f"Scan already imported: {scan_name}")
            return scan_name, False
        if not overwrite:
            warn(f"Scan exists with different content, skipping: {scan_name}")
            warn("Use `cerno demo --overwrite` to replace demo scans.")
            return scan_name, False

        if not Scan.delete_by_name(scan_name):
            raise RuntimeError(f"Failed to replace existing scan: {scan_name}")
        info(f"Replaced existing scan: {scan_name}")

    out_dir.mkdir(parents=True, exist_ok=True)
    result = import_nessus_file(
        nessus_file=nessus_file,
        output_dir=out_dir,
        scan_name=scan_name,
        include_ports=True,
    )
    ok(f"Imported {scan_name}: {result.plugins_exported} findings")
    return scan_name, True


@app.command(name="mcp")
def mcp_cmd() -> None:
    """Serve Cerno's scan database and tooling over the Model Context Protocol.

    Communicates over stdio (stdin/stdout), so this command is meant to be
    launched by an MCP client rather than run directly in a terminal. Register
    it with a client, e.g.:

        claude mcp add cerno -- cerno mcp

    Read and command-generation tools are always available. Gated tools are
    exposed only when enabled in config:

        cerno config set mcp_allow_execution true
        cerno config set mcp_allow_mutations true
        cerno config set mcp_allow_batch true
        cerno config set mcp_allow_cred_injection true
        cerno config set mcp_allow_cred_reveal true

    Execution unlocks execute_command and background jobs; mutations unlock
    review state, notes, verdicts, ingest and import; batch (which also needs
    execution) unlocks execute_batch; cred_injection resolves @cred:<ref>@
    placeholders at run time; cred_reveal unlocks reveal_credential (cleartext).

    execute_command only runs binaries matching mcp_exec_allowlist ("*" for any)
    and never runs binaries matching mcp_exec_denylist (the denylist always wins).
    See docs/MCP.md for the full tool reference.

    Gating flags are read once at startup. After changing them, reconnect or
    restart the server (e.g. via your MCP client) for the change to take effect.
    The active gating state is logged to the Cerno log on startup.
    """
    from cerno_pkg.mcp_server import main as mcp_main

    mcp_main()


@app.command(name="demo", help="Prepare bundled demo scans and NetExec enrichment")
def demo_cmd(
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Replace existing demo scans if their source files changed.",
    ),
    no_nxc: bool = typer.Option(
        False,
        "--no-nxc",
        help="Import demo scans without configuring the bundled NetExec workspace.",
    ),
) -> None:
    """Prepare Cerno demo data.

    Imports the bundled initial and expanded Nessus scans, and by default points
    `nxc_workspace_path` at the bundled synthetic NetExec workspace.
    """
    from cerno_pkg import load_config, save_config, get_config_path
    from cerno_pkg.nxc_db import reset_nxc_manager

    try:
        assets_dir = _demo_assets_dir()
    except FileNotFoundError as exc:
        err(str(exc))
        raise typer.Exit(1)

    initial_scan = assets_dir / "cerno-demo-initial.nessus"
    expanded_scan = assets_dir / "cerno-demo-expanded.nessus"
    nxc_workspace = assets_dir / "nxc-workspace"

    missing = [path for path in (initial_scan, expanded_scan) if not path.exists()]
    if not no_nxc and not nxc_workspace.exists():
        missing.append(nxc_workspace)

    if missing:
        err("Missing demo asset(s):")
        for path in missing:
            err(f"  {path}")
        raise typer.Exit(1)

    header("Preparing Cerno Demo Data")

    if not no_nxc:
        config = load_config()
        config.nxc_workspace_path = str(nxc_workspace.resolve())
        config.nxc_enrichment_enabled = True
        if not save_config(config):
            err("Failed to save demo NetExec configuration.")
            raise typer.Exit(1)
        reset_nxc_manager()
        ok(f"Configured NetExec workspace: {nxc_workspace.resolve()}")
        info(f"Config saved to {get_config_path()}")
    else:
        info("Skipping NetExec workspace configuration.")

    _console_global.print()
    imported = 0
    for nessus_file in (initial_scan, expanded_scan):
        _, did_import = _import_demo_nessus(nessus_file, overwrite=overwrite)
        if did_import:
            imported += 1

    _console_global.print()
    ok(f"Demo setup complete: {imported} scan(s) imported or updated.")
    info("Next commands:")
    info("  cerno scan list")
    info("  cerno scan compare Cerno_Demo_Initial_Scan Cerno_Demo_Expanded_Scan")
    info("  cerno review")
    if not no_nxc:
        info(
            "Open an SMB/SSH/FTP/VNC/LDAP/RDP finding and press [N] for NetExec context."
        )


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
    from cerno_pkg.database import SchemaVersionError, initialize_database

    config = load_config()

    # Initialize systems with config
    init_logger(config)
    initialize_colors(config)

    # Initialize database AFTER logger is ready (prevents logging bleed during import)
    try:
        initialize_database()
    except SchemaVersionError as e:
        # stderr: `cerno mcp` reserves stdout for JSON-RPC
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

    # Store config in context for access by commands
    _config_context.set(config)


@app.command(help="Interactive review of findings.")
def review(
    export_root: Optional[Path] = typer.Option(
        None,
        "--export-root",
        "-r",
        help="DEPRECATED and ignored: prints a reminder to use 'cerno import' and exits.",
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
    proxy: bool = typer.Option(
        False,
        "--proxy",
        help="Force-enable proxy routing via proxychains4 for this session (overrides config).",
    ),
    no_proxy: bool = typer.Option(
        False,
        "--no-proxy",
        help="Force-disable proxychains4 routing for this session (overrides config).",
    ),
) -> None:
    """
    Run interactive review mode with database-driven workflow.

    This command requires scans to be imported into the database first.
    Use 'cerno import' to import scans before reviewing.

    Note: The --export-root flag is deprecated and ignored: passing it skips
    the review and only prints a reminder to run 'cerno review'.

    Usage:
        cerno review                     # Select from imported scans
        cerno import nessus scan.nessus  # Import a scan first if needed
    """
    # Display promotional banner (unless suppressed)
    if not quiet:
        display_banner()
        _console_global.print()  # Add spacing after banner

    # Validate: can't use both flags
    if custom_workflows and custom_workflows_only:
        err("Cannot use both --custom-workflows and --custom-workflows-only")
        raise typer.Exit(1)

    if proxy and no_proxy:
        err("Cannot use both --proxy and --no-proxy")
        raise typer.Exit(1)

    args = types.SimpleNamespace(
        export_root=export_root,
        no_tools=no_tools,
        custom_workflows=custom_workflows,
        custom_workflows_only=custom_workflows_only,
        check=check,
        proxy=proxy,
        no_proxy=no_proxy,
    )
    try:
        main(args)
    except KeyboardInterrupt:
        warn("\nInterrupted — goodbye.")


def _show_nuclei_suggestion(scan_name: str) -> None:
    """Generate nuclei command suggestion from discovered HTTP services.

    Queries host_services table for HTTP/HTTPS services, writes URLs to a file,
    and displays a nuclei command suggestion.

    Args:
        scan_name: Name of the scan to query
    """
    try:
        from cerno_pkg.models import Scan, get_http_urls_for_scan
        from cerno_pkg.constants import SCANS_ROOT

        scan = Scan.get_by_name(scan_name)
        if not scan or scan.scan_id is None:
            return

        urls = get_http_urls_for_scan(scan.scan_id)

        if not urls:
            return  # No HTTP services discovered — skip silently

        # Write URLs to file
        urls_dir = SCANS_ROOT / scan_name
        urls_dir.mkdir(parents=True, exist_ok=True)
        urls_file = urls_dir / "http_urls.txt"
        urls_file.write_text("\n".join(urls) + "\n")

        # Display suggestion
        info(
            fmt_action(
                "3. nuclei (vulnerability scanner | https://github.com/projectdiscovery/nuclei):"
            )
        )
        info(
            f"   Found {len(urls)} HTTP/HTTPS services available — the URL(s) have been written to {urls_file}"
        )
        nuclei_cmd = f"nuclei -l {urls_file} -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0' -ts -mhe 500 -c 32 -stats -si 300 -o ~/nuclei_results.txt -je ~/nuclei_results.json -elog ~/nuclei_errors.txt -me ~/"
        info(f"   {nuclei_cmd}\n")

    except Exception:
        pass  # Non-fatal — don't break import flow


def show_nessus_tool_suggestions(nessus_file: Path, scan_name: str) -> None:
    """
    Display suggested tool commands after an import completes.

    Args:
        nessus_file: Path to the original .nessus file
        scan_name: Name of the imported scan (for DB queries)
    """
    header("Suggested Tool Commands")
    info("\nTry running these other tools too:\n")

    # eyewitness command
    info(
        fmt_action(
            "1. eyewitness (screenshot and report tool | https://github.com/RedSiege/EyeWitness):"
        )
    )
    eyewitness_cmd = f'python ~/EyeWitness/Python/EyeWitness.py -x {nessus_file} -d ~/eyewitness_report --results 500 --user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0" --timeout 30'
    info(f"   {eyewitness_cmd}\n")

    # gowitness command
    info(
        fmt_action(
            "2. gowitness (screenshot and report tool | https://github.com/sensepost/gowitness):"
        )
    )
    gowitness_cmd = f'gowitness scan nessus -f {nessus_file} --chrome-user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" --write-db -t 20'
    info(f"   {gowitness_cmd}\n")

    # nuclei command (from database service data)
    _show_nuclei_suggestion(scan_name)

    info("Tip: Copy these commands to run them in your terminal.\n")


# === Import Sub-App Commands ===
# Grouped under 'cerno import'


@import_app.command(
    name="nessus",
    help="Import .nessus file (or directory of .nessus files) and populate database with findings",
)
def import_scan(
    nessus: Path = typer.Argument(
        ..., help="Path to a .nessus file or directory containing .nessus files"
    ),
) -> None:
    """
    Import .nessus file(s) into the database.

    Accepts a single .nessus file or a directory. When given a directory, recursively
    discovers all .nessus files, lists them for confirmation, then imports each in sequence.
    The scan name is taken from the .nessus report name. No per-plugin files are
    written; ~/.cerno/scans/<scan_name>/ only receives http_urls.txt when web
    services are found.
    """
    if not nessus.exists():
        err(f"Path does not exist: {nessus}")
        raise typer.Exit(1)

    if nessus.is_dir():
        _import_nessus_directory(nessus)
    elif nessus.is_file():
        if nessus.suffix.lower() != ".nessus":
            err(f"File does not have .nessus extension: {nessus.name}")
            raise typer.Exit(1)
        _import_single_nessus(nessus)
    else:
        err(f"Path is not a file or directory: {nessus}")
        raise typer.Exit(1)


def _import_single_nessus(nessus: Path) -> bool:
    """Import a single .nessus file. Returns True on success, False on skip/cancel."""
    from cerno_pkg.nessus_import import (
        import_nessus_file,
        extract_scan_name_from_nessus,
    )
    from cerno_pkg.constants import SCANS_ROOT

    # Always extract scan name from .nessus file for consistency with database
    scan_name = extract_scan_name_from_nessus(nessus)

    # Determine output directory (always use SCANS_ROOT/<scan_name>)
    out_dir = SCANS_ROOT / scan_name
    info(f"Using scan name: {scan_name}")

    # Check for duplicate imports
    from cerno_pkg.database import compute_file_hash
    from cerno_pkg.models import Scan

    new_file_hash = compute_file_hash(nessus)
    existing_scan = Scan.get_by_name(scan_name)

    if existing_scan:
        # Check if it's the identical file
        if existing_scan.nessus_file_hash == new_file_hash:
            ok(f"Scan '{scan_name}' already imported (identical file). Skipping.")
            return False

        # Different file, same name - prompt user
        warn(f"A scan named '{scan_name}' already exists.")
        if existing_scan.created_at:
            warn(f"Existing: imported on {existing_scan.created_at}")
        warn(f"New file: {nessus.name}")
        _console_global.print()

        choices = [
            "1. Overwrite existing scan",
            "2. Import with new name (add suffix)",
            "3. Cancel import",
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
            return False

    # Run import
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
                include_ports=True,
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

            sev_table = Table(
                show_header=True,
                header_style=style_if_enabled("bold cyan"),
                box=box.SIMPLE,
            )
            sev_table.add_column("Severity", style=style_if_enabled("cyan"))
            sev_table.add_column(
                "Plugins", justify="right", style=style_if_enabled("yellow")
            )

            # Sort by severity (highest first: 4->0)
            for sev_int in sorted(result.severities.keys(), reverse=True):
                count = result.severities[sev_int]
                if count > 0:  # Only show non-zero severities
                    sev_label = severity_label_from_int(sev_int)
                    sev_table.add_row(severity_cell(sev_label), str(count))

            _console_global.print(sev_table)

    except Exception as e:
        err(f"Import failed: {e}")
        return False

    # Show suggested tool commands
    _console_global.print()  # Blank line for spacing
    show_nessus_tool_suggestions(nessus, scan_name)
    return True


def _import_nessus_directory(directory: Path) -> None:
    """Discover and import all .nessus files under a directory."""
    from rich.table import Table
    from rich import box
    from cerno_pkg.ansi import style_if_enabled

    files = sorted(directory.rglob("*.nessus"))
    if not files:
        err(f"No .nessus files found in: {directory}")
        raise typer.Exit(1)

    n = len(files)
    _console_global.print()
    header(f"Found {n} .nessus file{'s' if n != 1 else ''} in {directory}")

    stage_table = Table(
        show_header=True, header_style=style_if_enabled("bold cyan"), box=box.SIMPLE
    )
    stage_table.add_column("#", justify="right", style=style_if_enabled("cyan"))
    stage_table.add_column("File", style=style_if_enabled("white"))
    stage_table.add_column("Size", justify="right", style=style_if_enabled("yellow"))

    for i, f in enumerate(files, 1):
        size_bytes = f.stat().st_size
        if size_bytes >= 1_048_576:
            size_str = f"{size_bytes / 1_048_576:.1f} MB"
        elif size_bytes >= 1_024:
            size_str = f"{size_bytes / 1_024:.1f} KB"
        else:
            size_str = f"{size_bytes} B"
        stage_table.add_row(str(i), str(f.relative_to(directory)), size_str)

    _console_global.print(stage_table)
    _console_global.print()

    if not Confirm.ask(
        f"Import all {n} file{'s' if n != 1 else ''} above?", default=True
    ):
        info("Import cancelled.")
        raise typer.Exit(0)

    _console_global.print()
    imported = 0
    skipped = 0
    for i, f in enumerate(files, 1):
        _console_global.rule(f"[cyan][{i}/{n}] {safe_text(f.name)}[/cyan]")
        success = _import_single_nessus(f)
        if success:
            imported += 1
        else:
            skipped += 1
        _console_global.print()

    _console_global.rule("[bold cyan]Import Complete[/bold cyan]")
    ok(f"Summary: {imported} imported, {skipped} skipped")


# === Scan Sub-App Commands ===
# Grouped under 'cerno scan'


@scan_app.command(
    name="list", help="List all imported scans with statistics and review progress"
)
def list_scans(
    wide: bool = typer.Option(
        False, "--wide", "--details", help="Show the full per-severity breakdown"
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output scan data as JSON (for scripting)"
    ),
) -> None:
    """Display all scans in the database with finding counts and severity breakdown.

    The default view is compact (readable at 80 columns). Use --wide for every
    severity column, or --json for machine-readable output.
    """
    from cerno_pkg.models import Scan
    from rich.table import Table

    scans = Scan.get_all_with_stats()

    # --json: emit the raw rows and stop (scriptable, no Rich formatting).
    if json_output:
        import json

        print(json.dumps(scans, indent=2, default=str))
        return

    if not scans:
        info("No scans found in database.")
        info("Tip: Use 'cerno import nessus <scan.nessus>' to import a scan")
        return

    from cerno_pkg.ansi import style_if_enabled

    def _fmt_last_reviewed(value: object) -> str:
        if not value:
            return "Never"
        try:
            from datetime import datetime

            return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d")
        except Exception:
            return str(value)

    def _done_pct(scan: dict) -> str:
        total = scan["total_findings"] or 0
        if not total:
            return "0%"
        return f"{round((scan['done_count'] or 0) / total * 100)}%"

    table = Table(
        title="Imported Scans",
        show_header=True,
        header_style=style_if_enabled("bold cyan"),
    )

    if wide:
        table.add_column("Scan Name", style=style_if_enabled("yellow"), no_wrap=True)
        table.add_column(
            "Total Unique Hosts", justify="right", style=style_if_enabled("bright_cyan")
        )
        table.add_column("Total Findings", justify="right")
        table.add_column("Critical", justify="right", style=style_if_enabled("red"))
        table.add_column("High", justify="right", style=style_if_enabled("bright_red"))
        table.add_column("Medium", justify="right", style=style_if_enabled("yellow"))
        table.add_column("Low", justify="right", style=style_if_enabled("cyan"))
        table.add_column("Info", justify="right", style=style_if_enabled("dim"))
        table.add_column("Done", justify="right", style=style_if_enabled("green"))
        table.add_column("Last Reviewed", style=style_if_enabled("dim"))
        for scan in scans:
            table.add_row(
                scan["scan_name"],
                str(scan["unique_hosts"] or 0),
                str(scan["total_findings"] or 0),
                str(scan["critical_count"] or 0),
                str(scan["high_count"] or 0),
                str(scan["medium_count"] or 0),
                str(scan["low_count"] or 0),
                str(scan["info_count"] or 0),
                str(scan["done_count"] or 0),
                _fmt_last_reviewed(scan["last_reviewed_at"]),
            )
    else:
        table.add_column("Scan Name", style=style_if_enabled("yellow"), no_wrap=True)
        table.add_column(
            "Hosts", justify="right", style=style_if_enabled("bright_cyan")
        )
        table.add_column("Findings", justify="right")
        table.add_column("Crit", justify="right", style=style_if_enabled("red"))
        table.add_column("High", justify="right", style=style_if_enabled("bright_red"))
        table.add_column("Done %", justify="right", style=style_if_enabled("green"))
        table.add_column("Last Reviewed", style=style_if_enabled("dim"))
        for scan in scans:
            table.add_row(
                scan["scan_name"],
                str(scan["unique_hosts"] or 0),
                str(scan["total_findings"] or 0),
                str(scan["critical_count"] or 0),
                str(scan["high_count"] or 0),
                _done_pct(scan),
                _fmt_last_reviewed(scan["last_reviewed_at"]),
            )

    _console_global.print(table)
    _console_global.print()  # Blank line
    info(f"Total scans: {len(scans)}")
    if not wide:
        info("Tip: --wide shows all severities; --json outputs machine-readable data")
    info("Use 'cerno review' to start reviewing a scan")


@scan_app.command(name="delete", help="Delete a scan and its review data from database")
def delete_scan(
    scan_name: str = typer.Argument(..., help="Name of scan to delete")
) -> None:
    """Delete a scan and its review data from the database.

    This will permanently remove (via ON DELETE CASCADE):
    - The scan entry
    - All findings for this scan and their host:port data
    - Discovered services for this scan
    - Review sessions that include this scan
    - Verification verdicts and their evidence
    - Per-finding Claude Assistant chat history

    Tool execution and artifact records (and the verified ports / NSE results /
    NetExec flags ingested from them) are retained for audit/history, but their
    links to deleted findings or sessions are cleared.

    This action cannot be undone!
    """
    from cerno_pkg.models import Scan

    # Check if scan exists
    scan = Scan.get_by_name(scan_name)
    if not scan:
        err(f"Scan not found: {scan_name}")
        info("Use 'cerno scan list' to see available scans")
        raise typer.Exit(1)

    # Confirm deletion
    warn(f"You are about to delete scan: {scan_name}")
    warn("This will permanently delete scan review data:")
    warn("  - Findings and their host:port combinations")
    warn("  - Discovered services")
    warn("  - Review sessions")
    warn("  - Verification verdicts and evidence")
    warn("  - Per-finding Claude Assistant chat history")
    info(
        "Tool executions, artifacts and their ingested results are retained, "
        "but links to this scan's findings/sessions are cleared."
    )
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


@scan_app.command(
    name="compare",
    help="Compare findings between two scans to identify new, resolved, and persistent vulnerabilities",
)
def compare_scans_cmd(
    scan1: str = typer.Argument(..., help="First scan name (baseline)"),
    scan2: str = typer.Argument(..., help="Second scan name (comparison)"),
    severity: int = typer.Option(
        0,
        "--severity",
        "-s",
        help="Minimum severity level (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)",
    ),
) -> None:
    """Compare findings between two scans.

    Shows which vulnerabilities are new, resolved, or persistent between
    the baseline scan (scan1) and the comparison scan (scan2).

    Also shows host changes: new hosts, removed hosts, and persistent hosts.

    Examples:
        cerno scan compare "Q1-2024" "Q2-2024"
        cerno scan compare "Baseline" "Current" --severity 3
    """
    from cerno_pkg.cross_scan import compare_scans, get_scan_by_name
    from cerno_pkg.render import render_scan_comparison

    # Validate severity
    if severity < 0 or severity > 4:
        err(f"Invalid severity level: {severity}. Must be 0-4.")
        raise typer.Exit(1)

    # Look up scans by name
    scan1_data = get_scan_by_name(scan1)
    if not scan1_data:
        err(f"Scan not found: {scan1}")
        info("Use 'cerno scan list' to see available scans")
        raise typer.Exit(1)

    scan2_data = get_scan_by_name(scan2)
    if not scan2_data:
        err(f"Scan not found: {scan2}")
        info("Use 'cerno scan list' to see available scans")
        raise typer.Exit(1)

    # Check if comparing same scan
    if scan1_data["scan_id"] == scan2_data["scan_id"]:
        warn("Comparing a scan with itself - all findings will be persistent")

    # Perform comparison
    result = compare_scans(
        scan_id_1=scan1_data["scan_id"],
        scan_id_2=scan2_data["scan_id"],
        min_severity=severity,
    )

    if not result:
        err("Failed to compare scans")
        raise typer.Exit(1)

    # Render results
    render_scan_comparison(result)


@scan_app.command(
    name="history",
    help="Show vulnerability history for a specific host across all scans",
)
def host_history_cmd(
    host_ip: str = typer.Argument(..., help="Host IP address to query"),
) -> None:
    """Show vulnerability history for a specific host.

    Displays a timeline of all scans where this host appeared,
    showing how its vulnerability profile has changed over time.

    Examples:
        cerno scan history 192.168.1.10
        cerno scan history 10.0.0.5
    """
    from cerno_pkg.cross_scan import get_host_vulnerability_history
    from cerno_pkg.render import render_host_history

    # Get host history
    history = get_host_vulnerability_history(host_ip)

    if not history:
        err(f"No history found for host: {host_ip}")
        info("This host may not exist in any imported scans")
        raise typer.Exit(1)

    # Render history
    render_host_history(history)


# === Config Sub-App Commands ===
# Grouped under 'cerno config'


@config_app.command(
    name="reset", help="Reset all settings, or a single KEY, to defaults"
)
def config_reset(
    key: Optional[str] = typer.Argument(
        None, help="Config key to reset (omit to reset the whole file)"
    ),
) -> None:
    """Reset ~/.cerno/config.yaml (or just one key) to defaults."""
    from cerno_pkg import create_example_config, get_config_path
    import shutil

    if key is not None:
        from cerno_pkg import load_config, save_config
        from cerno_pkg.config import config_key_names, reset_config_key

        config = load_config()
        try:
            value = reset_config_key(config, key)
        except KeyError:
            err(f"Unknown config key: {key}")
            info("Available keys: " + ", ".join(config_key_names()))
            raise typer.Exit(1)

        if not save_config(config):
            err("Failed to save config")
            info(f"Check permissions on {get_config_path().parent}")
            raise typer.Exit(1)
        shown = "unset" if value is None else value
        ok(f"Reset {key} to default ({shown})")
        return

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
        info(f"Check permissions on {config_path.parent}")
        raise typer.Exit(1)


@config_app.command(
    name="show", help="Display current configuration with all settings and paths"
)
def config_show() -> None:
    """Display current configuration (merged from file and defaults)."""
    from cerno_pkg import load_config, get_config_path
    from cerno_pkg.config import build_config_rows
    from rich.table import Table
    from rich.text import Text

    config_path = get_config_path()
    config = load_config()

    header("Current Configuration")
    info(f"Config file: {config_path}")
    _console_global.print()

    # Rows are derived entirely from the CernoConfig dataclass fields (single
    # source of truth), grouped into sections in field (display) order.
    rows = build_config_rows(config)

    # Build the grouped table. The marker column flags settings changed from
    # their default with a ▶; changed rows are emphasized, defaults dimmed.
    table = Table(
        title="Configuration Values",
        show_header=True,
        header_style=style_if_enabled("bold cyan"),
    )
    table.add_column("", width=1, no_wrap=True)  # change marker
    table.add_column("Setting", no_wrap=True)
    table.add_column(
        "Value", overflow="fold"
    )  # fold (wrap) instead of truncating paths
    table.add_column("Description", style=style_if_enabled("dim white"))
    table.add_column("Status")

    changed_total = 0
    current_section = None
    first_section = True
    for section, key, value_str, is_default, description in rows:
        if section != current_section:
            if not first_section:
                table.add_section()
            first_section = False
            current_section = section
            table.add_row(
                "", Text(section, style=style_if_enabled("bold cyan")), "", "", ""
            )
        if is_default:
            table.add_row(
                "",
                Text(key, style=style_if_enabled("dim cyan")),
                Text(value_str, style=style_if_enabled("dim")),
                description,
                Text("default", style=style_if_enabled("dim")),
            )
        else:
            changed_total += 1
            table.add_row(
                Text("▶", style=style_if_enabled("bold yellow")),
                Text(key, style=style_if_enabled("cyan")),
                Text(value_str, style=style_if_enabled("bold yellow")),
                description,
                Text("changed", style=style_if_enabled("bold yellow")),
            )

    _console.print(table)
    _console_global.print()
    if changed_total:
        info(f"{changed_total} setting(s) changed from default (marked ▶).")
    else:
        info("All settings are at their defaults.")
    info(f"Edit config: {config_path}")
    info("Change values: cerno config set <key> <value>")
    info("Reset one setting: cerno config reset <key>")
    info("Reset to defaults: cerno config reset")


@config_app.command(name="get", help="Retrieve value of a specific configuration key")
def config_get(key: str = typer.Argument(..., help="Config key to retrieve")) -> None:
    """Get and display a specific configuration value."""
    from cerno_pkg import load_config
    from cerno_pkg.config import config_key_names

    config = load_config()

    # Map key to config attribute
    if not hasattr(config, key):
        err(f"Unknown config key: {key}")
        info("Available keys: " + ", ".join(config_key_names()))
        raise typer.Exit(1)

    value = getattr(config, key)
    if value is None:
        info(f"{key} is not set (using default)")
    else:
        _console_global.print(value)


@config_app.command(name="set", help="Update value of a specific configuration key")
def config_set(
    key: str = typer.Argument(..., help="Config key to set"),
    value: str = typer.Argument(..., help="Value to set"),
) -> None:
    """Set a configuration value in ~/.cerno/config.yaml."""
    from cerno_pkg import load_config, save_config, get_config_path
    from cerno_pkg.config import (
        coerce_str_list,
        config_field_choices,
        config_field_kind,
        config_key_names,
    )

    config = load_config()

    # Validate key
    if not hasattr(config, key):
        err(f"Unknown config key: {key}")
        info("Available keys: " + ", ".join(config_key_names()))
        raise typer.Exit(1)

    choices = config_field_choices(key)
    if choices and value not in choices:
        err(f"Invalid value for {key}: {value}")
        info("Valid values: " + ", ".join(choices))
        raise typer.Exit(1)

    # Type conversion driven by the field's ``kind`` metadata (single source of
    # truth), so every settable field is coerced correctly without a hand list.
    try:
        typed_value: int | bool | str | list[str]
        kind = config_field_kind(key)
        if kind == "int":
            typed_value = int(value)
        elif kind == "bool":
            typed_value = value.lower() in ("true", "1", "yes", "on")
        elif kind == "list":
            typed_value = coerce_str_list(value, [])
        else:
            typed_value = value

        setattr(config, key, typed_value)

        if save_config(config):
            ok(f"Set {key} = {typed_value}")
            info(f"Config saved to {get_config_path()}")
            if (
                key == "mcp_exec_allowlist"
                and isinstance(typed_value, list)
                and not typed_value
            ):
                warn("Empty allowlist: execute_command will deny every command.")
            elif (
                key == "mcp_exec_allowlist"
                and isinstance(typed_value, list)
                and "*" in typed_value
            ):
                warn(
                    "Wildcard allowlist: execute_command may run any binary not in "
                    "mcp_exec_denylist. The denylist is a guardrail, not a security "
                    "boundary (shells/interpreters can run denied programs unless "
                    "they are denied too)."
                )
        else:
            err("Failed to save config")
            info("Try: cerno config reset")
            raise typer.Exit(1)
    except ValueError as e:
        err(f"Invalid value for {key}: {e}")
        raise typer.Exit(1)


# ===== Credential Commands =====


@creds_app.command(
    name="list", help="List NetExec credential references (never shows secret values)"
)
def creds_list() -> None:
    """List credential refs/usernames/secret_kind from the NetExec workspace."""
    from cerno_pkg.ansi import style_if_enabled
    from cerno_pkg.creds import list_credential_refs
    from rich.table import Table

    refs = list_credential_refs()
    if not refs:
        warn("No NetExec credentials found (workspace empty or unavailable).")
        info("Set the workspace with: cerno config set nxc_workspace_path <dir>")
        return

    table = Table(
        title="NetExec Credentials",
        show_header=True,
        header_style=style_if_enabled("bold cyan"),
    )
    table.add_column("Ref", no_wrap=True)
    table.add_column("Protocol")
    table.add_column("Username")
    table.add_column("Domain")
    table.add_column("Secret")
    for r in refs:
        table.add_row(
            r.ref,
            r.protocol,
            r.username,
            r.domain or "-",
            r.secret_kind or "(none)",
        )
    _console_global.print(table)
    info("Reveal cleartext: cerno creds reveal <ref>")


@creds_app.command(
    name="reveal", help="Reveal a credential's cleartext secret (SENSITIVE, local)"
)
def creds_reveal(
    ref: str = typer.Argument(..., help="Credential ref from 'cerno creds list'"),
) -> None:
    """Print a credential's cleartext secret (audited). Secret stays on this host."""
    from cerno_pkg.creds import reveal_credential

    secret = reveal_credential(ref)
    if secret is None:
        err(f"No usable secret for credential ref: {ref}")
        info("Check available refs with: cerno creds list")
        raise typer.Exit(1)

    warn("SENSITIVE: the value below is a cleartext credential — handle with care.")
    _console_global.print(f"Username:    {secret.username}")
    if secret.domain:
        _console_global.print(f"Domain:      {secret.domain}")
    _console_global.print(f"Secret kind: {secret.secret_kind}")
    _console_global.print(f"Secret:      {secret.secret_value}")


# ===== Workflow Commands =====


@workflow_app.command(
    name="list", help="List all available workflows from bundled and custom YAML files"
)
def workflow_list(
    custom_workflows: Optional[Path] = typer.Option(
        None, "--custom-workflows", "-w", help="Path to custom workflows YAML file"
    ),
) -> None:
    """Display all available workflows with plugin IDs and descriptions."""
    from cerno_pkg.workflow_mapper import WorkflowMapper
    from rich.table import Table
    from cerno_pkg.ansi import get_console

    console = get_console()

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
    table = Table(
        title="[bold cyan]Available Workflows[/]",
        show_header=True,
        header_style="bold magenta",
    )
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


@app.command(
    name="reset", help="Reset cerno to a fresh installation state (destructive)"
)
def reset_installation() -> None:
    """Purge all cerno data under ~/.cerno and return to a fresh installation state.

    This permanently deletes:
    - cerno.db and its WAL/SHM sidecars (all scans, findings, sessions, tool executions)
    - config.yaml and config.yaml.backup (user configuration)
    - cerno.log and rotated log files
    - proxychains4.conf (generated proxy config)
    - artifacts/ directory (generated tool output)
    - scans/ directory (per-scan working directories, e.g. http_urls.txt)

    A custom results_root or log_path outside ~/.cerno is NOT touched, and
    neither are shell completions (e.g. ~/.bashrc entries).
    """
    import shutil

    cerno_dir = Path.home() / ".cerno"

    if not cerno_dir.exists():
        info("~/.cerno does not exist — nothing to reset.")
        raise typer.Exit(0)

    # Enumerate what will be deleted
    db_files = list(cerno_dir.glob("cerno.db*"))  # incl. -wal / -shm sidecars
    config_files = list(cerno_dir.glob("config.yaml*"))  # incl. .backup
    log_files = list(cerno_dir.glob("cerno.log*"))
    proxy_conf = cerno_dir / "proxychains4.conf"
    artifacts_dir = cerno_dir / "artifacts"
    scans_dir = cerno_dir / "scans"

    warn("This will permanently delete the following from ~/.cerno/:")
    if db_files:
        warn(
            "  cerno.db       — entire database (scans, findings, sessions, tool executions)"
        )
    if config_files:
        warn("  config.yaml    — user configuration (and any backup)")
    if log_files:
        warn(f"  cerno.log*     — {len(log_files)} log file(s)")
    if proxy_conf.exists():
        warn("  proxychains4.conf — generated proxy config")
    if artifacts_dir.exists():
        warn("  artifacts/     — generated tool output files")
    if scans_dir.exists():
        warn("  scans/         — per-scan working directories")
    _console_global.print()
    info("Shell completions (e.g. ~/.bashrc entries) are NOT affected.")
    _console_global.print()

    try:
        response = Prompt.ask('Type "reset" to confirm').strip()
    except KeyboardInterrupt:
        _console_global.print()
        info("Reset cancelled.")
        raise typer.Exit(0)

    if response != "reset":
        info("Reset cancelled.")
        raise typer.Exit(0)

    # Delete each item, continuing past failures
    had_error = False

    for target in [*db_files, *config_files, *log_files, proxy_conf]:
        if target.exists():
            try:
                target.unlink()
            except OSError as e:
                err(f"Failed to delete {target}: {e}")
                had_error = True

    for directory in [artifacts_dir, scans_dir]:
        if directory.exists():
            try:
                shutil.rmtree(directory)
            except OSError as e:
                err(f"Failed to delete {directory}: {e}")
                had_error = True

    # Remove the ~/.cerno directory itself if now empty
    try:
        cerno_dir.rmdir()  # Only succeeds if empty; ignore if non-empty
    except OSError:
        pass

    if had_error:
        warn("Reset completed with errors — some files may not have been deleted.")
    else:
        ok("cerno has been reset. Run any cerno command to reinitialize.")


if __name__ == "__main__":
    app()
