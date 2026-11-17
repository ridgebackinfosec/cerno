#!/usr/bin/env python3
"""
Cerno - Modern CLI for vulnerability finding review and security tool orchestration.

This tool provides an interactive TUI for reviewing findings imported from
Nessus, nuclei and Burp Suite -- or written by hand -- running security tools
(nmap, netexec, metasploit), and tracking progress.
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
    show_dataset_summary,
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
from cerno_pkg.ansi import get_console, get_terminal_width, print_verbatim, safe_text
from cerno_pkg.workflow_mapper import build_workflow_mapper
from cerno_pkg.models import count_review_states
from cerno_pkg.constants import (
    REVIEW_MOVE_LABELS,
    REVIEW_STATE_DONE,
    REVIEW_STATE_IN_PROGRESS,
    REVIEW_STATE_LABELS,
    REVIEW_STATE_STYLES,
    REVIEW_STATE_UNREVIEWED,
    REVIEW_STATES,
    REVIEW_TRANSITIONS,
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
    finding_type: Any,
    hosts: list[str],
    workflow: Optional["Workflow"] = None,
) -> None:
    """Interactive Claude Assistant chat panel for a finding.

    Opens a persistent chat overlay for the given finding. Loads prior conversation
    history from SQLite, displays it, and enters an input loop.

    Args:
        finding: Finding database object
        finding_type: FindingType database object
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
                    finding_type=finding_type,
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
    dataset_names: list[str],
    findings_with_finding_types: list[Any],
) -> None:
    """Interactive Claude Assistant chat for an aggregate scope.

    Used at severity-menu level (all findings in scan) and findings-list level
    (all findings in current filter/severity selection). Conversation history is
    persisted in SQLite keyed by context_key.

    Args:
        context_key: Deterministic string identifying the conversation scope
        scope_description: Human-readable scope label shown to the user
        dataset_names: Display names of the selected dataset(s)
        findings_with_finding_types: List of (Finding, FindingType) tuples in scope
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
                    dataset_names=dataset_names,
                    findings_with_finding_types=findings_with_finding_types,
                    question=raw,
                )

            turns = ClaudeAggregateConversationTurn.get_by_context(conn, context_key)
            is_resumed = bool(turns)


def browse_workflow_groups(
    dataset: Any,  # Dataset object (primary dataset)
    workflow_groups: Dict[str, List[Tuple[Any, Any]]],
    use_sudo: bool,
    in_progress_total: List[str],
    done_total: List[str],
    workflow_mapper,
    config: Optional["CernoConfig"] = None,
    session_start_time: Optional[Any] = None,
    dataset_label: Optional[str] = None,
    datasets: Optional[List[Any]] = None,
) -> None:
    """
    Browse workflow groups and findings within selected workflow.

    Displays a menu of workflow names with Unreviewed / In Progress / Done
    counts, allows selection, then shows findings for that workflow.

    Args:
        dataset: Primary Dataset database object
        workflow_groups: Dict mapping workflow_name -> list of (Finding, FindingType) tuples
        use_sudo: Whether sudo is available
        in_progress_total: List of findings viewed but not marked done
        done_total: List of findings marked done
        workflow_mapper: WorkflowMapper instance
        config: Optional config (loaded if omitted)
        session_start_time: Review session start, used for end-of-session statistics
        dataset_label: Optional display label override (used for multi-dataset breadcrumbs)
        datasets: Optional full list of selected Dataset objects for multi-dataset support
    """
    # Load config if not provided (defensive programming)
    if config is None:
        from cerno_pkg.config import load_config

        config = load_config()

    dataset_dir = Path(dataset.export_root) / dataset.dataset_name
    _wf_label = dataset_label if dataset_label else dataset_dir.name
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

        # Extract finding_type IDs from database records instead of filenames
        finding_type_ids = []
        for _finding, finding_type in workflow_files:
            finding_type_ids.append(finding_type.finding_type_id)

        # Browse findings for this workflow using database query filtered by finding_type IDs
        all_datasets = datasets if datasets else [dataset]
        browse_file_list(
            all_datasets,
            None,  # No specific severity dir (workflow may span multiple severities)
            None,  # No severity filter
            f"Workflow: {workflow_name}",
            use_sudo,
            in_progress_total,
            done_total,
            is_msf_mode=True,  # Show severity labels
            workflow_mapper=workflow_mapper,
            finding_type_ids_filter=finding_type_ids if finding_type_ids else None,
            config=config,
            session_start_time=session_start_time,
        )

        # Refresh workflow files from database to get updated review_state values
        # This ensures the statistics display shows current counts after moving findings between statuses
        from cerno_pkg.models import Finding

        all_dataset_ids = [
            s.dataset_id for s in all_datasets if s.dataset_id is not None
        ]
        if len(all_dataset_ids) > 1:
            refreshed_files, _ = Finding.get_by_dataset_ids_merged(
                dataset_ids=all_dataset_ids,
                finding_type_ids=finding_type_ids if finding_type_ids else None,
            )
        else:
            refreshed_files = Finding.get_by_dataset_with_finding_type(
                dataset_id=dataset.dataset_id,
                finding_type_ids=finding_type_ids if finding_type_ids else None,
            )
        workflow_groups[workflow_name] = refreshed_files


# === Unified file list browser ===


def browse_file_list(
    datasets: list[Any],  # List of Dataset objects (single-dataset: [dataset])
    sev_dir: Optional[Path],
    severity_dir_filter: Optional[str],
    severity_label: str,
    use_sudo: bool,
    in_progress_total: List[str],
    done_total: List[str],
    is_msf_mode: bool = False,
    workflow_mapper: Optional[WorkflowMapper] = None,
    has_metasploit_filter: Optional[bool] = None,
    finding_type_ids_filter: Optional[list[str]] = None,
    severity_dirs_filter: Optional[list[str]] = None,
    config: Optional["CernoConfig"] = None,
    session_start_time: Optional[Any] = None,
) -> None:
    """
    Browse and interact with the findings list (unified for severity and MSF modes).

    Args:
        datasets: List of Dataset database objects (single-dataset: pass [dataset])
        sev_dir: Severity display path, used for the preview and tool output paths
        severity_dir_filter: Severity directory filter for database query (e.g., "3_High")
        severity_label: Display label for the severity
        workflow_mapper: Optional workflow mapper for finding_type workflows
        use_sudo: Whether sudo is available
        in_progress_total: List to track findings viewed but not marked done
        done_total: List to track findings marked done
        is_msf_mode: If True, derive each finding's severity directory from
            its finding_type metadata rather than the single sev_dir
        has_metasploit_filter: Optional filter for metasploit finding_types
        finding_type_ids_filter: Optional list of specific finding_type IDs to include
        severity_dirs_filter: Optional list of severity filters for a multi-severity view
        config: Optional config (loaded if omitted)
        session_start_time: Review session start, used for end-of-session statistics
    """
    from cerno_pkg.models import Finding

    # Load config if not provided (defensive programming)
    if config is None:
        from cerno_pkg.config import load_config

        config = load_config()

    # Proxy routing is config-only (proxychains_enabled); the per-session
    # --proxy/--no-proxy overrides were removed in favour of that key.
    _proxy_active = config.proxychains_enabled

    file_filter = ""
    group_filter: Optional[Tuple[int, set, str]] = None
    # [I] / [D] toggles: None = all open statuses (Done hidden)
    status_filter: Optional[str] = None
    # Default sort: severity for mixed views (Critical at top), finding_type_id for single severity
    sort_mode = "finding_type_id" if severity_dir_filter is not None else "severity"

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

    # Derive dataset variables from datasets list
    primary_dataset = datasets[0]
    dataset_id = primary_dataset.dataset_id
    is_multi_dataset = len(datasets) > 1
    dataset_ids = [s.dataset_id for s in datasets]
    dataset_names = [s.dataset_name for s in datasets]
    dataset_dir = Path(primary_dataset.export_root) / primary_dataset.dataset_name

    # Claude availability check (once per browse session)
    from cerno_pkg.claude_assistant import check_claude_available, claude_enabled

    claude_installed = check_claude_available()
    has_claude = claude_enabled(config)

    def get_counts_for(finding: "Finding") -> Tuple[int, str]:
        """Get host/port counts from database.

        In multi-dataset mode, counts distinct hosts across all finding_ids for this finding_type.

        Args:
            finding: Finding database object

        Returns:
            Tuple of (host_count, ports_string)
        """
        from cerno_pkg.database import get_connection

        with get_connection() as conn:
            if is_multi_dataset and all_instances:
                all_fids = [
                    f.finding_id
                    for f in all_instances.get(finding.finding_type_id, [])
                    if f.finding_id is not None
                ]
            else:
                all_fids = (
                    [finding.finding_id] if finding.finding_id is not None else []
                )

            return (Finding.count_targets(all_fids, conn), "")

    # Initialize multi-dataset tracking variables (updated each loop iteration)
    all_instances: dict[str, list["Finding"]] = {}
    dataset_labels: Optional[dict[str, str]] = None

    while True:
        # Query database for findings with finding_type info
        if is_multi_dataset:
            all_records, all_instances = Finding.get_by_dataset_ids_merged(
                dataset_ids=dataset_ids,
                severity_dir=severity_dir_filter,
                severity_dirs=severity_dirs_filter,
                has_metasploit=has_metasploit_filter,
                finding_type_ids=finding_type_ids_filter,
            )
            # Build scan label strings: "All N" or "M of N"
            total_datasets = len(datasets)
            dataset_labels = {
                pid: (
                    f"All {total_datasets}"
                    if len(findings) == total_datasets
                    else f"{len(findings)} of {total_datasets}"
                )
                for pid, findings in all_instances.items()
            }
        else:
            all_records = Finding.get_by_dataset_with_finding_type(
                dataset_id=dataset_id,
                severity_dir=severity_dir_filter,
                severity_dirs=severity_dirs_filter,
                has_metasploit=has_metasploit_filter,
                finding_type_ids=finding_type_ids_filter,
            )
            all_instances = {}
            dataset_labels = None

        # Separate reviewed and unreviewed based on review_state from database
        reviewed = [
            (pf, p) for (pf, p) in all_records if pf.review_state == REVIEW_STATE_DONE
        ]
        unreviewed = [
            (pf, p) for (pf, p) in all_records if pf.review_state != REVIEW_STATE_DONE
        ]

        # Apply name, group, and status filters.
        # The Done-only filter ([D]) draws from the Done pool; every other
        # filter state draws from the open pool, so Done stays hidden by default.
        pool = reviewed if status_filter == REVIEW_STATE_DONE else unreviewed
        candidates = filter_finding_candidates(
            pool, file_filter, group_filter, status_filter
        )

        # Unique CVE count across all filtered candidates
        unique_cve_count = len({cve for _, p in candidates if p.cves for cve in p.cves})

        # Scan-target count across all filtered candidates (single DB query).
        # Targets, not machines: this labels the [V] host list, so it must equal
        # the number of lines that list renders.
        if candidates:
            if is_multi_dataset and all_instances:
                all_fids = [
                    f.finding_id
                    for pf, _ in candidates
                    for f in all_instances.get(pf.finding_type_id, [])
                    if f.finding_id is not None
                ]
            else:
                all_fids = [
                    pf.finding_id for pf, _ in candidates if pf.finding_id is not None
                ]

            if all_fids:
                from cerno_pkg.database import get_connection

                with get_connection() as conn:
                    unique_host_count = Finding.count_targets(all_fids, conn)
            else:
                unique_host_count = 0
        else:
            unique_cve_count = 0
            unique_host_count = 0

        # Apply sorting
        if sort_mode == "severity":
            # Sort by severity descending (Critical first), then by finding_type name
            display = sorted(
                candidates,
                key=lambda record: (
                    -record[1].severity_int,
                    natural_key(record[1].finding_type_name),
                ),
            )
        elif sort_mode == "hosts":
            display = sorted(
                candidates,
                key=lambda record: (
                    -get_counts_for(record[0])[0],
                    natural_key(record[1].finding_type_name),
                ),
            )
        elif sort_mode == "finding_type_id":
            # Sort by finding_type ID (numeric ascending)
            display = sorted(candidates, key=lambda record: record[1].finding_type_id)
        else:  # name
            display = sorted(
                candidates, key=lambda record: natural_key(record[1].finding_type_name)
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

            if is_multi_dataset:
                _names = [s.dataset_name for s in datasets]
                _dataset_label = (
                    f"{_names[0]} + {_names[1]}"
                    if len(_names) == 2
                    else f"{len(_names)} datasets"
                )
            else:
                _dataset_label = dataset_dir.name
            filter_info = f"filtered: '{file_filter}'" if file_filter else "Findings"
            if status_filter:
                filter_info += f" ({REVIEW_STATE_LABELS[status_filter]} only)"
            bc = breadcrumb(_dataset_label, severity_label, filter_info)
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

            # Counts by status. The Done total is always shown, even though Done
            # findings are hidden by default: it is the only thing that tells the
            # operator [D] has anything behind it.
            open_unrev, open_in_prog, _done, _total = count_review_states(
                pf for (pf, _p) in unreviewed
            )
            open_text = Text()
            for i, (state, count) in enumerate(
                (
                    (REVIEW_STATE_UNREVIEWED, open_unrev),
                    (REVIEW_STATE_IN_PROGRESS, open_in_prog),
                    (REVIEW_STATE_DONE, len(reviewed)),
                )
            ):
                if i:
                    open_text.append(" · ")
                open_text.append(
                    f"{REVIEW_STATE_LABELS[state]} {count}",
                    style=style_if_enabled(REVIEW_STATE_STYLES[state]),
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
                "finding_type_id": "Finding ID ↑",
                "hosts": "Host count ↓",
                "name": "Name A↑Z",
            }.get(sort_mode, "Severity ↓")

            # Show next sort mode indicator
            next_sort_mode = {
                "severity": "Finding ID ↑",
                "finding_type_id": "Name A↑Z",
                "name": "Host count ↓",
                "hosts": "Severity ↓",
            }.get(sort_mode, "Finding ID ↑")

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
                elif status_filter and all_records:
                    # Checked against all_records, not the pool: a Done-only
                    # filter with no Done findings must report the status
                    # mismatch rather than fall through to "all completed".
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
                    dataset_labels=dataset_labels,
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
                status_filter=status_filter,
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
                    print_verbatim(payload)

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

        # Status-filter toggles ([I] In Progress-only, [D] Done-only). These are
        # intercepted before the generic action handler because changing the
        # filter changes which pool of findings the list is built from.
        # They are symmetric: each key clears the filter only when its own
        # filter is the active one, so pressing the other one switches.
        if ans in ("i", "d"):
            wanted = REVIEW_STATE_IN_PROGRESS if ans == "i" else REVIEW_STATE_DONE
            if status_filter == wanted:
                status_filter = None
                ok("Showing all open statuses.")
            else:
                status_filter = wanted
                ok(f"Showing {REVIEW_STATE_LABELS[wanted]} findings only.")
            page_idx = 0
            continue

        # Add a hand-authored finding ([+]). Intercepted before the generic
        # action handler because a create can pull a second dataset into the
        # session, which changes the loop's own dataset variables.
        if ans == "+":
            from cerno_pkg.authored_findings import (
                AuthoredFindingError,
                create_authored_finding,
                get_or_create_authored_dataset,
            )
            from cerno_pkg.constants import SOURCE_OPERATOR
            from cerno_pkg.tui import prompt_new_finding

            drafted = prompt_new_finding()
            if drafted is None:
                continue
            try:
                # SOURCE_OPERATOR, not agent: this keystroke is the operator
                # typing. An MCP client's creates go in under `agent:`, which
                # is what keeps the two authorships distinguishable later.
                new_finding_type_id, _new_finding_id = create_authored_finding(
                    drafted, SOURCE_OPERATOR
                )
            except AuthoredFindingError as exc:
                err(f"Could not save the finding: {exc}")
                continue

            ok(f"Saved as {new_finding_type_id}.")
            operator_dataset = get_or_create_authored_dataset(SOURCE_OPERATOR)
            if operator_dataset.dataset_id not in dataset_ids:
                # Append in place: this list is the caller's `selected_datasets`,
                # reused across the whole severity menu and handed to
                # save_session(), so the Operator scan reaches session_datasets
                # and every later view without a new session API.
                datasets.append(operator_dataset)
                dataset_ids = [s.dataset_id for s in datasets]
                dataset_names = [s.dataset_name for s in datasets]
                is_multi_dataset = len(datasets) > 1
                info(
                    f"Added the {operator_dataset.dataset_name} scan to this review "
                    "session, so hand-authored findings show up in this list."
                )
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
                dataset_ids_str = ",".join(str(sid) for sid in sorted(dataset_ids))
                scope_hash = hashlib.md5(scope_desc.encode()).hexdigest()[:8]
                context_key = f"findings_list:{dataset_ids_str}:{scope_hash}"
                browse_claude_chat_aggregate(
                    context_key=context_key,
                    scope_description=scope_desc,
                    dataset_names=dataset_names,
                    findings_with_finding_types=candidates,
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
            group_filter,
            sort_mode,
            page_idx,
            total_pages,
            get_counts_for,
            unique_cve_count=unique_cve_count,
            unique_host_count=unique_host_count,
            status_filter=status_filter,
        )

        (
            action_type,
            file_filter,
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
            # Bulk move: each filtered finding moves one step along the cycle
            # (constants.REVIEW_TRANSITIONS). Under the Done-only filter that
            # step is Done → Unreviewed, so this reopens rather than advances.
            from cerno_pkg.fs import finding_label, move_review_state
            from rich.prompt import Confirm

            # Count the moves actually pending, keyed by destination, and name
            # only the non-empty ones: a Done-only list claiming
            # "0 → In Progress, 0 → Done" reads as a no-op.
            pending = {
                REVIEW_TRANSITIONS[state][0]: sum(
                    1 for (f, _p) in candidates if f.review_state == state
                )
                for state in REVIEW_STATES
            }
            move_summary = ", ".join(
                f"{count} → {REVIEW_STATE_LABELS[target]}"
                for target, count in pending.items()
                if count
            )
            is_reopen = status_filter == REVIEW_STATE_DONE
            action_phrase = (
                REVIEW_MOVE_LABELS[REVIEW_STATE_UNREVIEWED].replace("Move", "move", 1)
                if is_reopen
                else "move to their next status"
            )

            try:
                confirm_msg = (
                    f"Move {len(candidates)} findings — {action_phrase}? {move_summary}"
                )
                confirmed = Confirm.ask(confirm_msg, default=False)
            except KeyboardInterrupt:
                warn("\nInterrupted — cancelling bulk operation.")
                continue

            if not confirmed:
                info("Bulk operation cancelled.")
                continue

            # Tallied per destination. Reopened findings are deliberately kept
            # out of in_progress_total / done_total: those drive the end-of-
            # session statistics, which count work completed, not undone.
            moved: dict[str, int] = {}
            with Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=_console_global,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    (
                        "Moving findings back to Unreviewed..."
                        if is_reopen
                        else "Moving findings to next status..."
                    ),
                    total=len(candidates),
                )
                for finding, finding_type in candidates:
                    new_state = move_review_state(finding, finding_type, quiet=True)
                    if new_state is not None:
                        display_name = finding_label(finding, finding_type)
                        moved[new_state] = moved.get(new_state, 0) + 1
                        if new_state == REVIEW_STATE_DONE:
                            done_total.append(display_name)
                        elif new_state == REVIEW_STATE_IN_PROGRESS:
                            in_progress_total.append(display_name)
                        # Sync other scan instances in multi-dataset mode
                        if is_multi_dataset:
                            for other_f in all_instances.get(
                                finding_type.finding_type_id, []
                            ):
                                if other_f.finding_id != finding.finding_id:
                                    # Same actor as the move that triggered this
                                    # sync -- siblings never re-derive one.
                                    from cerno_pkg.constants import (
                                        SOURCE_OPERATOR as _ACTOR,
                                    )

                                    other_f.update_review_state(new_state, _ACTOR)
                    progress.advance(task)
            if moved:
                ok(
                    "Moved "
                    + ", ".join(
                        f"{count} to {REVIEW_STATE_LABELS[state]}"
                        for state, count in moved.items()
                    )
                    + "."
                )
            continue
        elif action_type == "file_selected":
            # Determine which record was selected
            if ans == "":
                chosen_record = page_items[0]
            else:
                global_idx = int(ans) - 1
                chosen_record = display[global_idx]

            # Extract finding_type info from record
            finding, finding_type = chosen_record

            # Create synthetic path for legacy code that still uses chosen.name
            # In database-only mode, construct a name from finding_type ID
            synthetic_name = f"{finding_type.finding_type_id}_{finding_type.finding_type_name.replace(' ', '_').replace('/', '_')}.txt"
            chosen_path = Path(synthetic_name)

            # Get severity directory from finding_type metadata
            if is_msf_mode:
                # Construct severity directory name from finding_type severity
                sev_label = (
                    finding_type.severity_label
                    or f"Severity_{finding_type.severity_int}"
                )
                chosen_sev_dir = (
                    dataset_dir / f"{finding_type.severity_int}_{sev_label}"
                )
            else:
                chosen_sev_dir = sev_dir

            # Process the file
            process_single_finding(
                chosen_path,
                finding_type,
                finding,
                dataset_dir,
                chosen_sev_dir,
                use_sudo,
                in_progress_total,
                done_total,
                show_severity=is_msf_mode,
                workflow_mapper=workflow_mapper,
                use_proxy=_proxy_active,
            )

            # In multi-dataset mode, broadcast review state changes to all other instances
            if is_multi_dataset and all_instances:
                from cerno_pkg.database import query_one, get_connection

                with get_connection() as conn:
                    state_row = query_one(
                        conn,
                        "SELECT review_state FROM findings WHERE finding_id = ?",
                        (finding.finding_id,),
                    )
                if state_row:
                    new_state = state_row["review_state"]
                    for other_f in all_instances.get(finding.finding_type_id, []):
                        if other_f.finding_id != finding.finding_id:
                            # Same actor as the move that triggered this sync.
                            from cerno_pkg.constants import (
                                SOURCE_OPERATOR as _ACTOR,
                            )

                            other_f.update_review_state(new_state, _ACTOR)

        elif action_type is None:
            continue


# === Main application logic ===


def show_session_statistics(
    session_start_time,
    in_progress_total: list[str],
    done_total: list[str],
    dataset_dir: Path,
    dataset_id: Optional[int] = None,
    dataset_ids: Optional[list[int]] = None,
) -> None:
    """
    Display rich session statistics at the end of a review session.

    Args:
        session_start_time: Datetime when session started
        in_progress_total: List of findings viewed but not marked done
        done_total: List of findings marked done
        dataset_dir: Dataset directory (only used by the legacy no-dataset_id fallback)
        dataset_id: Optional dataset ID for database queries
        dataset_ids: Optional list of dataset IDs for multi-dataset queries (overrides dataset_id)
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

        # Database query (multi-dataset or single-dataset). The filesystem branch below
        # is a legacy fallback, only reached when no dataset_id is passed.
        if dataset_ids and len(dataset_ids) > 1:
            from cerno_pkg.database import db_transaction, query_all

            with db_transaction() as conn:
                placeholders = ",".join("?" * len(dataset_ids))
                rows = query_all(
                    conn,
                    f"""
                    SELECT p.severity_label, COUNT(DISTINCT f.finding_type_id) as count
                    FROM findings f
                    JOIN v_finding_types_with_severity p ON f.finding_type_id = p.finding_type_id
                    WHERE f.dataset_id IN ({placeholders}) AND f.review_state = 'done'
                    GROUP BY p.severity_label
                    """,
                    tuple(dataset_ids),
                )
                for row in rows:
                    sev_label = pretty_severity_label(row[0])
                    severity_counts[sev_label] = row[1]
        elif dataset_id is not None:
            from cerno_pkg.database import db_transaction, query_all

            # Query database for completed findings grouped by severity
            with db_transaction() as conn:
                rows = query_all(
                    conn,
                    """
                    SELECT p.severity_label, COUNT(*) as count
                    FROM findings f
                    JOIN v_finding_types_with_severity p ON f.finding_type_id = p.finding_type_id
                    WHERE f.dataset_id = ? AND f.review_state = 'done'
                    GROUP BY p.severity_label
                    """,
                    (dataset_id,),
                )
                for row in rows:
                    sev_label = pretty_severity_label(row[0])
                    severity_counts[sev_label] = row[1]
        else:
            # Fallback to filesystem walk
            for sev_dir in dataset_dir.iterdir():
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

            # Counts cover every Done finding in the dataset(s), not just this session.
            console.print("Done by severity (all sessions):")
            console.print(sev_table)
            _console_global.print()


def main() -> None:
    """
    Main application entry point for interactive review mode.

    Takes no arguments: every per-session override this used to read off a CLI
    namespace is now a config key (``tools_enabled``, ``custom_workflows_path``,
    ``custom_workflows_exclusive``, ``proxychains_enabled``), read from the
    config loaded by ``main_callback``.
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
    dataset_id: int = 0  # Will be set when user selects a dataset
    dataset_dir: Optional[Path] = None  # Will be set when user selects a dataset

    # Initialize workflow mapper. build_workflow_mapper() reads
    # custom_workflows_path / custom_workflows_exclusive, so supplement and
    # exclusive mode behave identically here, in `cerno workflow list` and in
    # the MCP workflow tools.
    with _console_global.status("[bold green]Loading workflows..."):
        workflow_mapper = build_workflow_mapper(config)

    workflow_count = workflow_mapper.count()
    if workflow_count > 0:
        if config.custom_workflows_path and config.custom_workflows_exclusive:
            _console_global.print(
                f"Loaded {workflow_count} workflow(s) from "
                f"{config.custom_workflows_path} (bundled disabled)\n"
            )
        elif config.custom_workflows_path:
            _console_global.print(
                f"Loaded {workflow_count} workflow(s), including custom from "
                f"{config.custom_workflows_path}\n"
            )
        else:
            _console_global.print(f"Loaded {workflow_count} workflow(s)\n")
    else:
        warn("No workflows loaded.")

    use_sudo = root_or_sudo_available()
    if not use_sudo:
        warn(
            "Not running as root and no 'sudo' found — "
            "some scan types (e.g., UDP) may fail."
        )

    # Tool availability table, skipped in review-only mode. `cerno check`
    # renders the same table without entering review.
    if config.tools_enabled:
        from cerno_pkg.render import render_tool_availability_table

        render_tool_availability_table(include_unavailable=True)
        _console_global.print()  # Add spacing
    else:
        info("(tool prompts disabled: set tools_enabled true to re-enable)")

    in_progress_total: List[str] = []
    done_total: List[str] = []

    from cerno_pkg.models import Dataset, Finding
    from datetime import datetime

    def _additional_dataset_ids(datasets: list[Dataset]) -> Optional[list[int]]:
        """Return secondary dataset IDs for a multi-dataset selection (None for single dataset)."""
        ids = [s.dataset_id for s in datasets[1:] if s.dataset_id is not None]
        return ids or None

    selected_datasets: list[Dataset] = []
    # Carried across iterations of the dataset-selection loop below: the
    # previous scan's session is saved at the top of the next pass, after
    # this has been populated from that selection.
    all_dataset_ids: list[int] = []

    # Outer loop for scan selection
    # Wrapped in try/finally to ensure session is saved on ALL exit paths
    try:
        while True:
            # Save previous scan's session before loading next scan menu
            # This handles the case where user reviews multiple datasets (presses 'b' to go back)
            if dataset_id != 0:
                save_session(
                    dataset_id,
                    session_start_time,
                    in_progress_count=len(in_progress_total),
                    done_count=len(done_total),
                    additional_dataset_ids=_additional_dataset_ids(selected_datasets),
                )

                # Show statistics if work was done
                if in_progress_total or done_total:
                    if dataset_dir is not None:
                        show_session_statistics(
                            session_start_time,
                            in_progress_total,
                            done_total,
                            dataset_dir,
                            dataset_id=dataset_id,
                            dataset_ids=(
                                all_dataset_ids if len(all_dataset_ids) > 1 else None
                            ),
                        )

                delete_session(dataset_id)

                # Reset tracking for next scan
                dataset_id = 0
                dataset_dir = None
                in_progress_total = []
                done_total = []

            # Get all datasets from database
            try:
                with _console_global.status(
                    "[bold green]Loading datasets from database..."
                ):
                    all_datasets = Dataset.get_all()
            except Exception as e:
                err(f"Failed to query datasets from database: {e}")
                info(
                    "If the database is corrupted, try: rm ~/.cerno/cerno.db, then "
                    "re-import with cerno import nessus|nuclei|burp <file>"
                )
                return

            if not all_datasets:
                # First-time user - show guided tour
                from cerno_pkg.onboarding import show_guided_tour

                show_guided_tour()
                # After tour, show import instructions
                info("\nTo get started, import findings:")
                info("  cerno import nessus /path/to/scan.nessus")
                info("  cerno import nuclei /path/to/nuclei.json\n")
                return

            # Display scan selection menu
            header("Available Datasets")
            from rich.table import Table
            from rich import box
            from cerno_pkg.ansi import style_if_enabled

            dataset_table = Table(
                show_header=True,
                header_style=style_if_enabled("bold cyan"),
                box=box.SIMPLE,
            )
            dataset_table.add_column(
                "#", style=style_if_enabled("cyan"), justify="right"
            )
            dataset_table.add_column("Dataset Name", style=style_if_enabled("yellow"))
            dataset_table.add_column("Last Reviewed", style=style_if_enabled("magenta"))

            for idx, dataset in enumerate(all_datasets, 1):
                last_reviewed = "never"
                if dataset.last_reviewed_at:
                    try:
                        dt = datetime.fromisoformat(dataset.last_reviewed_at)
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
                        last_reviewed = dataset.last_reviewed_at[:10]  # Just date

                dataset_table.add_row(str(idx), dataset.dataset_name, last_reviewed)

            _console_global.print(dataset_table)
            print_action_menu([("Q", "Quit")])

            try:
                ans = Prompt.ask("Choose scan(s) (e.g. 1  or  1-3  or  1,3,5)").strip()
            except KeyboardInterrupt:
                warn("\nInterrupted — exiting.")
                return

            if ans in ("x", "exit", "q", "quit"):
                return

            from cerno_pkg.tui import parse_dataset_selection

            indices = parse_dataset_selection(ans, len(all_datasets))
            if indices is None:
                warn(
                    f"Invalid choice. Enter 1-{len(all_datasets)}, a range like 1-3, or [Q]uit."
                )
                continue

            selected_datasets = [all_datasets[i - 1] for i in indices]
            selected_dataset = selected_datasets[0]  # Primary scan for backward compat
            export_root = Path(selected_dataset.export_root)
            dataset_dir = export_root / selected_dataset.dataset_name

            # Note: dataset_dir is a Path object used for display (dataset_dir.name) only
            # In database-only mode, the directory doesn't need to exist

            # Type narrowing: ensure dataset_id is not None
            if selected_dataset.dataset_id is None:
                warn("Invalid dataset - missing dataset_id")
                continue

            dataset_id = selected_dataset.dataset_id
            all_dataset_ids = [
                s.dataset_id for s in selected_datasets if s.dataset_id is not None
            ]
            if len(selected_datasets) > 1:
                names = ", ".join(s.dataset_name for s in selected_datasets)
                ok(f"Selected: {names}")
            else:
                ok(f"Selected: {selected_dataset.dataset_name}")

            # Check for existing session
            previous_session = load_session(dataset_id)
            if previous_session:
                from datetime import datetime

                session_date = datetime.fromisoformat(previous_session.session_start)
                header("Previous Session Found")
                info(f"Session started: {session_date.strftime('%Y-%m-%d %H:%M:%S')}")
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
                    delete_session(dataset_id)
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

            show_dataset_summary(
                dataset_dir,
                top_ports_n=top_ports,
                dataset_id=dataset_id,
                dataset_ids=all_dataset_ids if len(all_dataset_ids) > 1 else None,
                dataset_names=(
                    [s.dataset_name for s in selected_datasets]
                    if len(selected_datasets) > 1
                    else None
                ),
            )

            # Show workflow guidance for first-time or returning users
            from cerno_pkg.onboarding import show_workflow_guidance

            show_workflow_guidance(
                dataset_name=selected_dataset.dataset_name,
                dataset_id=dataset_id,
                dataset_ids=all_dataset_ids if len(all_dataset_ids) > 1 else None,
                dataset_names=(
                    [s.dataset_name for s in selected_datasets]
                    if len(selected_datasets) > 1
                    else None
                ),
            )

            # Host filter state (persists across severity loop iterations)
            host_filter: Optional[str] = None  # Active host filter (IP/hostname)
            host_filter_finding_type_ids: Optional[list[str]] = (
                None  # Cached finding_type IDs for filter
            )

            # Claude availability (computed once per dataset selection)
            from cerno_pkg.claude_assistant import (
                check_claude_available as _check_claude,
            )
            from cerno_pkg.claude_assistant import claude_enabled as _claude_enabled

            _claude_installed_sev = _check_claude()
            _has_claude_sev = _claude_enabled(config)

            # Build multi-dataset display label for breadcrumb/header
            if len(selected_datasets) > 1:
                _label_names = [s.dataset_name for s in selected_datasets]
                if len(_label_names) == 2:
                    _dataset_label = f"{_label_names[0]} + {_label_names[1]}"
                else:
                    _dataset_label = f"{len(_label_names)} datasets"
            else:
                _dataset_label = dataset_dir.name

            # Severity loop (inner loop)
            while True:
                # Re-derived every pass, not once at selection: browse_file_list
                # appends the Operator scan to selected_datasets in place when the
                # operator writes a finding with [+], and the severity menu, the
                # aggregate Claude context key and the statistics all have to
                # see it.
                all_dataset_ids = [
                    s.dataset_id for s in selected_datasets if s.dataset_id is not None
                ]

                from cerno_pkg import breadcrumb

                bc = breadcrumb(_dataset_label, "Choose severity")
                header(bc if bc else f"Dataset: {_dataset_label} — choose severity")

                # Get severity directories from database (database-only mode)
                # Apply host filter if active
                severity_dir_names = Finding.get_severity_names_for_dataset(
                    dataset_id,
                    finding_type_ids=host_filter_finding_type_ids,
                    dataset_ids=all_dataset_ids if len(all_dataset_ids) > 1 else None,
                )
                if not severity_dir_names:
                    warn("No severity directories in this dataset.")
                    break

                # Create virtual Path objects for compatibility with existing render code
                # Database returns pre-sorted (DESC), so no additional sorting needed
                severities = [dataset_dir / sev_name for sev_name in severity_dir_names]

                # Metasploit Module virtual group (menu counts) - query from database
                # Apply host filter if active
                if len(all_dataset_ids) > 1:
                    msf_files, _ = Finding.get_by_dataset_ids_merged(
                        dataset_ids=all_dataset_ids,
                        has_metasploit=True,
                        finding_type_ids=host_filter_finding_type_ids,
                    )
                else:
                    msf_files = Finding.get_by_dataset_with_finding_type(
                        dataset_id=dataset_id,
                        has_metasploit=True,
                        finding_type_ids=host_filter_finding_type_ids,
                    )

                has_msf = len(msf_files) > 0
                msf_summary = (
                    count_review_states(pf for (pf, _p) in msf_files)
                    if has_msf
                    else None
                )

                # Workflow Mapped virtual group (menu counts) - query from database
                # Apply host filter if active (intersect workflow finding_types with host filter)
                workflow_finding_type_ids = workflow_mapper.get_all_finding_ids()
                if workflow_finding_type_ids:
                    # finding_type_id is TEXT and namespaced per source, so this
                    # must stay string-keyed: an int()/isdigit() filter here
                    # would silently drop every non-Nessus workflow id.
                    workflow_finding_type_ids_filtered = [
                        str(pid) for pid in workflow_finding_type_ids
                    ]
                    # If host filter is active, intersect with host filter finding_type IDs
                    if host_filter_finding_type_ids is not None:
                        host_filter_set = {
                            str(pid) for pid in host_filter_finding_type_ids
                        }
                        workflow_finding_type_ids_filtered = [
                            pid
                            for pid in workflow_finding_type_ids_filtered
                            if pid in host_filter_set
                        ]
                    if workflow_finding_type_ids_filtered:
                        if len(all_dataset_ids) > 1:
                            workflow_files, _ = Finding.get_by_dataset_ids_merged(
                                dataset_ids=all_dataset_ids,
                                finding_type_ids=workflow_finding_type_ids_filtered,
                            )
                        else:
                            workflow_files = Finding.get_by_dataset_with_finding_type(
                                dataset_id=dataset_id,
                                finding_type_ids=workflow_finding_type_ids_filtered,
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
                    dataset_id=dataset_id,
                    finding_type_ids=host_filter_finding_type_ids,
                    dataset_ids=all_dataset_ids if len(all_dataset_ids) > 1 else None,
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
                    warn("\nInterrupted — returning to dataset menu.")
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

                    # Query finding_type IDs for this host across all selected datasets
                    finding_type_ids = Host.get_finding_type_ids_for_dataset(
                        ip_address=host_input,
                        dataset_id=dataset_id,
                        partial_match=True,
                        dataset_ids=(
                            all_dataset_ids if len(all_dataset_ids) > 1 else None
                        ),
                    )

                    if not finding_type_ids:
                        warn(f"No findings found for host: {host_input}")
                        continue

                    # Set filter state
                    host_filter = host_input
                    host_filter_finding_type_ids = finding_type_ids
                    ok(
                        f"Found {len(finding_type_ids)} finding(s) for host '{host_input}'"
                    )
                    continue

                elif ans in ("c", "clear") and host_filter:
                    # Clear host filter
                    host_filter = None
                    host_filter_finding_type_ids = None
                    ok("Host filter cleared.")
                    continue

                elif ans == "a":
                    if not _has_claude_sev and _claude_installed_sev:
                        from cerno_pkg.claude_assistant import ensure_enabled

                        if ensure_enabled(config):
                            _has_claude_sev = True
                    if _has_claude_sev:
                        # Build aggregate context from all findings in the current scan scope
                        _sev_dataset_names = [s.dataset_name for s in selected_datasets]
                        _sev_scope = "All findings — " + ", ".join(_sev_dataset_names)
                        if host_filter:
                            _sev_scope += f" (host filter: {host_filter})"
                        _sev_dataset_ids_str = ",".join(
                            str(sid) for sid in sorted(all_dataset_ids)
                        )
                        _host_suffix = f":{host_filter}" if host_filter else ""
                        _sev_context_key = (
                            f"sev_menu:{_sev_dataset_ids_str}{_host_suffix}"
                        )
                        # Fetch all findings for context (no severity filter)
                        if len(all_dataset_ids) > 1:
                            _sev_findings, _ = Finding.get_by_dataset_ids_merged(
                                dataset_ids=all_dataset_ids,
                                finding_type_ids=host_filter_finding_type_ids,
                            )
                        else:
                            _sev_findings = Finding.get_by_dataset_with_finding_type(
                                dataset_id=dataset_id,
                                finding_type_ids=host_filter_finding_type_ids,
                            )
                        browse_claude_chat_aggregate(
                            context_key=_sev_context_key,
                            scope_description=_sev_scope,
                            dataset_names=_sev_dataset_names,
                            findings_with_finding_types=_sev_findings,
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
                    warn("No Metasploit modules available for this dataset.")
                    continue
                if selection.workflow_selected and not has_workflows:
                    warn("No workflow-mapped findings available for this dataset.")
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
                        selected_datasets,
                        selected_sev_dirs[0] if selected_sev_dirs else None,
                        None,  # Single severity filter not used for multi-severity
                        label,
                        use_sudo,
                        in_progress_total,
                        done_total,
                        is_msf_mode=True,  # Show severity labels for each file
                        workflow_mapper=workflow_mapper,
                        severity_dirs_filter=severity_dir_names,
                        finding_type_ids_filter=host_filter_finding_type_ids,
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
                        selected_datasets,
                        sev_dir,
                        severity_dir_filter,
                        label,
                        use_sudo,
                        in_progress_total,
                        done_total,
                        is_msf_mode=False,
                        workflow_mapper=workflow_mapper,
                        finding_type_ids_filter=host_filter_finding_type_ids,
                        config=config,
                        session_start_time=session_start_time,
                    )

                # === Metasploit Module only ===
                elif msf_in_selection:
                    # Build label with host filter if active
                    label = "Metasploit Module"
                    if host_filter:
                        label = f"{label} (Host: {host_filter})"

                    # Query database for metasploit finding_types across all severities
                    browse_file_list(
                        selected_datasets,
                        None,  # No single severity dir
                        None,  # No severity filter
                        label,
                        use_sudo,
                        in_progress_total,
                        done_total,
                        is_msf_mode=True,
                        workflow_mapper=workflow_mapper,
                        has_metasploit_filter=True,
                        finding_type_ids_filter=host_filter_finding_type_ids,
                        config=config,
                        session_start_time=session_start_time,
                    )

                # === Workflow Mapped only ===
                elif workflow_in_selection:
                    # Group findings by workflow name using database records
                    # Note: workflow_files is already filtered by host_filter_finding_type_ids
                    workflow_groups = group_findings_by_workflow(
                        workflow_files, workflow_mapper
                    )

                    browse_workflow_groups(
                        selected_dataset,
                        workflow_groups,
                        use_sudo,
                        in_progress_total,
                        done_total,
                        workflow_mapper,
                        config=config,
                        session_start_time=session_start_time,
                        dataset_label=_dataset_label,
                        datasets=selected_datasets,
                    )

            # End of severity loop - continue to scan selection loop
            # (User pressed 'b' or 'q' from severity menu)

    finally:
        # Always save session on exit (handles early exits via q, Ctrl+C, or errors)
        # Only save if scan was actually selected (dataset_id != 0)
        if dataset_id != 0:
            save_session(
                dataset_id,
                session_start_time,
                in_progress_count=len(in_progress_total),
                done_count=len(done_total),
                additional_dataset_ids=_additional_dataset_ids(selected_datasets),
            )

            # Session summary with rich statistics (only if work was done)
            if in_progress_total or done_total:
                # Type guard: dataset_dir must be defined if any work was done
                if dataset_dir is not None:
                    show_session_statistics(
                        session_start_time,
                        in_progress_total,
                        done_total,
                        dataset_dir,
                        dataset_id=dataset_id,
                        dataset_ids=(
                            all_dataset_ids if len(all_dataset_ids) > 1 else None
                        ),
                    )

            # Always end session (mark session_end timestamp in database)
            delete_session(dataset_id)


# === Typer CLI ===
# Main app + sub-apps (import, scan, config, workflow, creds)

app = typer.Typer(
    help="cerno — faster review & tooling runner for vulnerability datasets",
    add_completion=True,
)
_console = _console_global

# Sub-applications
import_app = typer.Typer(help="Import data from various sources into cerno")

dataset_app = typer.Typer(
    help="Dataset management - list, delete and compare datasets, and show host history"
)

config_app = typer.Typer(help="Configuration management - view and modify settings")

workflow_app = typer.Typer(help="Workflow management - list available workflows")

creds_app = typer.Typer(
    help="NetExec credential inspection - list refs and reveal cleartext (local)"
)

# Register sub-apps with main app
app.add_typer(import_app, name="import")
app.add_typer(dataset_app, name="dataset")
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


DEMO_NUCLEI_INITIAL_DATASET = "Cerno_Demo_Nuclei_Initial"
DEMO_NUCLEI_EXPANDED_DATASET = "Cerno_Demo_Nuclei_Expanded"
DEMO_BURP_DATASET = "Cerno_Demo_Burp"


def _import_demo_nuclei(
    nuclei_file: Path, dataset_name: str, overwrite: bool = False
) -> tuple[str, bool]:
    """Import a bundled demo nuclei results file.

    Mirrors :func:`_import_demo_nessus` -- same hash-based idempotency, same
    ``--overwrite`` semantics, and the same deliberate bypass of the interactive
    duplicate prompt. The one difference is that the dataset name must be supplied:
    nuclei output has no equivalent of a ``.nessus`` ``Report@name``.

    Args:
        nuclei_file: Bundled demo results file (a ``-je`` JSON array).
        dataset_name: Dataset name to import under.
        overwrite: Replace an existing scan whose source file changed.

    Returns:
        Tuple of (dataset_name, did_import).
    """
    from cerno_pkg.constants import DATASETS_ROOT
    from cerno_pkg.database import compute_file_hash
    from cerno_pkg.models import Dataset
    from cerno_pkg.nuclei_import import import_nuclei_file

    out_dir = DATASETS_ROOT / dataset_name
    new_file_hash = compute_file_hash(nuclei_file)
    existing_dataset = Dataset.get_by_name(dataset_name)

    if existing_dataset:
        if existing_dataset.source_file_hash == new_file_hash:
            info(f"Dataset already imported: {dataset_name}")
            return dataset_name, False
        if not overwrite:
            warn(f"Dataset exists with different content, skipping: {dataset_name}")
            warn("Use `cerno demo --overwrite` to replace demo datasets.")
            return dataset_name, False

        if not Dataset.delete_by_name(dataset_name):
            raise RuntimeError(f"Failed to replace existing dataset: {dataset_name}")
        info(f"Replaced existing dataset: {dataset_name}")

    out_dir.mkdir(parents=True, exist_ok=True)
    result = import_nuclei_file(nuclei_file, out_dir, dataset_name=dataset_name)
    ok(f"Imported {dataset_name}: {result.finding_types_exported} findings")
    return dataset_name, True


def _import_demo_burp(
    burp_file: Path, dataset_name: str, overwrite: bool = False
) -> tuple[str, bool]:
    """Import the bundled demo Burp report.

    Mirrors :func:`_import_demo_nuclei` exactly -- same hash-based idempotency,
    same ``--overwrite`` semantics, same deliberate bypass of the interactive
    duplicate prompt, and the same need for an explicit dataset name, since a Burp
    report has no equivalent of a ``.nessus`` ``Report@name`` either.

    Args:
        burp_file: Bundled demo report (Burp's "Report issues" XML export).
        dataset_name: Dataset name to import under.
        overwrite: Replace an existing scan whose source file changed.

    Returns:
        Tuple of (dataset_name, did_import).
    """
    from cerno_pkg.burp_import import import_burp_file
    from cerno_pkg.constants import DATASETS_ROOT
    from cerno_pkg.database import compute_file_hash
    from cerno_pkg.models import Dataset

    out_dir = DATASETS_ROOT / dataset_name
    new_file_hash = compute_file_hash(burp_file)
    existing_dataset = Dataset.get_by_name(dataset_name)

    if existing_dataset:
        if existing_dataset.source_file_hash == new_file_hash:
            info(f"Dataset already imported: {dataset_name}")
            return dataset_name, False
        if not overwrite:
            warn(f"Dataset exists with different content, skipping: {dataset_name}")
            warn("Use `cerno demo --overwrite` to replace demo datasets.")
            return dataset_name, False

        if not Dataset.delete_by_name(dataset_name):
            raise RuntimeError(f"Failed to replace existing dataset: {dataset_name}")
        info(f"Replaced existing dataset: {dataset_name}")

    out_dir.mkdir(parents=True, exist_ok=True)
    result = import_burp_file(burp_file, out_dir, dataset_name=dataset_name)
    ok(f"Imported {dataset_name}: {result.finding_types_exported} findings")
    return dataset_name, True


def _import_demo_nessus(nessus_file: Path, overwrite: bool = False) -> tuple[str, bool]:
    """Import a bundled demo Nessus file without post-import tool suggestions."""
    from cerno_pkg.constants import DATASETS_ROOT
    from cerno_pkg.database import compute_file_hash
    from cerno_pkg.models import Dataset
    from cerno_pkg.nessus_import import (
        extract_dataset_name_from_nessus,
        import_nessus_file,
    )

    dataset_name = extract_dataset_name_from_nessus(nessus_file)
    out_dir = DATASETS_ROOT / dataset_name
    new_file_hash = compute_file_hash(nessus_file)
    existing_dataset = Dataset.get_by_name(dataset_name)

    if existing_dataset:
        if existing_dataset.source_file_hash == new_file_hash:
            info(f"Dataset already imported: {dataset_name}")
            return dataset_name, False
        if not overwrite:
            warn(f"Dataset exists with different content, skipping: {dataset_name}")
            warn("Use `cerno demo --overwrite` to replace demo datasets.")
            return dataset_name, False

        if not Dataset.delete_by_name(dataset_name):
            raise RuntimeError(f"Failed to replace existing dataset: {dataset_name}")
        info(f"Replaced existing dataset: {dataset_name}")

    out_dir.mkdir(parents=True, exist_ok=True)
    result = import_nessus_file(
        nessus_file=nessus_file,
        output_dir=out_dir,
        dataset_name=dataset_name,
        include_ports=True,
    )
    ok(f"Imported {dataset_name}: {result.finding_types_exported} findings")
    return dataset_name, True


@app.command(name="mcp")
def mcp_cmd() -> None:
    """Serve Cerno's findings database and tooling over the Model Context Protocol.

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


@app.command(name="check", help="Check external tool availability and exit")
def check_cmd() -> None:
    """Report which external tools Cerno can find on PATH, then exit.

    Was ``cerno review --check``. Promoted to a command because it is an
    action rather than a review preference, and because it is then
    discoverable in ``cerno --help``.
    """
    from cerno_pkg.render import render_tool_availability_table

    if not root_or_sudo_available():
        warn(
            "Not running as root and no 'sudo' found — "
            "some scan types (e.g., UDP) may fail."
        )

    render_tool_availability_table(include_unavailable=True)


@app.command(name="demo", help="Prepare bundled demo datasets and NetExec enrichment")
def demo_cmd(
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help="Replace existing demo datasets if their source files changed.",
    ),
    no_nxc: bool = typer.Option(
        False,
        "--no-nxc",
        help="Import demo datasets without configuring the bundled NetExec workspace.",
    ),
) -> None:
    """Prepare Cerno demo data.

    Imports the bundled initial and expanded Nessus datasets, and by default points
    `nxc_workspace_path` at the bundled synthetic NetExec workspace.
    """
    from cerno_pkg import load_config, save_config, get_config_path
    from cerno_pkg.nxc_db import reset_nxc_manager

    try:
        assets_dir = _demo_assets_dir()
    except FileNotFoundError as exc:
        err(str(exc))
        raise typer.Exit(1)

    initial_dataset = assets_dir / "cerno-demo-initial.nessus"
    expanded_dataset = assets_dir / "cerno-demo-expanded.nessus"
    initial_nuclei = assets_dir / "cerno-demo-nuclei-initial.json"
    expanded_nuclei = assets_dir / "cerno-demo-nuclei-expanded.json"
    burp_report = assets_dir / "cerno-demo-burp-scan.xml"
    nxc_workspace = assets_dir / "nxc-workspace"

    demo_datasets = (
        initial_dataset,
        expanded_dataset,
        initial_nuclei,
        expanded_nuclei,
        burp_report,
    )
    missing = [path for path in demo_datasets if not path.exists()]
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
    for nessus_file in (initial_dataset, expanded_dataset):
        _, did_import = _import_demo_nessus(nessus_file, overwrite=overwrite)
        if did_import:
            imported += 1

    # The nuclei halves target exactly the web services the Nessus datasets found,
    # so they land on the same host rows and can be reviewed side by side.
    for nuclei_file, dataset_name in (
        (initial_nuclei, DEMO_NUCLEI_INITIAL_DATASET),
        (expanded_nuclei, DEMO_NUCLEI_EXPANDED_DATASET),
    ):
        _, did_import = _import_demo_nuclei(
            nuclei_file, dataset_name, overwrite=overwrite
        )
        if did_import:
            imported += 1

    # The Burp half targets the same web services again, from a third angle:
    # one finding per issue type, with several instances merged per host:port.
    _, did_import = _import_demo_burp(
        burp_report, DEMO_BURP_DATASET, overwrite=overwrite
    )
    if did_import:
        imported += 1

    _console_global.print()
    ok(f"Demo setup complete: {imported} dataset(s) imported or updated.")
    info("Next commands:")
    info("  cerno dataset list")
    info("  cerno dataset compare Cerno_Demo_Initial Cerno_Demo_Expanded")
    info(
        f"  cerno dataset compare {DEMO_NUCLEI_INITIAL_DATASET} "
        f"{DEMO_NUCLEI_EXPANDED_DATASET}"
    )
    info("  cerno review")
    info(
        "At the dataset prompt, select a Nessus, a nuclei and the Burp dataset "
        "together (e.g. '2,4,5') to review all three sources side by side."
    )
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
    """cerno CLI - faster review & tooling runner for vulnerability datasets."""
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
def review() -> None:
    """
    Run interactive review mode with database-driven workflow.

    This command requires datasets to be imported into the database first.
    Use 'cerno import' to import findings before reviewing.

    Takes no options: everything it used to accept as a flag is a
    ``config.yaml`` key, so the preference persists instead of being retyped.
    See ``cerno config show`` for current values.

        show_banner                 was -q / --quiet
        tools_enabled               was --no-tools
        custom_workflows_path       was -w / --custom-workflows
        custom_workflows_exclusive  was --custom-workflows-only
        proxychains_enabled         was --proxy / --no-proxy

    ``cerno review --check`` is now the ``cerno check`` command.

    Usage:
        cerno review                     # Select from imported datasets
        cerno import nessus scan.nessus  # Import findings first if needed
    """
    config = get_current_config()

    if config.show_banner:
        display_banner()
        _console_global.print()  # Add spacing after banner

    try:
        main()
    except KeyboardInterrupt:
        warn("\nInterrupted — goodbye.")


def _show_nuclei_suggestion(dataset_name: str) -> None:
    """Generate nuclei command suggestion from discovered HTTP services.

    Queries host_services table for HTTP/HTTPS services, writes URLs to a file,
    and displays a nuclei command suggestion.

    Args:
        dataset_name: Name of the dataset to query
    """
    try:
        from cerno_pkg.models import Dataset, get_http_urls_for_dataset
        from cerno_pkg.constants import DATASETS_ROOT

        dataset = Dataset.get_by_name(dataset_name)
        if not dataset or dataset.dataset_id is None:
            return

        urls = get_http_urls_for_dataset(dataset.dataset_id)

        if not urls:
            return  # No HTTP services discovered — skip silently

        # Write URLs to file
        urls_dir = DATASETS_ROOT / dataset_name
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
            f"   Found {len(urls)} HTTP/HTTPS service(s) — the URL(s) have been "
            f"written to {urls_file}"
        )
        # Built from config (templates dir, profile, User-Agent, concurrency) with
        # every output path inside the dataset directory, so the operator can run it
        # and hand the JSON straight back to `cerno import nuclei`.
        from cerno_pkg.tools import NUCLEI_OUTPUT_NAMES, build_nuclei_cmd

        nuclei_cmd = build_nuclei_cmd(urls_file, urls_dir)
        info(f"   {nuclei_cmd}\n")
        info("   Then import the results into this database:")
        info(f"   cerno import nuclei {urls_dir / NUCLEI_OUTPUT_NAMES['json']}\n")

    except Exception:
        pass  # Non-fatal — don't break import flow


def show_nessus_tool_suggestions(nessus_file: Path, dataset_name: str) -> None:
    """
    Display suggested tool commands after an import completes.

    Args:
        nessus_file: Path to the original .nessus file
        dataset_name: Name of the imported dataset (for DB queries)
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
    _show_nuclei_suggestion(dataset_name)

    info("Tip: Copy these commands to run them in your terminal.\n")


# === Import Sub-App Commands ===
# Grouped under 'cerno import'


@import_app.command(
    name="nessus",
    help="Import .nessus file (or directory of .nessus files) and populate database with findings",
)
def import_dataset(
    nessus: Path = typer.Argument(
        ..., help="Path to a .nessus file or directory containing .nessus files"
    ),
) -> None:
    """
    Import .nessus file(s) into the database.

    Accepts a single .nessus file or a directory. When given a directory, recursively
    discovers all .nessus files, lists them for confirmation, then imports each in sequence.
    The dataset name is taken from the .nessus report name. No per-finding_type files are
    written; ~/.cerno/datasets/<dataset_name>/ only receives http_urls.txt when web
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


def _show_severity_breakdown(severities: dict) -> None:
    """Print an import's severity breakdown as a table (shared by all sources).

    Args:
        severities: Mapping of ``severity_int`` to finding count.
    """
    if not severities:
        return

    from rich import box
    from rich.table import Table

    from cerno_pkg.ansi import style_if_enabled
    from cerno_pkg.nessus_import import severity_label_from_int
    from cerno_pkg.render import severity_cell

    _console_global.print()  # Blank line before table
    info("Severity Breakdown:")

    sev_table = Table(
        show_header=True,
        header_style=style_if_enabled("bold cyan"),
        box=box.SIMPLE,
    )
    sev_table.add_column("Severity", style=style_if_enabled("cyan"))
    sev_table.add_column("Findings", justify="right", style=style_if_enabled("yellow"))

    # Sort by severity (highest first: 4->0), skipping empty buckets
    for sev_int in sorted(severities.keys(), reverse=True):
        count = severities[sev_int]
        if count > 0:
            sev_table.add_row(
                severity_cell(severity_label_from_int(sev_int)), str(count)
            )

    _console_global.print(sev_table)


def _resolve_duplicate_dataset(dataset_name: str, source_file: Path) -> Optional[str]:
    """Settle a dataset-name collision before importing, whatever the source.

    Shared by every ``cerno import`` subcommand so each source behaves the same
    on re-import.

    Args:
        dataset_name: Dataset name the importer intends to use.
        source_file: File being imported (its hash decides "identical").

    Returns:
        The dataset name to import under -- the original, or a suffixed one if the
        operator chose to rename -- or None to skip/cancel the import.
    """
    from cerno_pkg.database import compute_file_hash
    from cerno_pkg.models import Dataset

    existing_dataset = Dataset.get_by_name(dataset_name)
    if not existing_dataset:
        return dataset_name

    if existing_dataset.source_file_hash == compute_file_hash(source_file):
        ok(f"Dataset '{dataset_name}' already imported (identical file). Skipping.")
        return None

    warn(f"A dataset named '{dataset_name}' already exists.")
    if existing_dataset.created_at:
        warn(f"Existing: imported on {existing_dataset.created_at}")
    warn(f"New file: {source_file.name}")
    _console_global.print()

    for choice in (
        "1. Overwrite existing scan",
        "2. Import with new name (add suffix)",
        "3. Cancel import",
    ):
        _console_global.print(f"  {choice}")

    ans = Prompt.ask("\nChoice", default="3").strip()

    if ans == "1":
        info("Overwriting existing scan...")
        return dataset_name
    if ans == "2":
        counter = 2
        candidate = f"{dataset_name}_{counter}"
        while Dataset.get_by_name(candidate):
            counter += 1
            candidate = f"{dataset_name}_{counter}"
        info(f"Importing as: {candidate}")
        return candidate

    info("Import cancelled.")
    return None


def _import_single_nessus(nessus: Path) -> bool:
    """Import a single .nessus file. Returns True on success, False on skip/cancel."""
    from cerno_pkg.nessus_import import (
        import_nessus_file,
        extract_dataset_name_from_nessus,
    )
    from cerno_pkg.constants import DATASETS_ROOT

    # Always extract dataset name from .nessus file for consistency with database
    dataset_name = extract_dataset_name_from_nessus(nessus)

    # Determine output directory (always use DATASETS_ROOT/<dataset_name>)
    out_dir = DATASETS_ROOT / dataset_name
    info(f"Using dataset name: {dataset_name}")

    # Check for duplicate imports
    resolved = _resolve_duplicate_dataset(dataset_name, nessus)
    if resolved is None:
        return False
    dataset_name = resolved
    out_dir = DATASETS_ROOT / dataset_name

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
                dataset_name=dataset_name,
                include_ports=True,
            )

        ok(f"Import complete: {result.finding_types_exported} findings")

        _show_severity_breakdown(result.severities)

    except Exception as e:
        err(f"Import failed: {e}")
        return False

    # Show suggested tool commands
    _console_global.print()  # Blank line for spacing
    show_nessus_tool_suggestions(nessus, dataset_name)
    return True


NUCLEI_SUFFIXES: tuple[str, ...] = (".json", ".jsonl")
"""File extensions ``cerno import nuclei`` accepts (``-je`` and ``-jle`` output)."""

BURP_SUFFIXES: tuple[str, ...] = (".xml",)
"""File extension ``cerno import burp`` accepts.

Not distinguishing on its own -- nmap and a renamed ``.nessus`` are also
``.xml`` -- so the parser checks the root element and the importer reports a
non-Burp file as such rather than as an import of zero findings."""


@import_app.command(
    name="nuclei",
    help="Import nuclei JSON/JSONL results (or a directory of them) and populate database with findings",
)
def import_nuclei(
    results: Path = typer.Argument(
        ...,
        help="Path to a nuclei .json/.jsonl results file, or a directory containing them",
    ),
    name: Optional[str] = typer.Option(
        None,
        "--name",
        help="Dataset name to import under (default: the file's stem)",
    ),
) -> None:
    """
    Import nuclei results into the database.

    Accepts either shape nuclei writes: a single JSON array (``-je``) or
    newline-delimited records (``-jle`` / ``-jsonl``). The shape is detected
    from the file contents, not the extension.

    Unlike a ``.nessus`` export, nuclei output carries no dataset name, so the
    file's stem is used unless ``--name`` is given. One finding is created per
    template; a template that matched the same host:port several times (six
    missing security headers, say) keeps every match's evidence in that host's
    finding_type output.

    Findings below ``nuclei_min_severity`` (config, default 0 = keep all) are
    dropped. This replaces the removed ``--min-severity`` flag.
    """
    min_severity = get_current_config().nuclei_min_severity
    # Validated here rather than at load: a hand-edited config.yaml can hold
    # anything, and silently importing everything would misrepresent the dataset.
    if not 0 <= min_severity <= 4:
        err(
            f"Invalid nuclei_min_severity: {min_severity}. Must be 0-4 "
            f"(0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)."
        )
        info("Fix with: cerno config set nuclei_min_severity 0")
        raise typer.Exit(1)

    if not results.exists():
        err(f"Path does not exist: {results}")
        raise typer.Exit(1)

    if results.is_dir():
        _import_nuclei_directory(results, min_severity)
    elif results.is_file():
        if results.suffix.lower() not in NUCLEI_SUFFIXES:
            err(f"File does not have a .json or .jsonl extension: {results.name}")
            raise typer.Exit(1)
        if not _import_single_nuclei(results, name, min_severity):
            raise typer.Exit(1)
    else:
        err(f"Path is not a file or directory: {results}")
        raise typer.Exit(1)


@import_app.command(
    name="burp",
    help="Import a Burp Suite XML report (or a directory of them) and populate database with findings",
)
def import_burp(
    report: Path = typer.Argument(
        ...,
        help="Path to a Burp Suite .xml report, or a directory containing them",
    ),
    name: Optional[str] = typer.Option(
        None,
        "--name",
        help="Dataset name to import under (default: the file's stem)",
    ),
) -> None:
    """
    Import a Burp Suite report into the database.

    Expects the XML produced by Burp's "Report issues" export (Target ->
    Issues -> Report issues, or Dashboard -> scan -> Export). Both
    request/response forms are read, base64-encoded or not.

    A Burp report carries no dataset name, so the file's stem is used unless
    ``--name`` is given. One finding is created per *issue type*; a type that
    fired several times on the same host:port (reflected XSS on three
    parameters, say) keeps every instance's evidence in that host's finding_type
    output, truncated to keep the finding panel readable.

    Issues the tester marked as false positives in Burp are skipped, and
    findings below ``burp_min_severity`` (config, default 0 = keep all) are
    dropped. Burp's scale tops out at High, so a floor of 4 drops everything.
    """
    min_severity = get_current_config().burp_min_severity
    # Validated here rather than at load: a hand-edited config.yaml can hold
    # anything, and silently importing everything would misrepresent the dataset.
    if not 0 <= min_severity <= 4:
        err(
            f"Invalid burp_min_severity: {min_severity}. Must be 0-4 "
            f"(0=Info, 1=Low, 2=Medium, 3=High; Burp has no Critical)."
        )
        info("Fix with: cerno config set burp_min_severity 0")
        raise typer.Exit(1)

    if not report.exists():
        err(f"Path does not exist: {report}")
        raise typer.Exit(1)

    if report.is_dir():
        _import_burp_directory(report, min_severity)
    elif report.is_file():
        if report.suffix.lower() not in BURP_SUFFIXES:
            err(f"File does not have a .xml extension: {report.name}")
            raise typer.Exit(1)
        if not _import_single_burp(report, name, min_severity):
            raise typer.Exit(1)
    else:
        err(f"Path is not a file or directory: {report}")
        raise typer.Exit(1)


def _derive_nuclei_dataset_name(results: Path) -> str:
    """Pick a dataset name for a nuclei results file that has no embedded name.

    The command Cerno suggests after an import writes
    ``~/.cerno/datasets/<scan>/nuclei.json``, so the file stem is *always*
    ``nuclei``. Naming every such import "nuclei" makes the second one collide
    with the first, so a file sitting directly inside a dataset directory is named
    after that directory instead -- keeping it tied to the Nessus scan whose
    target list produced it.

    Args:
        results: Path to the nuclei results file.

    Returns:
        A sanitized dataset name.
    """
    from cerno_pkg.constants import DATASETS_ROOT
    from cerno_pkg.nessus_import import sanitize_filename

    try:
        in_dataset_dir = results.resolve().parent.parent == DATASETS_ROOT.resolve()
    except OSError:
        in_dataset_dir = False

    if in_dataset_dir and results.parent.name:
        return sanitize_filename(f"{results.parent.name}-nuclei")
    return sanitize_filename(results.stem)


#: Stems that say nothing about which engagement a results file belongs to.
GENERIC_NUCLEI_STEMS = frozenset({"nuclei", "results", "output", "nuclei_results"})


def show_web_tool_suggestions(dataset_name: str, source_label: str = "nuclei") -> None:
    """Display suggested next steps after a web-source import completes.

    A web-only scan is a first-class case -- a web-app engagement may import
    nothing but nuclei results or a Burp report -- so it needs its own
    suggestions. The Nessus path reaches ``_show_nuclei_suggestion`` and stops
    there, which would leave an operator who started with nuclei or Burp no
    onward step at all.

    The web services are read back out of the database rather than from the
    file just imported, so this is source-agnostic; ``source_label`` only names
    the scanner in the prose.

    Args:
        dataset_name: Name of the imported dataset (for DB queries)
        source_label: Scanner that produced the dataset, for the wording.
    """
    try:
        from cerno_pkg.constants import DATASETS_ROOT
        from cerno_pkg.models import Dataset, get_http_urls_for_dataset
        from cerno_pkg.tools import NUCLEI_OUTPUT_NAMES, build_nuclei_cmd

        dataset = Dataset.get_by_name(dataset_name)
        if not dataset or dataset.dataset_id is None:
            return

        urls = get_http_urls_for_dataset(dataset.dataset_id)
        if not urls:
            return  # Nothing web-shaped to follow up on — skip silently

        out_dir = DATASETS_ROOT / dataset_name
        out_dir.mkdir(parents=True, exist_ok=True)
        urls_file = out_dir / "http_urls.txt"
        urls_file.write_text("\n".join(urls) + "\n")

        header("Suggested Next Steps")
        info(
            f"\n{source_label} matched {len(urls)} web service(s) — the URL(s) "
            f"have been written to {urls_file}\n"
        )

        info(fmt_action(f"1. nmap (fingerprint the services {source_label} matched):"))
        info(f"   nmap -sV -iL {urls_file} -oA {out_dir / 'nmap-web'}\n")

        info(fmt_action("2. nuclei (re-run with a wider template set):"))
        info(f"   {build_nuclei_cmd(urls_file, out_dir)}\n")
        info("   Then import the results into this database:")
        info(f"   cerno import nuclei {out_dir / NUCLEI_OUTPUT_NAMES['json']}\n")

        info(fmt_action("3. Corroborate these findings with a Nessus scan:"))
        info("   cerno import nessus /path/to/scan.nessus\n")

        info("Tip: Copy these commands to run them in your terminal.\n")

    except Exception:
        pass  # Non-fatal — never break the import flow over a hint


def _import_single_nuclei(
    results: Path, name: Optional[str], min_severity: int
) -> bool:
    """Import one nuclei results file. Returns True on success."""
    from cerno_pkg.constants import DATASETS_ROOT
    from cerno_pkg.nessus_import import sanitize_filename
    from cerno_pkg.nuclei_import import import_nuclei_file

    if results.stat().st_size == 0:
        warn(f"{results.name} is empty — nothing to import.")
        info(
            "nuclei writes an empty results file when no template matched — "
            "including when no target was reachable."
        )
        info("For pre-built data to explore, run: cerno demo")
        return False

    if name:
        dataset_name = sanitize_filename(name)
    else:
        dataset_name = _derive_nuclei_dataset_name(results)
        if dataset_name.lower() in GENERIC_NUCLEI_STEMS:
            warn(
                f"'{dataset_name}' says nothing about this engagement — "
                "pass --name to label the dataset."
            )
    info(f"Using dataset name: {dataset_name}")

    resolved = _resolve_duplicate_dataset(dataset_name, results)
    if resolved is None:
        return False
    dataset_name = resolved
    out_dir = DATASETS_ROOT / dataset_name

    header("Importing nuclei results to database")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task(f"Importing {results.name}...", total=None)
            result = import_nuclei_file(
                results,
                out_dir,
                dataset_name=dataset_name,
                min_severity=min_severity,
            )
    except Exception as e:
        err(f"Import failed: {e}")
        return False

    if result.finding_types_exported == 0:
        warn("No nuclei findings were imported.")
        if min_severity > 0:
            info(f"--min-severity {min_severity} may have filtered everything out.")
        else:
            info("The file parsed, but it contains no matched findings.")
        return False

    ok(f"Import complete: {result.finding_types_exported} findings")
    _show_severity_breakdown(result.severities)

    show_web_tool_suggestions(dataset_name)

    _console_global.print()
    info("Review them with: cerno review")
    return True


def _import_nuclei_directory(directory: Path, min_severity: int) -> None:
    """Discover and import every nuclei .json/.jsonl file under a directory."""
    from rich import box
    from rich.table import Table

    from cerno_pkg.ansi import safe_text, style_if_enabled

    files = sorted(
        f
        for suffix in NUCLEI_SUFFIXES
        for f in directory.rglob(f"*{suffix}")
        if f.is_file()
    )
    if not files:
        err(f"No .json or .jsonl files found in: {directory}")
        raise typer.Exit(1)

    count = len(files)
    header(
        f"Found {count} nuclei result file{'s' if count != 1 else ''} in {directory}"
    )

    table = Table(
        show_header=True,
        header_style=style_if_enabled("bold cyan"),
        box=box.SIMPLE,
    )
    table.add_column("#", justify="right", style=style_if_enabled("cyan"))
    table.add_column("File")
    table.add_column("Size", justify="right", style=style_if_enabled("yellow"))
    for idx, f in enumerate(files, 1):
        size = f.stat().st_size
        if size >= 1_048_576:
            human = f"{size / 1_048_576:.1f} MB"
        elif size >= 1024:
            human = f"{size / 1024:.1f} KB"
        else:
            human = f"{size} B"
        table.add_row(str(idx), safe_text(str(f.relative_to(directory))), human)
    _console_global.print(table)

    if not Confirm.ask(f"\nImport all {count} file(s) above?", default=True):
        info("Import cancelled.")
        raise typer.Exit(0)

    imported = skipped = 0
    for idx, f in enumerate(files, 1):
        _console_global.rule(f"[cyan][{idx}/{count}] {safe_text(f.name)}[/cyan]")
        if _import_single_nuclei(f, None, min_severity):
            imported += 1
        else:
            skipped += 1

    _console_global.rule("[bold cyan]Import Complete[/bold cyan]")
    ok(f"Summary: {imported} imported, {skipped} skipped")


#: Stems that say nothing about which engagement a Burp report belongs to.
GENERIC_BURP_STEMS = frozenset({"burp", "issues", "report", "burp_report", "export"})


def _import_single_burp(report: Path, name: Optional[str], min_severity: int) -> bool:
    """Import one Burp XML report. Returns True on success."""
    from cerno_pkg.burp_import import import_burp_file
    from cerno_pkg.constants import DATASETS_ROOT
    from cerno_pkg.nessus_import import sanitize_filename

    if report.stat().st_size == 0:
        warn(f"{report.name} is empty — nothing to import.")
        info("For pre-built data to explore, run: cerno demo")
        return False

    if name:
        dataset_name = sanitize_filename(name)
    else:
        dataset_name = sanitize_filename(report.stem)
        if dataset_name.lower() in GENERIC_BURP_STEMS:
            warn(
                f"'{dataset_name}' says nothing about this engagement — "
                "pass --name to label the dataset."
            )
    info(f"Using dataset name: {dataset_name}")

    resolved = _resolve_duplicate_dataset(dataset_name, report)
    if resolved is None:
        return False
    dataset_name = resolved
    out_dir = DATASETS_ROOT / dataset_name

    header("Importing Burp report to database")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=_console_global,
            transient=True,
        ) as progress:
            progress.add_task(f"Importing {report.name}...", total=None)
            result = import_burp_file(
                report,
                out_dir,
                dataset_name=dataset_name,
                min_severity=min_severity,
            )
    except Exception as e:
        err(f"Import failed: {e}")
        return False

    if result.finding_types_exported == 0:
        warn("No Burp findings were imported.")
        if min_severity > 0:
            info(
                f"burp_min_severity {min_severity} may have filtered everything "
                "out — Burp's highest severity is High (3)."
            )
        else:
            info(
                "The file parsed, but it holds no importable issues. Check it is "
                "Burp's 'Report issues' XML export, not an nmap or Nessus file."
            )
        return False

    ok(f"Import complete: {result.finding_types_exported} findings")
    _show_severity_breakdown(result.severities)

    # Source-agnostic: it reads the dataset's web services back out of the
    # database, so a Burp import flows into a nuclei sweep of the same targets.
    show_web_tool_suggestions(dataset_name, source_label="Burp")

    _console_global.print()
    info("Review them with: cerno review")
    return True


def _import_burp_directory(directory: Path, min_severity: int) -> None:
    """Discover and import every Burp .xml report under a directory."""
    from rich import box
    from rich.table import Table

    from cerno_pkg.ansi import safe_text, style_if_enabled

    files = sorted(
        f
        for suffix in BURP_SUFFIXES
        for f in directory.rglob(f"*{suffix}")
        if f.is_file()
    )
    if not files:
        err(f"No .xml files found in: {directory}")
        raise typer.Exit(1)

    count = len(files)
    header(f"Found {count} XML file{'s' if count != 1 else ''} in {directory}")
    info("Any that are not Burp reports will be reported and skipped.")

    table = Table(
        show_header=True,
        header_style=style_if_enabled("bold cyan"),
        box=box.SIMPLE,
    )
    table.add_column("#", justify="right", style=style_if_enabled("cyan"))
    table.add_column("File")
    table.add_column("Size", justify="right", style=style_if_enabled("yellow"))
    for idx, f in enumerate(files, 1):
        size = f.stat().st_size
        if size >= 1_048_576:
            human = f"{size / 1_048_576:.1f} MB"
        elif size >= 1024:
            human = f"{size / 1024:.1f} KB"
        else:
            human = f"{size} B"
        table.add_row(str(idx), safe_text(str(f.relative_to(directory))), human)
    _console_global.print(table)

    if not Confirm.ask(f"\nImport all {count} file(s) above?", default=True):
        info("Import cancelled.")
        raise typer.Exit(0)

    imported = skipped = 0
    for idx, f in enumerate(files, 1):
        _console_global.rule(f"[cyan][{idx}/{count}] {safe_text(f.name)}[/cyan]")
        if _import_single_burp(f, None, min_severity):
            imported += 1
        else:
            skipped += 1

    _console_global.rule("[bold cyan]Import Complete[/bold cyan]")
    ok(f"Summary: {imported} imported, {skipped} skipped")


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


# === Dataset Sub-App Commands ===
# Grouped under 'cerno dataset'


@dataset_app.command(
    name="list", help="List all imported datasets with statistics and review progress"
)
def list_datasets(
    json_output: bool = typer.Option(
        False, "--json", help="Output scan data as JSON (for scripting)"
    ),
) -> None:
    """Display all datasets in the database with finding counts and severity breakdown.

    The default view is compact (readable at 80 columns). Set
    ``dataset_list_wide`` to true for every severity column, or pass --json for
    machine-readable output (which bypasses the table entirely).
    """
    from cerno_pkg.models import Dataset
    from rich.table import Table

    wide = get_current_config().dataset_list_wide

    datasets = Dataset.get_all_with_stats()

    # --json: emit the raw rows and stop (scriptable, no Rich formatting).
    if json_output:
        import json

        print(json.dumps(datasets, indent=2, default=str))
        return

    if not datasets:
        info("No datasets found in database.")
        info(
            "Tip: Use 'cerno import nessus <scan.nessus>' or "
            "'cerno import nuclei <nuclei.json>' to import findings"
        )
        return

    from cerno_pkg.ansi import style_if_enabled
    from rich.text import Text

    def _fmt_last_reviewed(value: object) -> str:
        if not value:
            return "Never"
        try:
            from datetime import datetime

            return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d")
        except Exception:
            return str(value)

    def _fmt_source(dataset: dict) -> str:
        """Scanner that produced the dataset, or "-" for an empty dataset."""
        return str(dataset.get("source") or "-")

    def _done_pct(dataset: dict) -> str:
        total = dataset["total_findings"] or 0
        if not total:
            return "0%"
        return f"{round((dataset['done_count'] or 0) / total * 100)}%"

    table = Table(
        title="Imported Datasets",
        show_header=True,
        header_style=style_if_enabled("bold cyan"),
    )

    if wide:
        table.add_column("Dataset Name", style=style_if_enabled("yellow"), no_wrap=True)
        # min_width: "nessus"/"nuclei" are 6 chars and the column is useless
        # truncated to "ne…", so it keeps its width when the table is cramped.
        table.add_column(
            "Source", style=style_if_enabled("magenta"), no_wrap=True, min_width=6
        )
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
        for dataset in datasets:
            table.add_row(
                Text(dataset["dataset_name"]),  # Text: scan-derived
                Text(_fmt_source(dataset)),
                str(dataset["unique_hosts"] or 0),
                str(dataset["total_findings"] or 0),
                str(dataset["critical_count"] or 0),
                str(dataset["high_count"] or 0),
                str(dataset["medium_count"] or 0),
                str(dataset["low_count"] or 0),
                str(dataset["info_count"] or 0),
                str(dataset["done_count"] or 0),
                _fmt_last_reviewed(dataset["last_reviewed_at"]),
            )
    else:
        table.add_column("Dataset Name", style=style_if_enabled("yellow"), no_wrap=True)
        # min_width: "nessus"/"nuclei" are 6 chars and the column is useless
        # truncated to "ne…", so it keeps its width when the table is cramped.
        table.add_column(
            "Source", style=style_if_enabled("magenta"), no_wrap=True, min_width=6
        )
        table.add_column(
            "Hosts", justify="right", style=style_if_enabled("bright_cyan")
        )
        table.add_column("Findings", justify="right")
        table.add_column("Crit", justify="right", style=style_if_enabled("red"))
        table.add_column("High", justify="right", style=style_if_enabled("bright_red"))
        table.add_column("Done %", justify="right", style=style_if_enabled("green"))
        table.add_column("Last Reviewed", style=style_if_enabled("dim"))
        for dataset in datasets:
            table.add_row(
                Text(dataset["dataset_name"]),  # Text: scan-derived
                Text(_fmt_source(dataset)),
                str(dataset["unique_hosts"] or 0),
                str(dataset["total_findings"] or 0),
                str(dataset["critical_count"] or 0),
                str(dataset["high_count"] or 0),
                _done_pct(dataset),
                _fmt_last_reviewed(dataset["last_reviewed_at"]),
            )

    _console_global.print(table)
    _console_global.print()  # Blank line
    info(f"Total datasets: {len(datasets)}")
    if not wide:
        info(
            "Tip: set dataset_list_wide for all severities; "
            "--json outputs machine-readable data"
        )
    info("Use 'cerno review' to start reviewing a dataset")


@dataset_app.command(
    name="delete", help="Delete a dataset and its review data from database"
)
def delete_dataset(
    dataset_name: str = typer.Argument(..., help="Name of scan to delete")
) -> None:
    """Delete a dataset and its review data from the database.

    This will permanently remove (via ON DELETE CASCADE):
    - The dataset entry
    - All findings for this dataset and their host:port data
    - Discovered services for this dataset
    - Review sessions that include this dataset
    - Verification verdicts and their evidence
    - Per-finding Claude Assistant chat history

    Tool execution and artifact records (and the verified ports / NSE results /
    NetExec flags ingested from them) are retained for audit/history, but their
    links to deleted findings or sessions are cleared.

    This action cannot be undone!
    """
    from cerno_pkg.models import Dataset

    # Check if scan exists
    dataset = Dataset.get_by_name(dataset_name)
    if not dataset:
        err(f"Dataset not found: {dataset_name}")
        info("Use 'cerno dataset list' to see available datasets")
        raise typer.Exit(1)

    # Confirm deletion
    warn(f"You are about to delete dataset: {dataset_name}")
    warn("This will permanently delete dataset review data:")
    warn("  - Findings and their host:port combinations")
    warn("  - Discovered services")
    warn("  - Review sessions")
    warn("  - Verification verdicts and evidence")
    warn("  - Per-finding Claude Assistant chat history")
    info(
        "Tool executions, artifacts and their ingested results are retained, "
        "but links to this dataset's findings/sessions are cleared."
    )
    _console_global.print()  # Blank line

    try:
        response = Prompt.ask("Type the dataset name to confirm deletion").strip()
    except KeyboardInterrupt:
        _console_global.print()  # Newline after ^C
        info("Deletion cancelled")
        raise typer.Exit(0)

    if response != dataset_name:
        err("Dataset name does not match. Deletion cancelled.")
        raise typer.Exit(1)

    # Delete dataset
    if Dataset.delete_by_name(dataset_name):
        ok(f"Dataset deleted: {dataset_name}")
    else:
        err(f"Failed to delete dataset: {dataset_name}")
        raise typer.Exit(1)


@dataset_app.command(
    name="compare",
    help="Compare findings between two datasets to identify new, resolved, and persistent vulnerabilities",
)
def compare_datasets_cmd(
    dataset1: str = typer.Argument(..., help="First dataset name (baseline)"),
    dataset2: str = typer.Argument(..., help="Second dataset name (comparison)"),
    severity: int = typer.Option(
        0,
        "--severity",
        "-s",
        help="Minimum severity level (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)",
    ),
) -> None:
    """Compare findings between two datasets.

    Shows which vulnerabilities are new, resolved, or persistent between
    the baseline scan (scan1) and the comparison scan (scan2).

    Also shows host changes: new hosts, removed hosts, and persistent hosts.

    Examples:
        cerno dataset compare "Q1-2024" "Q2-2024"
        cerno dataset compare "Baseline" "Current" --severity 3
    """
    from cerno_pkg.cross_dataset import compare_datasets, get_dataset_by_name
    from cerno_pkg.render import render_dataset_comparison

    # Validate severity
    if severity < 0 or severity > 4:
        err(f"Invalid severity level: {severity}. Must be 0-4.")
        raise typer.Exit(1)

    # Look up datasets by name
    scan1_data = get_dataset_by_name(dataset1)
    if not scan1_data:
        err(f"Dataset not found: {dataset1}")
        info("Use 'cerno dataset list' to see available datasets")
        raise typer.Exit(1)

    scan2_data = get_dataset_by_name(dataset2)
    if not scan2_data:
        err(f"Dataset not found: {dataset2}")
        info("Use 'cerno dataset list' to see available datasets")
        raise typer.Exit(1)

    # Check if comparing same scan
    if scan1_data["dataset_id"] == scan2_data["dataset_id"]:
        warn("Comparing a dataset with itself - all findings will be persistent")

    # Perform comparison
    from cerno_pkg.cross_dataset import MixedSourceComparisonError

    try:
        result = compare_datasets(
            dataset_id_1=scan1_data["dataset_id"],
            dataset_id_2=scan2_data["dataset_id"],
            min_severity=severity,
        )
    except MixedSourceComparisonError as e:
        err(str(e))
        raise typer.Exit(1)

    if not result:
        err("Failed to compare datasets")
        raise typer.Exit(1)

    # Render results
    render_dataset_comparison(result)


@dataset_app.command(
    name="history",
    help="Show vulnerability history for a specific host across all datasets",
)
def host_history_cmd(
    host_ip: str = typer.Argument(..., help="Host IP address to query"),
) -> None:
    """Show vulnerability history for a specific host.

    Displays a timeline of all datasets where this host appeared,
    showing how its vulnerability profile has changed over time.

    Examples:
        cerno dataset history 192.168.1.10
        cerno dataset history 10.0.0.5
    """
    from cerno_pkg.cross_dataset import get_host_vulnerability_history
    from cerno_pkg.render import render_host_history

    # Get host history
    history = get_host_vulnerability_history(host_ip)

    if not history:
        err(f"No history found for host: {host_ip}")
        info("This host may not exist in any imported datasets")
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
def workflow_list() -> None:
    """Display all available workflows with finding IDs and descriptions.

    Reads the same two config keys the review TUI and the MCP workflow tools
    read -- ``custom_workflows_path`` and ``custom_workflows_exclusive`` -- via
    ``build_workflow_mapper()``. The former ``-w/--custom-workflows`` flag was
    the only way a custom file reached this command, which meant
    ``custom_workflows_path`` was silently ignored here while being honoured
    everywhere else.
    """
    from rich.table import Table
    from cerno_pkg.ansi import get_console

    console = get_console()

    config = get_current_config()
    workflow_mapper = build_workflow_mapper(config)
    if config.custom_workflows_path:
        mode = "exclusive" if config.custom_workflows_exclusive else "supplementing"
        info(f"Using custom workflows from {config.custom_workflows_path} ({mode})")

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
    # Folds rather than no_wrap: namespacing every id made the longest
    # multi-finding value ~160 chars, which with no_wrap squeezed the name
    # and description columns down to nothing.
    table.add_column("Finding ID(s)", style="cyan", max_width=34, overflow="fold")
    table.add_column("Workflow Name", style="yellow")
    table.add_column("Description", style="dim")

    for workflow in all_workflows:
        finding_ids = workflow.get("finding_type_id", "")
        workflow_name = workflow.get("workflow_name", "")
        description = workflow.get("description", "")

        # Truncate long descriptions
        if len(description) > 80:
            description = description[:77] + "..."

        table.add_row(finding_ids, workflow_name, description)

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
    - cerno.db and its WAL/SHM sidecars (all datasets, findings, sessions, tool executions)
    - config.yaml and config.yaml.backup (user configuration)
    - cerno.log and rotated log files
    - proxychains4.conf (generated proxy config)
    - artifacts/ directory (generated tool output)
    - datasets/ directory (per-dataset working directories, e.g. http_urls.txt)

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
    datasets_dir = cerno_dir / "datasets"

    warn("This will permanently delete the following from ~/.cerno/:")
    if db_files:
        warn(
            "  cerno.db       — entire database (datasets, findings, sessions, tool executions)"
        )
    if config_files:
        warn("  config.yaml    — user configuration (and any backup)")
    if log_files:
        warn(f"  cerno.log*     — {len(log_files)} log file(s)")
    if proxy_conf.exists():
        warn("  proxychains4.conf — generated proxy config")
    if artifacts_dir.exists():
        warn("  artifacts/     — generated tool output files")
    if datasets_dir.exists():
        warn("  datasets/         — per-dataset working directories")
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

    for directory in [artifacts_dir, datasets_dir]:
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
