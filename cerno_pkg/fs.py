"""Filesystem operations and path utilities.

This module provides the finding view (handle_finding_view), review-state
moves (move_review_state), page-size detection, file I/O helpers and work-file
generation for tool runs. Review state lives in the database, not in filenames.
"""

from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Any, TYPE_CHECKING

from rich.prompt import Prompt, Confirm

from .ansi import err, header, ok, warn, get_console, info, print_verbatim, safe_text
from .constants import (
    REVIEW_MOVE_LABELS,
    REVIEW_STATE_DONE,
    REVIEW_STATE_IN_PROGRESS,
    REVIEW_TRANSITIONS,
    SOURCE_OPERATOR,
    VERDICT_LABELS,
    get_results_root,
)

if TYPE_CHECKING:
    from .models import Finding, FindingType
    from .workflow_mapper import WorkflowMapper, Workflow


_console_global = get_console()


def finding_label(finding, finding_type=None) -> str:
    """Return a ``Finding <id>: <name>`` label for a finding.

    **This is a contract, not just a label.** `[H]` Compare and `[O]`
    Overlapping return *lists of these strings* as their groups, and
    ``tui.filter_finding_candidates`` re-derives the label from the ``FindingType``
    row and tests set membership against them. Two independent producers of the
    same literal format therefore have to agree exactly: change one and the
    group filter silently matches zero findings, with the
    ``[ACTIVE FILTER] Group #N`` footer still showing and no error anywhere.

    Every one of those sites calls this function, so the format is defined
    once. Do not inline it again.

    Note the no-finding_type fallback omits the name, which the membership test can
    never produce -- unreachable in practice, since the callers always pass
    both halves.
    """
    if finding_type:
        return (
            f"Finding {finding_type.finding_type_id}: {finding_type.finding_type_name}"
        )
    return f"Finding {finding.finding_type_id}"


def move_review_state(
    finding: "Finding",
    finding_type: Optional["FindingType"] = None,
    *,
    target: Optional[str] = None,
    quiet: bool = False,
) -> Optional[str]:
    """Move a finding to its next status (or ``target``) in the database.

    Statuses cycle Unreviewed -> In Progress -> Done -> Unreviewed; only those
    moves are allowed (``constants.REVIEW_TRANSITIONS``).

    Args:
        finding: Finding object to move
        finding_type: Optional FindingType object for display name
        target: Status to move to; defaults to the next status in the cycle
        quiet: Suppress the per-finding success message (bulk operations)

    Returns:
        The new review state, or None if nothing changed.
    """
    if target is None:
        target = REVIEW_TRANSITIONS[finding.review_state][0]
    moved = REVIEW_MOVE_LABELS[target].replace("Move", "Moved", 1)

    try:
        from .database import db_transaction

        with db_transaction() as conn:
            # The TUI is the operator channel; attribution is never defaulted.
            finding.transition_review_state(target, SOURCE_OPERATOR, conn=conn)
    except Exception as e:
        from .logging_setup import log_error

        log_error(f"Failed to move review state: {e}")
        err(f"Could not {REVIEW_MOVE_LABELS[target].lower()}: {e}")
        return None

    if not quiet:
        ok(f"{moved}: {finding_label(finding, finding_type)}")
    return target


_VERDICT_CHOICES: dict[str, str] = {
    "1": "confirmed",
    "2": "false_positive",
    "3": "unable",
}


def update_authored_finding_interactive(finding: "Finding") -> bool:
    """Prompt the operator to edit a hand-authored finding, and write it.

    The counterpart to :func:`record_verdict`: prompt, write, report. Only
    findings from :data:`~cerno_pkg.constants.AUTHORED_SOURCES` reach here --
    the ``[U]`` action is hidden otherwise and :func:`handle_finding_view`
    refuses an explicit ``u`` on anything else, because a scanner finding is a
    record of what the scanner reported.

    An ``agent:`` finding is editable here just like an ``operator:`` one: the
    operator owns the engagement and must be able to correct what an agent
    asserted. The finding keeps its original namespace, so the edit does not
    reattribute it.

    Returns:
        True if the finding was changed (so the caller can refresh its view).
    """
    from .authored_findings import AuthoredFindingError, update_authored_finding
    from .tui import prompt_edit_finding

    fid = getattr(finding, "finding_id", None)
    if not isinstance(fid, int):
        warn("This finding has no database id - cannot edit it")
        return False

    edited = prompt_edit_finding(fid)
    if edited is None:
        return False

    try:
        finding_type_id = update_authored_finding(
            fid,
            title=edited.title,
            severity_int=edited.severity_int,
            targets=edited.targets,
            description=edited.description,
            cves=edited.cves,
            reference_url=edited.reference_url,
        )
    except AuthoredFindingError as exc:
        err(f"Could not update the finding: {exc}")
        return False

    ok(f"Updated {finding_type_id}.")
    return True


def record_verdict(
    finding: "Finding", finding_type: Optional["FindingType"] = None
) -> bool:
    """Prompt the operator to record a verification verdict for a finding.

    Writes an append-only verdict (truth value, distinct from review status) via
    ``FindingVerdict.set``. On a confirmed / false-positive verdict, offers to
    advance the finding to Done.

    Returns:
        True if the finding was moved to Done as a result (so the caller can
        refresh the list), else False.
    """
    from .models import FindingVerdict
    from .database import db_transaction

    fid = getattr(finding, "finding_id", None)
    if not isinstance(fid, int):
        warn("Finding not available - cannot record a verdict.")
        return False

    header("Record Verification Verdict")
    info("1) Confirmed")
    info("2) False Positive")
    info("3) Unable to Verify")
    try:
        choice = Prompt.ask(
            "Verdict (Enter to cancel)",
            choices=["1", "2", "3", ""],
            default="",
            show_choices=False,
        ).strip()
    except KeyboardInterrupt:
        choice = ""
    label = _VERDICT_CHOICES.get(choice)
    if label is None:
        info("Cancelled - no verdict recorded.")
        return False

    note = Prompt.ask("Note (optional)", default="").strip() or None
    try:
        with db_transaction() as conn:
            # The TUI is the operator channel.
            FindingVerdict.set(fid, label, SOURCE_OPERATOR, note=note, conn=conn)
    except Exception as e:
        from .logging_setup import log_error

        log_error(f"Failed to record verdict: {e}")
        err(f"Could not record verdict: {e}")
        return False

    ok(f"Verdict recorded: {VERDICT_LABELS.get(label, label)}")

    # A verified finding is a candidate to close out. Only confirmed / false
    # positive offer the move; 'unable' stays open for follow-up.
    if label in ("confirmed", "false_positive") and (
        finding.review_state != REVIEW_STATE_DONE
    ):
        if Confirm.ask("Move this finding to Done now?", default=True):
            # Advance through the allowed cycle (unreviewed -> in_progress -> done).
            while finding.review_state != REVIEW_STATE_DONE:
                nxt = REVIEW_TRANSITIONS[finding.review_state][0]
                move_review_state(
                    finding, finding_type, target=nxt, quiet=(nxt != REVIEW_STATE_DONE)
                )
                if finding.review_state != nxt:
                    break  # a transition failed; stop advancing
            return finding.review_state == REVIEW_STATE_DONE
    return False


def build_results_paths(
    dataset_dir: Path, sev_dir: Path, finding_type_filename: str
) -> tuple[Path, Path]:
    """Build output directory and base path for scan results.

    Creates a structured output directory based on dataset name, severity level,
    and finding_type name with a timestamped run identifier.

    Args:
        dataset_dir: Directory containing the dataset
        sev_dir: Directory for the severity level
        finding_type_filename: Name of the finding_type file

    Returns:
        Tuple of (output_directory, output_base_path) where output_base_path
        includes a timestamp prefix for unique run identification
    """
    stem = Path(finding_type_filename).stem
    severity_label = pretty_severity_label(sev_dir.name)
    output_dir = get_results_root() / dataset_dir.name / severity_label / stem
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_base = output_dir / f"run-{timestamp}"
    return output_dir, output_base


def pretty_severity_label(name: str) -> str:
    """Convert a severity directory name to a human-readable label.

    Expects format like "4_Critical" and converts to "Critical"; a plain
    label such as "High" is returned title-cased.

    Args:
        name: Directory name to convert

    Returns:
        Title-cased, space-separated severity label
    """
    match = re.match(r"^\d+_(.+)$", name)
    label = match.group(1) if match else name
    label = label.replace("_", " ").strip()
    return " ".join(w[:1].upper() + w[1:] for w in label.split())


# Module-level flag to track if fallback warning has been shown
_page_size_fallback_warned = False


def default_page_size() -> int:
    """Calculate page size from config or terminal height.

    Checks config for user override first, then auto-detects from terminal.
    Falls back to 12 if detection fails (logs hint on first occurrence).

    Returns:
        Number of items per page (minimum 8)
    """
    global _page_size_fallback_warned

    # Check config first for manual override
    from .config import load_config

    config = load_config()

    if config.default_page_size:
        return max(8, config.default_page_size)

    # Auto-detect from terminal height
    try:
        terminal_height = shutil.get_terminal_size((80, 24)).lines
        return max(8, terminal_height - 15)
    except Exception:
        # Fallback to 12, log hint once
        if not _page_size_fallback_warned:
            from .logging_setup import log_debug

            log_debug(
                "Terminal height detection failed, using default page size (12). "
                "Set 'default_page_size' in config.yaml to override."
            )
            _page_size_fallback_warned = True
        return 12


def write_work_files(
    workdir: Path, hosts: list[str], ports_str: str, udp: bool
) -> tuple[Path, Path, Path]:
    """Write temporary work files for tool execution.

    Creates lists of IPs and host:port combinations for use with security
    scanning tools like nmap and netexec.

    Args:
        workdir: Working directory to write files to
        hosts: List of host IPs or hostnames
        ports_str: Comma-separated port list string
        udp: Whether to generate UDP IP list

    Returns:
        Tuple of (tcp_ips_path, udp_ips_path, tcp_sockets_path)
    """
    workdir.mkdir(parents=True, exist_ok=True)
    tcp_ips = workdir / "tcp_ips.list"
    udp_ips = workdir / "udp_ips.list"
    tcp_sockets = workdir / "tcp_host_ports.list"

    # Trailing newline only when there is something to terminate: an empty list
    # must produce an empty file, not one blank line. A blank line made the
    # TUI's host_count read 1 where the MCP's _parse_nmap_output read 0.
    tcp_ips.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    if udp:
        udp_ips.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    if ports_str:
        with tcp_sockets.open("w", encoding="utf-8") as f:
            for host in hosts:
                f.write(f"{host}:{ports_str}\n")
    return tcp_ips, udp_ips, tcp_sockets


# ===================================================================
# File/Finding Processing and Viewing (moved from cerno.py)
# ===================================================================


def display_workflow(workflow: "Workflow") -> None:
    """
    Display a verification workflow for one or more findings.

    Args:
        workflow: Workflow object to display
    """
    from rich.panel import Panel

    console = get_console()

    # Header
    header(f"Verification Workflow: {workflow.workflow_name}")
    info(f"Finding ID(s): {workflow.finding_type_id}")
    info(f"Description: {workflow.description}")
    _console_global.print()

    # Steps
    from cerno_pkg.ansi import style_if_enabled

    for idx, step in enumerate(workflow.steps, 1):
        step_panel = Panel(
            # safe_text: workflow titles/notes come from YAML, which may be a
            # user-supplied custom_workflows_path.
            f"[bold cyan]{safe_text(step.title)}[/bold cyan]\n\n"
            + "\n".join(f"  {cmd}" for cmd in step.commands)
            + (
                f"\n\n[yellow]Notes:[/yellow] {safe_text(step.notes)}"
                if step.notes
                else ""
            ),
            title=f"Step {idx}",
            border_style=style_if_enabled("cyan"),
        )
        console.print(step_panel)
        _console_global.print()

    # References
    if workflow.references:
        info("References:")
        for ref in workflow.references:
            _console_global.print(f"  - {ref}")
        _console_global.print()

    # Prominent continuation hint
    from rich.text import Text

    hint = Text()
    hint.append("[Press ", style="dim")
    hint.append("Enter", style="bold yellow")
    hint.append(" to continue]", style="dim")
    _console_global.print(hint)
    _console_global.print()

    try:
        Prompt.ask("", default="")
    except KeyboardInterrupt:
        pass


def handle_finding_view(
    chosen: Path,
    finding: Optional["Finding"] = None,
    finding_type: Optional["FindingType"] = None,
    details_url: Optional[str] = None,
    workflow_mapper: Optional["WorkflowMapper"] = None,
    dataset_dir: Optional[Path] = None,
    sev_dir: Optional[Path] = None,
    hosts: Optional[List[str]] = None,
    ports_str: Optional[str] = None,
    use_sudo: bool = False,
    use_proxy: bool = False,
) -> Optional[str]:
    """
    Interactive finding view menu: Info [I], Details [D], View hosts [V], CVE info [E],
    Workflow [W], NetExec data [N], Run tool [T], Ask Claude [A], Record verdict [R],
    Move status [M].

    NOTE: This function uses FindingType and Finding database objects directly for all operations.
    No filename parsing is performed - finding_type_id comes from FindingType.finding_type_id field.

    Args:
        chosen: Synthetic finding_type file path (used only for display, not parsing)
        finding: Finding database object (None if database not available)
        finding_type: FindingType metadata object (None if database not available) - used for CVE lookup, workflow check
        details_url: Unused (kept for call compatibility); CVEs come from finding_type.cves
        workflow_mapper: Optional workflow mapper for finding_type workflows
        dataset_dir: Dataset directory for tool workflow
        sev_dir: Severity directory for tool workflow
        hosts: List of target hosts for tool workflow
        ports_str: Comma-separated ports for tool workflow
        use_sudo: Whether to use sudo for tools
        use_proxy: Whether to route tools through proxychains4

    Returns:
        "back": User wants to go back to file selection
        "mark_complete": Finding was moved to Done
        None: Continue normally
    """
    # Lazy imports to avoid circular dependencies
    from .render import (
        file_raw_paged_text,
        file_raw_payload_text,
        grouped_paged_text,
        grouped_payload_text,
        hosts_only_paged_text,
        hosts_only_payload_text,
        build_evidence_details,
        display_finding_preview,
        print_action_menu,
        menu_pager,
        display_nxc_per_host_detail,
        render_finding_actions_footer,
    )
    from .tools import copy_to_clipboard, run_tool_workflow
    from .nxc_db import get_nxc_manager, reset_nxc_manager

    # Alias for consistency with original code
    _console = _console_global

    # Check if workflow is available
    has_workflow = False
    if workflow_mapper and finding_type:
        has_workflow = workflow_mapper.has_workflow(str(finding_type.finding_type_id))

    # Only a hand-authored finding is editable; see the [U] branch below.
    # Membership, not equality: `operator:` and `agent:` are both authored, and
    # testing one of them would leave the other's findings uneditable.
    from .constants import AUTHORED_SOURCES

    is_authored_finding = (
        finding_type is not None and finding_type.source in AUTHORED_SOURCES
    )

    # Check Claude Assistant availability (cheap: shutil.which + config load)
    from .claude_assistant import check_claude_available
    from .config import load_config as _load_config

    _cfg = _load_config()
    claude_installed = check_claude_available()
    has_claude = claude_installed and _cfg.claude_assistant_enabled

    # Loop to allow multiple actions on the same file
    while True:
        # Check if NetExec data is available for these hosts (refreshed each iteration)
        has_nxc_data = False
        if hosts:
            nxc_mgr = get_nxc_manager()
            if nxc_mgr:
                summary = nxc_mgr.get_hosts_enrichment(hosts)
                has_nxc_data = summary.hosts_with_data > 0

        # Render responsive action menu
        render_finding_actions_footer(
            review_state=finding.review_state if finding else None,
            has_workflow=has_workflow,
            has_nxc_data=has_nxc_data,
            has_claude=has_claude,
            claude_installed=claude_installed,
            use_proxy=use_proxy,
            no_tools=not _cfg.tools_enabled,
            is_authored_finding=is_authored_finding,
        )
        try:
            action_choice = Prompt.ask("Choose action").strip().lower()
        except KeyboardInterrupt:
            # User cancelled - treat as back
            return "back"

        # Handle Back action
        if action_choice in ("b", "back"):
            return "back"

        # Handle Move (next status) action
        if action_choice in ("m", "mark"):
            if finding is None:
                warn("Database not available - cannot change review state")
                continue
            if move_review_state(finding, finding_type) == REVIEW_STATE_DONE:
                return "mark_complete"
            # Now In Progress (stay in view), or move_review_state() reported why not
            continue

        # Handle Record verdict action
        if action_choice in ("r", "verdict"):
            if finding is None:
                warn("Database not available - cannot record a verdict")
                continue
            if record_verdict(finding, finding_type):
                return "mark_complete"
            continue

        # Handle Update finding action (hand-authored findings only)
        if action_choice in ("u", "update"):
            if finding is None:
                warn("Database not available - cannot edit this finding")
                continue
            if not is_authored_finding:
                warn(
                    "Only hand-authored findings can be edited; this one came "
                    "from a scanner."
                )
                info("Record a verdict with [R] instead.")
                continue
            if update_authored_finding_interactive(finding):
                # Everything on screen is now stale: the finding_type row carries the
                # new title and severity, and the targets may have changed
                # under the tool workflow's feet. Re-read both and redraw the
                # panel rather than leaving the operator looking at the old one.
                from .models import FindingType as _Plugin

                refreshed = _Plugin.get_by_id(str(finding.finding_type_id))
                if refreshed is not None:
                    finding_type = refreshed
                hosts, ports_str = finding.get_hosts_and_ports()
                if finding_type is not None:
                    display_finding_preview(
                        finding_type, finding, sev_dir, chosen, workflow_mapper
                    )
            continue

        # Handle Run tool action
        if action_choice in ("t", "tool"):
            # Review-only mode: [T] is hidden from the footer, but refuse here
            # too so typing it explicitly cannot start a tool run.
            if not _cfg.tools_enabled:
                warn(
                    "Tool prompts are disabled (tools_enabled is false). "
                    "Re-enable with: cerno config set tools_enabled true"
                )
                continue
            if dataset_dir is None or sev_dir is None or hosts is None:
                warn("Tool execution not available in this context.")
                continue
            if not finding_type or not finding:
                warn("Finding information not available for tool execution.")
                continue

            # Run tool workflow with database objects. Guard against any deeper
            # hard-exit (e.g. a require_cmd on a missing binary) so a tooling
            # problem never drops the operator out of the review session.
            try:
                run_tool_workflow(
                    finding_type,
                    finding,
                    dataset_dir,
                    sev_dir,
                    hosts,
                    ports_str or "",
                    use_sudo,
                )
            except SystemExit:
                warn("Tool execution aborted; returning to the finding menu.")
            # Reset NXC manager to pick up any new data from tool execution
            reset_nxc_manager()
            # After tool completes, loop back to show menu again
            continue

        # Handle NetExec context option
        if action_choice in ("n", "netexec", "nxc"):
            if has_nxc_data and hosts:
                display_nxc_per_host_detail(hosts)
            else:
                warn("No NetExec data available for these hosts.")
            continue

        # Handle Claude Assistant action
        if action_choice in ("a", "ask", "claude"):
            if not claude_installed:
                warn(
                    "Claude CLI not found on PATH. Install claude to use this feature."
                )
                continue
            if not has_claude:
                # Installed but off: show the data-path disclosure and let the
                # operator opt in (persisted). Decline returns to the menu.
                from .claude_assistant import ensure_enabled

                if not ensure_enabled(_cfg):
                    continue
                has_claude = True
            if finding is None or finding_type is None:
                warn("Finding information not available for Claude Assistant.")
                continue
            # Deferred import to avoid circular dependency (cerno.py imports fs.py)
            try:
                from cerno import browse_claude_chat

                _workflow = (
                    workflow_mapper.get_workflow(str(finding_type.finding_type_id))
                    if workflow_mapper and finding_type
                    else None
                )
                browse_claude_chat(
                    finding=finding,
                    finding_type=finding_type,
                    hosts=hosts or [],
                    workflow=_workflow,
                )
            except ImportError:
                warn("Claude Assistant not available in this context.")
            continue

        # Enter/skip keys treated as back navigation
        if action_choice in ("", "none", "skip"):
            return "back"

        # Handle workflow option
        if action_choice in ("w", "workflow"):
            if not finding_type:
                warn("Finding information not available.")
                continue
            if not has_workflow or workflow_mapper is None:
                warn("No workflow available for this finding.")
                continue

            finding_type_id = str(finding_type.finding_type_id)
            workflow = workflow_mapper.get_workflow(finding_type_id)
            if workflow:
                display_workflow(workflow)
            continue

        # Handle CVE info option (read-only from database)
        if action_choice in ("e", "cve"):
            # Use FindingType object already available as parameter
            try:
                header("CVE Information")

                if finding_type and finding_type.cves:
                    info(
                        f"Found {len(finding_type.cves)} CVE(s) for {finding_type.finding_type_id}:"
                    )
                    for cve in finding_type.cves:
                        info(f"{cve}")
                elif finding_type:
                    warn(
                        f"No CVEs associated with this finding ({finding_type.finding_type_id})."
                    )
                else:
                    warn("Finding information not available.")
            except Exception as exc:
                warn(f"Failed to retrieve CVE information: {exc}")

            continue

        # Handle Finding Info action
        if action_choice in ("i", "info"):
            # Redisplay the preview panel
            if finding_type is None or sev_dir is None or finding is None:
                warn("FindingType metadata not available - cannot display finding info")
                continue
            display_finding_preview(
                finding_type, finding, sev_dir, chosen, workflow_mapper
            )
            continue

        # Handle Finding Details action
        if action_choice in ("d", "details"):
            if finding is None or finding_type is None:
                warn("Database not available - cannot display finding details")
                continue

            # Generate and display finding_type output details
            details_text = build_evidence_details(finding, finding_type)

            if details_text:
                menu_pager(details_text)
            else:
                warn("No output recorded for this finding.")

            continue

        # Handle View file action - streamlined workflow
        if not action_choice in ("v", "view"):
            warn("Invalid action choice.")
            continue

        # Check if finding/finding_type is available (database mode)
        if finding is None or finding_type is None:
            warn("Database not available - cannot view file contents")
            continue

        # Default to grouped format (no prompt) for instant viewing
        text = grouped_paged_text(finding, finding_type)
        payload = grouped_payload_text(finding)

        # Display content immediately
        menu_pager(text)

        # Post-view actions: Copy, Change format, or Back
        print_action_menu(
            [("C", "Copy to clipboard"), ("F", "Change format"), ("B", "Back to menu")]
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
            # Offer format change
            print_action_menu(
                [("R", "Raw"), ("H", "Hosts only"), ("G", "Grouped (current)")]
            )
            try:
                format_choice = Prompt.ask("Choose format", default="g").lower()
            except KeyboardInterrupt:
                continue

            # Generate new format
            if format_choice in ("r", "raw"):
                text = file_raw_paged_text(finding, finding_type)
                payload = file_raw_payload_text(finding)
            elif format_choice in ("h", "hosts", "hosts-only"):
                text = hosts_only_paged_text(finding, finding_type)
                payload = hosts_only_payload_text(finding)
            else:
                continue  # Already in grouped

            if text and payload:
                menu_pager(text)
                # Offer clipboard after format change
                try:
                    if Confirm.ask("Copy to clipboard?", default=True):
                        ok_flag, detail = copy_to_clipboard(payload)
                        if ok_flag:
                            ok("Copied to clipboard.")
                        else:
                            warn(f"{detail}")
                except KeyboardInterrupt:
                    pass

        # Loop back to main action menu
        continue


def process_single_finding(
    chosen: Path,
    finding_type: "FindingType",
    finding: "Finding",
    dataset_dir: Path,
    sev_dir: Optional[Path],
    use_sudo: bool,
    in_progress_total: List[str],
    done_total: List[str],
    show_severity: bool = False,
    workflow_mapper: Optional["WorkflowMapper"] = None,
    use_proxy: bool = False,
) -> None:
    """
    Process a single finding: preview, view, run tools, move status (database-only).

    Args:
        chosen: Synthetic display path of the selected finding
        finding_type: FindingType metadata object
        finding: Finding database object (required)
        dataset_dir: Dataset directory
        sev_dir: Severity directory
        use_sudo: Whether sudo is available
        in_progress_total: List to track findings marked in progress
        done_total: List to track findings marked done
        show_severity: Whether to show severity label (for MSF mode)
        workflow_mapper: Optional workflow mapper for finding_type workflows
        use_proxy: Whether to route tools through proxychains4
    """
    # Lazy imports to avoid circular dependencies
    from .render import display_finding_preview

    # Get hosts and ports from database
    hosts, ports_str = finding.get_hosts_and_ports()

    # Construct display name from finding_type metadata
    display_name = finding_label(finding, finding_type)

    if not hosts:
        # A hand-authored finding may legitimately name no host -- an
        # engagement-level observation has none -- and refusing to open it
        # would make it uneditable, since [U] lives in this view.
        from .constants import AUTHORED_SOURCES

        if not finding_type or finding_type.source not in AUTHORED_SOURCES:
            info(
                "Finding has no affected hosts. This usually means the vulnerability doesn't affect any hosts."
            )
            return
        info("This finding names no affected host. Press [U] to add one.")

    # Display finding preview panel
    display_finding_preview(finding_type, finding, sev_dir, chosen, workflow_mapper)

    # details_url is no longer used by the finding view (CVEs and the Tenable
    # link come from the FindingType row); passed as None for call compatibility.
    details_url = None

    state_before = finding.review_state

    # View file and handle actions
    result = handle_finding_view(
        chosen,
        finding=finding,
        finding_type=finding_type,
        details_url=details_url,
        workflow_mapper=workflow_mapper,
        dataset_dir=dataset_dir,
        sev_dir=sev_dir,
        hosts=hosts,
        ports_str=ports_str,
        use_sudo=use_sudo,
        use_proxy=use_proxy,
    )

    # Tally state changes made during this view (finding is updated in place)
    if result == "mark_complete":
        done_total.append(display_name)
    elif (
        finding.review_state != state_before
        and finding.review_state == REVIEW_STATE_IN_PROGRESS
    ):
        in_progress_total.append(display_name)
