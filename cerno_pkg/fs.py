"""Filesystem operations and path utilities.

This module provides the finding view (handle_finding_view), review-state
moves (move_review_state), page-size detection, file I/O helpers and work-file
generation for tool runs. Review state lives in the database, not in filenames.
"""

from __future__ import annotations

import re
import shutil
import types
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Any, TYPE_CHECKING

from rich.prompt import Prompt, Confirm

from .ansi import err, header, ok, warn, get_console, info, safe_text
from .constants import (
    REVIEW_MOVE_LABELS,
    REVIEW_STATE_DONE,
    REVIEW_STATE_IN_PROGRESS,
    REVIEW_TRANSITIONS,
    VERDICT_LABELS,
    get_results_root,
)

if TYPE_CHECKING:
    from .models import Finding, Plugin
    from .workflow_mapper import WorkflowMapper, Workflow


_console_global = get_console()


def _display_name(finding, plugin=None) -> str:
    """Return a 'Plugin <id>: <name>' label for status messages."""
    if plugin:
        return f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
    return f"Plugin {finding.plugin_id}"


def move_review_state(
    finding: "Finding",
    plugin: Optional["Plugin"] = None,
    *,
    target: Optional[str] = None,
    quiet: bool = False,
) -> Optional[str]:
    """Move a finding to its next status (or ``target``) in the database.

    Statuses cycle Unreviewed -> In Progress -> Done -> Unreviewed; only those
    moves are allowed (``constants.REVIEW_TRANSITIONS``).

    Args:
        finding: Finding object to move
        plugin: Optional Plugin object for display name
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
            finding.transition_review_state(target, conn=conn)
    except Exception as e:
        from .logging_setup import log_error

        log_error(f"Failed to move review state: {e}")
        err(f"Could not {REVIEW_MOVE_LABELS[target].lower()}: {e}")
        return None

    if not quiet:
        ok(f"{moved}: {_display_name(finding, plugin)}")
    return target


_VERDICT_CHOICES: dict[str, str] = {
    "1": "confirmed",
    "2": "false_positive",
    "3": "unable",
}


def record_verdict(finding: "Finding", plugin: Optional["Plugin"] = None) -> bool:
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
            FindingVerdict.set(fid, label, note=note, conn=conn)
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
                    finding, plugin, target=nxt, quiet=(nxt != REVIEW_STATE_DONE)
                )
                if finding.review_state != nxt:
                    break  # a transition failed; stop advancing
            return finding.review_state == REVIEW_STATE_DONE
    return False


def build_results_paths(
    scan_dir: Path, sev_dir: Path, plugin_filename: str
) -> tuple[Path, Path]:
    """Build output directory and base path for scan results.

    Creates a structured output directory based on scan name, severity level,
    and plugin name with a timestamped run identifier.

    Args:
        scan_dir: Directory containing the scan
        sev_dir: Directory for the severity level
        plugin_filename: Name of the plugin file

    Returns:
        Tuple of (output_directory, output_base_path) where output_base_path
        includes a timestamp prefix for unique run identification
    """
    stem = Path(plugin_filename).stem
    severity_label = pretty_severity_label(sev_dir.name)
    output_dir = get_results_root() / scan_dir.name / severity_label / stem
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

    tcp_ips.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    if udp:
        udp_ips.write_text("\n".join(hosts) + "\n", encoding="utf-8")
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
    Display a verification workflow for plugin(s).

    Args:
        workflow: Workflow object to display
    """
    from rich.panel import Panel

    console = get_console()

    # Header
    header(f"Verification Workflow: {workflow.workflow_name}")
    info(f"Plugin ID(s): {workflow.plugin_id}")
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
    plugin: Optional["Plugin"] = None,
    plugin_url: Optional[str] = None,
    workflow_mapper: Optional["WorkflowMapper"] = None,
    scan_dir: Optional[Path] = None,
    sev_dir: Optional[Path] = None,
    hosts: Optional[List[str]] = None,
    ports_str: Optional[str] = None,
    args: Any = None,
    use_sudo: bool = False,
    use_proxy: bool = False,
) -> Optional[str]:
    """
    Interactive finding view menu: Info [I], Details [D], View hosts [V], CVE info [E],
    Workflow [W], NetExec data [N], Run tool [T], Ask Claude [A], Record verdict [R],
    Move status [M].

    NOTE: This function uses Plugin and Finding database objects directly for all operations.
    No filename parsing is performed - plugin_id comes from Plugin.plugin_id field.

    Args:
        chosen: Synthetic plugin file path (used only for display, not parsing)
        finding: Finding database object (None if database not available)
        plugin: Plugin metadata object (None if database not available) - used for CVE lookup, workflow check
        plugin_url: Unused (kept for call compatibility); CVEs come from plugin.cves
        workflow_mapper: Optional workflow mapper for plugin workflows
        scan_dir: Scan directory for tool workflow
        sev_dir: Severity directory for tool workflow
        hosts: List of target hosts for tool workflow
        ports_str: Comma-separated ports for tool workflow
        args: CLI arguments for tool workflow
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
        build_plugin_output_details,
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
    if workflow_mapper and plugin:
        has_workflow = workflow_mapper.has_workflow(str(plugin.plugin_id))

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
            if move_review_state(finding, plugin) == REVIEW_STATE_DONE:
                return "mark_complete"
            # Now In Progress (stay in view), or move_review_state() reported why not
            continue

        # Handle Record verdict action
        if action_choice in ("r", "verdict"):
            if finding is None:
                warn("Database not available - cannot record a verdict")
                continue
            if record_verdict(finding, plugin):
                return "mark_complete"
            continue

        # Handle Run tool action
        if action_choice in ("t", "tool"):
            if scan_dir is None or sev_dir is None or hosts is None or args is None:
                warn("Tool execution not available in this context.")
                continue
            if not plugin or not finding:
                warn("Plugin/Finding information not available for tool execution.")
                continue

            # Run tool workflow with database objects. Guard against any deeper
            # hard-exit (e.g. a require_cmd on a missing binary) so a tooling
            # problem never drops the operator out of the review session.
            try:
                run_tool_workflow(
                    plugin,
                    finding,
                    scan_dir,
                    sev_dir,
                    hosts,
                    ports_str or "",
                    args,
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
            if finding is None or plugin is None:
                warn("Finding/Plugin information not available for Claude Assistant.")
                continue
            # Deferred import to avoid circular dependency (cerno.py imports fs.py)
            try:
                from cerno import browse_claude_chat

                _workflow = (
                    workflow_mapper.get_workflow(str(plugin.plugin_id))
                    if workflow_mapper and plugin
                    else None
                )
                browse_claude_chat(
                    finding=finding,
                    plugin=plugin,
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
            if not plugin:
                warn("Plugin information not available.")
                continue
            if not has_workflow or workflow_mapper is None:
                warn("No workflow available for this finding.")
                continue

            plugin_id = str(plugin.plugin_id)
            workflow = workflow_mapper.get_workflow(plugin_id)
            if workflow:
                display_workflow(workflow)
            continue

        # Handle CVE info option (read-only from database)
        if action_choice in ("e", "cve"):
            # Use Plugin object already available as parameter
            try:
                header("CVE Information")

                if plugin and plugin.cves:
                    info(
                        f"Found {len(plugin.cves)} CVE(s) for plugin {plugin.plugin_id}:"
                    )
                    for cve in plugin.cves:
                        info(f"{cve}")
                elif plugin:
                    warn(
                        f"No CVEs associated with this finding (plugin {plugin.plugin_id})."
                    )
                else:
                    warn("Plugin information not available.")
            except Exception as exc:
                warn(f"Failed to retrieve CVE information: {exc}")

            continue

        # Handle Finding Info action
        if action_choice in ("i", "info"):
            # Redisplay the preview panel
            if plugin is None or sev_dir is None or finding is None:
                warn("Plugin metadata not available - cannot display finding info")
                continue
            display_finding_preview(plugin, finding, sev_dir, chosen, workflow_mapper)
            continue

        # Handle Finding Details action
        if action_choice in ("d", "details"):
            if finding is None or plugin is None:
                warn("Database not available - cannot display finding details")
                continue

            # Generate and display plugin output details
            details_text = build_plugin_output_details(finding, plugin)

            if details_text:
                menu_pager(details_text)
            else:
                warn("No plugin output available for this finding.")

            continue

        # Handle View file action - streamlined workflow
        if not action_choice in ("v", "view"):
            warn("Invalid action choice.")
            continue

        # Check if finding/plugin is available (database mode)
        if finding is None or plugin is None:
            warn("Database not available - cannot view file contents")
            continue

        # Default to grouped format (no prompt) for instant viewing
        text = grouped_paged_text(finding, plugin)
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
                _console_global.print(payload)

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
                text = file_raw_paged_text(finding, plugin)
                payload = file_raw_payload_text(finding)
            elif format_choice in ("h", "hosts", "hosts-only"):
                text = hosts_only_paged_text(finding, plugin)
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
    plugin: "Plugin",
    finding: "Finding",
    scan_dir: Path,
    sev_dir: Optional[Path],
    args: types.SimpleNamespace,
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
        plugin: Plugin metadata object
        finding: Finding database object (required)
        scan_dir: Scan directory
        sev_dir: Severity directory
        args: Command-line arguments
        use_sudo: Whether sudo is available
        in_progress_total: List to track findings marked in progress
        done_total: List to track findings marked done
        show_severity: Whether to show severity label (for MSF mode)
        workflow_mapper: Optional workflow mapper for plugin workflows
        use_proxy: Whether to route tools through proxychains4
    """
    # Lazy imports to avoid circular dependencies
    from .render import display_finding_preview

    # Get hosts and ports from database
    hosts, ports_str = finding.get_hosts_and_ports()

    # Construct display name from plugin metadata
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"

    if not hosts:
        info(
            "Finding has no affected hosts. This usually means the vulnerability doesn't affect any hosts."
        )
        return

    # Display finding preview panel
    display_finding_preview(plugin, finding, sev_dir, chosen, workflow_mapper)

    # plugin_url is no longer used by the finding view (CVEs and the Tenable
    # link come from the Plugin row); passed as None for call compatibility.
    plugin_url = None

    state_before = finding.review_state

    # View file and handle actions
    result = handle_finding_view(
        chosen,
        finding=finding,
        plugin=plugin,
        plugin_url=plugin_url,
        workflow_mapper=workflow_mapper,
        scan_dir=scan_dir,
        sev_dir=sev_dir,
        hosts=hosts,
        ports_str=ports_str,
        args=args,
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
