"""Filesystem operations and path utilities.

This module provides functions for file I/O, directory traversal, file
renaming, and work file generation for security testing workflows.
"""

from __future__ import annotations

import re
import shutil
import types
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Any, TYPE_CHECKING

from rich.prompt import Prompt, Confirm

from .ansi import err, header, ok, warn, get_console, info
from .constants import get_results_root

if TYPE_CHECKING:
    from .models import Finding, Plugin
    from .workflow_mapper import WorkflowMapper, Workflow


_console_global = get_console()
def mark_review_complete(plugin_file, plugin=None) -> bool:
    """Mark a file as review complete in the database.

    Args:
        plugin_file: Finding object to mark as completed
        plugin: Optional Plugin object for display name

    Returns:
        True if successful, False otherwise
    """
    try:
        from .database import db_transaction

        if plugin_file.review_state == "completed":
            warn("Already marked as review complete.")
            return False

        # Update review state in database
        with db_transaction() as conn:
            plugin_file.update_review_state("completed", conn=conn)

        # Display plugin metadata instead of filename
        if plugin:
            display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
        else:
            display_name = f"Plugin {plugin_file.plugin_id}"
        ok(f"Marked as review complete: {display_name}")
        return True

    except Exception as e:
        from .logging_setup import log_error
        log_error(f"Failed to mark file as review complete: {e}")
        err(f"Failed to mark as review complete: {e}")
        return False


def undo_review_complete(plugin_file, plugin=None) -> bool:
    """Remove review complete status from the database.

    Args:
        plugin_file: Finding object to mark as pending
        plugin: Optional Plugin object for display name

    Returns:
        True if successful, False otherwise
    """
    try:
        from .database import db_transaction

        if plugin_file.review_state != "completed":
            warn("File is not marked as review complete.")
            return False

        # Update review state in database
        with db_transaction() as conn:
            plugin_file.update_review_state("pending", conn=conn)

        # Display plugin metadata instead of filename
        if plugin:
            display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
        else:
            display_name = f"Plugin {plugin_file.plugin_id}"
        ok(f"Removed review complete marker: {display_name}")
        return True

    except Exception as e:
        from .logging_setup import log_error
        log_error(f"Failed to undo review complete: {e}")
        err(f"Failed to undo review complete: {e}")
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

    Expects format like "1_critical" and converts to "Critical".

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
            f"[bold cyan]{step.title}[/bold cyan]\n\n"
            + "\n".join(f"  {cmd}" for cmd in step.commands)
            + (f"\n\n[yellow]Notes:[/yellow] {step.notes}" if step.notes else ""),
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
) -> Optional[str]:
    """
    Interactive file viewing menu (raw/grouped/hosts-only/copy/CVE info/workflow/tool/mark).

    NOTE: This function uses Plugin and Finding database objects directly for all operations.
    No filename parsing is performed - plugin_id comes from Plugin.plugin_id field.

    Args:
        chosen: Synthetic plugin file path (used only for display, not parsing)
        finding: Finding database object (None if database not available)
        plugin: Plugin metadata object (None if database not available) - used for CVE lookup, workflow check
        plugin_url: Optional Tenable plugin URL for CVE extraction
        workflow_mapper: Optional workflow mapper for plugin workflows
        scan_dir: Scan directory for tool workflow
        sev_dir: Severity directory for tool workflow
        hosts: List of target hosts for tool workflow
        ports_str: Comma-separated ports for tool workflow
        args: CLI arguments for tool workflow
        use_sudo: Whether to use sudo for tools

    Returns:
        "back": User wants to go back to file selection
        "mark_complete": File was marked as reviewed
        None: Continue normally
    """
    # Lazy imports to avoid circular dependencies
    from .render import (
        file_raw_paged_text, file_raw_payload_text,
        grouped_paged_text, grouped_payload_text,
        hosts_only_paged_text, hosts_only_payload_text,
        build_plugin_output_details, display_finding_preview,
        print_action_menu, menu_pager, display_nxc_per_host_detail,
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
            has_workflow=has_workflow,
            has_nxc_data=has_nxc_data,
        )
        try:
            action_choice = Prompt.ask("Choose action").strip().lower()
        except KeyboardInterrupt:
            # User cancelled - treat as back
            return "back"

        # Handle Back action
        if action_choice in ("b", "back"):
            return "back"

        # Handle Mark reviewed action
        if action_choice in ("m", "mark"):
            if finding is None:
                warn("Database not available - cannot mark file as reviewed")
                continue
            try:
                if mark_review_complete(finding, plugin):
                    return "mark_complete"
            except Exception as exc:
                warn(f"Failed to mark file: {exc}")
                continue

        # Handle Run tool action
        if action_choice in ("t", "tool"):
            if scan_dir is None or sev_dir is None or hosts is None or args is None:
                warn("Tool execution not available in this context.")
                continue
            if not plugin or not finding:
                warn("Plugin/Finding information not available for tool execution.")
                continue

            # Run tool workflow with database objects
            run_tool_workflow(plugin, finding, scan_dir, sev_dir, hosts, ports_str or "", args, use_sudo)
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
                    info(f"Found {len(plugin.cves)} CVE(s) for plugin {plugin.plugin_id}:")
                    for cve in plugin.cves:
                        info(f"{cve}")
                elif plugin:
                    warn(f"No CVEs associated with this finding (plugin {plugin.plugin_id}).")
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
        print_action_menu([
            ("C", "Copy to clipboard"),
            ("F", "Change format"),
            ("B", "Back to menu")
        ])

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
            print_action_menu([
                ("R", "Raw"),
                ("H", "Hosts only"),
                ("G", "Grouped (current)")
            ])
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
    skipped_total: List[str],
    reviewed_total: List[str],
    completed_total: List[str],
    show_severity: bool = False,
    workflow_mapper: Optional["WorkflowMapper"] = None,
) -> None:
    """
    Process a single plugin file: preview, view, run tools, mark complete (database-only).

    Args:
        chosen: Selected plugin file
        plugin: Plugin metadata object
        finding: Finding database object (required)
        scan_dir: Scan directory
        sev_dir: Severity directory
        args: Command-line arguments
        use_sudo: Whether sudo is available
        skipped_total: List to track skipped findings
        reviewed_total: List to track reviewed findings
        completed_total: List to track completed findings
        show_severity: Whether to show severity label (for MSF mode)
        workflow_mapper: Optional workflow mapper for plugin workflows
    """
    # Lazy imports to avoid circular dependencies
    from .render import display_finding_preview

    # Get hosts and ports from database
    hosts, ports_str = finding.get_hosts_and_ports()

    # Construct display name from plugin metadata
    display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"

    if not hosts:
        info("File is empty (no hosts found). This usually means the vulnerability doesn't affect any hosts.")
        skipped_total.append(display_name)
        return

    # Display finding preview panel
    display_finding_preview(plugin, finding, sev_dir, chosen, workflow_mapper)

    # Extract plugin URL for handle_finding_view
    plugin_url = None
    # Note: _plugin_details_line is no longer available after refactoring
    # This functionality is handled by the database plugin metadata instead

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
    )

    # Handle result from file view
    if result == "back":
        # User chose to go back - add to reviewed list
        reviewed_total.append(display_name)
        return
    elif result == "mark_complete":
        # File was marked as reviewed
        completed_total.append(display_name)
        return
    else:
        # Implicit completion - add to reviewed list
        reviewed_total.append(display_name)
        return


