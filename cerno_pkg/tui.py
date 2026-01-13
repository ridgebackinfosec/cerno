"""Terminal User Interface (TUI) components for cerno.

This module handles interactive navigation, menus, and action handling:
- Generic menu selectors (choose_from_list, parse_severity_selection)
- File list browser with filtering, sorting, pagination
- Workflow group browser
- Action handlers for file operations
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional, Tuple, Dict, Callable, TYPE_CHECKING

from rich.prompt import Prompt

from .ansi import warn, info, ok, header, get_console, colorize_severity_label
from .render import print_action_menu, show_actions_help, show_reviewed_help
from .constants import VISIBLE_GROUPS

if TYPE_CHECKING:
    from .models import Finding

_console_global = get_console()

# Action result type for handle_finding_list_actions
ActionResult = Tuple[
    Optional[str],  # action_type: None, "back", "file_selected", "help", "mark_all"
    str,  # file_filter
    str,  # reviewed_filter
    Optional[Tuple[int, set, str]],  # group_filter: (index, plugin_ids, description)
    str,  # sort_mode
    int   # page_idx
]


# ===================================================================
# Generic Menu Components
# ===================================================================


def parse_severity_selection(
    selection: str, max_index: int
) -> Optional[List[int]]:
    """
    Parse user selection into list of severity indices.

    Supports:
        - Single number: "1" -> [1]
        - Range: "1-3" -> [1, 2, 3]
        - Comma-separated: "1,3,5" -> [1, 3, 5]
        - Mixed: "1-3,5,7-9" -> [1, 2, 3, 5, 7, 8, 9]

    Args:
        selection: User input string
        max_index: Maximum valid index (inclusive)

    Returns:
        List of valid 1-based indices, or None if invalid
    """
    indices = set()

    # Split by comma first
    parts = [p.strip() for p in selection.split(",")]

    for part in parts:
        if not part:
            continue

        # Check if it's a range
        if "-" in part:
            range_parts = part.split("-", 1)
            if len(range_parts) != 2:
                return None

            start_str, end_str = range_parts
            if not start_str.isdigit() or not end_str.isdigit():
                return None

            start = int(start_str)
            end = int(end_str)

            if start < 1 or end > max_index or start > end:
                return None

            indices.update(range(start, end + 1))
        else:
            # Single number
            if not part.isdigit():
                return None

            num = int(part)
            if num < 1 or num > max_index:
                return None

            indices.add(num)

    if not indices:
        return None

    return sorted(list(indices))


def choose_from_list(
    items: List[Any],
    title: str,
    allow_back: bool = False,
    allow_exit: bool = False,
) -> Any:
    """
    Display a numbered menu and get user selection.

    Args:
        items: List of items to choose from
        title: Menu title to display
        allow_back: Show [B] Back option
        allow_exit: Show [Q] Quit option

    Returns:
        Selected item, None if back chosen, "exit" if exit chosen

    Raises:
        KeyboardInterrupt: If user interrupts with Ctrl+C
    """
    header(title)
    for index, item in enumerate(items, 1):
        _console_global.print(f"[{index}] {item}")

    if allow_back:
        print_action_menu([("B", "Back")])
    if allow_exit:
        print_action_menu([("Q", "Quit")])

    while True:
        try:
            ans = Prompt.ask("Choose").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            raise

        if allow_back and ans in ("b", "back", "q"):
            return None
        if allow_exit and ans in ("x", "exit", "q", "quit"):
            return "exit"
        if ans.isdigit():
            idx = int(ans)
            if 1 <= idx <= len(items):
                return items[idx - 1]

        options_text = f"1-{len(items)}"
        if allow_back and allow_exit:
            warn(f"Invalid choice. Please enter {options_text}, [B]ack, or [Q]uit.")
        elif allow_back:
            warn(f"Invalid choice. Please enter {options_text} or [B]ack.")
        elif allow_exit:
            warn(f"Invalid choice. Please enter {options_text} or [Q]uit.")
        else:
            warn(f"Invalid choice. Please enter {options_text}.")


# ===================================================================
# File List Navigation
# ===================================================================


def handle_finding_list_actions(
    ans: str,
    candidates: List[Any],  # List of (Finding, Plugin) tuples
    page_items: List[Any],  # List of (Finding, Plugin) tuples
    display: List[Any],  # List of (Finding, Plugin) tuples
    file_filter: str,
    reviewed_filter: str,
    group_filter: Optional[Tuple[int, set, str]],
    sort_mode: str,
    page_idx: int,
    total_pages: int,
    reviewed: List[Any],  # List of (Finding, Plugin) tuples
    sev_map: Optional[Dict[Path, Path]] = None,
    get_counts_for: Optional[Callable[["Finding"], Tuple[int, str]]] = None,
) -> ActionResult:
    """
    Handle file list actions (filter, sort, navigate, group, etc.).

    Args:
        ans: User input command
        candidates: Filtered candidate records (Finding, Plugin) tuples
        page_items: Records on current page
        display: All records to display (after sort)
        file_filter: Current file filter string
        reviewed_filter: Current reviewed filter string
        group_filter: Optional group filter tuple (index, filenames)
        sort_mode: Current sort mode ("plugin_id", "hosts", or "name")
        page_idx: Current page index
        total_pages: Total number of pages
        reviewed: List of reviewed records
        sev_map: Map of file to severity dir (deprecated, unused)
        get_counts_for: Function to get host counts for a Finding (database-driven)

    Returns:
        Tuple of (action_type, file_filter, reviewed_filter,
                 group_filter, sort_mode, page_idx)
        action_type: None (continue), "back", "file_selected", "help", "mark_all"
    """
    if ans in ("?", "help"):
        show_actions_help(
            group_applied=bool(group_filter),
            candidates_count=len(candidates),
            sort_mode=sort_mode,
            can_next=(page_idx + 1 < total_pages),
            can_prev=(page_idx > 0),
        )
        return "help", file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans in ("b", "back", "q"):
        return "back", file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "n":
        if page_idx + 1 < total_pages:
            page_idx += 1
        else:
            warn("Already at last page.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "p":
        if page_idx > 0:
            page_idx -= 1
        else:
            warn("Already at first page.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "f":
        info("Filter help: Enter any text to match finding names (case-insensitive)")
        info("Examples: 'apache' matches 'Apache HTTP Server', 'ssl' matches 'SSL Certificate'")
        file_filter = Prompt.ask(
            "Enter substring to filter by (e.g., 'apache', 'ssl', 'windows') or press Enter for none",
            default=""
        ).strip()
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "c":
        file_filter = ""
        page_idx = 0
        ok("Filter cleared. Showing all findings.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "s":
        # Cycle through sort modes: plugin_id -> name -> hosts -> plugin_id
        if sort_mode == "plugin_id":
            sort_mode = "name"
        elif sort_mode == "name":
            sort_mode = "hosts"
        else:  # hosts
            sort_mode = "plugin_id"

        sort_label = {
            "plugin_id": "Plugin ID ↑",
            "hosts": "Host count ↓",
            "name": "Name A↑Z"
        }.get(sort_mode, "Plugin ID ↑")
        ok(f"Sorting by {sort_label}")

        # No need to pre-load host counts - they're already in the database!

        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "x" and group_filter:
        group_filter = None
        ok("Cleared group filter.")
        page_idx = 0
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "r":
        header("Completed Findings (Undo Available)")
        _console_global.print(f"Current filter: '{reviewed_filter or '*'}'")
        filtered_reviewed = [
            (pf, p)
            for (pf, p) in reviewed
            if (reviewed_filter.lower() in p.plugin_name.lower())
        ]

        for idx, (finding, plugin) in enumerate(filtered_reviewed, 1):
            display_name = f"Plugin {plugin.plugin_id}: {plugin.plugin_name}"
            if sev_map:  # MSF mode with severity labels (deprecated)
                # Get severity label from plugin metadata
                sev_label = plugin.severity_label or f"Severity {plugin.severity_int}"
                sev_col = colorize_severity_label(sev_label)
                # Use Rich markup instead of ANSI codes for Rich console
                _console_global.print(f"[{idx}] [magenta]✓ {display_name}[/magenta]  — {sev_col}")
            else:
                # Use Rich markup instead of ANSI codes for Rich console
                _console_global.print(f"[{idx}] [magenta]✓ {display_name}[/magenta]")

        print_action_menu([
            ("?", "Help"),
            ("U", "Undo completion"),
            ("F", "Filter"),
            ("C", "Clear filter"),
            ("B", "Back")
        ])

        try:
            choice = Prompt.ask("Action or [B]ack").strip().lower()
        except KeyboardInterrupt:
            warn("\nInterrupted — returning.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        if choice in ("?", "help"):
            show_reviewed_help()
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice == "u":
            # Undo review-complete for one or more findings
            if not filtered_reviewed:
                warn("No reviewed findings to undo.")
                return (
                    None,
                    file_filter,
                    reviewed_filter,
                    group_filter,
                    sort_mode,
                    page_idx,
                )

            try:
                selection = Prompt.ask("Enter file number(s) to undo (e.g., 1 or 1,3,5) or [A]ll").strip()
            except KeyboardInterrupt:
                return (
                    None,
                    file_filter,
                    reviewed_filter,
                    group_filter,
                    sort_mode,
                    page_idx,
                )

            if selection.lower() == "a":
                files_to_undo = filtered_reviewed
            else:
                try:
                    indices = [int(i.strip()) for i in selection.split(",")]
                    files_to_undo = [filtered_reviewed[i - 1] for i in indices if 1 <= i <= len(filtered_reviewed)]
                except (ValueError, IndexError):
                    warn("Invalid selection.")
                    return (
                        None,
                        file_filter,
                        reviewed_filter,
                        group_filter,
                        sort_mode,
                        page_idx,
                    )

            # Undo each file (lists will be regenerated on next loop)
            from .fs import undo_review_complete
            for finding, plugin in files_to_undo:
                undo_review_complete(finding)

            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice == "f":
            info("Filter help: Enter any text to match filenames (case-insensitive)")
            info("Examples: 'apache' matches 'Apache_2.4', 'ssl' matches 'SSL_Certificate'")
            reviewed_filter = Prompt.ask(
                "Enter substring to filter by (e.g., 'apache', 'ssl', 'windows') or press Enter for none",
                default=""
            ).strip()
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice == "c":
            reviewed_filter = ""
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        if choice in ("b", "back", "q"):
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        warn("Read-only view; no file selection here.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "e":
        if not candidates:
            warn("No findings match the current filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Extract plugin info from (Finding, Plugin) tuples for CVE extraction
        # Pass list of (plugin_id, plugin_name) tuples instead of file paths
        from .render import bulk_extract_cves_for_plugins
        plugin_info_list = [(p.plugin_id, p.plugin_name) for _pf, p in candidates]
        bulk_extract_cves_for_plugins(plugin_info_list)
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "m":
        if not candidates:
            warn("No findings match the current filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        from rich.prompt import Confirm
        from rich import print as rprint

        # Show warning message
        rprint(f"[red]You are about to mark {len(candidates)} items as review completed.[/red]")

        # Use standard Confirm.ask pattern
        confirmed = Confirm.ask("Mark all filtered findings as completed?", default=False)

        if not confirmed:
            info("Canceled.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Return special action to handle in browse_file_list where we have
        # access to completed_total
        return (
            "mark_all",
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
        )

    if ans == "h":
        if not candidates:
            warn("No findings match the current filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Pass (Finding, Plugin) tuples for database queries with plugin info
        from .analysis import compare_filtered
        groups = compare_filtered(candidates)
        if groups:
            visible = min(VISIBLE_GROUPS, len(groups))
            opts = " | ".join(f"g{i+1}" for i in range(visible))
            ellipsis = " | etc." if len(groups) > VISIBLE_GROUPS else ""
            choice = Prompt.ask(
                f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group",
                default=""
            ).strip().lower()

            if choice.startswith("g") and choice[1:].isdigit():
                idx = int(choice[1:]) - 1
                if 0 <= idx < len(groups):
                    # Enhanced tuple with description
                    group_desc = "Identical host:port combinations"
                    group_filter = (idx + 1, set(groups[idx]), group_desc)
                    ok(f"Applied group filter #{idx+1} ({len(groups[idx])} findings).")
                    page_idx = 0

        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    if ans == "o":
        if not candidates:
            warn("No findings match the current filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Pass full (Finding, Plugin) tuples to preserve display names
        from .analysis import analyze_inclusions
        groups = analyze_inclusions(candidates)
        if groups:
            # Display context explanation
            header(f"\nFound {len(groups)} overlapping groups")
            info("")
            info("What this means: One finding's affected systems are a superset of another.")
            info("The larger finding might be more comprehensive to review.")
            info("")

            visible = min(VISIBLE_GROUPS, len(groups))
            opts = " | ".join(f"g{i+1}" for i in range(visible))
            ellipsis = " | etc." if len(groups) > VISIBLE_GROUPS else ""
            choice = Prompt.ask(
                f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group",
                default=""
            ).strip().lower()

            if choice.startswith("g") and choice[1:].isdigit():
                idx = int(choice[1:]) - 1
                if 0 <= idx < len(groups):
                    # Enhanced tuple with description
                    group_desc = "Overlapping findings"
                    group_filter = (idx + 1, set(groups[idx]), group_desc)
                    ok(
                        f"Applied overlapping group #{idx+1} "
                        f"({len(groups[idx])} findings)."
                    )
                    page_idx = 0

        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    # File selection logic
    if ans == "":
        if not page_items:
            warn("No findings match the current page/filter.")
            return (
                None,
                file_filter,
                reviewed_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        return (
            "file_selected",
            file_filter,
            reviewed_filter,
            group_filter,
            sort_mode,
            page_idx,
        )

    if not ans.isdigit():
        warn("Please select a file by number, or use actions above.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    global_idx = int(ans) - 1
    if global_idx < 0 or global_idx >= len(display):
        warn("Invalid index.")
        return None, file_filter, reviewed_filter, group_filter, sort_mode, page_idx

    return (
        "file_selected",
        file_filter,
        reviewed_filter,
        group_filter,
        sort_mode,
        page_idx,
    )


# Note: browse_file_list and browse_workflow_groups are complex, large functions
# They will be implemented in cerno.py for now and moved in Phase 6 during cleanup


# ===================================================================
# Workflow Navigation
# ===================================================================

# Note: browse_workflow_groups will be moved from cerno.py in Phase 6
