"""Terminal User Interface (TUI) components for cerno.

This module handles interactive menus and findings-list action handling:
- Generic menu selectors (choose_from_list, parse_severity_selection, parse_scan_selection)
- Findings-list actions: filtering, sorting, pagination, grouping
  (the [I] / [D] status-filter toggles are handled by browse_file_list, not here)
- Multi-line free-text input (Claude Assistant, authored finding descriptions)
- Authored-finding prompts (create and edit), which validate through
  ``authored_findings.validate_authored_input`` and re-prompt rather than
  discard what was typed. These serve the TUI, so what they collect is written
  under ``operator:``; an MCP client's findings go in under ``agent:``

The findings-list and workflow-group browsers themselves (browse_file_list,
browse_workflow_groups) live in cerno.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Tuple, Callable, TYPE_CHECKING

from rich.prompt import Prompt
from rich.text import Text


@dataclass
class SeveritySelection:
    """Parsed severity selection result.

    Separates numeric severity indices (1-5) from special filter flags (M, W).
    """

    severity_indices: List[int]  # 1-based indices for severities (1-5)
    msf_selected: bool  # True if 'M' was in selection
    workflow_selected: bool  # True if 'W' was in selection


from .ansi import warn, info, ok, header, get_console
from .fs import finding_label
from .render import print_action_menu, show_actions_help
from .constants import VISIBLE_GROUPS

if TYPE_CHECKING:
    from .models import Finding
    from .authored_findings import AuthoredFindingInput

_console_global = get_console()

# Action result type for handle_finding_list_actions
ActionResult = Tuple[
    Optional[str],  # action_type: None, "back", "file_selected", "help", "mark_all"
    str,  # file_filter
    Optional[Tuple[int, set, str]],  # group_filter: (index, plugin_ids, description)
    str,  # sort_mode
    int,  # page_idx
]


# ===================================================================
# Generic Menu Components
# ===================================================================


def parse_severity_selection(
    selection: str, max_index: int
) -> Optional[SeveritySelection]:
    """
    Parse user selection into severity indices and special filter flags.

    Supports:
        - Single number: "1" -> severities [1]
        - Range: "1-3" -> severities [1, 2, 3]
        - Comma-separated: "1,3,5" -> severities [1, 3, 5]
        - Mixed: "1-3,5" -> severities [1, 2, 3, 5]
        - Special filters: "M" -> Metasploit, "W" -> Workflow
        - Combined: "1-3,M" -> severities [1, 2, 3] + Metasploit
        - Combined: "M,W" -> both special filters, no severities

    Args:
        selection: User input string
        max_index: Maximum valid severity index (usually 5 for severity levels)

    Returns:
        SeveritySelection with indices and flags, or None if invalid
    """
    indices: set[int] = set()
    msf_selected = False
    workflow_selected = False

    # Split by comma first
    parts = [p.strip().upper() for p in selection.split(",")]

    for part in parts:
        if not part:
            continue

        # Check for special filter letters
        if part == "M":
            msf_selected = True
            continue
        if part == "W":
            workflow_selected = True
            continue

        # Check if it's a range (e.g., "1-3")
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

    # Must have at least one selection
    if not indices and not msf_selected and not workflow_selected:
        return None

    return SeveritySelection(
        severity_indices=sorted(list(indices)),
        msf_selected=msf_selected,
        workflow_selected=workflow_selected,
    )


def parse_scan_selection(selection: str, max_index: int) -> Optional[list[int]]:
    """Parse user scan selection into a list of 1-based indices.

    Supports:
        - Single number: "1" -> [1]
        - Range: "1-3" -> [1, 2, 3]
        - Comma-separated: "1,3" -> [1, 3]
        - Mixed: "1-3,5" -> [1, 2, 3, 5]

    Args:
        selection: User input string
        max_index: Maximum valid scan index (number of available scans)

    Returns:
        Sorted list of 1-based indices, or None if input is invalid
    """
    indices: set[int] = set()

    # Split by comma first
    parts = [p.strip() for p in selection.split(",")]

    for part in parts:
        if not part:
            continue

        # Check if it's a range (e.g., "1-3")
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

    # Must have at least one selection
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
        # Text: items may be scan-derived, and Rich markup-parses a bare str.
        # One Text for the whole line also keeps the [N] prefix literal.
        _console_global.print(Text(f"[{index}] {item}"))

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


def filter_finding_candidates(
    records: List[Any],  # List of (Finding, Plugin) tuples
    file_filter: str,
    group_filter: Optional[Tuple[int, set, str]],
    status_filter: Optional[str],
) -> List[Any]:
    """Apply the findings-list name, group, and status filters.

    Args:
        records: (Finding, Plugin) tuples to filter (open findings)
        file_filter: Case-insensitive plugin-name substring ("" = no filter)
        group_filter: Optional group filter tuple (index, plugin labels, description)
        status_filter: Review state to keep (e.g. "in_progress"), or None for all

    Returns:
        Records matching every active filter, in their original order
    """
    needle = file_filter.lower()
    return [
        (pf, p)
        for (pf, p) in records
        if needle in p.plugin_name.lower()
        and (group_filter is None or finding_label(pf, p) in group_filter[1])
        and (status_filter is None or pf.review_state == status_filter)
    ]


def handle_finding_list_actions(
    ans: str,
    candidates: List[Any],  # List of (Finding, Plugin) tuples
    page_items: List[Any],  # List of (Finding, Plugin) tuples
    display: List[Any],  # List of (Finding, Plugin) tuples
    file_filter: str,
    group_filter: Optional[Tuple[int, set, str]],
    sort_mode: str,
    page_idx: int,
    total_pages: int,
    get_counts_for: Optional[Callable[["Finding"], Tuple[int, str]]] = None,
    unique_cve_count: int = 0,
    unique_host_count: int = 0,
    status_filter: Optional[str] = None,
) -> ActionResult:
    """
    Handle findings-list actions (filter, sort, navigate, group, etc.).

    The status-filter keys ``[I]`` and ``[D]`` are *not* handled here --
    ``browse_file_list`` intercepts them before calling this, because changing
    the filter changes which pool of findings the list is built from.

    Args:
        ans: User input command
        candidates: Filtered candidate records (Finding, Plugin) tuples
        page_items: Records on current page
        display: All records to display (after sort)
        file_filter: Current name filter string
        group_filter: Optional group filter tuple (index, set of
            "Plugin <id>: <name>" labels, description)
        sort_mode: Current sort mode ("severity", "plugin_id", "name" or "hosts")
        page_idx: Current page index
        total_pages: Total number of pages
        get_counts_for: Function to get host counts for a Finding (database-driven)
        unique_cve_count: Unique CVEs across candidates (help display only)
        unique_host_count: Unique hosts across candidates (help display only)
        status_filter: Active review-state filter (help display only)

    Returns:
        Tuple of (action_type, file_filter, group_filter, sort_mode, page_idx)
        action_type: None (continue), "back", "file_selected", "help", "mark_all"
    """
    if ans in ("?", "help"):
        show_actions_help(
            group_applied=bool(group_filter),
            candidates_count=len(candidates),
            unique_cve_count=unique_cve_count,
            unique_host_count=unique_host_count,
            sort_mode=sort_mode,
            can_next=(page_idx + 1 < total_pages),
            can_prev=(page_idx > 0),
            status_filter=status_filter,
        )
        return "help", file_filter, group_filter, sort_mode, page_idx

    if ans in ("b", "back", "q"):
        return "back", file_filter, group_filter, sort_mode, page_idx

    if ans == "n":
        if page_idx + 1 < total_pages:
            page_idx += 1
        else:
            warn("Already at last page.")
        return None, file_filter, group_filter, sort_mode, page_idx

    if ans == "p":
        if page_idx > 0:
            page_idx -= 1
        else:
            warn("Already at first page.")
        return None, file_filter, group_filter, sort_mode, page_idx

    if ans == "f":
        info("Filter help: Enter any text to match finding names (case-insensitive)")
        info(
            "Examples: 'apache' matches 'Apache HTTP Server', 'ssl' matches 'SSL Certificate'"
        )
        file_filter = Prompt.ask(
            "Enter substring to filter by (e.g., 'apache', 'ssl', 'windows') or press Enter for none",
            default="",
        ).strip()
        page_idx = 0
        return None, file_filter, group_filter, sort_mode, page_idx

    if ans == "c":
        file_filter = ""
        page_idx = 0
        ok("Filter cleared. Showing all findings.")
        return None, file_filter, group_filter, sort_mode, page_idx

    if ans == "s":
        # Cycle through sort modes: severity -> plugin_id -> name -> hosts -> severity
        if sort_mode == "severity":
            sort_mode = "plugin_id"
        elif sort_mode == "plugin_id":
            sort_mode = "name"
        elif sort_mode == "name":
            sort_mode = "hosts"
        else:  # hosts
            sort_mode = "severity"

        sort_label = {
            "severity": "Severity ↓",
            "plugin_id": "Finding ID ↑",
            "hosts": "Host count ↓",
            "name": "Name A↑Z",
        }.get(sort_mode, "Severity ↓")
        ok(f"Sorting by {sort_label}")

        # No need to pre-load host counts - they're already in the database!

        page_idx = 0
        return None, file_filter, group_filter, sort_mode, page_idx

    if ans == "x" and group_filter:
        group_filter = None
        ok("Cleared group filter.")
        page_idx = 0
        return None, file_filter, group_filter, sort_mode, page_idx

    if ans == "e":
        if not candidates:
            warn("No findings match the current filter.")
            return (
                None,
                file_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Extract plugin info from (Finding, Plugin) tuples for CVE extraction
        # Pass list of (plugin_id, plugin_name) tuples instead of file paths
        from .render import bulk_extract_cves_for_plugins

        plugin_info_list = [(p.plugin_id, p.plugin_name) for _pf, p in candidates]
        bulk_extract_cves_for_plugins(plugin_info_list)
        return None, file_filter, group_filter, sort_mode, page_idx

    if ans == "m":
        if not candidates:
            warn("No findings match the current filter.")
            return (
                None,
                file_filter,
                group_filter,
                sort_mode,
                page_idx,
            )

        # Return special action to handle in browse_file_list where we have
        # access to done_total
        return (
            "mark_all",
            file_filter,
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
            choice = (
                Prompt.ask(
                    f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group",
                    default="",
                )
                .strip()
                .lower()
            )

            if choice.startswith("g") and choice[1:].isdigit():
                idx = int(choice[1:]) - 1
                if 0 <= idx < len(groups):
                    # Enhanced tuple with description
                    group_desc = "Identical host:port combinations"
                    group_filter = (idx + 1, set(groups[idx]), group_desc)
                    ok(f"Applied group filter #{idx+1} ({len(groups[idx])} findings).")
                    page_idx = 0

        return None, file_filter, group_filter, sort_mode, page_idx

    if ans == "o":
        if not candidates:
            warn("No findings match the current filter.")
            return (
                None,
                file_filter,
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
            info(
                "What this means: One finding's affected systems are a superset of another."
            )
            info("The larger finding might be more comprehensive to review.")
            info("")

            visible = min(VISIBLE_GROUPS, len(groups))
            opts = " | ".join(f"g{i+1}" for i in range(visible))
            ellipsis = " | etc." if len(groups) > VISIBLE_GROUPS else ""
            choice = (
                Prompt.ask(
                    f"\n[Enter] back | choose {opts}{ellipsis} to filter to a group",
                    default="",
                )
                .strip()
                .lower()
            )

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

        return None, file_filter, group_filter, sort_mode, page_idx

    # File selection logic
    if ans == "":
        if not page_items:
            warn("No findings match the current page/filter.")
            return (
                None,
                file_filter,
                group_filter,
                sort_mode,
                page_idx,
            )
        return (
            "file_selected",
            file_filter,
            group_filter,
            sort_mode,
            page_idx,
        )

    if not ans.isdigit():
        warn("Please select a finding by number, or use actions above.")
        return None, file_filter, group_filter, sort_mode, page_idx

    global_idx = int(ans) - 1
    if global_idx < 0 or global_idx >= len(display):
        warn("Invalid index.")
        return None, file_filter, group_filter, sort_mode, page_idx

    return (
        "file_selected",
        file_filter,
        group_filter,
        sort_mode,
        page_idx,
    )


def prompt_multiline(label: str, default: str = "") -> str:
    """Prompt for free text with multi-line support.

    Enter inserts a newline; Alt+Enter (prompt_toolkit default) or Ctrl+J
    (the custom c-j binding; many terminals send it for Ctrl+Enter) submits.
    Returns "" on Ctrl+D; Ctrl+C re-raises KeyboardInterrupt for the caller.

    Args:
        label: Prompt text shown to the left of the cursor.
        default: Pre-filled, editable text -- what makes editing a stored
            description a correction rather than a retype.
    """
    from prompt_toolkit import PromptSession
    from prompt_toolkit.key_binding import KeyBindings

    kb = KeyBindings()

    @kb.add("c-j")
    def _submit(event):
        event.current_buffer.validate_and_handle()

    session: PromptSession[str] = PromptSession(key_bindings=kb, multiline=True)
    try:
        return session.prompt(label, default=default).strip()
    except KeyboardInterrupt:
        raise
    except EOFError:
        return ""


def ask_claude_multiline() -> str:
    """Prompt for Claude assistant input with multi-line support."""
    return prompt_multiline("Ask Claude: ")


# ===================================================================
# Operator-authored findings (the TUI's channel; see authored_findings)
# ===================================================================

#: Severity choices offered when writing a finding by hand.
_SEVERITY_CHOICES = {
    "0": "Info",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}


def _prompt_authored_fields(
    existing: Optional["AuthoredFindingInput"] = None,
) -> Optional["AuthoredFindingInput"]:
    """Prompt for every authored-finding field, pre-filled from ``existing``.

    Shared by the create and edit flows so the two cannot ask different
    questions. Re-prompts on validation failure with everything the operator
    typed still in place -- discarding a written-up description because a port
    was out of range would be unforgivable.

    Collects fields only; the ``source`` the result is written under is the
    caller's to supply, and for every path through this module that is
    :data:`~cerno_pkg.constants.SOURCE_OPERATOR`.

    Returns:
        The collected input, or None if the operator cancelled (Ctrl+C).
    """
    from .authored_findings import AuthoredFindingInput, parse_target_tokens
    from .authored_findings import validate_authored_input

    draft = existing or AuthoredFindingInput(title="", severity_int=2)

    while True:
        try:
            title = Prompt.ask("Title", default=draft.title or None) or ""

            severity_label = ", ".join(f"{k}={v}" for k, v in _SEVERITY_CHOICES.items())
            info(f"Severity: {severity_label}")
            severity_raw = Prompt.ask(
                "Severity",
                choices=list(_SEVERITY_CHOICES),
                default=str(draft.severity_int),
                show_choices=False,
            )

            targets_default = ", ".join(
                f"{host}:{port}" if port is not None else host
                for host, port in draft.targets
            )
            info("Affected hosts: 'host' or 'host:port', comma-separated")
            targets_raw = Prompt.ask(
                "Affected hosts (blank for none)", default=targets_default
            )

            info("Description: Enter inserts a newline, Ctrl+J submits")
            description = prompt_multiline("Description: ", default=draft.description)

            cves_raw = Prompt.ask(
                "CVEs, comma-separated (optional)", default=", ".join(draft.cves)
            )
            reference = Prompt.ask(
                "Reference URL (optional)", default=draft.reference_url or ""
            )
        except KeyboardInterrupt:
            warn("Cancelled.")
            return None

        draft = AuthoredFindingInput(
            title=title.strip(),
            severity_int=int(severity_raw),
            targets=parse_target_tokens([targets_raw]),
            description=description,
            cves=[c.strip() for c in cves_raw.split(",") if c.strip()],
            reference_url=reference.strip() or None,
        )

        problems = validate_authored_input(draft)
        if not problems:
            return draft

        warn("That finding cannot be saved yet:")
        for problem in problems:
            warn(f"  - {problem}")
        info("Your answers are kept below; correct the ones that are wrong.")


def prompt_new_finding() -> Optional["AuthoredFindingInput"]:
    """Collect a brand-new operator finding, or None if cancelled."""
    header("Add a finding")
    info("Press Ctrl+C at any prompt to cancel.")
    return _prompt_authored_fields()


def prompt_edit_finding(finding_id: int) -> Optional["AuthoredFindingInput"]:
    """Collect edits to an existing authored finding, or None if cancelled.

    Every prompt starts pre-filled with what is stored, so an unchanged answer
    writes the same value back. Accepts an ``agent:`` finding as readily as an
    ``operator:`` one -- the operator owns the engagement and must be able to
    correct what an agent asserted.
    """
    from .authored_findings import AuthoredFindingError, load_authored_finding

    try:
        existing = load_authored_finding(finding_id)
    except AuthoredFindingError as exc:
        warn(str(exc))
        return None

    header("Update finding")
    info("Press Ctrl+C at any prompt to cancel; Enter keeps the current value.")
    return _prompt_authored_fields(existing)


# Note: browse_file_list and browse_workflow_groups live in cerno.py.
