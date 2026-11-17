"""Onboarding and workflow guidance for first-time Cerno users.

This module provides:
- Interactive guided tour for first-time users
- Context-aware workflow guidance after scan selection
- Tips and keyboard shortcut references
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from .ansi import get_console, header, info, ok, style_if_enabled
from .constants import (
    REVIEW_STATE_DONE,
    REVIEW_STATE_IN_PROGRESS,
    REVIEW_STATE_LABELS,
    REVIEW_STATE_STYLES,
    REVIEW_STATE_UNREVIEWED,
)

if TYPE_CHECKING:
    pass


def show_guided_tour() -> str:
    """Show interactive guided tour for first-time users.

    Displays a 4-step walkthrough covering:
    1. Importing datasets
    2. Reviewing findings by severity
    3. Running tools
    4. Tracking progress

    Returns:
        "completed" - User finished tour
        "skipped" - User skipped tour
    """
    # Welcome screen
    print()  # Blank line for spacing
    header("Welcome to Cerno! 🎯")
    info("")
    info("Cerno helps you review findings from Nessus, nuclei and Burp, and run")
    info("security tools (nmap, NetExec, Metasploit) against findings.")
    info("")
    info("This quick tour covers:")
    info("  1. Importing datasets")
    info("  2. Reviewing findings by severity")
    info("  3. Running tools against vulnerable hosts")
    info("  4. Tracking your progress")
    info("")

    choice = (
        Prompt.ask("[Enter] Start tour | [S] Skip tour", default="").strip().lower()
    )
    if choice == "s":
        ok("Tour skipped. To get started, import findings:")
        info("  cerno import nessus /path/to/scan.nessus")
        info("  cerno import nuclei /path/to/nuclei.json")
        info("")
        return "skipped"

    # Tour steps (1-4)
    current_step = 1
    while current_step <= 4:
        show_tour_step(current_step)

        if current_step == 4:
            # Last step - only forward/exit
            choice = (
                Prompt.ask("[Enter] Exit tour | [B] Back", default="").strip().lower()
            )
        else:
            choice = (
                Prompt.ask("[N] Next | [B] Back | [Q] Skip tour", default="")
                .strip()
                .lower()
            )

        if choice in ("n", "next", ""):
            current_step += 1
        elif choice in ("b", "back"):
            current_step = max(1, current_step - 1)
        elif choice in ("q", "skip", "quit"):
            ok("Tour skipped. To get started, import findings:")
            info("  cerno import nessus /path/to/scan.nessus")
            info("  cerno import nuclei /path/to/nuclei.json")
            info("")
            return "skipped"

    ok("Tour completed! Import your first scan to get started:")
    info("  cerno import nessus /path/to/scan.nessus")
    info("  cerno import nuclei /path/to/nuclei.json")
    info("")
    return "completed"


def show_tour_step(step: int) -> None:
    """Display specific tour step content.

    Args:
        step: Step number (1-4)
    """
    print()  # Blank line for spacing

    if step == 1:
        header("Step 1/4: Importing Datasets")
        info("─" * 60)
        info("")
        info("First, import a .nessus file:")
        info("")
        info("  $ cerno import nessus /path/to/scan.nessus")
        info("  $ cerno import nuclei /path/to/nuclei.json")
        info("")
        info("This parses findings and stores them in ~/.cerno/cerno.db")
        info("You can import multiple datasets and switch between them.")
        info("")

    elif step == 2:
        header("Step 2/4: Reviewing Findings by Severity")
        info("─" * 60)
        info("")
        info("After importing, you'll see findings grouped by severity:")
        info("")
        info("  Critical (12 findings) ← Start here!")
        info("  High (34 findings)")
        info("  Medium (89 findings)")
        info("  Low (45 findings)")
        info("")
        info("Navigate with keyboard:")
        info("  [1-5] Select severity level")
        info("")

    elif step == 3:
        header("Step 3/4: Running Tools")
        info("─" * 60)
        info("")
        info("For each finding, you can:")
        info("  [T] Run tools (nmap, NetExec, Metasploit)")
        info("  [V] View affected hosts/ports")
        info("  [E] See CVE details")
        info("  [W] View workflow steps [if available]")
        info("")
        info("Tools run against the exact hosts/ports affected by the finding.")
        info("Results are saved to ~/.cerno/artifacts/ (configurable: results_root)")
        info("")

    elif step == 4:
        header("Step 4/4: Tracking Progress")
        info("─" * 60)
        info("")
        info("Each finding has a status: Unreviewed → In Progress → Done.")
        info("")
        info("  [M] Move - move a finding to its next status")
        info("  [D] Done only - show Done findings here; [M] then moves them back")
        info("")
        info("Resume where you left off - Cerno saves your progress!")
        info("")


def show_workflow_guidance(
    dataset_name: str,
    dataset_id: int,
    dataset_ids: Optional[list[int]] = None,
    dataset_names: Optional[list[str]] = None,
) -> None:
    """Show workflow guidance with context-aware tips.

    Only displays for first-time users of a dataset. Skips if any session
    exists for the dataset (indicating previous review activity).

    Args:
        dataset_name: Name of the primary selected dataset
        dataset_id: Database dataset ID of the primary dataset
        dataset_ids: All selected dataset IDs (multi-dataset mode); if None, single-dataset
        dataset_names: All selected dataset names (multi-dataset mode)
    """
    from .database import get_connection

    # Narrow dataset_ids inline so the Optional is discharged for type checkers;
    # is_multi then follows from the result rather than being computed twice.
    effective_dataset_ids = (
        dataset_ids
        if dataset_ids is not None and len(dataset_ids) > 1
        else [dataset_id]
    )
    is_multi = len(effective_dataset_ids) > 1

    # Query scan statistics
    with get_connection() as conn:
        # Check if user has reviewed this dataset before (use primary dataset_id)
        cursor = conn.execute(
            "SELECT session_id FROM sessions WHERE dataset_id = ? LIMIT 1",
            (dataset_id,),
        )
        existing_session = cursor.fetchone()

        # Skip guidance if user has seen this dataset before
        if existing_session:
            return

        placeholders = ",".join("?" * len(effective_dataset_ids))
        cursor = conn.execute(
            f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN review_state = 'unreviewed' THEN 1 ELSE 0 END) as unreviewed,
                SUM(CASE WHEN review_state = 'in_progress' THEN 1 ELSE 0 END) as in_progress,
                SUM(CASE WHEN review_state = 'done' THEN 1 ELSE 0 END) as done
            FROM findings
            WHERE dataset_id IN ({placeholders})
            """,
            effective_dataset_ids,
        )
        stats = cursor.fetchone()

    total, unreviewed, in_progress, completed = stats[0], stats[1], stats[2], stats[3]

    # Skip guidance if scan has no findings or none are still unreviewed
    if total == 0 or unreviewed == 0:
        return

    # Build display name
    if is_multi and dataset_names:
        if len(dataset_names) == 2:
            display_name = f"{dataset_names[0]} + {dataset_names[1]}"
        else:
            display_name = f"{len(dataset_names)} datasets"
    else:
        display_name = dataset_name

    # Build main content as Text object
    content = Text()

    # Dataset info section with styled labels
    content.append("Dataset: ", style="bold")
    content.append(f"{display_name}\n\n")

    # Statistics with colored labels
    content.append("Findings: ", style="bold cyan")
    content.append(f"{total} findings  ")
    for state, count in (
        (REVIEW_STATE_UNREVIEWED, unreviewed),
        (REVIEW_STATE_IN_PROGRESS, in_progress),
        (REVIEW_STATE_DONE, completed),
    ):
        content.append("│  ", style="dim")
        content.append(
            f"{REVIEW_STATE_LABELS[state]}: ",
            style=f"bold {REVIEW_STATE_STYLES[state]}",
        )
        content.append(f"{count}  ")
    content.append("\n\n")

    # Recommended workflow with icons and inline styled keys
    content.append("Recommended Workflow:\n", style="bold")
    content.append("  1️⃣  Start with Critical/High severity findings\n")
    content.append("  2️⃣  Open findings to see affected hosts ")
    content.append("[V]", style="cyan")
    content.append(" for grouped view\n")
    content.append("  3️⃣  Run verification tools ")
    content.append("[T]", style="cyan")
    content.append(" for nmap/NetExec/Metasploit\n")
    content.append("  4️⃣  Move findings Unreviewed → In Progress → Done with ")
    content.append("[M]", style="cyan")
    content.append("\n")
    content.append("  5️⃣  Use ")
    content.append("[H]", style="cyan")
    content.append(" to find duplicate findings across the list\n")
    content.append("  6️⃣  Check ")
    content.append("[D]", style="cyan")
    content.append(
        " to show Done findings ([M] then moves them back to Unreviewed)\n\n"
    )

    # Combine content and shortcuts
    combined = Text()
    combined.append_text(content)
    combined.append_text(Text.from_markup("\n"))

    # Wrap in Panel
    console = get_console()
    print()  # Blank line for spacing
    panel = Panel(
        combined,
        title="[bold cyan]Getting Started with This Dataset[/]",
        border_style=style_if_enabled("cyan"),
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)

    # Context-aware tips
    tips_panel = _show_context_aware_tips(
        dataset_id, total, unreviewed, completed, dataset_ids=dataset_ids
    )
    if tips_panel:
        console.print(tips_panel)

    # Styled prompt with key formatting
    prompt_text = Text()
    prompt_text.append("[Enter] ", style=style_if_enabled("cyan"))
    prompt_text.append("Start reviewing  ")
    prompt_text.append("[?] ", style=style_if_enabled("cyan"))
    prompt_text.append("More tips")

    choice = Prompt.ask(prompt_text, default="").strip().lower()

    if choice == "?":
        show_additional_tips()


def _show_context_aware_tips(
    dataset_id: int,
    total: int,
    unreviewed: int,
    completed: int,
    dataset_ids: Optional[list[int]] = None,
) -> Panel | None:
    """Build context-aware tips panel based on scan state.

    Args:
        dataset_id: Database dataset ID of the primary dataset
        total: Total finding count (already aggregated across dataset_ids if multi)
        unreviewed: Unreviewed finding count
        completed: Done finding count
        dataset_ids: All selected dataset IDs (multi-dataset mode); if None, single-dataset

    Returns:
        Panel with tips, or None if no tips to show
    """
    from .database import get_connection

    # Narrow dataset_ids inline so the Optional is discharged for type checkers;
    # is_multi then follows from the result rather than being computed twice.
    effective_dataset_ids = (
        dataset_ids
        if dataset_ids is not None and len(dataset_ids) > 1
        else [dataset_id]
    )
    is_multi = len(effective_dataset_ids) > 1
    placeholders = ",".join("?" * len(effective_dataset_ids))

    tips = []  # Collect tips as Text objects

    # Check for Critical findings
    with get_connection() as conn:
        cursor = conn.execute(
            f"""
            SELECT COUNT(*) FROM findings f
            JOIN finding_types p ON f.finding_type_id = p.finding_type_id
            WHERE f.dataset_id IN ({placeholders}) AND p.severity_int = 4
            """,
            effective_dataset_ids,
        )
        critical_count = cursor.fetchone()[0]

    if critical_count > 0:
        tip = Text()
        dataset_label = "These datasets have" if is_multi else "This dataset has"
        tip.append(
            f"{dataset_label} {critical_count} Critical finding(s) - prioritize these first!"
        )
        tips.append(tip)

    # Check for Metasploit modules
    with get_connection() as conn:
        cursor = conn.execute(
            f"""
            SELECT COUNT(DISTINCT f.finding_id)
            FROM findings f
            JOIN finding_types p ON f.finding_type_id = p.finding_type_id
            WHERE f.dataset_id IN ({placeholders}) AND p.metasploit_names IS NOT NULL AND p.metasploit_names != '[]'
            """,
            effective_dataset_ids,
        )
        msf_count = cursor.fetchone()[0]

    if msf_count > 0:
        tip = Text()
        tip.append("⚡ ", style="cyan")
        tip.append(f"{msf_count} finding(s) have Metasploit modules!")
        tips.append(tip)

    # Progress encouragement
    if completed > 0 and total > 0:
        progress_pct = int((completed / total) * 100)
        if progress_pct >= 50:
            tip = Text()
            tip.append("✅ ", style="green")
            tip.append(
                f"Progress: {completed}/{total} findings Done ({progress_pct}%) - keep going!"
            )
            tips.append(tip)

    # Return panel if tips exist
    if tips:
        content = Text("\n").join(tips)
        return Panel(
            content,
            title="[bold yellow]Tips[/]",
            border_style=style_if_enabled("yellow"),
            padding=(1, 2),
            expand=False,
        )
    return None


def show_additional_tips() -> None:
    """Show additional tips and keyboard shortcuts with Rich UI."""
    console = get_console()
    print()  # Blank line for spacing

    # Build content as Text object
    content = Text()

    # Filtering & Navigation section
    content.append("Filtering & Navigation:\n", style="bold cyan")
    content.append("  • Use ")
    content.append("[F]", style="cyan")
    content.append(" to filter findings by name\n")
    content.append("  • Press ")
    content.append("[C]", style="cyan")
    content.append(" to clear active filters\n")
    content.append("  • Use ")
    content.append("[N]", style="cyan")
    content.append("/")
    content.append("[P]", style="cyan")
    content.append(" for next/previous page in long lists\n")
    content.append("  • Press ")
    content.append("[B]", style="cyan")
    content.append(" or ")
    content.append("[Q]", style="cyan")
    content.append(" to go back/quit at any time\n\n")

    # Finding Analysis section
    content.append("Finding Analysis:\n", style="bold cyan")
    content.append("  • ")
    content.append("[H]", style="cyan")
    content.append(" Compare findings - see which have identical hosts\n")
    content.append("  • ")
    content.append("[O]", style="cyan")
    content.append(" Overlapping analysis - find subset relationships\n")
    content.append("  • ")
    content.append("[V]", style="cyan")
    content.append(" View hosts in grouped format for easier review\n\n")

    # Tool Execution section
    content.append("Tool Execution:\n", style="bold cyan")
    content.append("  • Tool results are saved to ", style="")
    content.append("~/.cerno/artifacts/", style="yellow")
    content.append("\n")
    content.append("  • You can run multiple tools on the same finding\n")
    content.append("  • Press ")
    content.append("[T]", style="cyan")
    content.append(" to see tool menu with nmap, NetExec, Metasploit\n\n")

    # Progress Tracking section
    content.append("Progress Tracking:\n", style="bold cyan")
    content.append("  • ")
    content.append("[M]", style="cyan")
    content.append(" Move - Unreviewed → In Progress → Done\n")
    content.append("  • ")
    content.append("[D]", style="cyan")
    content.append(" Done only - review Done findings, or move them back with ")
    content.append("[M]", style="cyan")
    content.append("\n")
    content.append("  • Sessions auto-save - resume where you left off!")

    # Wrap in Panel
    panel = Panel(
        content,
        title="[bold cyan]Additional Tips & Tricks[/]",
        border_style=style_if_enabled("cyan"),
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)

    # Styled prompt
    prompt_text = Text()
    prompt_text.append("[Enter] ", style=style_if_enabled("cyan"))
    prompt_text.append("Continue")

    Prompt.ask(prompt_text, default="")
