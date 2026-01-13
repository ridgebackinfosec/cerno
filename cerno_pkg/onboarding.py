"""Onboarding and workflow guidance for first-time Cerno users.

This module provides:
- Interactive guided tour for first-time users
- Context-aware workflow guidance after scan selection
- Tips and keyboard shortcut references
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from .ansi import get_console, get_terminal_width, header, info, ok, style_if_enabled

if TYPE_CHECKING:
    pass


def show_guided_tour() -> str:
    """Show interactive guided tour for first-time users.

    Displays a 4-step walkthrough covering:
    1. Importing scans
    2. Reviewing findings by severity
    3. Running tools
    4. Tracking progress

    Returns:
        "completed" - User finished tour
        "skipped" - User skipped tour
        "exit" - User wants to exit and import scan
    """
    # Welcome screen
    print()  # Blank line for spacing
    header("Welcome to Cerno! 🎯")
    info("")
    info("Cerno helps you review Nessus vulnerability scans and run")
    info("security tools (nmap, NetExec, Metasploit) against findings.")
    info("")
    info("This quick tour covers:")
    info("  1. Importing scans")
    info("  2. Reviewing findings by severity")
    info("  3. Running tools against vulnerable hosts")
    info("  4. Tracking your progress")
    info("")

    choice = Prompt.ask("[Enter] Start tour | [S] Skip tour", default="").strip().lower()
    if choice == "s":
        ok("Tour skipped. To get started, import a Nessus scan:")
        info("  cerno import nessus /path/to/scan.nessus")
        info("")
        return "skipped"

    # Tour steps (1-4)
    current_step = 1
    while current_step <= 4:
        show_tour_step(current_step)

        if current_step == 4:
            # Last step - only forward/exit
            choice = Prompt.ask("[Enter] Exit tour | [B] Back", default="").strip().lower()
        else:
            choice = Prompt.ask("[N] Next | [B] Back | [Q] Skip tour", default="").strip().lower()

        if choice in ("n", "next", ""):
            current_step += 1
        elif choice in ("b", "back"):
            current_step = max(1, current_step - 1)
        elif choice in ("q", "skip", "quit"):
            ok("Tour skipped. To get started, import a Nessus scan:")
            info("  cerno import nessus /path/to/scan.nessus")
            info("")
            return "skipped"

    ok("Tour completed! Import your first scan to get started:")
    info("  cerno import nessus /path/to/scan.nessus")
    info("")
    return "completed"


def show_tour_step(step: int) -> None:
    """Display specific tour step content.

    Args:
        step: Step number (1-4)
    """
    print()  # Blank line for spacing

    if step == 1:
        header("Step 1/4: Importing Scans")
        info("─" * 60)
        info("")
        info("First, import a .nessus file:")
        info("")
        info("  $ cerno import nessus /path/to/scan.nessus")
        info("")
        info("This parses findings and stores them in ~/.cerno/cerno.db")
        info("You can import multiple scans and switch between them.")
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
        info("  [1-4] Select severity level")
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
        info("Results are saved to ~/.cerno/artifacts/")
        info("")

    elif step == 4:
        header("Step 4/4: Tracking Progress")
        info("─" * 60)
        info("")
        info("Mark findings to track what you've reviewed:")
        info("")
        info("  [M] Mark reviewed - Fully investigated")
        info("")
        info("Resume where you left off - Cerno saves your progress!")
        info("")


def show_workflow_guidance(scan_name: str, scan_id: int) -> None:
    """Show workflow guidance with context-aware tips.

    Only displays for first-time users of a scan. Skips if any session
    exists for the scan (indicating previous review activity).

    Args:
        scan_name: Name of selected scan
        scan_id: Database scan ID
    """
    from .database import get_connection

    # Query scan statistics
    with get_connection() as conn:
        # Check if user has reviewed this scan before
        cursor = conn.execute(
            "SELECT session_id FROM sessions WHERE scan_id = ? LIMIT 1",
            (scan_id,)
        )
        existing_session = cursor.fetchone()

        # Skip guidance if user has seen this scan before
        if existing_session:
            return

        cursor = conn.execute(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN review_state = 'pending' THEN 1 ELSE 0 END) as unreviewed,
                SUM(CASE WHEN review_state = 'reviewed' THEN 1 ELSE 0 END) as reviewed,
                SUM(CASE WHEN review_state = 'completed' THEN 1 ELSE 0 END) as completed
            FROM findings
            WHERE scan_id = ?
        """,
            (scan_id,),
        )
        stats = cursor.fetchone()

    total, unreviewed, reviewed, completed = stats[0], stats[1], stats[2], stats[3]

    # Skip guidance if scan has no findings or all are reviewed
    if total == 0 or unreviewed == 0:
        return

    # Import key_text helper for keyboard shortcuts
    from .render import key_text

    # Build main content as Text object
    content = Text()

    # Scan info section with styled labels
    content.append("Scan: ", style="bold")
    content.append(f"{scan_name}\n\n")

    # Statistics with colored labels
    content.append("Findings: ", style="bold cyan")
    content.append(f"{total} plugins  ")
    content.append("│  ", style="dim")
    content.append("Unreviewed: ", style="bold yellow")
    content.append(f"{unreviewed}  ")
    content.append("│  ", style="dim")
    content.append("Reviewed: ", style="bold green")
    content.append(f"{reviewed}\n\n")

    # Recommended workflow with icons and inline styled keys
    content.append("Recommended Workflow:\n", style="bold")
    content.append("  1️⃣  Start with Critical/High severity findings\n")
    content.append("  2️⃣  Open findings to see affected hosts ")
    content.append("[V]", style="cyan")
    content.append(" for grouped view\n")
    content.append("  3️⃣  Run verification tools ")
    content.append("[T]", style="cyan")
    content.append(" for nmap/NetExec/Metasploit\n")
    content.append("  4️⃣  Mark findings as reviewed ")
    content.append("[M]", style="cyan")
    content.append("\n")
    content.append("  5️⃣  Use ")
    content.append("[H]", style="cyan")
    content.append(" to find duplicate findings across plugins\n")
    content.append("  6️⃣  Check ")
    content.append("[R]", style="cyan")
    content.append(" to see reviewed findings (undo available)\n\n")

    # Keyboard shortcuts section with responsive grid
    content.append("Quick Reference:\n", style="bold")

    # Create keyboard shortcuts grid (responsive)
    term_width = get_terminal_width()
    shortcuts_grid = Table.grid(padding=(0, 2))

    if term_width >= 100:
        # 2-column layout for wide terminals
        shortcuts_grid.add_column()
        shortcuts_grid.add_column()

        shortcuts_grid.add_row(
            key_text("F", "Filter by plugin name"),
            key_text("C", "Clear filter")
        )
        shortcuts_grid.add_row(
            key_text("H", "Compare host:port sets"),
            key_text("O", "Find overlapping findings")
        )
        shortcuts_grid.add_row(
            key_text("?", "Help"),
            key_text("Q", "Quit")
        )
    else:
        # Single-column for narrow terminals
        shortcuts_grid.add_column()
        shortcuts_grid.add_row(key_text("F", "Filter by plugin name"))
        shortcuts_grid.add_row(key_text("C", "Clear filter"))
        shortcuts_grid.add_row(key_text("H", "Compare host:port sets"))
        shortcuts_grid.add_row(key_text("O", "Find overlapping findings"))
        shortcuts_grid.add_row(key_text("?", "Help"))
        shortcuts_grid.add_row(key_text("Q", "Quit"))

    # Combine content and shortcuts
    combined = Text()
    combined.append_text(content)
    combined.append_text(Text.from_markup("\n"))

    # Wrap in Panel
    console = get_console()
    print()  # Blank line for spacing
    panel = Panel(
        combined,
        title="[bold cyan]Getting Started with This Scan[/]",
        border_style=style_if_enabled("cyan"),
        padding=(1, 2),
        expand=False
    )
    console.print(panel)
    console.print(shortcuts_grid)

    # Context-aware tips
    tips_panel = _show_context_aware_tips(scan_id, total, unreviewed, completed)
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


def _show_context_aware_tips(scan_id: int, total: int, unreviewed: int, completed: int) -> Panel | None:
    """Build context-aware tips panel based on scan state.

    Args:
        scan_id: Database scan ID
        total: Total finding count
        unreviewed: Unreviewed finding count
        completed: Completed finding count

    Returns:
        Panel with tips, or None if no tips to show
    """
    from .database import get_connection

    tips = []  # Collect tips as Text objects

    # Check for Critical findings
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT COUNT(*) FROM findings f
            JOIN plugins p ON f.plugin_id = p.plugin_id
            WHERE f.scan_id = ? AND p.severity_int = 4
        """,
            (scan_id,),
        )
        critical_count = cursor.fetchone()[0]

    if critical_count > 0:
        tip = Text()
        tip.append("💡 ", style="yellow")
        tip.append(f"This scan has {critical_count} Critical finding(s) - prioritize these first!")
        tips.append(tip)

    # Check for Metasploit modules
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT COUNT(DISTINCT f.finding_id)
            FROM findings f
            JOIN plugins p ON f.plugin_id = p.plugin_id
            WHERE f.scan_id = ? AND p.metasploit_names IS NOT NULL AND p.metasploit_names != '[]'
        """,
            (scan_id,),
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
            tip.append(f"Progress: You've reviewed {completed}/{total} findings ({progress_pct}%) - keep going!")
            tips.append(tip)

    # Return panel if tips exist
    if tips:
        content = Text("\n").join(tips)
        return Panel(
            content,
            title="[bold yellow]Tips[/]",
            border_style=style_if_enabled("yellow"),
            padding=(1, 2),
            expand=False
        )
    return None


def show_additional_tips() -> None:
    """Show additional tips and keyboard shortcuts."""
    print()
    header("Additional Tips & Tricks")
    info("─" * 60)
    info("")
    info("Filtering & Navigation:")
    info("  • Use [F] to filter findings by plugin name")
    info("  • Press [C] to clear active filters")
    info("  • Use [N]/[P] for next/previous page in long lists")
    info("  • Press [B] or [Q] to go back/quit at any time")
    info("")
    info("Finding Analysis:")
    info("  • [H] Compare findings - see which have identical hosts")
    info("  • [O] Overlapping analysis - find subset relationships across findings")
    info("  • [V] View hosts in grouped format for easier review")
    info("")
    info("Tool Execution:")
    info("  • Tool results are saved to ~/.cerno/artifacts/")
    info("  • You can run multiple tools on the same finding")
    info("  • Press [T] to see tool menu with nmap, NetExec, Metasploit")
    info("")
    info("Progress Tracking:")
    info("  • [M] Mark reviewed - fully investigated")
    info("  • [R] View reviewed findings - you can undo with [U]")
    info("  • Sessions auto-save - resume where you left off!")
    info("")

    Prompt.ask("[Enter] Continue", default="")
