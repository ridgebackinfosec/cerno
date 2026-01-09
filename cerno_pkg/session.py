"""Session persistence for cerno review sessions.

Database-only mode: all session state stored in SQLite database.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from .logging_setup import log_error, log_info


@dataclass
class SessionState:
    """
    Represents the state of a cerno review session.

    In database-only mode, file lists are replaced with counts queried
    from the findings table review_state field.

    Attributes:
        scan_name: Name of the scan (for display)
        session_start: ISO format timestamp of session start
        reviewed_count: Count of reviewed (not marked complete) files
        completed_count: Count of marked complete files
        skipped_count: Count of skipped (empty) files
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions performed
    """

    scan_name: str
    session_start: str
    reviewed_count: int
    completed_count: int
    skipped_count: int
    tool_executions: int
    cve_extractions: int


def save_session(
    scan_id: int,
    session_start: datetime,
    reviewed_count: int = 0,
    completed_count: int = 0,
    skipped_count: int = 0,
    tool_executions: int = 0,
    cve_extractions: int = 0,
) -> Optional[int]:
    """
    Save session state to database.

    Args:
        scan_id: Scan ID
        session_start: Session start datetime
        reviewed_count: Count of reviewed files
        completed_count: Count of completed files
        skipped_count: Count of skipped files
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions

    Returns:
        session_id if successful, None otherwise
    """
    session_id = _db_save_session(
        scan_id, session_start, reviewed_count, completed_count,
        skipped_count, tool_executions, cve_extractions
    )

    if session_id:
        log_info(f"Session saved to database (ID: {session_id})")

    return session_id


def load_session(scan_id: int) -> Optional[SessionState]:
    """
    Load active session state from database.

    Queries the database for the most recent active session (session_end IS NULL)
    and retrieves file counts by querying the findings review_state field.

    Args:
        scan_id: Scan ID

    Returns:
        SessionState object with counts from database, or None if no active session
    """
    try:
        from .database import db_transaction, query_one

        with db_transaction() as conn:
            # Query active session using v_session_stats view
            row = query_one(
                conn,
                """
                SELECT
                    vs.session_id,
                    vs.session_start,
                    vs.tools_executed,
                    vs.cves_extracted,
                    vs.files_reviewed as reviewed_count,
                    vs.files_completed as completed_count,
                    vs.files_skipped as skipped_count,
                    sc.scan_name
                FROM v_session_stats vs
                JOIN sessions s ON vs.session_id = s.session_id
                JOIN scans sc ON vs.scan_id = sc.scan_id
                WHERE vs.scan_id = ? AND vs.session_end IS NULL
                ORDER BY vs.session_start DESC
                LIMIT 1
                """,
                (scan_id,)
            )

            if not row:
                return None

            return SessionState(
                scan_name=row["scan_name"],
                session_start=row["session_start"],
                reviewed_count=row["reviewed_count"],
                completed_count=row["completed_count"],
                skipped_count=row["skipped_count"],
                tool_executions=row["tools_executed"],
                cve_extractions=row["cves_extracted"],
            )

    except Exception as e:
        log_error(f"Failed to load session from database: {e}")
        return None


def delete_session(scan_id: int) -> None:
    """
    Mark database session as ended.

    Args:
        scan_id: Scan ID
    """
    _db_end_session(scan_id)


# ========== Database Integration ==========


def _db_save_session(
    scan_id: int,
    session_start: datetime,
    reviewed_count: int,
    completed_count: int,
    skipped_count: int,
    tool_executions: int,
    cve_extractions: int,
) -> Optional[int]:
    """Save session to database (internal helper).

    Args:
        scan_id: Scan ID
        session_start: Session start datetime
        reviewed_count: Count of reviewed files
        completed_count: Count of completed files
        skipped_count: Count of skipped files
        tool_executions: Tool execution count
        cve_extractions: CVE extraction count

    Returns:
        session_id if successful, None otherwise
    """
    try:
        from .database import db_transaction, query_one
        from .models import now_iso

        with db_transaction() as conn:
            # Update last_reviewed_at for scan
            conn.execute(
                "UPDATE scans SET last_reviewed_at = ? WHERE scan_id = ?",
                (now_iso(), scan_id)
            )

            # Check for active session
            row = query_one(
                conn,
                "SELECT session_id FROM sessions WHERE scan_id = ? AND session_end IS NULL ORDER BY session_start DESC LIMIT 1",
                (scan_id,)
            )

            if row:
                # Session exists - statistics will be computed via v_session_stats view
                # No need to update aggregate columns (removed in schema v5)
                session_id = row["session_id"]
            else:
                # Create new session
                cursor = conn.execute(
                    """
                    INSERT INTO sessions (scan_id, session_start)
                    VALUES (?, ?)
                    """,
                    (scan_id, session_start.isoformat())
                )
                session_id = cursor.lastrowid

        return session_id

    except Exception as e:
        log_error(f"Failed to save session to database: {e}")
        return None


def _db_end_session(scan_id: int) -> None:
    """Mark active session as ended in database (internal helper).

    Args:
        scan_id: Scan ID
    """
    try:
        from .database import db_transaction

        with db_transaction() as conn:
            # End active session (duration_seconds computed via v_session_stats view in schema v5)
            now = datetime.now().isoformat()
            conn.execute(
                """
                UPDATE sessions
                SET session_end = ?
                WHERE scan_id = ? AND session_end IS NULL
                """,
                (now, scan_id)
            )

    except Exception as e:
        log_error(f"Failed to end session in database: {e}")


# ===================================================================
# Scan Summary and Statistics Display (moved from cerno.py)
# ===================================================================


def show_scan_summary(
    scan_dir: Path,
    top_ports_n: int = 25,
    scan_id: Optional[int] = None
) -> None:
    """
    Display comprehensive scan overview with host/port statistics.

    Database-only mode: queries all statistics from database.

    Args:
        scan_dir: Scan directory (used for display name only)
        top_ports_n: Number of top ports to display
        scan_id: Scan ID (required for database queries)
    """
    from collections import Counter
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box
    from .ansi import header, err, get_console, style_if_enabled
    from .analysis import count_reviewed_in_scan
    from .database import db_transaction, query_all

    if scan_id is None:
        err("Database scan_id is required for scan summary")
        return

    _console_global = get_console()
    header(f"Scan Overview — {scan_dir.name}")

    total_files, reviewed_files = count_reviewed_in_scan(scan_dir, scan_id=scan_id)

    # Query all host/port data from database
    unique_hosts = set()
    ipv4_set = set()
    ipv6_set = set()
    ports_counter: Counter = Counter()
    empties = 0

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=_console_global,
        transient=True,
    ) as progress:
        task = progress.add_task("Querying database for overview...", total=None)

        with db_transaction() as conn:
            # Get all host/port combinations for this scan
            rows = query_all(
                conn,
                """
                SELECT DISTINCT h.host_address, fah.port_number, h.host_type, fah.finding_id
                FROM finding_affected_hosts fah
                JOIN findings f ON fah.finding_id = f.finding_id
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE f.scan_id = ?
                """,
                (scan_id,)
            )

            # Count findings with no hosts (empty findings)
            empty_files = query_all(
                conn,
                """
                SELECT f.finding_id
                FROM findings f
                LEFT JOIN finding_affected_hosts fah ON f.finding_id = fah.finding_id
                WHERE f.scan_id = ? AND fah.finding_id IS NULL
                """,
                (scan_id,)
            )
            empties = len(empty_files)

        # Track unique host:port combinations to avoid counting duplicates
        unique_host_port_pairs = set()

        # Process query results
        for row in rows:
            host = row["host_address"]
            port = row["port_number"]
            host_type = row["host_type"]
            is_ipv4 = (host_type == 'ipv4')
            is_ipv6 = (host_type == 'ipv6')

            unique_hosts.add(host)

            if is_ipv4:
                ipv4_set.add(host)
            elif is_ipv6:
                ipv6_set.add(host)

            if port is not None:
                # Track unique (host, port) pairs instead of counting every row
                unique_host_port_pairs.add((host, str(port)))

        # Now count ports from unique host:port combinations only
        for host, port in unique_host_port_pairs:
            ports_counter[port] += 1

        progress.update(task, completed=True)

    # File Statistics - Inline Display
    # Calculate reviewed percentage and color code
    review_pct = (reviewed_files / total_files * 100) if total_files > 0 else 0
    if review_pct > 75:
        review_color = "green"
    elif review_pct >= 25:
        review_color = "yellow"
    else:
        review_color = "red"

    # Build inline file stats with conditional display
    file_stats_parts = [
        f"[cyan]Findings:[/cyan] {total_files} total",
        f"[cyan]Reviewed:[/cyan] [{review_color}]{reviewed_files} ({review_pct:.1f}%)[/{review_color}]"
    ]
    if empties > 0:
        file_stats_parts.append(f"[cyan]Empty:[/cyan] {empties}")

    _console_global.print(" │ ".join(file_stats_parts))
    _console_global.print()  # Blank line

    # Host & Port Analysis Table
    analysis_table = Table(show_header=True, header_style=style_if_enabled("bold cyan"), box=box.SIMPLE, title="Host & Port Analysis", title_style=style_if_enabled("bold blue"))
    analysis_table.add_column("Metric", style=style_if_enabled("cyan"))
    analysis_table.add_column("Value", justify="right", style=style_if_enabled("yellow"))

    analysis_table.add_row("Unique Hosts", str(len(unique_hosts)))
    analysis_table.add_row("  └─ IPv4", str(len(ipv4_set)))
    analysis_table.add_row("  └─ IPv6", str(len(ipv6_set)))

    port_set = set(ports_counter.keys())
    analysis_table.add_row("Unique Ports", str(len(port_set)))

    _console_global.print(analysis_table)
    _console_global.print()  # Blank line after table

    # Top Ports Table (if any ports found)
    if ports_counter and top_ports_n > 0:
        top_ports_table = Table(
            show_header=True,
            header_style=style_if_enabled("bold cyan"),
            box=box.SIMPLE,
            title=f"Top {min(top_ports_n, len(ports_counter))} Ports",
            title_style=style_if_enabled("bold blue")
        )
        top_ports_table.add_column("Port", justify="right", style=style_if_enabled("cyan"))
        top_ports_table.add_column("Occurrences", justify="right", style=style_if_enabled("yellow"))

        # Get top N ports by occurrence count
        for port, count in ports_counter.most_common(top_ports_n):
            top_ports_table.add_row(str(port), str(count))

        _console_global.print(top_ports_table)
        _console_global.print()  # Blank line after table
