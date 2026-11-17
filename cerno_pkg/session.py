"""Session persistence for cerno review sessions.

Database-only mode: all session state stored in SQLite database.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from .logging_setup import log_error, log_info


@dataclass
class SessionState:
    """
    Represents the state of a cerno review session.

    In database-only mode, finding lists are replaced with counts queried
    from the findings table review_state field.

    Attributes:
        dataset_name: Name of the dataset (for display)
        session_start: ISO format timestamp of session start
        in_progress_count: Count of findings viewed but not marked done
        done_count: Count of findings marked done
        tool_executions: Count of tool executions
        cve_extractions: Count of CVE extractions performed
        additional_dataset_ids: List of additional dataset IDs included in a multi-dataset session
    """

    dataset_name: str
    session_start: str
    in_progress_count: int
    done_count: int
    tool_executions: int
    cve_extractions: int
    additional_dataset_ids: list[int] = field(default_factory=list)


def save_session(
    dataset_id: int,
    session_start: datetime,
    in_progress_count: int = 0,
    done_count: int = 0,
    tool_executions: int = 0,
    cve_extractions: int = 0,
    additional_dataset_ids: Optional[list[int]] = None,
) -> Optional[int]:
    """
    Save session state to database.

    Args:
        dataset_id: Dataset ID
        session_start: Session start datetime
        in_progress_count: Accepted for compatibility; not stored (counts come
            from the v_session_stats view)
        done_count: Accepted for compatibility; not stored
        tool_executions: Accepted for compatibility; not stored
        cve_extractions: Accepted for compatibility; not stored
        additional_dataset_ids: Additional dataset IDs for multi-dataset sessions

    Returns:
        session_id if successful, None otherwise
    """
    session_id = _db_save_session(
        dataset_id,
        session_start,
        in_progress_count,
        done_count,
        tool_executions,
        cve_extractions,
        additional_dataset_ids=additional_dataset_ids,
    )

    if session_id:
        log_info(f"Session saved to database (ID: {session_id})")
        if additional_dataset_ids:
            _db_save_session_datasets(session_id, dataset_id, additional_dataset_ids)

    return session_id


def load_session(dataset_id: int) -> Optional[SessionState]:
    """
    Load active session state from database.

    Queries the database for the most recent active session (session_end IS NULL)
    and retrieves finding counts by querying the findings review_state field.

    Args:
        dataset_id: Dataset ID

    Returns:
        SessionState object with counts from database, or None if no active session
    """
    try:
        from .database import db_transaction, query_one, query_all

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
                    vs.findings_in_progress as in_progress_count,
                    vs.findings_done as done_count,
                    sc.dataset_name
                FROM v_session_stats vs
                JOIN sessions s ON vs.session_id = s.session_id
                JOIN datasets sc ON vs.dataset_id = sc.dataset_id
                WHERE vs.dataset_id = ? AND vs.session_end IS NULL
                ORDER BY vs.session_start DESC
                LIMIT 1
                """,
                (dataset_id,),
            )

            if not row:
                return None

            # Load additional dataset IDs for multi-dataset sessions
            additional_ids_rows = query_all(
                conn,
                "SELECT dataset_id FROM session_datasets WHERE session_id = ? AND dataset_id != ?",
                (row["session_id"], dataset_id),
            )
            additional_dataset_ids = [r["dataset_id"] for r in additional_ids_rows]

            return SessionState(
                dataset_name=row["dataset_name"],
                session_start=row["session_start"],
                in_progress_count=row["in_progress_count"],
                done_count=row["done_count"],
                tool_executions=row["tools_executed"],
                cve_extractions=row["cves_extracted"],
                additional_dataset_ids=additional_dataset_ids,
            )

    except Exception as e:
        log_error(f"Failed to load session from database: {e}")
        return None


def delete_session(dataset_id: int) -> None:
    """
    Mark the dataset's active session as ended.

    Despite the name, this does **not** delete the row: it stamps
    ``session_end`` and leaves the record in place. That is deliberate — the
    surviving row is what tells ``onboarding.show_workflow_guidance()`` the dataset
    has been reviewed before, so first-run guidance stays suppressed on
    re-entry. The name is kept because it is part of the public API
    (``cerno_pkg.__all__``).

    Args:
        dataset_id: Dataset ID
    """
    _db_end_session(dataset_id)


# ========== Database Integration ==========


def _db_save_session(
    dataset_id: int,
    session_start: datetime,
    in_progress_count: int,
    done_count: int,
    tool_executions: int,
    cve_extractions: int,
    additional_dataset_ids: Optional[list[int]] = None,
) -> Optional[int]:
    """Save session to database (internal helper).

    Args:
        dataset_id: Dataset ID
        session_start: Session start datetime
        in_progress_count: Not stored (see v_session_stats)
        done_count: Not stored
        tool_executions: Not stored
        cve_extractions: Not stored
        additional_dataset_ids: Additional dataset IDs in a multi-dataset session; their
            last_reviewed_at is stamped alongside the primary dataset

    Returns:
        session_id if successful, None otherwise
    """
    try:
        from .database import db_transaction, query_one
        from .models import now_iso

        with db_transaction() as conn:
            # Update last_reviewed_at for every scan in the session
            stamp_ids = [dataset_id] + (additional_dataset_ids or [])
            placeholders = ",".join("?" * len(stamp_ids))
            conn.execute(
                f"UPDATE datasets SET last_reviewed_at = ? WHERE dataset_id IN ({placeholders})",
                (now_iso(), *stamp_ids),
            )

            # Check for active session
            row = query_one(
                conn,
                "SELECT session_id FROM sessions WHERE dataset_id = ? AND session_end IS NULL ORDER BY session_start DESC LIMIT 1",
                (dataset_id,),
            )

            session_id: int | None
            if row:
                # Session exists - statistics will be computed via v_session_stats view
                # Aggregate statistics are computed by SQL views, not cached in columns
                session_id = row["session_id"]
            else:
                # Create new session
                cursor = conn.execute(
                    """
                    INSERT INTO sessions (dataset_id, session_start)
                    VALUES (?, ?)
                    """,
                    (dataset_id, session_start.isoformat()),
                )
                session_id = cursor.lastrowid

        return session_id

    except Exception as e:
        log_error(f"Failed to save session to database: {e}")
        return None


def _db_save_session_datasets(
    session_id: int,
    primary_dataset_id: int,
    additional_dataset_ids: list[int],
) -> None:
    """Upsert scan associations for a multi-dataset session.

    Stores all dataset_ids (primary + additional) in session_datasets table.
    Uses INSERT OR IGNORE to be idempotent (safe to call multiple times).

    Args:
        session_id: Session ID to associate datasets with
        primary_dataset_id: Primary dataset ID for the session
        additional_dataset_ids: Additional dataset IDs included in the session
    """
    try:
        from .database import db_transaction

        all_dataset_ids = [primary_dataset_id] + additional_dataset_ids
        with db_transaction() as conn:
            for sid in all_dataset_ids:
                conn.execute(
                    "INSERT OR IGNORE INTO session_datasets (session_id, dataset_id) VALUES (?, ?)",
                    (session_id, sid),
                )
    except Exception as e:
        log_error(f"Failed to save session_datasets: {e}")


def _db_end_session(dataset_id: int) -> None:
    """Mark active session as ended in database (internal helper).

    Args:
        dataset_id: Dataset ID
    """
    try:
        from .database import db_transaction

        with db_transaction() as conn:
            # End active session (duration_seconds computed via v_session_stats view)
            now = datetime.now().isoformat()
            conn.execute(
                """
                UPDATE sessions
                SET session_end = ?
                WHERE dataset_id = ? AND session_end IS NULL
                """,
                (now, dataset_id),
            )

    except Exception as e:
        log_error(f"Failed to end session in database: {e}")


# ===================================================================
# Dataset Summary and Statistics Display (moved from cerno.py)
# ===================================================================


def show_dataset_summary(
    dataset_dir: Path,
    top_ports_n: int = 25,
    dataset_id: Optional[int] = None,
    dataset_ids: Optional[list[int]] = None,
    dataset_names: Optional[list[str]] = None,
) -> None:
    """
    Display comprehensive dataset overview with host/port statistics.

    Database-only mode: queries all statistics from database.

    Args:
        dataset_dir: Dataset directory (used for display name only in single-dataset mode)
        top_ports_n: Number of top ports to display
        dataset_id: Dataset ID (required for database queries in single-dataset mode)
        dataset_ids: Optional list of dataset IDs for multi-dataset queries (overrides dataset_id)
        dataset_names: Optional list of dataset names for multi-dataset header display
    """
    from collections import Counter
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich import box
    from .ansi import header, err, get_console, style_if_enabled
    from .analysis import count_reviewed_in_dataset
    from .database import db_transaction, query_all
    from .parsing import is_ipv4, is_ipv6

    if dataset_id is None and not dataset_ids:
        err("Database dataset_id is required for dataset summary")
        return

    _console_global = get_console()

    # Build title: single dataset uses dataset_dir.name, multi-dataset lists all names
    is_multi = dataset_ids and len(dataset_ids) > 1
    if is_multi and dataset_names:
        if len(dataset_names) == 2:
            title_names = f"{dataset_names[0]} + {dataset_names[1]}"
        else:
            title_names = ", ".join(dataset_names)
        header(f"Dataset Overview — {title_names}")
    else:
        header(f"Dataset Overview — {dataset_dir.name}")

    effective_dataset_id = dataset_id or (dataset_ids[0] if dataset_ids else 0)
    total_files, reviewed_files = count_reviewed_in_dataset(
        dataset_dir,
        dataset_id=effective_dataset_id,
        dataset_ids=dataset_ids if is_multi else None,
    )

    # Query all host/port data from database
    unique_hosts = set()
    scan_targets = set()
    ipv4_set = set()
    ipv6_set = set()
    no_ip_set = set()
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
            # Get all host/port combinations for this dataset (or all selected datasets)
            if is_multi and dataset_ids:
                id_placeholders = ",".join("?" * len(dataset_ids))
                rows = query_all(
                    conn,
                    f"""
                    SELECT DISTINCT h.ip_address, h.scan_target, fah.port_number, fah.finding_id
                    FROM finding_affected_hosts fah
                    JOIN findings f ON fah.finding_id = f.finding_id
                    JOIN hosts h ON fah.host_id = h.host_id
                    WHERE f.dataset_id IN ({id_placeholders})
                    """,
                    tuple(dataset_ids),
                )
                empty_files = query_all(
                    conn,
                    f"""
                    SELECT DISTINCT f.finding_type_id
                    FROM findings f
                    LEFT JOIN finding_affected_hosts fah ON f.finding_id = fah.finding_id
                    WHERE f.dataset_id IN ({id_placeholders}) AND fah.finding_id IS NULL
                    """,
                    tuple(dataset_ids),
                )
            else:
                rows = query_all(
                    conn,
                    """
                    SELECT DISTINCT h.ip_address, h.scan_target, fah.port_number, fah.finding_id
                    FROM finding_affected_hosts fah
                    JOIN findings f ON fah.finding_id = f.finding_id
                    JOIN hosts h ON fah.host_id = h.host_id
                    WHERE f.dataset_id = ?
                    """,
                    (effective_dataset_id,),
                )
                empty_files = query_all(
                    conn,
                    """
                    SELECT f.finding_id
                    FROM findings f
                    LEFT JOIN finding_affected_hosts fah ON f.finding_id = fah.finding_id
                    WHERE f.dataset_id = ? AND fah.finding_id IS NULL
                    """,
                    (effective_dataset_id,),
                )
            empties = len(empty_files)

        # Track unique host:port combinations to avoid counting duplicates
        unique_host_port_pairs = set()

        # Process query results.
        #
        # Classify by the ip_address VALUE, not by hosts.scan_target_type: that
        # column describes the *scan target string*, so a host reached by
        # hostname is 'fqdn' even when its resolved IP is a perfectly good
        # IPv4/IPv6 address. Bucketing on it left those hosts in neither child
        # row, so the breakdown did not sum to Unique Hosts.
        for row in rows:
            host = row["ip_address"]
            port = row["port_number"]

            unique_hosts.add(host)
            scan_targets.add(row["scan_target"])

            if is_ipv4(host):
                ipv4_set.add(host)
            elif is_ipv6(host):
                ipv6_set.add(host)
            else:
                # ip_address holds a hostname: nuclei_import and ingest create
                # hosts keyed (host, host) when no address was resolved.
                no_ip_set.add(host)

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
        f"[cyan]Done:[/cyan] [{review_color}]{reviewed_files} ({review_pct:.1f}%)[/{review_color}]",
    ]
    if empties > 0:
        file_stats_parts.append(f"[cyan]Empty:[/cyan] {empties}")

    _console_global.print(" │ ".join(file_stats_parts))
    _console_global.print()  # Blank line

    # Host & Port Analysis Table
    analysis_table = Table(
        show_header=True,
        header_style=style_if_enabled("bold cyan"),
        box=box.SIMPLE,
        title="Host & Port Analysis",
        title_style=style_if_enabled("bold blue"),
    )
    analysis_table.add_column("Metric", style=style_if_enabled("cyan"))
    analysis_table.add_column(
        "Value", justify="right", style=style_if_enabled("yellow")
    )

    # "Unique Hosts" counts machines (distinct resolved ip_address). The three
    # children are mutually exclusive and always sum to it.
    analysis_table.add_row("Unique Hosts", str(len(unique_hosts)))
    analysis_table.add_row("  └─ IPv4", str(len(ipv4_set)))
    analysis_table.add_row("  └─ IPv6", str(len(ipv6_set)))
    if no_ip_set:
        analysis_table.add_row("  └─ No resolved IP", str(len(no_ip_set)))

    # Scan targets are what you point a tool at. Virtual hosting makes one
    # machine own several, so this legitimately exceeds Unique Hosts; show it
    # only when the two differ, to keep the common case uncluttered.
    if len(scan_targets) != len(unique_hosts):
        analysis_table.add_row("Scan Targets", str(len(scan_targets)))

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
            title_style=style_if_enabled("bold blue"),
        )
        top_ports_table.add_column(
            "Port", justify="right", style=style_if_enabled("cyan")
        )
        top_ports_table.add_column(
            "Occurrences", justify="right", style=style_if_enabled("yellow")
        )

        # Get top N ports by occurrence count
        for port, count in ports_counter.most_common(top_ports_n):
            top_ports_table.add_row(str(port), str(count))

        _console_global.print(top_ports_table)
        _console_global.print()  # Blank line after table
