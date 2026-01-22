"""Cross-scan analysis functions for comparing findings and tracking host vulnerabilities.

This module provides functions to compare vulnerability findings between scans,
track host vulnerability history across multiple scans, and identify new/resolved/persistent
findings.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Optional

from .database import get_connection, query_all, query_one
from .logging_setup import log_timing


@dataclass
class ScanComparisonResult:
    """Result of comparing two scans.

    Contains new/resolved/persistent findings and hosts between two scans,
    along with summary statistics broken down by severity.
    """
    scan1_id: int
    scan1_name: str
    scan1_date: str
    scan2_id: int
    scan2_name: str
    scan2_date: str

    # Findings: list of dicts with plugin_id, plugin_name, severity_int, severity_label, affected_hosts
    new_findings: list[dict] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    persistent_findings: list[dict] = field(default_factory=list)

    # Hosts: list of dicts with host_id, ip_address, scan_target
    new_hosts: list[dict] = field(default_factory=list)
    removed_hosts: list[dict] = field(default_factory=list)
    persistent_hosts: list[dict] = field(default_factory=list)

    # Summary counts by severity (severity_int -> count)
    new_by_severity: dict[int, int] = field(default_factory=dict)
    resolved_by_severity: dict[int, int] = field(default_factory=dict)
    persistent_by_severity: dict[int, int] = field(default_factory=dict)

    @property
    def total_new(self) -> int:
        """Total count of new findings."""
        return len(self.new_findings)

    @property
    def total_resolved(self) -> int:
        """Total count of resolved findings."""
        return len(self.resolved_findings)

    @property
    def total_persistent(self) -> int:
        """Total count of persistent findings."""
        return len(self.persistent_findings)


@dataclass
class ScanSnapshot:
    """Snapshot of a host's vulnerability status in a specific scan."""
    scan_id: int
    scan_name: str
    scan_date: str
    finding_count: int
    max_severity: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    plugin_ids: list[int] = field(default_factory=list)


@dataclass
class HostVulnerabilityHistory:
    """Vulnerability history for a single host across all scans.

    Contains the host's identification and a timeline of scan snapshots
    showing how vulnerabilities have changed over time.
    """
    host_id: int
    ip_address: str
    scan_target: str
    scan_target_type: str
    first_seen: str
    last_seen: str
    scans: list[ScanSnapshot] = field(default_factory=list)

    @property
    def scan_count(self) -> int:
        """Number of scans this host appeared in."""
        return len(self.scans)


@log_timing
def compare_scans(
    scan_id_1: int,
    scan_id_2: int,
    min_severity: int = 0,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[ScanComparisonResult]:
    """Compare findings and hosts between two scans.

    Identifies new, resolved, and persistent findings by comparing plugin presence.
    Also tracks host changes between scans.

    Args:
        scan_id_1: Baseline scan ID (older scan)
        scan_id_2: Comparison scan ID (newer scan)
        min_severity: Minimum severity to include (0-4, default 0 includes all)
        conn: Optional database connection (creates new one if not provided)

    Returns:
        ScanComparisonResult with comparison data, or None if scans not found
    """
    close_conn = conn is None
    if conn is None:
        conn = get_connection()

    try:
        # Get scan metadata
        scan1 = query_one(
            conn,
            "SELECT scan_id, scan_name, created_at FROM scans WHERE scan_id = ?",
            (scan_id_1,)
        )
        scan2 = query_one(
            conn,
            "SELECT scan_id, scan_name, created_at FROM scans WHERE scan_id = ?",
            (scan_id_2,)
        )

        if not scan1 or not scan2:
            return None

        # Get plugins from each scan using the view
        scan1_plugins = query_all(
            conn,
            """
            SELECT plugin_id, plugin_name, severity_int, severity_label,
                   has_metasploit, cvss3_score, affected_hosts
            FROM v_scan_plugin_summary
            WHERE scan_id = ? AND severity_int >= ?
            ORDER BY severity_int DESC, plugin_name
            """,
            (scan_id_1, min_severity)
        )

        scan2_plugins = query_all(
            conn,
            """
            SELECT plugin_id, plugin_name, severity_int, severity_label,
                   has_metasploit, cvss3_score, affected_hosts
            FROM v_scan_plugin_summary
            WHERE scan_id = ? AND severity_int >= ?
            ORDER BY severity_int DESC, plugin_name
            """,
            (scan_id_2, min_severity)
        )

        # Build plugin ID sets for comparison
        scan1_plugin_ids = {row["plugin_id"] for row in scan1_plugins}
        scan2_plugin_ids = {row["plugin_id"] for row in scan2_plugins}

        # Classify findings
        new_plugin_ids = scan2_plugin_ids - scan1_plugin_ids
        resolved_plugin_ids = scan1_plugin_ids - scan2_plugin_ids
        persistent_plugin_ids = scan1_plugin_ids & scan2_plugin_ids

        # Build result lists and severity counts
        new_findings = []
        new_by_severity: dict[int, int] = {}
        for row in scan2_plugins:
            if row["plugin_id"] in new_plugin_ids:
                new_findings.append(dict(row))
                sev = row["severity_int"]
                new_by_severity[sev] = new_by_severity.get(sev, 0) + 1

        resolved_findings = []
        resolved_by_severity: dict[int, int] = {}
        for row in scan1_plugins:
            if row["plugin_id"] in resolved_plugin_ids:
                resolved_findings.append(dict(row))
                sev = row["severity_int"]
                resolved_by_severity[sev] = resolved_by_severity.get(sev, 0) + 1

        persistent_findings = []
        persistent_by_severity: dict[int, int] = {}
        for row in scan2_plugins:
            if row["plugin_id"] in persistent_plugin_ids:
                persistent_findings.append(dict(row))
                sev = row["severity_int"]
                persistent_by_severity[sev] = persistent_by_severity.get(sev, 0) + 1

        # Get hosts from each scan
        scan1_hosts = query_all(
            conn,
            """
            SELECT DISTINCT h.host_id, h.ip_address, h.scan_target
            FROM hosts h
            JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
            JOIN findings f ON fah.finding_id = f.finding_id
            WHERE f.scan_id = ?
            ORDER BY h.ip_address
            """,
            (scan_id_1,)
        )

        scan2_hosts = query_all(
            conn,
            """
            SELECT DISTINCT h.host_id, h.ip_address, h.scan_target
            FROM hosts h
            JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
            JOIN findings f ON fah.finding_id = f.finding_id
            WHERE f.scan_id = ?
            ORDER BY h.ip_address
            """,
            (scan_id_2,)
        )

        # Build host ID sets for comparison
        scan1_host_ids = {row["host_id"] for row in scan1_hosts}
        scan2_host_ids = {row["host_id"] for row in scan2_hosts}

        # Classify hosts
        new_host_ids = scan2_host_ids - scan1_host_ids
        removed_host_ids = scan1_host_ids - scan2_host_ids
        persistent_host_ids = scan1_host_ids & scan2_host_ids

        # Build host lists
        new_hosts = [dict(row) for row in scan2_hosts if row["host_id"] in new_host_ids]
        removed_hosts = [dict(row) for row in scan1_hosts if row["host_id"] in removed_host_ids]
        persistent_hosts = [dict(row) for row in scan2_hosts if row["host_id"] in persistent_host_ids]

        return ScanComparisonResult(
            scan1_id=scan_id_1,
            scan1_name=scan1["scan_name"],
            scan1_date=scan1["created_at"],
            scan2_id=scan_id_2,
            scan2_name=scan2["scan_name"],
            scan2_date=scan2["created_at"],
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            new_hosts=new_hosts,
            removed_hosts=removed_hosts,
            persistent_hosts=persistent_hosts,
            new_by_severity=new_by_severity,
            resolved_by_severity=resolved_by_severity,
            persistent_by_severity=persistent_by_severity,
        )
    finally:
        if close_conn:
            conn.close()


@log_timing
def get_host_vulnerability_history(
    ip_address: str,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[HostVulnerabilityHistory]:
    """Get vulnerability history for a specific host across all scans.

    Returns a timeline showing how the host's vulnerabilities have changed
    across all scans where it appeared.

    Args:
        ip_address: IP address of the host to query
        conn: Optional database connection (creates new one if not provided)

    Returns:
        HostVulnerabilityHistory with scan timeline, or None if host not found
    """
    close_conn = conn is None
    if conn is None:
        conn = get_connection()

    try:
        # Get host metadata
        host = query_one(
            conn,
            """
            SELECT host_id, ip_address, scan_target, scan_target_type,
                   first_seen, last_seen
            FROM hosts
            WHERE ip_address = ?
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (ip_address,)
        )

        if not host:
            return None

        # Get scan history using the view
        scan_history = query_all(
            conn,
            """
            SELECT scan_id, scan_name, scan_date, finding_count, max_severity,
                   critical_count, high_count, medium_count, low_count, info_count
            FROM v_host_scan_findings
            WHERE ip_address = ?
            ORDER BY scan_date ASC
            """,
            (ip_address,)
        )

        # Build scan snapshots with plugin IDs
        scans = []
        for row in scan_history:
            # Get plugin IDs for this host in this scan
            plugin_rows = query_all(
                conn,
                """
                SELECT DISTINCT f.plugin_id
                FROM findings f
                JOIN finding_affected_hosts fah ON f.finding_id = fah.finding_id
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE f.scan_id = ? AND h.ip_address = ?
                ORDER BY f.plugin_id
                """,
                (row["scan_id"], ip_address)
            )
            plugin_ids = [r["plugin_id"] for r in plugin_rows]

            scans.append(ScanSnapshot(
                scan_id=row["scan_id"],
                scan_name=row["scan_name"],
                scan_date=row["scan_date"],
                finding_count=row["finding_count"],
                max_severity=row["max_severity"] or 0,
                critical_count=row["critical_count"] or 0,
                high_count=row["high_count"] or 0,
                medium_count=row["medium_count"] or 0,
                low_count=row["low_count"] or 0,
                info_count=row["info_count"] or 0,
                plugin_ids=plugin_ids,
            ))

        return HostVulnerabilityHistory(
            host_id=host["host_id"],
            ip_address=host["ip_address"],
            scan_target=host["scan_target"],
            scan_target_type=host["scan_target_type"],
            first_seen=host["first_seen"],
            last_seen=host["last_seen"],
            scans=scans,
        )
    finally:
        if close_conn:
            conn.close()


def get_scan_by_name(
    scan_name: str,
    conn: Optional[sqlite3.Connection] = None
) -> Optional[sqlite3.Row]:
    """Get scan metadata by name.

    Args:
        scan_name: Name of the scan to look up
        conn: Optional database connection

    Returns:
        Row with scan_id, scan_name, created_at, or None if not found
    """
    close_conn = conn is None
    if conn is None:
        conn = get_connection()

    try:
        return query_one(
            conn,
            "SELECT scan_id, scan_name, created_at FROM scans WHERE scan_name = ?",
            (scan_name,)
        )
    finally:
        if close_conn:
            conn.close()
