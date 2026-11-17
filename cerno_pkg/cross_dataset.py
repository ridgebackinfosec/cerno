"""Cross-dataset analysis functions for comparing findings and tracking host vulnerabilities.

This module provides functions to compare vulnerability findings between datasets,
track host vulnerability history across multiple datasets, and identify new/resolved/persistent
findings.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Optional

from .database import get_connection, finding_type_id_order_sql, query_all, query_one
from .logging_setup import log_timing
from .constants import SOURCE_UNKNOWN
from .parsing import finding_type_source


class MixedSourceComparisonError(ValueError):
    """Raised when asked to compare two datasets from different scan sources.

    ``compare_datasets`` classifies findings purely by ``finding_type_id`` set
    membership. FindingType ids are namespaced per source, so a Nessus scan and a
    nuclei scan share none: every finding would be reported as "new" in one and
    "resolved" in the other. That is not a comparison, so it is refused rather
    than rendered.
    """


@dataclass
class DatasetComparisonResult:
    """Result of comparing two datasets.

    Contains new/resolved/persistent findings and hosts between two datasets,
    along with summary statistics broken down by severity.
    """

    dataset1_id: int
    dataset1_name: str
    dataset1_date: str
    dataset2_id: int
    dataset2_name: str
    dataset2_date: str

    # Findings: list of dicts with finding_type_id, finding_type_name, severity_int, severity_label, affected_targets
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
class DatasetSnapshot:
    """Snapshot of a host's vulnerability status in a specific scan."""

    dataset_id: int
    dataset_name: str
    dataset_date: str
    finding_count: int
    max_severity: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    finding_type_ids: list[str] = field(default_factory=list)

    @property
    def source(self) -> str:
        """Scanner this snapshot's findings came from.

        Derived from the namespaced ``finding_type_ids`` the snapshot already
        carries, so no schema or view change is needed. Returns
        :data:`~cerno_pkg.constants.SOURCE_UNKNOWN` for an empty snapshot and
        ``"mixed"`` for the (currently unreachable) case of one scan holding
        more than one source -- never a guess, because the caller uses this to
        decide whether two snapshots are comparable at all.
        """
        sources = {finding_type_source(pid) for pid in self.finding_type_ids}
        if not sources:
            return SOURCE_UNKNOWN
        if len(sources) > 1:
            return "mixed"
        return sources.pop()


@dataclass
class HostVulnerabilityHistory:
    """Vulnerability history for a single host across all datasets.

    Contains the host's identification and a timeline of scan snapshots
    showing how vulnerabilities have changed over time.
    """

    host_id: int
    ip_address: str
    scan_target: str
    scan_target_type: str
    first_seen: str
    last_seen: str
    datasets: list[DatasetSnapshot] = field(default_factory=list)

    @property
    def dataset_count(self) -> int:
        """Number of datasets this host appeared in."""
        return len(self.datasets)


@log_timing
def compare_datasets(
    dataset_id_1: int,
    dataset_id_2: int,
    min_severity: int = 0,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[DatasetComparisonResult]:
    """Compare findings and hosts between two datasets.

    Identifies new, resolved, and persistent findings by comparing finding_type presence.
    Also tracks host changes between datasets.

    Args:
        dataset_id_1: Baseline dataset ID (older dataset)
        dataset_id_2: Comparison dataset ID (newer dataset)
        min_severity: Minimum severity to include (0-4, default 0 includes all)
        conn: Optional database connection (creates new one if not provided)

    Returns:
        DatasetComparisonResult with comparison data, or None if datasets not found
    """
    close_conn = conn is None
    if conn is None:
        conn = get_connection()

    try:
        # Get dataset metadata
        dataset1 = query_one(
            conn,
            "SELECT dataset_id, dataset_name, created_at FROM datasets WHERE dataset_id = ?",
            (dataset_id_1,),
        )
        dataset2 = query_one(
            conn,
            "SELECT dataset_id, dataset_name, created_at FROM datasets WHERE dataset_id = ?",
            (dataset_id_2,),
        )

        if not dataset1 or not dataset2:
            return None

        # Get finding_types from each dataset using the view
        dataset1_finding_types = query_all(
            conn,
            """
            SELECT finding_type_id, finding_type_name, severity_int, severity_label,
                   has_metasploit, cvss3_score, affected_targets
            FROM v_dataset_finding_type_summary
            WHERE dataset_id = ? AND severity_int >= ?
            ORDER BY severity_int DESC, finding_type_name
            """,
            (dataset_id_1, min_severity),
        )

        dataset2_finding_types = query_all(
            conn,
            """
            SELECT finding_type_id, finding_type_name, severity_int, severity_label,
                   has_metasploit, cvss3_score, affected_targets
            FROM v_dataset_finding_type_summary
            WHERE dataset_id = ? AND severity_int >= ?
            ORDER BY severity_int DESC, finding_type_name
            """,
            (dataset_id_2, min_severity),
        )

        # Refuse a cross-source comparison before it produces nonsense.
        sources_1 = {
            finding_type_source(row["finding_type_id"])
            for row in dataset1_finding_types
        }
        sources_2 = {
            finding_type_source(row["finding_type_id"])
            for row in dataset2_finding_types
        }
        if sources_1 and sources_2 and sources_1 != sources_2:
            raise MixedSourceComparisonError(
                f"Cannot compare '{dataset1['dataset_name']}' "
                f"({'/'.join(sorted(sources_1))}) with "
                f"'{dataset2['dataset_name']}' ({'/'.join(sorted(sources_2))}): "
                "findings from different sources share no finding_type ids, so "
                "every finding would be reported as both new and resolved. "
                "Compare datasets from the same source."
            )

        # Build finding_type ID sets for comparison
        dataset1_finding_type_ids = {
            row["finding_type_id"] for row in dataset1_finding_types
        }
        dataset2_finding_type_ids = {
            row["finding_type_id"] for row in dataset2_finding_types
        }

        # Classify findings
        new_finding_type_ids = dataset2_finding_type_ids - dataset1_finding_type_ids
        resolved_finding_type_ids = (
            dataset1_finding_type_ids - dataset2_finding_type_ids
        )
        persistent_finding_type_ids = (
            dataset1_finding_type_ids & dataset2_finding_type_ids
        )

        # Build result lists and severity counts
        new_findings = []
        new_by_severity: dict[int, int] = {}
        for row in dataset2_finding_types:
            if row["finding_type_id"] in new_finding_type_ids:
                new_findings.append(dict(row))
                sev = row["severity_int"]
                new_by_severity[sev] = new_by_severity.get(sev, 0) + 1

        resolved_findings = []
        resolved_by_severity: dict[int, int] = {}
        for row in dataset1_finding_types:
            if row["finding_type_id"] in resolved_finding_type_ids:
                resolved_findings.append(dict(row))
                sev = row["severity_int"]
                resolved_by_severity[sev] = resolved_by_severity.get(sev, 0) + 1

        persistent_findings = []
        persistent_by_severity: dict[int, int] = {}
        for row in dataset2_finding_types:
            if row["finding_type_id"] in persistent_finding_type_ids:
                persistent_findings.append(dict(row))
                sev = row["severity_int"]
                persistent_by_severity[sev] = persistent_by_severity.get(sev, 0) + 1

        # Get hosts from each dataset
        dataset1_hosts = query_all(
            conn,
            """
            SELECT DISTINCT h.host_id, h.ip_address, h.scan_target
            FROM hosts h
            JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
            JOIN findings f ON fah.finding_id = f.finding_id
            WHERE f.dataset_id = ?
            ORDER BY h.ip_address
            """,
            (dataset_id_1,),
        )

        dataset2_hosts = query_all(
            conn,
            """
            SELECT DISTINCT h.host_id, h.ip_address, h.scan_target
            FROM hosts h
            JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
            JOIN findings f ON fah.finding_id = f.finding_id
            WHERE f.dataset_id = ?
            ORDER BY h.ip_address
            """,
            (dataset_id_2,),
        )

        # Build host ID sets for comparison
        dataset1_host_ids = {row["host_id"] for row in dataset1_hosts}
        dataset2_host_ids = {row["host_id"] for row in dataset2_hosts}

        # Classify hosts
        new_host_ids = dataset2_host_ids - dataset1_host_ids
        removed_host_ids = dataset1_host_ids - dataset2_host_ids
        persistent_host_ids = dataset1_host_ids & dataset2_host_ids

        # Build host lists
        new_hosts = [
            dict(row) for row in dataset2_hosts if row["host_id"] in new_host_ids
        ]
        removed_hosts = [
            dict(row) for row in dataset1_hosts if row["host_id"] in removed_host_ids
        ]
        persistent_hosts = [
            dict(row) for row in dataset2_hosts if row["host_id"] in persistent_host_ids
        ]

        return DatasetComparisonResult(
            dataset1_id=dataset_id_1,
            dataset1_name=dataset1["dataset_name"],
            dataset1_date=dataset1["created_at"],
            dataset2_id=dataset_id_2,
            dataset2_name=dataset2["dataset_name"],
            dataset2_date=dataset2["created_at"],
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
    ip_address: str, conn: Optional[sqlite3.Connection] = None
) -> Optional[HostVulnerabilityHistory]:
    """Get vulnerability history for a specific host across all datasets.

    Returns a timeline showing how the host's vulnerabilities have changed
    across all datasets where it appeared.

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
            (ip_address,),
        )

        if not host:
            return None

        # Get dataset history using the view
        dataset_history = query_all(
            conn,
            """
            SELECT dataset_id, dataset_name, dataset_date, finding_count, max_severity,
                   critical_count, high_count, medium_count, low_count, info_count
            FROM v_host_dataset_findings
            WHERE ip_address = ?
            ORDER BY dataset_date ASC
            """,
            (ip_address,),
        )

        # Build scan snapshots with finding_type IDs
        datasets = []
        for row in dataset_history:
            # Get finding_type IDs for this host in this dataset
            finding_type_rows = query_all(
                conn,
                f"""
                SELECT DISTINCT f.finding_type_id
                FROM findings f
                JOIN finding_affected_hosts fah ON f.finding_id = fah.finding_id
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE f.dataset_id = ? AND h.ip_address = ?
                ORDER BY {finding_type_id_order_sql("f.finding_type_id")}
                """,
                (row["dataset_id"], ip_address),
            )
            finding_type_ids = [r["finding_type_id"] for r in finding_type_rows]

            datasets.append(
                DatasetSnapshot(
                    dataset_id=row["dataset_id"],
                    dataset_name=row["dataset_name"],
                    dataset_date=row["dataset_date"],
                    finding_count=row["finding_count"],
                    max_severity=row["max_severity"] or 0,
                    critical_count=row["critical_count"] or 0,
                    high_count=row["high_count"] or 0,
                    medium_count=row["medium_count"] or 0,
                    low_count=row["low_count"] or 0,
                    info_count=row["info_count"] or 0,
                    finding_type_ids=finding_type_ids,
                )
            )

        return HostVulnerabilityHistory(
            host_id=host["host_id"],
            ip_address=host["ip_address"],
            scan_target=host["scan_target"],
            scan_target_type=host["scan_target_type"],
            first_seen=host["first_seen"],
            last_seen=host["last_seen"],
            datasets=datasets,
        )
    finally:
        if close_conn:
            conn.close()


def get_dataset_by_name(
    dataset_name: str, conn: Optional[sqlite3.Connection] = None
) -> Optional[sqlite3.Row]:
    """Get dataset metadata by name.

    Args:
        dataset_name: Name of the dataset to look up
        conn: Optional database connection

    Returns:
        Row with dataset_id, dataset_name, created_at, or None if not found
    """
    close_conn = conn is None
    if conn is None:
        conn = get_connection()

    try:
        return query_one(
            conn,
            "SELECT dataset_id, dataset_name, created_at FROM datasets WHERE dataset_name = ?",
            (dataset_name,),
        )
    finally:
        if close_conn:
            conn.close()
