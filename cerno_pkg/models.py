"""ORM models and CRUD operations for cerno database.

This module provides dataclass-based models and database operations for
tracking findings, review state, tool executions, and artifacts.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, cast

from .database import db_transaction, query_all, query_one
from .logging_setup import log_error, log_info


# ========== Helper Functions ==========

def now_iso() -> str:
    """Get current timestamp in ISO 8601 format.

    Returns:
        ISO formatted timestamp string
    """
    return datetime.now().isoformat()


# ========== Model: Scan ==========

@dataclass
class Scan:
    """Represents a Nessus scan and its exported findings."""

    scan_id: Optional[int] = None
    scan_name: str = ""
    nessus_file_path: Optional[str] = None
    nessus_file_hash: Optional[str] = None
    export_root: str = ""
    created_at: Optional[str] = None
    last_reviewed_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Scan:
        """Create Scan from database row.

        Args:
            row: SQLite row

        Returns:
            Scan instance
        """
        return cls(
            scan_id=row["scan_id"],
            scan_name=row["scan_name"],
            nessus_file_path=row["nessus_file_path"],
            nessus_file_hash=row["nessus_file_hash"],
            export_root=row["export_root"],
            created_at=row["created_at"],
            last_reviewed_at=row["last_reviewed_at"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        """Insert or update scan in database.

        Args:
            conn: Database connection (creates new if None)

        Returns:
            scan_id of saved record (or None if not set)
        """
        with db_transaction(conn) as c:
            if self.scan_id is None:
                # Insert new scan
                cursor = c.execute(
                    """
                    INSERT INTO scans (scan_name, nessus_file_path, nessus_file_hash, export_root)
                    VALUES (?, ?, ?, ?)
                    """,
                    (self.scan_name, self.nessus_file_path, self.nessus_file_hash, self.export_root)
                )
                self.scan_id = cursor.lastrowid
                log_info(f"Created scan: {self.scan_name} (ID: {self.scan_id})")
            else:
                # Update existing scan
                c.execute(
                    """
                    UPDATE scans
                    SET scan_name=?, nessus_file_path=?, nessus_file_hash=?,
                        export_root=?, last_reviewed_at=?
                    WHERE scan_id=?
                    """,
                    (self.scan_name, self.nessus_file_path, self.nessus_file_hash,
                     self.export_root, self.last_reviewed_at, self.scan_id)
                )

        return self.scan_id

    @classmethod
    def get_by_name(cls, scan_name: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Scan]:
        """Retrieve scan by name.

        Args:
            scan_name: Name of scan
            conn: Database connection

        Returns:
            Scan instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM scans WHERE scan_name = ?", (scan_name,))
            return cls.from_row(row) if row else None

    @classmethod
    def get_by_id(cls, scan_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[Scan]:
        """Retrieve scan by ID.

        Args:
            scan_id: Scan ID
            conn: Database connection

        Returns:
            Scan instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            return cls.from_row(row) if row else None

    @classmethod
    def get_all(cls, conn: Optional[sqlite3.Connection] = None) -> list[Scan]:
        """Retrieve all scans ordered by last reviewed (most recent first).

        Scans with NULL last_reviewed_at appear last, ordered by created_at DESC.

        Args:
            conn: Database connection

        Returns:
            List of Scan instances (may be empty)
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT * FROM scans
                ORDER BY last_reviewed_at DESC NULLS LAST, created_at DESC
                """
            )
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_all_with_stats(cls, conn: Optional[sqlite3.Connection] = None) -> list[dict]:
        """Retrieve all scans with statistics (finding counts, severity breakdown).

        Args:
            conn: Database connection

        Returns:
            List of dicts with scan info and statistics
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT
                    s.scan_id,
                    s.scan_name,
                    s.created_at,
                    s.last_reviewed_at,
                    (SELECT COUNT(DISTINCT fah.host_id)
                     FROM finding_affected_hosts fah
                     JOIN findings f2 ON fah.finding_id = f2.finding_id
                     WHERE f2.scan_id = s.scan_id) as unique_hosts,
                    COUNT(DISTINCT f.finding_id) as total_findings,
                    SUM(CASE WHEN p.severity_int = 4 THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN p.severity_int = 3 THEN 1 ELSE 0 END) as high_count,
                    SUM(CASE WHEN p.severity_int = 2 THEN 1 ELSE 0 END) as medium_count,
                    SUM(CASE WHEN p.severity_int = 1 THEN 1 ELSE 0 END) as low_count,
                    SUM(CASE WHEN p.severity_int = 0 THEN 1 ELSE 0 END) as info_count,
                    SUM(CASE WHEN f.review_state = 'completed' THEN 1 ELSE 0 END) as reviewed_count
                FROM scans s
                LEFT JOIN findings f ON s.scan_id = f.scan_id
                LEFT JOIN plugins p ON f.plugin_id = p.plugin_id
                GROUP BY s.scan_id, s.scan_name, s.created_at, s.last_reviewed_at
                ORDER BY s.last_reviewed_at DESC NULLS LAST, s.created_at DESC
                """
            )
            return [dict(row) for row in rows]

    @classmethod
    def delete_by_name(cls, scan_name: str, conn: Optional[sqlite3.Connection] = None) -> bool:
        """Delete a scan and all associated data by name.

        Due to CASCADE DELETE constraints, this will automatically delete:
        - All findings entries
        - All finding_affected_hosts entries
        - All sessions
        - All tool_executions (and their artifacts)

        Args:
            scan_name: Name of scan to delete
            conn: Database connection

        Returns:
            True if scan was deleted, False if scan not found
        """
        with db_transaction(conn) as c:
            # Check if scan exists
            scan = cls.get_by_name(scan_name, c)
            if not scan:
                return False

            # Delete scan (CASCADE will handle related tables)
            c.execute("DELETE FROM scans WHERE scan_name = ?", (scan_name,))
            return True


# ========== Model: Plugin ==========

@dataclass
class Plugin:
    """Represents a Nessus plugin (finding type).

    NOTE: "plugin" is internal terminology. User-facing commands use "findings".
    The severity_label is fetched from the v_plugins_with_severity view, not stored in plugins table.
    """

    plugin_id: int
    plugin_name: str = ""
    severity_int: int = 0
    severity_label: str = ""  # Populated from v_plugins_with_severity view, not stored in plugins table
    has_metasploit: bool = False
    cvss3_score: Optional[float] = None
    cvss2_score: Optional[float] = None
    metasploit_names: Optional[list[str]] = None  # JSON array
    cves: Optional[list[str]] = None  # JSON array
    plugin_url: Optional[str] = None
    metadata_fetched_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Plugin:
        """Create Plugin from database row.

        Args:
            row: SQLite row

        Returns:
            Plugin instance
        """
        metasploit_names_json = row["metasploit_names"]
        metasploit_names = json.loads(metasploit_names_json) if metasploit_names_json else None

        cves_json = row["cves"]
        cves = json.loads(cves_json) if cves_json else None

        return cls(
            plugin_id=row["plugin_id"],
            plugin_name=row["plugin_name"],
            severity_int=row["severity_int"],
            severity_label=row["severity_label"] if "severity_label" in row.keys() else "",  # Optional, from v_plugins_with_severity view
            has_metasploit=bool(row["has_metasploit"]),
            cvss3_score=row["cvss3_score"],
            cvss2_score=row["cvss2_score"],
            metasploit_names=metasploit_names,
            cves=cves,
            plugin_url=row["plugin_url"],
            metadata_fetched_at=row["metadata_fetched_at"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        """Insert or update plugin in database (upsert).

        Args:
            conn: Database connection

        Returns:
            plugin_id (or None if not set)
        """
        metasploit_names_json = json.dumps(self.metasploit_names) if self.metasploit_names else None
        cves_json = json.dumps(self.cves) if self.cves else None

        with db_transaction(conn) as c:
            c.execute(
                """
                INSERT OR REPLACE INTO plugins (
                    plugin_id, plugin_name, severity_int,
                    has_metasploit, cvss3_score, cvss2_score, metasploit_names, cves,
                    plugin_url, metadata_fetched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self.plugin_id, self.plugin_name, self.severity_int,
                 self.has_metasploit, self.cvss3_score, self.cvss2_score, metasploit_names_json, cves_json,
                 self.plugin_url, self.metadata_fetched_at)
            )

        return self.plugin_id

    @classmethod
    def get_by_id(cls, plugin_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[Plugin]:
        """Retrieve plugin by ID.

        Args:
            plugin_id: Plugin ID
            conn: Database connection

        Returns:
            Plugin instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM plugins WHERE plugin_id = ?", (plugin_id,))
            return cls.from_row(row) if row else None


# ========== Model: Finding ==========

@dataclass
class Finding:
    """Represents a finding (plugin instance) for a specific scan.

    Host and port counts are computed via the v_finding_stats view rather than stored as columns.
    """

    finding_id: Optional[int] = None
    scan_id: int = 0
    plugin_id: int = 0
    review_state: str = "pending"  # 'pending', 'reviewed', 'completed', 'skipped'
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Finding:
        """Create Finding from database row.

        Args:
            row: SQLite row

        Returns:
            Finding instance
        """
        return cls(
            finding_id=row["finding_id"],
            scan_id=row["scan_id"],
            plugin_id=row["plugin_id"],
            review_state=row["review_state"],
            reviewed_at=row["reviewed_at"],
            reviewed_by=row["reviewed_by"],
            review_notes=row["review_notes"]
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        """Insert or update finding in database.

        Args:
            conn: Database connection

        Returns:
            finding_id of saved record (or None if not set)
        """
        with db_transaction(conn) as c:
            if self.finding_id is None:
                # Insert new finding
                cursor = c.execute(
                    """
                    INSERT INTO findings (
                        scan_id, plugin_id, review_state,
                        reviewed_at, reviewed_by, review_notes
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (self.scan_id, self.plugin_id, self.review_state,
                     self.reviewed_at, self.reviewed_by, self.review_notes)
                )
                self.finding_id = cursor.lastrowid
            else:
                # Update existing finding
                c.execute(
                    """
                    UPDATE findings
                    SET review_state=?, reviewed_at=?, reviewed_by=?, review_notes=?
                    WHERE finding_id=?
                    """,
                    (self.review_state, self.reviewed_at, self.reviewed_by, self.review_notes, self.finding_id)
                )

        return self.finding_id

    @classmethod
    def get_by_id(cls, finding_id: int, conn: Optional[sqlite3.Connection] = None) -> Optional[Finding]:
        """Retrieve finding by ID.

        Args:
            finding_id: Finding ID
            conn: Database connection

        Returns:
            Finding instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM findings WHERE finding_id = ?", (finding_id,))
            return cls.from_row(row) if row else None

    def update_review_state(
        self,
        new_state: str,
        notes: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None
    ) -> None:
        """Update review state and timestamp.

        Args:
            new_state: New review state ('pending', 'reviewed', 'completed', 'skipped')
            notes: Optional review notes
            conn: Database connection
        """
        self.review_state = new_state
        self.reviewed_at = now_iso()
        if notes:
            self.review_notes = notes

        self.save(conn)

    @classmethod
    def get_by_scan_with_plugin(
        cls,
        scan_id: int,
        severity_dir: Optional[str] = None,
        severity_dirs: Optional[list[str]] = None,
        review_state: Optional[str] = None,
        plugin_name_filter: Optional[str] = None,
        has_metasploit: Optional[bool] = None,
        plugin_ids: Optional[list[int]] = None,
        conn: Optional[sqlite3.Connection] = None
    ) -> list[tuple[Finding, Plugin]]:
        """Retrieve findings with plugin info for a scan.

        Args:
            scan_id: Scan ID to filter by
            severity_dir: Optional single severity directory filter (e.g., "3_High")
            severity_dirs: Optional list of severity directories to filter by (e.g., ["1_Critical", "2_High"])
            review_state: Optional review state filter ('pending', 'completed', etc.)
            plugin_name_filter: Optional case-insensitive substring to match plugin names
            has_metasploit: Optional filter for metasploit plugins
            plugin_ids: Optional list of specific plugin IDs to include
            conn: Database connection

        Returns:
            List of (Finding, Plugin) tuples
        """
        with db_transaction(conn) as c:
            # Build query with JOIN (use v_plugins_with_severity view to get severity_label)
            query = """
                SELECT
                    f.finding_id, f.scan_id, f.plugin_id,
                    f.review_state, f.reviewed_at, f.reviewed_by, f.review_notes,
                    p.plugin_id as p_plugin_id, p.plugin_name, p.severity_int, p.severity_label,
                    p.has_metasploit, p.cvss3_score, p.cvss2_score, p.cves,
                    p.plugin_url, p.metadata_fetched_at
                FROM findings f
                INNER JOIN v_plugins_with_severity p ON f.plugin_id = p.plugin_id
                WHERE f.scan_id = ?
            """
            params: list[Any] = [scan_id]

            # Add optional filters
            # severity_dir filter now uses severity_int from plugins table
            if severity_dir is not None:
                # Parse severity_dir format like "4_Critical" to extract severity_int
                try:
                    severity_int = int(severity_dir.split('_')[0])
                    query += " AND p.severity_int = ?"
                    params.append(severity_int)
                except (ValueError, IndexError):
                    pass  # Invalid format, skip filter
            elif severity_dirs is not None and len(severity_dirs) > 0:
                # Parse multiple severity_dirs to extract severity_ints
                severity_ints = []
                for sd in severity_dirs:
                    try:
                        severity_ints.append(int(sd.split('_')[0]))
                    except (ValueError, IndexError):
                        pass
                if severity_ints:
                    placeholders = ",".join("?" * len(severity_ints))
                    query += f" AND p.severity_int IN ({placeholders})"
                    params.extend(severity_ints)

            if review_state is not None:
                query += " AND f.review_state = ?"
                params.append(review_state)

            if plugin_name_filter is not None:
                query += " AND p.plugin_name LIKE ?"
                params.append(f"%{plugin_name_filter}%")

            if has_metasploit is not None:
                query += " AND p.has_metasploit = ?"
                params.append(1 if has_metasploit else 0)

            if plugin_ids is not None and len(plugin_ids) > 0:
                placeholders = ",".join("?" * len(plugin_ids))
                query += f" AND f.plugin_id IN ({placeholders})"
                params.extend(plugin_ids)

            # Order by plugin_id for consistent results
            query += " ORDER BY p.plugin_id ASC"

            rows = query_all(c, query, tuple(params))

            results = []
            for row in rows:
                # Create Finding from row (columns 0-6, host_count/port_count removed from query)
                plugin_file = cls(
                    finding_id=row[0],
                    scan_id=row[1],
                    plugin_id=row[2],
                    review_state=row[3],
                    reviewed_at=row[4],
                    reviewed_by=row[5],
                    review_notes=row[6]
                )

                # Create Plugin from row (columns 7-15, indices shifted down by 2)
                cves_json = row[14]
                cves = json.loads(cves_json) if cves_json else None

                plugin = Plugin(
                    plugin_id=row[7],
                    plugin_name=row[8],
                    severity_int=row[9],
                    severity_label=row[10],
                    has_metasploit=bool(row[11]),
                    cvss3_score=row[12],
                    cvss2_score=row[13],
                    cves=cves,
                    plugin_url=row[15],
                    metadata_fetched_at=row[16]
                )

                results.append((plugin_file, plugin))

            return results

    @classmethod
    def count_by_scan_severity(
        cls,
        scan_id: int,
        severity_dir: str,
        plugin_ids: Optional[list[int]] = None,
        conn: Optional[sqlite3.Connection] = None
    ) -> tuple[int, int, int]:
        """Count files in a severity directory by review state.

        Args:
            scan_id: Scan ID to count files for
            severity_dir: Severity directory (e.g., "3_High")
            plugin_ids: Optional list of plugin IDs to filter by (for host filtering)
            conn: Database connection

        Returns:
            Tuple of (unreviewed_count, reviewed_count, total_count)
            where reviewed means review_state == 'completed'
        """
        with db_transaction(conn) as c:
            # Parse severity_dir to get severity_int (e.g., "4_Critical" -> 4)
            try:
                severity_int = int(severity_dir.split('_')[0])
            except (ValueError, IndexError):
                # Invalid format, return zeros
                return (0, 0, 0)

            # Build base query and params
            base_query = """SELECT COUNT(*) FROM findings pf
                   JOIN plugins p ON pf.plugin_id = p.plugin_id
                   WHERE pf.scan_id = ? AND p.severity_int = ?"""
            base_params: list[Any] = [scan_id, severity_int]

            # Add plugin_ids filter if provided
            plugin_filter = ""
            plugin_params: list[Any] = []
            if plugin_ids is not None and len(plugin_ids) > 0:
                placeholders = ",".join("?" * len(plugin_ids))
                plugin_filter = f" AND pf.plugin_id IN ({placeholders})"
                plugin_params = list(plugin_ids)

            # Count total files in this severity
            total_row = query_one(
                c,
                base_query + plugin_filter,
                tuple(base_params + plugin_params)
            )
            total_count = total_row[0] if total_row else 0

            # Count reviewed files (review_state = 'completed')
            reviewed_row = query_one(
                c,
                base_query + " AND pf.review_state = 'completed'" + plugin_filter,
                tuple(base_params + plugin_params)
            )
            reviewed_count = reviewed_row[0] if reviewed_row else 0

            # Calculate unreviewed
            unreviewed_count = total_count - reviewed_count

            return unreviewed_count, reviewed_count, total_count

    @classmethod
    def count_by_scan(
        cls,
        scan_id: int,
        conn: Optional[sqlite3.Connection] = None
    ) -> tuple[int, int]:
        """Count total and reviewed files across all severities for a scan.

        Args:
            scan_id: Scan ID to count files for
            conn: Database connection

        Returns:
            Tuple of (total_files, reviewed_files)
            where reviewed means review_state == 'completed'
        """
        with db_transaction(conn) as c:
            # Count total files
            total_row = query_one(
                c,
                "SELECT COUNT(*) FROM findings WHERE scan_id = ?",
                (scan_id,)
            )
            total_count = total_row[0] if total_row else 0

            # Count reviewed files (review_state = 'completed')
            reviewed_row = query_one(
                c,
                "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND review_state = 'completed'",
                (scan_id,)
            )
            reviewed_count = reviewed_row[0] if reviewed_row else 0

            return total_count, reviewed_count

    @classmethod
    def get_severity_dirs_for_scan(
        cls,
        scan_id: int,
        conn: Optional[sqlite3.Connection] = None,
        *,
        plugin_ids: Optional[list[int]] = None
    ) -> list[str]:
        """Get distinct severity directories for a scan, sorted by severity level.

        Reconstructs severity directory names from plugins table.
        Returns names like ["4_Critical", "3_High", "2_Medium", "1_Low", "0_Info"].

        Args:
            scan_id: Scan ID to query
            conn: Database connection
            plugin_ids: Optional list of plugin IDs to filter by (for host filtering)

        Returns:
            List of severity directory names sorted by severity (highest first)
        """
        with db_transaction(conn) as c:
            query = """
                SELECT DISTINCT p.severity_int, p.severity_label
                FROM findings pf
                JOIN v_plugins_with_severity p ON pf.plugin_id = p.plugin_id
                WHERE pf.scan_id = ?
            """
            params: list[Any] = [scan_id]

            if plugin_ids is not None and len(plugin_ids) > 0:
                placeholders = ",".join("?" * len(plugin_ids))
                query += f" AND pf.plugin_id IN ({placeholders})"
                params.extend(plugin_ids)

            query += " ORDER BY p.severity_int DESC"

            rows = query_all(c, query, tuple(params))
            # Construct severity_dir format: "4_Critical", "3_High", etc.
            result = []
            for row in rows:
                result.append(f"{row['severity_int']}_{row['severity_label']}")
            return result

    def get_hosts_and_ports(self, conn: Optional[sqlite3.Connection] = None) -> tuple[list[str], str]:
        """Retrieve hosts and formatted port string from database.

        Queries the finding_affected_hosts table to get all host:port combinations
        for this finding. Returns data in the same format as parse_hosts_ports()
        for backward compatibility.

        Args:
            conn: Database connection

        Returns:
            Tuple of (unique_hosts_list, comma_separated_ports_string)
            Example: (["192.168.1.1", "192.168.1.2"], "80,443,8080")
        """
        if self.finding_id is None:
            log_error("Cannot get hosts for unsaved Finding (finding_id is None)")
            return [], ""

        with db_transaction(conn) as c:
            # Query all host:port combinations for this file
            rows = query_all(
                c,
                """
                SELECT
                    h.ip_address,
                    fah.port_number,
                    h.scan_target_type
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id = ?
                ORDER BY
                    CASE WHEN h.scan_target_type = 'ipv4' THEN 0
                         WHEN h.scan_target_type = 'ipv6' THEN 1
                         ELSE 2 END,
                    h.ip_address ASC
                """,
                (self.finding_id,)
            )

            if not rows:
                return [], ""

            # Extract unique hosts (preserving order: IPs first, then hostnames)
            seen_hosts = set()
            hosts = []
            ports = set()

            for row in rows:
                host = row[0]
                port = row[1]

                # Add host to list if not seen (preserves order)
                if host not in seen_hosts:
                    hosts.append(host)
                    seen_hosts.add(host)

                # Collect ports
                if port is not None:
                    ports.add(str(port))

            # Format ports as comma-separated string, sorted numerically
            ports_str = ",".join(sorted(ports, key=lambda x: int(x))) if ports else ""

            return hosts, ports_str

    def get_port_distribution(self, conn: Optional[sqlite3.Connection] = None) -> dict[str, int]:
        """Get count of hosts per port for this finding.

        Args:
            conn: Database connection

        Returns:
            Dictionary mapping port number (as string) to host count
            Example: {"80": 8, "443": 3, "8080": 1}
        """
        if self.finding_id is None:
            log_error("Cannot get port distribution for unsaved Finding (finding_id is None)")
            return {}

        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT
                    fah.port_number,
                    COUNT(DISTINCT fah.host_id) as host_count
                FROM finding_affected_hosts fah
                WHERE fah.finding_id = ?
                GROUP BY fah.port_number
                ORDER BY fah.port_number ASC
                """,
                (self.finding_id,)
            )

            if not rows:
                return {}

            # Build dictionary of port -> host count
            distribution = {}
            for row in rows:
                port = row[0]
                count = row[1]
                if port is not None:
                    distribution[str(port)] = count

            return distribution

    def get_all_host_port_lines(self, conn: Optional[sqlite3.Connection] = None) -> list[str]:
        """Retrieve all host:port combinations as formatted lines.

        Queries the finding_affected_hosts table and returns each entry as a
        "host:port" string, matching the format of plugin file contents.

        Args:
            conn: Database connection

        Returns:
            List of "host:port" strings, sorted (IPs first, then hostnames)
            Example: ["192.168.1.1:80", "192.168.1.1:443", "example.com:80"]
        """
        if self.finding_id is None:
            log_error("Cannot get host:port lines for unsaved Finding (finding_id is None)")
            return []

        with db_transaction(conn) as c:
            # Query all host:port combinations for this file
            rows = query_all(
                c,
                """
                SELECT
                    h.ip_address,
                    fah.port_number,
                    h.scan_target_type
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id = ?
                ORDER BY
                    CASE WHEN h.scan_target_type = 'ipv4' THEN 0
                         WHEN h.scan_target_type = 'ipv6' THEN 1
                         ELSE 2 END,
                    h.ip_address ASC,
                    fah.port_number ASC
                """,
                (self.finding_id,)
            )

            if not rows:
                return []

            # Format as "host:port" strings
            lines = []
            for row in rows:
                host = row[0]
                port = row[1]

                if port is not None:
                    # Format with port
                    # Handle IPv6 addresses (add brackets if needed)
                    is_ipv6 = (row[2] == 'ipv6')
                    if is_ipv6 and ":" in host and not host.startswith("["):
                        lines.append(f"[{host}]:{port}")
                    else:
                        lines.append(f"{host}:{port}")
                else:
                    # No port specified
                    lines.append(host)

            return lines

    def get_plugin_outputs_by_host(
        self,
        conn: Optional[sqlite3.Connection] = None
    ) -> list[tuple[str, Optional[int], Optional[str]]]:
        """Retrieve all plugin outputs grouped by host:port.

        Queries the finding_affected_hosts table and returns plugin output for each
        host:port combination. Used by the Finding Details UI action.

        Args:
            conn: Database connection

        Returns:
            List of (host, port, plugin_output) tuples, sorted (IPs first, then hostnames)
            Example: [
                ("192.168.1.1", 80, "Path: C:\\...\\nInstalled version: 9.52"),
                ("192.168.1.1", 443, "Server: nginx/1.18.0"),
                ("example.com", 80, None)  # No plugin output for this host
            ]
        """
        if self.finding_id is None:
            log_error("Cannot get plugin outputs for unsaved Finding (finding_id is None)")
            return []

        with db_transaction(conn) as c:
            # Query all host:port:plugin_output combinations for this file
            rows = query_all(
                c,
                """
                SELECT
                    h.ip_address,
                    fah.port_number,
                    fah.plugin_output
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id = ?
                ORDER BY
                    CASE WHEN h.scan_target_type = 'ipv4' THEN 0
                         WHEN h.scan_target_type = 'ipv6' THEN 1
                         ELSE 2 END,
                    h.ip_address ASC,
                    fah.port_number ASC
                """,
                (self.finding_id,)
            )

            if not rows:
                return []

            # Return as list of tuples (host, port, plugin_output)
            return [(row[0], row[1], row[2]) for row in rows]


# ========== Model: ToolExecution ==========

@dataclass
class ToolExecution:
    """Represents a single tool execution (nmap, netexec, etc.)."""

    execution_id: Optional[int] = None
    session_id: Optional[int] = None
    finding_id: Optional[int] = None
    tool_name: str = ""
    tool_protocol: Optional[str] = None
    command_text: str = ""
    command_args: Optional[list[str]] = None  # JSON array
    executed_at: Optional[str] = None
    exit_code: Optional[int] = None
    duration_seconds: Optional[float] = None
    host_count: Optional[int] = None
    sampled: bool = False
    ports: Optional[str] = None
    used_sudo: bool = False

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ToolExecution:
        """Create ToolExecution from database row.

        Args:
            row: SQLite row

        Returns:
            ToolExecution instance
        """
        cmd_args_json = row["command_args"]
        cmd_args = json.loads(cmd_args_json) if cmd_args_json else None

        return cls(
            execution_id=row["execution_id"],
            session_id=row["session_id"],
            finding_id=row["finding_id"],
            tool_name=row["tool_name"],
            tool_protocol=row["tool_protocol"],
            command_text=row["command_text"],
            command_args=cmd_args,
            executed_at=row["executed_at"],
            exit_code=row["exit_code"],
            duration_seconds=row["duration_seconds"],
            host_count=row["host_count"],
            sampled=bool(row["sampled"]),
            ports=row["ports"],
            used_sudo=bool(row["used_sudo"])
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        """Insert or update tool execution in database.

        Args:
            conn: Database connection

        Returns:
            execution_id of saved record (or None if not set)
        """
        cmd_args_json = json.dumps(self.command_args) if self.command_args else None

        with db_transaction(conn) as c:
            if self.execution_id is None:
                # Insert new execution
                cursor = c.execute(
                    """
                    INSERT INTO tool_executions (
                        session_id, finding_id, tool_name, tool_protocol, command_text,
                        command_args, executed_at, exit_code, duration_seconds,
                        host_count, sampled, ports, used_sudo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (self.session_id, self.finding_id, self.tool_name, self.tool_protocol,
                     self.command_text, cmd_args_json, self.executed_at or now_iso(),
                     self.exit_code, self.duration_seconds, self.host_count,
                     self.sampled, self.ports, self.used_sudo)
                )
                self.execution_id = cursor.lastrowid
            else:
                # Update existing execution
                c.execute(
                    """
                    UPDATE tool_executions
                    SET exit_code=?, duration_seconds=?
                    WHERE execution_id=?
                    """,
                    (self.exit_code, self.duration_seconds, self.execution_id)
                )

        return self.execution_id


# ========== Model: Artifact ==========

@dataclass
class Artifact:
    """Represents a generated artifact file (nmap output, logs, etc.).

    The artifact_type_id is a foreign key reference to the artifact_types lookup table.
    Use v_artifacts_with_types view to get type_name.
    """

    artifact_id: Optional[int] = None
    execution_id: Optional[int] = None
    artifact_path: str = ""
    artifact_type_id: Optional[int] = None  # FK to artifact_types table
    file_size_bytes: Optional[int] = None
    file_hash: Optional[str] = None
    created_at: Optional[str] = None
    last_accessed_at: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None  # JSON object

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Artifact:
        """Create Artifact from database row.

        Args:
            row: SQLite row

        Returns:
            Artifact instance
        """
        metadata_json = row["metadata"]
        metadata = json.loads(metadata_json) if metadata_json else None

        return cls(
            artifact_id=row["artifact_id"],
            execution_id=row["execution_id"],
            artifact_path=row["artifact_path"],
            artifact_type_id=row["artifact_type_id"],
            file_size_bytes=row["file_size_bytes"],
            file_hash=row["file_hash"],
            created_at=row["created_at"],
            last_accessed_at=row["last_accessed_at"],
            metadata=metadata
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        """Insert artifact in database.

        Args:
            conn: Database connection

        Returns:
            artifact_id of saved record (or None if not set)
        """
        metadata_json = json.dumps(self.metadata) if self.metadata else None

        with db_transaction(conn) as c:
            cursor = c.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, execution_id, artifact_path, artifact_type_id,
                    file_size_bytes, file_hash, created_at, last_accessed_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (self.artifact_id, self.execution_id, self.artifact_path, self.artifact_type_id,
                 self.file_size_bytes, self.file_hash, self.created_at or now_iso(),
                 self.last_accessed_at, metadata_json)
            )
            if self.artifact_id is None:
                self.artifact_id = cursor.lastrowid

        return self.artifact_id

    @classmethod
    def get_by_execution(cls, execution_id: int, conn: Optional[sqlite3.Connection] = None) -> list[Artifact]:
        """Retrieve all artifacts for a tool execution.

        Args:
            execution_id: Tool execution ID
            conn: Database connection

        Returns:
            List of Artifact instances
        """
        with db_transaction(conn) as c:
            rows = query_all(c, "SELECT * FROM artifacts WHERE execution_id = ?", (execution_id,))
            return [cls.from_row(row) for row in rows]


# ========== Model: SeverityLevel ==========

@dataclass
class SeverityLevel:
    """Represents a severity level (normalized lookup table).

    This model provides a single source of truth for severity metadata,
    eliminating the need to store severity_label in every plugin record.
    """

    severity_int: int
    severity_label: str = ""
    severity_order: int = 0
    color_hint: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> SeverityLevel:
        """Create SeverityLevel from database row.

        Args:
            row: SQLite row

        Returns:
            SeverityLevel instance
        """
        return cls(
            severity_int=row["severity_int"],
            severity_label=row["severity_label"],
            severity_order=row["severity_order"],
            color_hint=row["color_hint"]
        )

    @classmethod
    def get_all(cls, conn: Optional[sqlite3.Connection] = None) -> list[SeverityLevel]:
        """Retrieve all severity levels ordered by severity_int descending.

        Args:
            conn: Database connection

        Returns:
            List of SeverityLevel instances (Critical to Info)
        """
        with db_transaction(conn) as c:
            rows = query_all(c, "SELECT * FROM severity_levels ORDER BY severity_int DESC")
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_by_int(cls, severity_int: int, conn: Optional[sqlite3.Connection] = None) -> Optional[SeverityLevel]:
        """Retrieve severity level by integer value.

        Args:
            severity_int: Severity integer (0-4)
            conn: Database connection

        Returns:
            SeverityLevel instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM severity_levels WHERE severity_int = ?", (severity_int,))
            return cls.from_row(row) if row else None


# ========== Model: ArtifactType ==========

@dataclass
class ArtifactType:
    """Represents an artifact type (normalized lookup table).

    Enforces consistent artifact type naming and provides metadata
    for each type (file extension, description, parser module).
    """

    artifact_type_id: Optional[int] = None
    type_name: str = ""
    file_extension: Optional[str] = None
    description: Optional[str] = None
    parser_module: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ArtifactType:
        """Create ArtifactType from database row.

        Args:
            row: SQLite row

        Returns:
            ArtifactType instance
        """
        return cls(
            artifact_type_id=row["artifact_type_id"],
            type_name=row["type_name"],
            file_extension=row["file_extension"],
            description=row["description"],
            parser_module=row["parser_module"]
        )

    @classmethod
    def get_all(cls, conn: Optional[sqlite3.Connection] = None) -> list[ArtifactType]:
        """Retrieve all artifact types ordered by type_name.

        Args:
            conn: Database connection

        Returns:
            List of ArtifactType instances
        """
        with db_transaction(conn) as c:
            rows = query_all(c, "SELECT * FROM artifact_types ORDER BY type_name")
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_by_name(cls, type_name: str, conn: Optional[sqlite3.Connection] = None) -> Optional[ArtifactType]:
        """Retrieve artifact type by name.

        Args:
            type_name: Type name (e.g., 'nmap_xml')
            conn: Database connection

        Returns:
            ArtifactType instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(c, "SELECT * FROM artifact_types WHERE type_name = ?", (type_name,))
            return cls.from_row(row) if row else None


# ========== Model: AuditLog ==========

@dataclass
class AuditLog:
    """Represents an audit log entry (change tracking).

    Tracks INSERT, UPDATE, DELETE operations on critical tables
    for compliance and debugging purposes.
    """

    audit_id: Optional[int] = None
    table_name: str = ""
    record_id: int = 0
    action: str = ""  # INSERT, UPDATE, DELETE
    changed_by: Optional[str] = None
    changed_at: Optional[str] = None
    old_values: Optional[dict[str, Any]] = None  # JSON object
    new_values: Optional[dict[str, Any]] = None  # JSON object

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> AuditLog:
        """Create AuditLog from database row.

        Args:
            row: SQLite row

        Returns:
            AuditLog instance
        """
        old_values_json = row["old_values"]
        old_values = json.loads(old_values_json) if old_values_json else None

        new_values_json = row["new_values"]
        new_values = json.loads(new_values_json) if new_values_json else None

        return cls(
            audit_id=row["audit_id"],
            table_name=row["table_name"],
            record_id=row["record_id"],
            action=row["action"],
            changed_by=row["changed_by"],
            changed_at=row["changed_at"],
            old_values=old_values,
            new_values=new_values
        )

    @classmethod
    def get_by_table_and_record(
        cls,
        table_name: str,
        record_id: int,
        conn: Optional[sqlite3.Connection] = None
    ) -> list[AuditLog]:
        """Retrieve audit log entries for a specific table record.

        Args:
            table_name: Table name
            record_id: Record ID
            conn: Database connection

        Returns:
            List of AuditLog instances ordered by timestamp
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                "SELECT * FROM audit_log WHERE table_name = ? AND record_id = ? ORDER BY changed_at ASC",
                (table_name, record_id)
            )
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_recent(cls, limit: int = 100, conn: Optional[sqlite3.Connection] = None) -> list[AuditLog]:
        """Retrieve recent audit log entries.

        Args:
            limit: Maximum number of entries to return
            conn: Database connection

        Returns:
            List of AuditLog instances ordered by timestamp (newest first)
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                "SELECT * FROM audit_log ORDER BY changed_at DESC LIMIT ?",
                (limit,)
            )
            return [cls.from_row(row) for row in rows]


# ========== Model: Host ==========

@dataclass
class Host:
    """Represents a unique host across all scans.

    Supports both IP-targeted and FQDN-targeted scans:
    - ip_address: Always the resolved IP (from host-ip tag in Nessus)
    - scan_target: What was scanned (IP or FQDN from ReportHost@name)
    - Composite unique: same IP via same target = same host
    """

    host_id: Optional[int] = None
    ip_address: str = ""
    scan_target: str = ""
    scan_target_type: str = "ipv4"  # 'ipv4', 'ipv6', 'fqdn'
    netbios_name: Optional[str] = None
    fqdn: Optional[str] = None
    reverse_dns: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Host":
        """Create Host from database row.

        Args:
            row: SQLite row from hosts table

        Returns:
            Host instance
        """
        return cls(
            host_id=row["host_id"],
            ip_address=row["ip_address"],
            scan_target=row["scan_target"],
            scan_target_type=row["scan_target_type"],
            netbios_name=row["netbios_name"] if "netbios_name" in row.keys() else None,
            fqdn=row["fqdn"] if "fqdn" in row.keys() else None,
            reverse_dns=row["reverse_dns"] if "reverse_dns" in row.keys() else None,
            first_seen=row["first_seen"] if "first_seen" in row.keys() else None,
            last_seen=row["last_seen"] if "last_seen" in row.keys() else None
        )

    @classmethod
    def get_or_create(
        cls,
        ip_address: str,
        scan_target: str,
        scan_target_type: str,
        netbios_name: Optional[str] = None,
        fqdn: Optional[str] = None,
        reverse_dns: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None
    ) -> int:
        """Get existing host_id or create new host.

        Uses composite key (ip_address, scan_target) for lookup.
        Updates last_seen timestamp and metadata on existing hosts.

        Args:
            ip_address: Resolved IP address (from host-ip tag)
            scan_target: What was scanned (IP or FQDN from ReportHost@name)
            scan_target_type: One of 'ipv4', 'ipv6', 'fqdn'
            netbios_name: Optional NetBIOS name from Nessus
            fqdn: Optional FQDN from Nessus
            reverse_dns: Optional reverse DNS from Nessus
            conn: Database connection (optional)

        Returns:
            host_id of existing or newly created host
        """
        with db_transaction(conn) as c:
            # Try to get existing by composite key
            row = query_one(
                c,
                "SELECT host_id FROM hosts WHERE ip_address = ? AND scan_target = ?",
                (ip_address, scan_target)
            )

            if row:
                # Update last_seen and any new metadata
                c.execute(
                    """UPDATE hosts SET
                        last_seen = CURRENT_TIMESTAMP,
                        netbios_name = COALESCE(?, netbios_name),
                        fqdn = COALESCE(?, fqdn),
                        reverse_dns = COALESCE(?, reverse_dns)
                    WHERE host_id = ?""",
                    (netbios_name, fqdn, reverse_dns, row["host_id"])
                )
                return cast(int, row["host_id"])

            # Create new
            cursor = c.execute(
                """INSERT INTO hosts
                    (ip_address, scan_target, scan_target_type, netbios_name, fqdn, reverse_dns)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (ip_address, scan_target, scan_target_type, netbios_name, fqdn, reverse_dns)
            )
            # lastrowid should always be set after INSERT, but satisfy type checker
            return cursor.lastrowid if cursor.lastrowid is not None else 0

    @classmethod
    def get_by_ip_and_target(
        cls,
        ip_address: str,
        scan_target: str,
        conn: Optional[sqlite3.Connection] = None
    ) -> Optional["Host"]:
        """Get host by composite key (ip_address, scan_target).

        Args:
            ip_address: Resolved IP address
            scan_target: Scan target (IP or FQDN)
            conn: Database connection (optional)

        Returns:
            Host instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(
                c,
                "SELECT * FROM hosts WHERE ip_address = ? AND scan_target = ?",
                (ip_address, scan_target)
            )
            return cls.from_row(row) if row else None

    @classmethod
    def get_by_ip(
        cls,
        ip_address: str,
        conn: Optional[sqlite3.Connection] = None
    ) -> list["Host"]:
        """Get all hosts with a given IP address.

        May return multiple hosts if same IP was scanned via different targets.

        Args:
            ip_address: IP address to search
            conn: Database connection (optional)

        Returns:
            List of Host instances
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                "SELECT * FROM hosts WHERE ip_address = ?",
                (ip_address,)
            )
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_by_scan_target(
        cls,
        scan_target: str,
        conn: Optional[sqlite3.Connection] = None
    ) -> list["Host"]:
        """Get all hosts with a given scan target.

        May return multiple hosts if same FQDN resolved to different IPs.

        Args:
            scan_target: Scan target (IP or FQDN)
            conn: Database connection (optional)

        Returns:
            List of Host instances
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                "SELECT * FROM hosts WHERE scan_target = ?",
                (scan_target,)
            )
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_all_with_stats(
        cls,
        conn: Optional[sqlite3.Connection] = None
    ) -> list[dict]:
        """Get all hosts with finding counts (cross-scan query).

        Returns:
            List of dicts with host info and statistics
        """
        with db_transaction(conn) as c:
            rows = query_all(c, """
                SELECT
                    h.host_id,
                    h.ip_address,
                    h.scan_target,
                    h.scan_target_type,
                    h.netbios_name,
                    h.fqdn,
                    h.first_seen,
                    h.last_seen,
                    COUNT(DISTINCT fah.finding_id) as finding_count,
                    COUNT(DISTINCT f.scan_id) as scan_count,
                    MAX(p.severity_int) as max_severity
                FROM hosts h
                LEFT JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
                LEFT JOIN findings f ON fah.finding_id = f.finding_id
                LEFT JOIN plugins p ON f.plugin_id = p.plugin_id
                GROUP BY h.host_id
                ORDER BY finding_count DESC
            """)
            return [dict(row) for row in rows]

    @classmethod
    def get_plugin_ids_for_scan(
        cls,
        ip_address: str,
        scan_id: int,
        partial_match: bool = False,
        conn: Optional[sqlite3.Connection] = None
    ) -> list[int]:
        """Get plugin IDs for findings affecting a specific host in a scan.

        Args:
            ip_address: IP address to search
            scan_id: Scan ID to filter by
            partial_match: If True, use LIKE for substring matching
            conn: Database connection (optional)

        Returns:
            List of distinct plugin_id values for findings affecting this host
        """
        with db_transaction(conn) as c:
            if partial_match:
                query = """
                    SELECT DISTINCT f.plugin_id
                    FROM finding_affected_hosts fah
                    JOIN findings f ON fah.finding_id = f.finding_id
                    JOIN hosts h ON fah.host_id = h.host_id
                    WHERE f.scan_id = ? AND h.ip_address LIKE ?
                    ORDER BY f.plugin_id ASC
                """
                rows = query_all(c, query, (scan_id, f"%{ip_address}%"))
            else:
                query = """
                    SELECT DISTINCT f.plugin_id
                    FROM finding_affected_hosts fah
                    JOIN findings f ON fah.finding_id = f.finding_id
                    JOIN hosts h ON fah.host_id = h.host_id
                    WHERE f.scan_id = ? AND h.ip_address = ?
                    ORDER BY f.plugin_id ASC
                """
                rows = query_all(c, query, (scan_id, ip_address))

            return [row["plugin_id"] for row in rows]


# ========== Model: Port ==========

@dataclass
class Port:
    """Represents a port number with optional service metadata."""

    port_number: int
    service_name: Optional[str] = None
    description: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Port":
        """Create Port from database row.

        Args:
            row: SQLite row from ports table

        Returns:
            Port instance
        """
        return cls(
            port_number=row["port_number"],
            service_name=row["service_name"] if "service_name" in row.keys() else None,
            description=row["description"] if "description" in row.keys() else None
        )

    @classmethod
    def get_or_create(
        cls,
        port_number: int,
        service_name: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None
    ) -> int:
        """Get existing port or create new.

        Args:
            port_number: Port number (1-65535)
            service_name: Optional service name
            conn: Database connection (optional)

        Returns:
            port_number
        """
        with db_transaction(conn) as c:
            row = query_one(
                c,
                "SELECT port_number FROM ports WHERE port_number = ?",
                (port_number,)
            )

            if row:
                # Update service_name if provided
                if service_name:
                    c.execute(
                        "UPDATE ports SET service_name = ? WHERE port_number = ?",
                        (service_name, port_number)
                    )
                return port_number

            # Create new
            c.execute(
                "INSERT INTO ports (port_number, service_name) VALUES (?, ?)",
                (port_number, service_name)
            )
            return port_number
