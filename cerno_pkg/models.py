"""ORM models and CRUD operations for cerno database.

This module provides dataclass-based models and database operations for
tracking findings, review state, tool executions, and artifacts.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional, cast

from .constants import (
    REVIEW_STATE_DONE,
    REVIEW_STATE_IN_PROGRESS,
    REVIEW_STATE_UNREVIEWED,
    REVIEW_TRANSITIONS,
)
from .database import db_transaction, finding_type_id_order_sql, query_all, query_one
from .parsing import (
    channel_source_id,
    finding_type_details_url,
    finding_type_source,
    finding_type_source_id,
)
from .logging_setup import log_error, log_info

# ========== Helper Functions ==========


def now_iso() -> str:
    """Get current timestamp in ISO 8601 format.

    Returns:
        ISO formatted timestamp string
    """
    return datetime.now().isoformat()


# ========== Model: Dataset ==========


@dataclass
class Dataset:
    """Represents a Nessus scan and its exported findings."""

    dataset_id: Optional[int] = None
    dataset_name: str = ""
    source_file_path: Optional[str] = None
    source_file_hash: Optional[str] = None
    export_root: str = ""
    created_at: Optional[str] = None
    last_reviewed_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> Dataset:
        """Create Dataset from database row.

        Args:
            row: SQLite row

        Returns:
            Dataset instance
        """
        return cls(
            dataset_id=row["dataset_id"],
            dataset_name=row["dataset_name"],
            source_file_path=row["source_file_path"],
            source_file_hash=row["source_file_hash"],
            export_root=row["export_root"],
            created_at=row["created_at"],
            last_reviewed_at=row["last_reviewed_at"],
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        """Insert or update scan in database.

        Args:
            conn: Database connection (creates new if None)

        Returns:
            dataset_id of saved record (or None if not set)
        """
        with db_transaction(conn) as c:
            if self.dataset_id is None:
                # Insert new scan
                cursor = c.execute(
                    """
                    INSERT INTO datasets (dataset_name, source_file_path, source_file_hash, export_root)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        self.dataset_name,
                        self.source_file_path,
                        self.source_file_hash,
                        self.export_root,
                    ),
                )
                self.dataset_id = cursor.lastrowid
                log_info(
                    f"Created dataset: {self.dataset_name} (ID: {self.dataset_id})"
                )
            else:
                # Update existing scan
                c.execute(
                    """
                    UPDATE datasets
                    SET dataset_name=?, source_file_path=?, source_file_hash=?,
                        export_root=?, last_reviewed_at=?
                    WHERE dataset_id=?
                    """,
                    (
                        self.dataset_name,
                        self.source_file_path,
                        self.source_file_hash,
                        self.export_root,
                        self.last_reviewed_at,
                        self.dataset_id,
                    ),
                )

        return self.dataset_id

    @classmethod
    def get_by_name(
        cls, dataset_name: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[Dataset]:
        """Retrieve a dataset by name.

        Args:
            dataset_name: Name of the dataset
            conn: Database connection

        Returns:
            Dataset instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(
                c, "SELECT * FROM datasets WHERE dataset_name = ?", (dataset_name,)
            )
            return cls.from_row(row) if row else None

    @classmethod
    def get_by_id(
        cls, dataset_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[Dataset]:
        """Retrieve scan by ID.

        Args:
            dataset_id: Dataset ID
            conn: Database connection

        Returns:
            Dataset instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(
                c, "SELECT * FROM datasets WHERE dataset_id = ?", (dataset_id,)
            )
            return cls.from_row(row) if row else None

    @classmethod
    def get_all(cls, conn: Optional[sqlite3.Connection] = None) -> list[Dataset]:
        """Retrieve all datasets ordered by last reviewed (most recent first).

        Datasets with NULL last_reviewed_at appear last, ordered by created_at DESC.

        Args:
            conn: Database connection

        Returns:
            List of Dataset instances (may be empty)
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT * FROM datasets
                -- dataset_id breaks the tie: created_at is CURRENT_TIMESTAMP at
                -- second resolution, so datasets imported in the same second (a
                -- scripted import, or `cerno demo`'s four) tie on BOTH keys and
                -- SQLite's row order for a full tie is unspecified.
                ORDER BY last_reviewed_at DESC NULLS LAST, created_at DESC,
                         dataset_id DESC
                """,
            )
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_all_with_stats(
        cls, conn: Optional[sqlite3.Connection] = None
    ) -> list[dict]:
        """Retrieve all datasets with statistics (finding counts, severity breakdown).

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
                    s.dataset_id,
                    s.dataset_name,
                    s.created_at,
                    s.last_reviewed_at,
                    -- Machines, not scan targets: count distinct resolved IPs
                    -- so a host recorded under both its IP and its hostname
                    -- counts once, and a machine serving several virtual hosts
                    -- counts once. Finding.count_targets() is the per-finding
                    -- target count the findings list and [V] footer use.
                    (SELECT COUNT(DISTINCT h.ip_address)
                     FROM finding_affected_hosts fah
                     JOIN findings f2 ON fah.finding_id = f2.finding_id
                     JOIN hosts h ON fah.host_id = h.host_id
                     WHERE f2.dataset_id = s.dataset_id) as unique_hosts,
                    COUNT(DISTINCT f.finding_id) as total_findings,
                    SUM(CASE WHEN p.severity_int = 4 THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN p.severity_int = 3 THEN 1 ELSE 0 END) as high_count,
                    SUM(CASE WHEN p.severity_int = 2 THEN 1 ELSE 0 END) as medium_count,
                    SUM(CASE WHEN p.severity_int = 1 THEN 1 ELSE 0 END) as low_count,
                    SUM(CASE WHEN p.severity_int = 0 THEN 1 ELSE 0 END) as info_count,
                    SUM(CASE WHEN f.review_state = 'done' THEN 1 ELSE 0 END) as done_count,
                    -- Which scanner produced this scan's findings. GROUP_CONCAT
                    -- over DISTINCT source names so a (currently unreachable)
                    -- mixed-source scan reports both rather than one at random,
                    -- and an empty scan reports NULL rather than a wrong guess.
                    (SELECT GROUP_CONCAT(src) FROM (
                        SELECT DISTINCT fs.source_name AS src
                        FROM findings f3
                        JOIN finding_types p3 ON f3.finding_type_id = p3.finding_type_id
                        JOIN finding_sources fs ON p3.source_id = fs.source_id
                        WHERE f3.dataset_id = s.dataset_id
                        ORDER BY fs.source_name
                     )) as source
                FROM datasets s
                LEFT JOIN findings f ON s.dataset_id = f.dataset_id
                LEFT JOIN finding_types p ON f.finding_type_id = p.finding_type_id
                GROUP BY s.dataset_id, s.dataset_name, s.created_at, s.last_reviewed_at
                -- dataset_id breaks the tie: see Dataset.get_all(). Without it the
                -- row order of `cerno dataset list` (and MCP list_datasets, which
                -- shares this query) varies between invocations whenever two
                -- datasets were imported in the same second.
                ORDER BY s.last_reviewed_at DESC NULLS LAST, s.created_at DESC,
                         s.dataset_id DESC
                """,
            )
            return [dict(row) for row in rows]

    @classmethod
    def delete_by_name(
        cls, dataset_name: str, conn: Optional[sqlite3.Connection] = None
    ) -> bool:
        """Delete a dataset and all associated data by name.

        Due to CASCADE DELETE constraints, this will automatically delete:
        - findings, and per finding: finding_affected_hosts,
          claude_conversations, finding_verdicts (-> verdict_evidence)
        - host_services
        - sessions and session_datasets

        Tool executions and artifacts are retained for audit/history, but their
        finding_id/session_id links are set to NULL by foreign key constraints
        when referenced rows are deleted.

        Args:
            dataset_name: Name of the dataset to delete
            conn: Database connection

        Returns:
            True if the dataset was deleted, False if it was not found
        """
        with db_transaction(conn) as c:
            # Check if the dataset exists
            dataset = cls.get_by_name(dataset_name, c)
            if not dataset:
                return False

            # Delete scan (CASCADE will handle related tables)
            c.execute("DELETE FROM datasets WHERE dataset_name = ?", (dataset_name,))
            return True


# ========== Model: FindingType ==========


@dataclass
class FindingType:
    """Represents one finding type from a finding source (a "finding_type").

    NOTE: "finding_type" is internal terminology. User-facing commands use "findings".
    The severity_label is fetched from the v_finding_types_with_severity view, not stored in finding_types table.

    ``finding_type_id`` is TEXT and namespaced per source from schema v5 on, for
    **every** source -- Nessus included (``'nessus:57608'``,
    ``'nuclei:apache-detect'``). No source is the default, so a bare token
    (``'57608'``) is not a valid id anywhere. Use :attr:`source` rather than
    inspecting the prefix at call sites.
    """

    finding_type_id: str
    finding_type_name: str = ""
    severity_int: int = 0
    severity_label: str = (
        ""  # Populated from v_finding_types_with_severity view, not stored in finding_types table
    )
    has_metasploit: bool = False
    cvss3_score: Optional[float] = None
    cvss2_score: Optional[float] = None
    metasploit_names: Optional[list[str]] = None  # JSON array
    cves: Optional[list[str]] = None  # JSON array
    #: Raw ``finding_types.details_url`` as stored. Readers almost always want
    #: the :attr:`details_url` property instead, which falls back to the
    #: per-source template when nothing was stored.
    stored_details_url: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> FindingType:
        """Create FindingType from database row.

        Args:
            row: SQLite row

        Returns:
            FindingType instance
        """
        metasploit_names_json = row["metasploit_names"]
        metasploit_names = (
            json.loads(metasploit_names_json) if metasploit_names_json else None
        )

        cves_json = row["cves"]
        cves = json.loads(cves_json) if cves_json else None

        return cls(
            finding_type_id=row["finding_type_id"],
            finding_type_name=row["finding_type_name"],
            severity_int=row["severity_int"],
            severity_label=(
                row["severity_label"] if "severity_label" in row.keys() else ""
            ),  # Optional, from v_finding_types_with_severity view
            has_metasploit=bool(row["has_metasploit"]),
            cvss3_score=row["cvss3_score"],
            cvss2_score=row["cvss2_score"],
            metasploit_names=metasploit_names,
            cves=cves,
            stored_details_url=row["details_url"],
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[str]:
        """Insert or update finding_type in database (upsert).

        Args:
            conn: Database connection

        Returns:
            finding_type_id (or None if not set)
        """
        metasploit_names_json = (
            json.dumps(self.metasploit_names) if self.metasploit_names else None
        )
        cves_json = json.dumps(self.cves) if self.cves else None

        with db_transaction(conn) as c:
            c.execute(
                """
                INSERT OR REPLACE INTO finding_types (
                    finding_type_id, source_id, finding_type_name, severity_int,
                    has_metasploit, cvss3_score, cvss2_score, metasploit_names, cves,
                    details_url
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(self.finding_type_id),
                    finding_type_source_id(self.finding_type_id),
                    self.finding_type_name,
                    self.severity_int,
                    self.has_metasploit,
                    self.cvss3_score,
                    self.cvss2_score,
                    metasploit_names_json,
                    cves_json,
                    self.stored_details_url,
                ),
            )

        return self.finding_type_id

    def __post_init__(self) -> None:
        # finding_types.finding_type_id is TEXT (schema v5). Normalizing here means a caller
        # that passes the integer 57608 and a row read back as '57608' compare
        # equal, hash alike and key the same dict -- the alternative is an
        # int/str split that only shows up at a comparison far from the cause.
        self.finding_type_id = str(self.finding_type_id)

    @property
    def source(self) -> str:
        """Name of the source this finding_type came from (``nessus``, ``nuclei``).

        Derived from the ``finding_type_id`` namespace rather than read back from
        ``finding_types.source_id``; the stored column exists so SQL can filter on
        source with an index, and the two are kept consistent by
        :meth:`save`.
        """
        return finding_type_source(self.finding_type_id)

    @property
    def details_url(self) -> Optional[str]:
        """Best known details page, or None when the source has no template."""
        return finding_type_details_url(self.finding_type_id, self.stored_details_url)

    @classmethod
    def get_by_id(
        cls, finding_type_id: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[FindingType]:
        """Retrieve finding_type by ID.

        Args:
            finding_type_id: FindingType ID
            conn: Database connection

        Returns:
            FindingType instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(
                c,
                "SELECT * FROM finding_types WHERE finding_type_id = ?",
                (finding_type_id,),
            )
            return cls.from_row(row) if row else None


# ========== Model: Finding ==========


class InvalidReviewTransition(ValueError):
    """Raised when a review-state change is not allowed by the workflow."""


def count_review_states(findings: Iterable["Finding"]) -> tuple[int, int, int, int]:
    """Tally findings by review state.

    Args:
        findings: Finding objects to count

    Returns:
        Tuple of (unreviewed, in_progress, done, total)
    """
    states = [f.review_state for f in findings]
    in_progress = states.count(REVIEW_STATE_IN_PROGRESS)
    done = states.count(REVIEW_STATE_DONE)
    return (len(states) - in_progress - done, in_progress, done, len(states))


@dataclass
class Finding:
    """Represents a finding (finding_type instance) for a specific scan.

    Host and port counts are computed via the v_finding_stats view rather than stored as columns.
    """

    finding_id: Optional[int] = None
    dataset_id: int = 0
    finding_type_id: str = ""
    review_state: str = REVIEW_STATE_UNREVIEWED  # 'unreviewed', 'in_progress', 'done'
    reviewed_at: Optional[str] = None
    #: ``finding_sources.source_id`` of the channel that moved this finding to
    #: ``done`` -- 4 (operator/TUI) or 5 (agent/MCP). NULL whenever the finding
    #: is not done. Written only by :meth:`update_review_state`.
    completed_by: Optional[int] = None
    review_notes: Optional[str] = None
    # Transient (not stored in DB): extra finding_ids from other selected datasets.
    # Set by get_by_dataset_ids_merged() (and query.py merged results) so all host/port
    # queries cover every selected dataset.
    extra_finding_ids: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        # See FindingType.__post_init__: findings.finding_type_id is TEXT from v5 on.
        self.finding_type_id = str(self.finding_type_id)

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
            dataset_id=row["dataset_id"],
            finding_type_id=row["finding_type_id"],
            review_state=row["review_state"],
            reviewed_at=row["reviewed_at"],
            completed_by=row["completed_by"],
            review_notes=row["review_notes"],
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
                        dataset_id, finding_type_id, review_state,
                        reviewed_at, completed_by, review_notes
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.dataset_id,
                        self.finding_type_id,
                        self.review_state,
                        self.reviewed_at,
                        self.completed_by,
                        self.review_notes,
                    ),
                )
                self.finding_id = cursor.lastrowid
            else:
                # Update existing finding
                c.execute(
                    """
                    UPDATE findings
                    SET review_state=?, reviewed_at=?, completed_by=?, review_notes=?
                    WHERE finding_id=?
                    """,
                    (
                        self.review_state,
                        self.reviewed_at,
                        self.completed_by,
                        self.review_notes,
                        self.finding_id,
                    ),
                )

        return self.finding_id

    @classmethod
    def get_by_id(
        cls, finding_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[Finding]:
        """Retrieve finding by ID.

        Args:
            finding_id: Finding ID
            conn: Database connection

        Returns:
            Finding instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(
                c, "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
            )
            return cls.from_row(row) if row else None

    def next_review_state(self) -> Optional[str]:
        """Return the forward workflow step from the current state.

        Returns:
            'in_progress' from 'unreviewed', 'done' from 'in_progress',
            or None when already 'done' (resetting is not a forward step).
        """
        if self.review_state == REVIEW_STATE_DONE:
            return None
        allowed = REVIEW_TRANSITIONS.get(self.review_state, ())
        return allowed[0] if allowed else None

    def transition_review_state(
        self,
        new_state: str,
        actor: str,
        notes: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> None:
        """Move to ``new_state`` if the review workflow allows it.

        Allowed transitions are defined by ``constants.REVIEW_TRANSITIONS``:
        unreviewed -> in_progress -> done, and done -> unreviewed.

        Args:
            new_state: Target review state
            actor: Channel making the change -- ``SOURCE_OPERATOR`` from the
                TUI or ``SOURCE_AGENT`` from an MCP client. Required: the
                channel is never defaulted, so a new caller cannot silently
                file an agent's change under the operator's name.
            notes: Optional review notes
            conn: Database connection

        Raises:
            InvalidReviewTransition: If the transition is not allowed.
            ValueError: If ``actor`` is not an authored (channel) source.
        """
        allowed = REVIEW_TRANSITIONS.get(self.review_state, ())
        if new_state not in allowed:
            raise InvalidReviewTransition(
                f"Cannot change review state from {self.review_state!r} to "
                f"{new_state!r}; allowed next state(s): {list(allowed)}"
            )
        self.update_review_state(new_state, actor, notes=notes, conn=conn)

    def update_review_state(
        self,
        new_state: str,
        actor: str,
        notes: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> None:
        """Set review state, timestamp and attribution without a workflow check.

        Use ``transition_review_state()`` for user-initiated changes; this raw
        setter is for syncing sibling findings in multi-dataset mode, which must
        pass the **same** actor rather than deriving a new one.

        ``completed_by`` is written only when the finding lands on ``done``, and
        cleared again (with ``reviewed_at``) on any move away from it, so the
        column never claims someone completed a finding that is back in review.

        Args:
            new_state: New review state ('unreviewed', 'in_progress', 'done')
            actor: Channel making the change (see
                :meth:`transition_review_state`)
            notes: Optional review notes
            conn: Database connection

        Raises:
            ValueError: If ``actor`` is not an authored (channel) source.
        """
        actor_id = channel_source_id(actor)
        self.review_state = new_state
        if new_state == REVIEW_STATE_DONE:
            self.reviewed_at = now_iso()
            self.completed_by = actor_id
        elif new_state == REVIEW_STATE_UNREVIEWED:
            self.reviewed_at = None
            self.completed_by = None
        else:
            self.reviewed_at = now_iso()
            self.completed_by = None
        if notes:
            self.review_notes = self._with_appended_note(notes)

        self.save(conn)

    def _with_appended_note(self, note: str) -> str:
        """Return ``review_notes`` with a timestamped ``note`` appended.

        Pure string helper (does not persist). Existing notes are preserved so
        callers never clobber prior entries.
        """
        prefix = (self.review_notes + "\n") if self.review_notes else ""
        return prefix + f"[{now_iso()}] {note}"

    def append_note(self, note: str, conn: Optional[sqlite3.Connection] = None) -> None:
        """Append a timestamped note to ``review_notes`` and persist.

        Unlike ``update_review_state``, this does not touch the review state;
        it only accumulates notes without overwriting existing ones.

        Args:
            note: Note text to append
            conn: Database connection
        """
        self.review_notes = self._with_appended_note(note)
        self.save(conn)

    @classmethod
    def get_by_dataset_with_finding_type(
        cls,
        dataset_id: int,
        severity_dir: Optional[str] = None,
        severity_dirs: Optional[list[str]] = None,
        review_state: Optional[str] = None,
        finding_type_name_filter: Optional[str] = None,
        has_metasploit: Optional[bool] = None,
        finding_type_ids: Optional[list[str]] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> list[tuple[Finding, FindingType]]:
        """Retrieve findings with finding_type info for a dataset.

        Args:
            dataset_id: Dataset ID to filter by
            severity_dir: Optional single severity directory filter (e.g., "3_High")
            severity_dirs: Optional list of severity directories to filter by (e.g., ["4_Critical", "3_High"])
            review_state: Optional review state filter ('unreviewed', 'in_progress', 'done')
            finding_type_name_filter: Optional case-insensitive substring to match finding_type names
            has_metasploit: Optional filter for metasploit finding_types
            finding_type_ids: Optional list of specific finding_type IDs to include
            conn: Database connection

        Returns:
            List of (Finding, FindingType) tuples
        """
        with db_transaction(conn) as c:
            # Build query with JOIN (use v_finding_types_with_severity view to get severity_label)
            query = """
                SELECT
                    f.finding_id, f.dataset_id, f.finding_type_id,
                    f.review_state, f.reviewed_at, f.completed_by, f.review_notes,
                    p.finding_type_id as p_finding_type_id, p.finding_type_name, p.severity_int, p.severity_label,
                    p.has_metasploit, p.cvss3_score, p.cvss2_score, p.cves,
                    p.details_url, p.metasploit_names
                FROM findings f
                INNER JOIN v_finding_types_with_severity p ON f.finding_type_id = p.finding_type_id
                WHERE f.dataset_id = ?
            """
            params: list[Any] = [dataset_id]

            # Add optional filters
            # severity_dir filter uses severity_int from v_finding_types_with_severity
            if severity_dir is not None:
                # Parse severity_dir format like "4_Critical" to extract severity_int
                try:
                    severity_int = int(severity_dir.split("_")[0])
                    query += " AND p.severity_int = ?"
                    params.append(severity_int)
                except (ValueError, IndexError):
                    pass  # Invalid format, skip filter
            elif severity_dirs is not None and len(severity_dirs) > 0:
                # Parse multiple severity_dirs to extract severity_ints
                severity_ints = []
                for sd in severity_dirs:
                    try:
                        severity_ints.append(int(sd.split("_")[0]))
                    except (ValueError, IndexError):
                        pass
                if severity_ints:
                    placeholders = ",".join("?" * len(severity_ints))
                    query += f" AND p.severity_int IN ({placeholders})"
                    params.extend(severity_ints)

            if review_state is not None:
                query += " AND f.review_state = ?"
                params.append(review_state)

            if finding_type_name_filter is not None:
                query += " AND p.finding_type_name LIKE ?"
                params.append(f"%{finding_type_name_filter}%")

            if has_metasploit is not None:
                query += " AND p.has_metasploit = ?"
                params.append(1 if has_metasploit else 0)

            if finding_type_ids is not None and len(finding_type_ids) > 0:
                placeholders = ",".join("?" * len(finding_type_ids))
                query += f" AND f.finding_type_id IN ({placeholders})"
                params.extend(finding_type_ids)

            # Order by finding_type_id for consistent results
            query += f" ORDER BY {finding_type_id_order_sql('p.finding_type_id')}"

            rows = query_all(c, query, tuple(params))

            results = []
            for row in rows:
                # Create Finding from row (columns 0-6, host_count/port_count removed from query)
                finding_type_file = cls(
                    finding_id=row[0],
                    dataset_id=row[1],
                    finding_type_id=row[2],
                    review_state=row[3],
                    reviewed_at=row[4],
                    completed_by=row[5],
                    review_notes=row[6],
                )

                # Create FindingType from row (columns 7-16)
                cves_json = row[14]
                cves = json.loads(cves_json) if cves_json else None
                msf_names_json = row[16]
                msf_names = json.loads(msf_names_json) if msf_names_json else None

                finding_type = FindingType(
                    finding_type_id=row[7],
                    finding_type_name=row[8],
                    severity_int=row[9],
                    severity_label=row[10],
                    has_metasploit=bool(row[11]),
                    cvss3_score=row[12],
                    cvss2_score=row[13],
                    cves=cves,
                    stored_details_url=row[15],
                    metasploit_names=msf_names,
                )

                results.append((finding_type_file, finding_type))

            return results

    @classmethod
    def get_by_dataset_ids_merged(
        cls,
        dataset_ids: list[int],
        severity_dir: Optional[str] = None,
        severity_dirs: Optional[list[str]] = None,
        has_metasploit: Optional[bool] = None,
        finding_type_ids: Optional[list[str]] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> tuple[list[tuple["Finding", "FindingType"]], dict[str, list["Finding"]]]:
        """Retrieve findings across multiple datasets, merged and deduplicated by finding_type_id.

        Queries findings for all provided dataset IDs and groups results by finding_type_id.
        One representative Finding (from the dataset with the lowest dataset_id) is selected
        per finding_type_id for display purposes, while all Finding instances across datasets
        are returned for full cross-dataset visibility.

        Args:
            dataset_ids: List of dataset IDs to query across.
            severity_dir: Optional single severity directory filter (e.g., "3_High").
            severity_dirs: Optional list of severity directories to filter by
                (e.g., ["4_Critical", "3_High"]).
            has_metasploit: Optional filter for finding_types with Metasploit modules.
            finding_type_ids: Optional list of specific finding_type IDs to include.
            conn: Database connection.

        Returns:
            A tuple of:
            - display_list: list of (Finding, FindingType) tuples — one representative
              Finding per finding_type_id (from the dataset with the lowest dataset_id), with
              ``extra_finding_ids`` set to the sibling finding IDs from the other
              datasets so host/port queries span all selected datasets.
            - all_instances: dict mapping finding_type_id → list of all Finding objects
              across all selected datasets, ordered by dataset_id ascending.

        Examples:
            display_list, all_instances = Finding.get_by_dataset_ids_merged(
                dataset_ids=[1, 2, 3],
                severity_dirs=["4_Critical", "3_High"],
            )
            for finding, finding_type in display_list:
                other_datasets = all_instances[finding_type.finding_type_id]
        """
        if not dataset_ids:
            return [], {}

        with db_transaction(conn) as c:
            placeholders = ",".join("?" * len(dataset_ids))
            query = f"""
                SELECT
                    f.finding_id, f.dataset_id, f.finding_type_id,
                    f.review_state, f.reviewed_at, f.completed_by, f.review_notes,
                    p.finding_type_id as p_finding_type_id, p.finding_type_name, p.severity_int, p.severity_label,
                    p.has_metasploit, p.cvss3_score, p.cvss2_score, p.cves,
                    p.details_url, p.metasploit_names
                FROM findings f
                INNER JOIN v_finding_types_with_severity p ON f.finding_type_id = p.finding_type_id
                WHERE f.dataset_id IN ({placeholders})
            """
            params: list[Any] = list(dataset_ids)

            # Add optional filters
            if severity_dir is not None:
                try:
                    severity_int = int(severity_dir.split("_")[0])
                    query += " AND p.severity_int = ?"
                    params.append(severity_int)
                except (ValueError, IndexError):
                    pass  # Invalid format, skip filter
            elif severity_dirs is not None and len(severity_dirs) > 0:
                severity_ints = []
                for sd in severity_dirs:
                    try:
                        severity_ints.append(int(sd.split("_")[0]))
                    except (ValueError, IndexError):
                        pass
                if severity_ints:
                    sev_placeholders = ",".join("?" * len(severity_ints))
                    query += f" AND p.severity_int IN ({sev_placeholders})"
                    params.extend(severity_ints)

            if has_metasploit is not None:
                query += " AND p.has_metasploit = ?"
                params.append(1 if has_metasploit else 0)

            if finding_type_ids is not None and len(finding_type_ids) > 0:
                pid_placeholders = ",".join("?" * len(finding_type_ids))
                query += f" AND f.finding_type_id IN ({pid_placeholders})"
                params.extend(finding_type_ids)

            # Order by finding_type_id then dataset_id so grouping logic finds lowest dataset_id first
            query += f" ORDER BY {finding_type_id_order_sql('p.finding_type_id')}, f.dataset_id ASC"

            rows = query_all(c, query, tuple(params))

            # Group rows by finding_type_id; track all Finding instances and one FindingType per finding_type_id
            all_instances: dict[str, list[Finding]] = {}
            finding_type_map: dict[str, FindingType] = {}

            for row in rows:
                finding = cls(
                    finding_id=row[0],
                    dataset_id=row[1],
                    finding_type_id=row[2],
                    review_state=row[3],
                    reviewed_at=row[4],
                    completed_by=row[5],
                    review_notes=row[6],
                )

                pid = row[2]

                if pid not in all_instances:
                    all_instances[pid] = []
                    # First row for this finding_type_id has the lowest dataset_id (due to ORDER BY)
                    cves_json = row[14]
                    cves = json.loads(cves_json) if cves_json else None
                    msf_names_json = row[16]
                    msf_names = json.loads(msf_names_json) if msf_names_json else None
                    finding_type_map[pid] = FindingType(
                        finding_type_id=row[7],
                        finding_type_name=row[8],
                        severity_int=row[9],
                        severity_label=row[10],
                        has_metasploit=bool(row[11]),
                        cvss3_score=row[12],
                        cvss2_score=row[13],
                        cves=cves,
                        stored_details_url=row[15],
                        metasploit_names=msf_names,
                    )

                all_instances[pid].append(finding)

            # Build display_list: representative Finding (lowest dataset_id) paired with FindingType.
            # Attach sibling finding_ids so host/port queries cover all selected datasets.
            display_list: list[tuple[Finding, FindingType]] = []
            for pid, instances in all_instances.items():
                rep = instances[0]
                rep.extra_finding_ids = [
                    f.finding_id for f in instances[1:] if f.finding_id is not None
                ]
                display_list.append((rep, finding_type_map[pid]))

            return display_list, all_instances

    @classmethod
    def count_by_dataset_severity(
        cls,
        dataset_id: int,
        severity_dir: str,
        finding_type_ids: Optional[list[str]] = None,
        conn: Optional[sqlite3.Connection] = None,
        *,
        dataset_ids: Optional[list[int]] = None,
    ) -> tuple[int, int, int, int]:
        """Count findings in a severity directory by review state.

        In multi-dataset mode a finding_type is counted once; its state is taken from
        the furthest-along instance (done > in_progress > unreviewed), matching
        how review-state changes are broadcast to all selected datasets.

        Args:
            dataset_id: Dataset ID to count files for (ignored when dataset_ids is provided)
            severity_dir: Severity directory (e.g., "3_High")
            finding_type_ids: Optional list of finding_type IDs to filter by (for host filtering)
            conn: Database connection
            dataset_ids: Optional list of dataset IDs for multi-dataset queries (overrides dataset_id)

        Returns:
            Tuple of (unreviewed, in_progress, done, total)
        """
        try:
            severity_int = int(severity_dir.split("_")[0])
        except (ValueError, IndexError):
            return (0, 0, 0, 0)

        effective_ids = (
            list(dataset_ids) if dataset_ids and len(dataset_ids) > 1 else [dataset_id]
        )
        id_placeholders = ",".join("?" * len(effective_ids))
        params: list[Any] = effective_ids + [severity_int]

        finding_type_filter = ""
        if finding_type_ids:
            finding_type_filter = (
                f" AND pf.finding_type_id IN ({','.join('?' * len(finding_type_ids))})"
            )
            params += list(finding_type_ids)

        # One row per finding_type with its most advanced state (rank 2=done, 1=in_progress, 0=unreviewed)
        query = f"""
            SELECT
                SUM(CASE WHEN rank = 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN rank = 1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN rank = 2 THEN 1 ELSE 0 END),
                COUNT(*)
            FROM (
                SELECT pf.finding_type_id,
                       MAX(CASE pf.review_state
                               WHEN '{REVIEW_STATE_DONE}' THEN 2
                               WHEN '{REVIEW_STATE_IN_PROGRESS}' THEN 1
                               ELSE 0 END) AS rank
                FROM findings pf
                JOIN finding_types p ON pf.finding_type_id = p.finding_type_id
                WHERE pf.dataset_id IN ({id_placeholders}) AND p.severity_int = ?{finding_type_filter}
                GROUP BY pf.finding_type_id
            )
        """
        with db_transaction(conn) as c:
            row = query_one(c, query, tuple(params))
        if not row or not row[3]:
            return (0, 0, 0, 0)
        return (row[0] or 0, row[1] or 0, row[2] or 0, row[3])

    @classmethod
    def count_by_dataset(
        cls,
        dataset_id: int,
        conn: Optional[sqlite3.Connection] = None,
        *,
        dataset_ids: Optional[list[int]] = None,
    ) -> tuple[int, int]:
        """Count total and Done findings across all severities for a dataset.

        Args:
            dataset_id: Dataset ID to count findings for (ignored when dataset_ids is provided)
            conn: Database connection
            dataset_ids: Optional list of dataset IDs for multi-dataset queries (overrides dataset_id);
                uses COUNT(DISTINCT finding_type_id) to deduplicate across datasets

        Returns:
            Tuple of (total_findings, done_findings)
            where reviewed means review_state == 'done'
        """
        with db_transaction(conn) as c:
            if dataset_ids and len(dataset_ids) > 1:
                placeholders = ",".join("?" * len(dataset_ids))
                total_row = query_one(
                    c,
                    f"SELECT COUNT(DISTINCT finding_type_id) FROM findings WHERE dataset_id IN ({placeholders})",
                    tuple(dataset_ids),
                )
                total_count = total_row[0] if total_row else 0
                reviewed_row = query_one(
                    c,
                    f"SELECT COUNT(DISTINCT finding_type_id) FROM findings WHERE dataset_id IN ({placeholders}) AND review_state = 'done'",
                    tuple(dataset_ids),
                )
                reviewed_count = reviewed_row[0] if reviewed_row else 0
            else:
                total_row = query_one(
                    c,
                    "SELECT COUNT(*) FROM findings WHERE dataset_id = ?",
                    (dataset_id,),
                )
                total_count = total_row[0] if total_row else 0
                reviewed_row = query_one(
                    c,
                    "SELECT COUNT(*) FROM findings WHERE dataset_id = ? AND review_state = 'done'",
                    (dataset_id,),
                )
                reviewed_count = reviewed_row[0] if reviewed_row else 0

            return total_count, reviewed_count

    @classmethod
    def get_severity_names_for_dataset(
        cls,
        dataset_id: int,
        conn: Optional[sqlite3.Connection] = None,
        *,
        finding_type_ids: Optional[list[str]] = None,
        dataset_ids: Optional[list[int]] = None,
    ) -> list[str]:
        """Get distinct severity directories for a dataset, sorted by severity level.

        Reconstructs severity directory names from finding_types table.
        Returns names like ["4_Critical", "3_High", "2_Medium", "1_Low", "0_Info"].

        Args:
            dataset_id: Dataset ID to query (ignored when dataset_ids is provided)
            conn: Database connection
            finding_type_ids: Optional list of finding_type IDs to filter by (for host filtering)
            dataset_ids: Optional list of dataset IDs for multi-dataset queries (overrides dataset_id)

        Returns:
            List of severity directory names sorted by severity (highest first)
        """
        with db_transaction(conn) as c:
            if dataset_ids and len(dataset_ids) > 1:
                id_placeholders = ",".join("?" * len(dataset_ids))
                query = f"""
                    SELECT DISTINCT p.severity_int, p.severity_label
                    FROM findings pf
                    JOIN v_finding_types_with_severity p ON pf.finding_type_id = p.finding_type_id
                    WHERE pf.dataset_id IN ({id_placeholders})
                """
                params: list[Any] = list(dataset_ids)
            else:
                query = """
                    SELECT DISTINCT p.severity_int, p.severity_label
                    FROM findings pf
                    JOIN v_finding_types_with_severity p ON pf.finding_type_id = p.finding_type_id
                    WHERE pf.dataset_id = ?
                """
                params = [dataset_id]

            if finding_type_ids is not None and len(finding_type_ids) > 0:
                placeholders = ",".join("?" * len(finding_type_ids))
                query += f" AND pf.finding_type_id IN ({placeholders})"
                params.extend(finding_type_ids)

            query += " ORDER BY p.severity_int DESC"

            rows = query_all(c, query, tuple(params))
            # Construct severity_dir format: "4_Critical", "3_High", etc.
            result = []
            for row in rows:
                result.append(f"{row['severity_int']}_{row['severity_label']}")
            return result

    def get_hosts_and_ports(
        self, conn: Optional[sqlite3.Connection] = None
    ) -> tuple[list[str], str]:
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
            all_ids = [self.finding_id] + self.extra_finding_ids
            placeholders = ",".join("?" * len(all_ids))
            rows = query_all(
                c,
                f"""
                SELECT DISTINCT
                    h.scan_target,
                    fah.port_number,
                    h.scan_target_type
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id IN ({placeholders})
                ORDER BY
                    CASE WHEN h.scan_target_type = 'ipv4' THEN 0
                         WHEN h.scan_target_type = 'ipv6' THEN 1
                         ELSE 2 END,
                    h.scan_target ASC
                """,
                tuple(all_ids),
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

    def get_host_identifiers(
        self, conn: Optional[sqlite3.Connection] = None
    ) -> list[str]:
        """Every name this finding's hosts are known by (IP, scan target, FQDN,
        NetBIOS, reverse DNS), de-duplicated in first-seen order.

        Used by the workflow contribution sanitizer to replace a host however it
        was written in a command (``10.0.0.5``, ``dc01.corp.local``, ``DC01``).

        Args:
            conn: Database connection

        Returns:
            List of non-empty identifier strings (empty for an unsaved Finding).
        """
        if self.finding_id is None:
            return []

        with db_transaction(conn) as c:
            all_ids = [self.finding_id] + self.extra_finding_ids
            placeholders = ",".join("?" * len(all_ids))
            rows = query_all(
                c,
                f"""
                SELECT DISTINCT h.ip_address, h.scan_target, h.fqdn,
                       h.netbios_name, h.reverse_dns
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id IN ({placeholders})
                ORDER BY h.host_id
                """,
                tuple(all_ids),
            )
        return _dedupe_identifiers(rows)

    @classmethod
    def count_targets(
        cls,
        finding_ids: Iterable[int],
        conn: Optional[sqlite3.Connection] = None,
    ) -> int:
        """Count distinct scan targets across the given findings.

        A *target* is ``hosts.scan_target`` -- what a tool is pointed at. This
        is deliberately not ``COUNT(DISTINCT host_id)``: ``host_id`` keys the
        ``(ip_address, scan_target)`` pair, so a machine recorded under both
        its IP and its hostname would count twice. Counting targets keeps every
        virtual host separate (one IP may own many) while matching exactly the
        number of lines :meth:`get_hosts_and_ports` renders.

        Use :meth:`Dataset.get_all_with_stats` (distinct ``ip_address``) when you
        want machines rather than targets.

        Args:
            finding_ids: Finding ids to count across (empty = 0)
            conn: Database connection

        Returns:
            Number of distinct scan targets
        """
        ids = [fid for fid in finding_ids if fid is not None]
        if not ids:
            return 0

        with db_transaction(conn) as c:
            placeholders = ",".join("?" * len(ids))
            row = query_one(
                c,
                f"""
                SELECT COUNT(DISTINCT h.scan_target)
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id IN ({placeholders})
                """,
                tuple(ids),
            )
            return row[0] if row else 0

    def get_port_distribution(
        self, conn: Optional[sqlite3.Connection] = None
    ) -> dict[str, int]:
        """Get count of hosts per port for this finding.

        Args:
            conn: Database connection

        Returns:
            Dictionary mapping port number (as string) to host count
            Example: {"80": 8, "443": 3, "8080": 1}
        """
        if self.finding_id is None:
            log_error(
                "Cannot get port distribution for unsaved Finding (finding_id is None)"
            )
            return {}

        with db_transaction(conn) as c:
            all_ids = [self.finding_id] + self.extra_finding_ids
            placeholders = ",".join("?" * len(all_ids))
            rows = query_all(
                c,
                f"""
                SELECT
                    fah.port_number,
                    COUNT(DISTINCT h.scan_target) as host_count
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id IN ({placeholders})
                GROUP BY fah.port_number
                ORDER BY fah.port_number ASC
                """,
                tuple(all_ids),
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

    def get_all_host_port_lines(
        self, conn: Optional[sqlite3.Connection] = None
    ) -> list[str]:
        """Retrieve all host:port combinations as formatted lines.

        Queries the finding_affected_hosts table and returns each entry as a
        "host:port" string (one line per affected host:port).

        Args:
            conn: Database connection

        Returns:
            List of "host:port" strings, sorted (IPs first, then hostnames)
            Example: ["192.168.1.1:80", "192.168.1.1:443", "example.com:80"]
        """
        if self.finding_id is None:
            log_error(
                "Cannot get host:port lines for unsaved Finding (finding_id is None)"
            )
            return []

        with db_transaction(conn) as c:
            all_ids = [self.finding_id] + self.extra_finding_ids
            placeholders = ",".join("?" * len(all_ids))
            rows = query_all(
                c,
                f"""
                SELECT DISTINCT
                    h.scan_target,
                    fah.port_number,
                    h.scan_target_type
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id IN ({placeholders})
                ORDER BY
                    CASE WHEN h.scan_target_type = 'ipv4' THEN 0
                         WHEN h.scan_target_type = 'ipv6' THEN 1
                         ELSE 2 END,
                    h.scan_target ASC,
                    fah.port_number ASC
                """,
                tuple(all_ids),
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
                    is_ipv6 = row[2] == "ipv6"
                    if is_ipv6 and ":" in host and not host.startswith("["):
                        lines.append(f"[{host}]:{port}")
                    else:
                        lines.append(f"{host}:{port}")
                else:
                    # No port specified
                    lines.append(host)

            return lines

    def get_evidence_by_host(
        self, conn: Optional[sqlite3.Connection] = None
    ) -> list[tuple[str, Optional[int], Optional[str]]]:
        """Retrieve all finding_type outputs grouped by host:port.

        Queries the finding_affected_hosts table and returns finding_type output for each
        host:port combination. Used by the Finding Details UI action.

        Args:
            conn: Database connection

        Returns:
            List of (host, port, evidence) tuples, sorted (IPs first, then hostnames)
            Example: [
                ("192.168.1.1", 80, "Path: C:\\...\\nInstalled version: 9.52"),
                ("192.168.1.1", 443, "Server: nginx/1.18.0"),
                ("example.com", 80, None)  # No finding_type output for this host
            ]
        """
        if self.finding_id is None:
            log_error(
                "Cannot get finding_type outputs for unsaved Finding (finding_id is None)"
            )
            return []

        with db_transaction(conn) as c:
            all_ids = [self.finding_id] + self.extra_finding_ids
            placeholders = ",".join("?" * len(all_ids))
            rows = query_all(
                c,
                f"""
                SELECT DISTINCT
                    h.scan_target,
                    fah.port_number,
                    fah.evidence
                FROM finding_affected_hosts fah
                JOIN hosts h ON fah.host_id = h.host_id
                WHERE fah.finding_id IN ({placeholders})
                ORDER BY
                    CASE WHEN h.scan_target_type = 'ipv4' THEN 0
                         WHEN h.scan_target_type = 'ipv6' THEN 1
                         ELSE 2 END,
                    h.scan_target ASC,
                    fah.port_number ASC
                """,
                tuple(all_ids),
            )

            if not rows:
                return []

            # Return as list of tuples (host, port, evidence)
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
            used_sudo=bool(row["used_sudo"]),
        )

    @classmethod
    def get_by_finding(
        cls, finding_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[ToolExecution]:
        """All executions attributed to a finding, oldest first.

        Args:
            finding_id: Finding the runs were attributed to (``tool_executions.finding_id``)
            conn: Database connection

        Returns:
            List of ToolExecution (uses ``idx_tool_executions_finding``).
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT * FROM tool_executions
                WHERE finding_id = ?
                ORDER BY executed_at, execution_id
                """,
                (finding_id,),
            )
        return [cls.from_row(row) for row in rows]

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        """Insert a tool execution, or update an existing one's exit_code and duration.

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
                    (
                        self.session_id,
                        self.finding_id,
                        self.tool_name,
                        self.tool_protocol,
                        self.command_text,
                        cmd_args_json,
                        self.executed_at or now_iso(),
                        self.exit_code,
                        self.duration_seconds,
                        self.host_count,
                        self.sampled,
                        self.ports,
                        self.used_sudo,
                    ),
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
                    (self.exit_code, self.duration_seconds, self.execution_id),
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
            metadata=metadata,
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        """Insert or replace (upsert) an artifact row (unique on artifact_path).

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
                (
                    self.artifact_id,
                    self.execution_id,
                    self.artifact_path,
                    self.artifact_type_id,
                    self.file_size_bytes,
                    self.file_hash,
                    self.created_at or now_iso(),
                    self.last_accessed_at,
                    metadata_json,
                ),
            )
            if self.artifact_id is None:
                self.artifact_id = cursor.lastrowid

        return self.artifact_id

    @classmethod
    def get_by_execution(
        cls, execution_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[Artifact]:
        """Retrieve all artifacts for a tool execution.

        Args:
            execution_id: Tool execution ID
            conn: Database connection

        Returns:
            List of Artifact instances
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c, "SELECT * FROM artifacts WHERE execution_id = ?", (execution_id,)
            )
            return [cls.from_row(row) for row in rows]


# ========== Model: SeverityLevel ==========


@dataclass
class SeverityLevel:
    """Represents a severity level (normalized lookup table).

    This model provides a single source of truth for severity metadata,
    eliminating the need to store severity_label in every finding_type record.
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
            color_hint=row["color_hint"],
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
            rows = query_all(
                c, "SELECT * FROM severity_levels ORDER BY severity_int DESC"
            )
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_by_int(
        cls, severity_int: int, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[SeverityLevel]:
        """Retrieve severity level by integer value.

        Args:
            severity_int: Severity integer (0-4)
            conn: Database connection

        Returns:
            SeverityLevel instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(
                c,
                "SELECT * FROM severity_levels WHERE severity_int = ?",
                (severity_int,),
            )
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
            parser_module=row["parser_module"],
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
    def get_by_name(
        cls, type_name: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[ArtifactType]:
        """Retrieve artifact type by name.

        Args:
            type_name: Type name (e.g., 'nmap_xml')
            conn: Database connection

        Returns:
            ArtifactType instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(
                c, "SELECT * FROM artifact_types WHERE type_name = ?", (type_name,)
            )
            return cls.from_row(row) if row else None


# ========== Model: Host ==========


@dataclass
class Host:
    """Represents a unique host across all datasets.

    Supports both IP-targeted and FQDN-targeted datasets:
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
            last_seen=row["last_seen"] if "last_seen" in row.keys() else None,
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
        conn: Optional[sqlite3.Connection] = None,
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
                (ip_address, scan_target),
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
                    (netbios_name, fqdn, reverse_dns, row["host_id"]),
                )
                return cast(int, row["host_id"])

            # Create new
            cursor = c.execute(
                """INSERT INTO hosts
                    (ip_address, scan_target, scan_target_type, netbios_name, fqdn, reverse_dns)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    ip_address,
                    scan_target,
                    scan_target_type,
                    netbios_name,
                    fqdn,
                    reverse_dns,
                ),
            )
            # lastrowid should always be set after INSERT, but satisfy type checker
            return cursor.lastrowid if cursor.lastrowid is not None else 0

    @classmethod
    def get_by_ip_and_target(
        cls,
        ip_address: str,
        scan_target: str,
        conn: Optional[sqlite3.Connection] = None,
    ) -> Optional["Host"]:
        """Get host by composite key (ip_address, scan_target).

        Args:
            ip_address: Resolved IP address
            scan_target: Dataset target (IP or FQDN)
            conn: Database connection (optional)

        Returns:
            Host instance or None if not found
        """
        with db_transaction(conn) as c:
            row = query_one(
                c,
                "SELECT * FROM hosts WHERE ip_address = ? AND scan_target = ?",
                (ip_address, scan_target),
            )
            return cls.from_row(row) if row else None

    @classmethod
    def get_by_ip(
        cls, ip_address: str, conn: Optional[sqlite3.Connection] = None
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
                c, "SELECT * FROM hosts WHERE ip_address = ?", (ip_address,)
            )
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_by_scan_target(
        cls, scan_target: str, conn: Optional[sqlite3.Connection] = None
    ) -> list["Host"]:
        """Get all hosts with a given scan target.

        May return multiple hosts if same FQDN resolved to different IPs.

        Args:
            scan_target: Dataset target (IP or FQDN)
            conn: Database connection (optional)

        Returns:
            List of Host instances
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c, "SELECT * FROM hosts WHERE scan_target = ?", (scan_target,)
            )
            return [cls.from_row(row) for row in rows]

    @classmethod
    def get_all_with_stats(
        cls, conn: Optional[sqlite3.Connection] = None
    ) -> list[dict]:
        """Get all hosts with finding counts (cross-dataset query).

        Returns:
            List of dicts with host info and statistics
        """
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
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
                    COUNT(DISTINCT f.dataset_id) as dataset_count,
                    MAX(p.severity_int) as max_severity
                FROM hosts h
                LEFT JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
                LEFT JOIN findings f ON fah.finding_id = f.finding_id
                LEFT JOIN finding_types p ON f.finding_type_id = p.finding_type_id
                GROUP BY h.host_id
                ORDER BY finding_count DESC
            """,
            )
            return [dict(row) for row in rows]

    @classmethod
    def get_finding_type_ids_for_dataset(
        cls,
        ip_address: str,
        dataset_id: int,
        partial_match: bool = False,
        conn: Optional[sqlite3.Connection] = None,
        *,
        dataset_ids: Optional[list[int]] = None,
    ) -> list[str]:
        """Get finding_type IDs for findings affecting a specific host in one or more datasets.

        Args:
            ip_address: IP address to search
            dataset_id: Dataset ID to filter by (ignored when dataset_ids has more than one entry)
            partial_match: If True, use LIKE for substring matching
            conn: Database connection (optional)
            dataset_ids: Optional list of dataset IDs for multi-dataset queries (overrides dataset_id)

        Returns:
            List of distinct finding_type_id values for findings affecting this host
        """
        order = finding_type_id_order_sql("f.finding_type_id")

        if dataset_ids and len(dataset_ids) > 1:
            dataset_clause = f"f.dataset_id IN ({','.join('?' * len(dataset_ids))})"
            params: list[Any] = list(dataset_ids)
        else:
            dataset_clause = "f.dataset_id = ?"
            params = [dataset_id]

        if partial_match:
            host_clause = "h.ip_address LIKE ?"
            params.append(f"%{ip_address}%")
        else:
            host_clause = "h.ip_address = ?"
            params.append(ip_address)

        query = f"""
            SELECT DISTINCT f.finding_type_id
            FROM finding_affected_hosts fah
            JOIN findings f ON fah.finding_id = f.finding_id
            JOIN hosts h ON fah.host_id = h.host_id
            WHERE {dataset_clause} AND {host_clause}
            ORDER BY {order}
        """
        with db_transaction(conn) as c:
            rows = query_all(c, query, tuple(params))
            return [row["finding_type_id"] for row in rows]

    @classmethod
    def identifiers_for_datasets(
        cls, dataset_ids: list[int], conn: Optional[sqlite3.Connection] = None
    ) -> list[str]:
        """Every host name/address seen in the given datasets (findings + services).

        Returns IPs, scan targets, FQDNs, NetBIOS names and reverse DNS names,
        de-duplicated. The workflow contribution leak scan treats each of these as
        engagement data that must never appear in an exported workflow.

        Args:
            dataset_ids: Datasets to collect hosts from (empty list → empty result)
            conn: Database connection (optional)

        Returns:
            List of non-empty identifier strings.
        """
        if not dataset_ids:
            return []
        placeholders = ",".join("?" * len(dataset_ids))
        query = f"""
            SELECT h.ip_address, h.scan_target, h.fqdn, h.netbios_name, h.reverse_dns
            FROM hosts h
            WHERE h.host_id IN (
                SELECT fah.host_id
                FROM finding_affected_hosts fah
                JOIN findings f ON fah.finding_id = f.finding_id
                WHERE f.dataset_id IN ({placeholders})
                UNION
                SELECT hs.host_id FROM host_services hs
                WHERE hs.dataset_id IN ({placeholders})
            )
            ORDER BY h.host_id
        """
        with db_transaction(conn) as c:
            rows = query_all(c, query, tuple(dataset_ids) * 2)
        return _dedupe_identifiers(rows)


def _dedupe_identifiers(rows: Iterable[Any]) -> list[str]:
    """Flatten host rows into unique, non-empty identifier strings (first-seen order)."""
    seen: set[str] = set()
    out: list[str] = []
    for row in rows:
        for value in tuple(row):
            text = str(value).strip() if value is not None else ""
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    return out


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
            description=row["description"] if "description" in row.keys() else None,
        )

    @classmethod
    def get_or_create(
        cls,
        port_number: int,
        service_name: Optional[str] = None,
        conn: Optional[sqlite3.Connection] = None,
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
                c, "SELECT port_number FROM ports WHERE port_number = ?", (port_number,)
            )

            if row:
                # Update service_name if provided
                if service_name:
                    c.execute(
                        "UPDATE ports SET service_name = ? WHERE port_number = ?",
                        (service_name, port_number),
                    )
                return port_number

            # Create new
            c.execute(
                "INSERT INTO ports (port_number, service_name) VALUES (?, ?)",
                (port_number, service_name),
            )
            return port_number


# ========== Query Helpers: Host Services ==========


def get_http_urls_for_dataset(
    dataset_id: int, conn: Optional[sqlite3.Connection] = None
) -> list[str]:
    """Query HTTP/HTTPS URLs discovered in a dataset.

    Uses the v_http_services view to identify web services and
    construct URLs from host:port data.

    Args:
        dataset_id: Dataset ID to query
        conn: Database connection

    Returns:
        Sorted list of URL strings (e.g., ["http://192.168.1.1:80", "https://10.0.0.5:443"])
    """
    with db_transaction(conn) as c:
        rows = query_all(
            c,
            """
            SELECT DISTINCT scan_target, port_number, http_scheme
            FROM v_http_services
            WHERE dataset_id = ? AND http_scheme IS NOT NULL
            ORDER BY scan_target, port_number
            """,
            (dataset_id,),
        )

        urls = []
        for row in rows:
            host = row["scan_target"]
            port = row["port_number"]
            scheme = row["http_scheme"]
            urls.append(f"{scheme}://{host}:{port}")

        return urls


# ========== Model: ClaudeConversationTurn ==========


@dataclass
class ClaudeConversationTurn:
    """Represents a single turn in a Claude Assistant conversation for a finding."""

    id: Optional[int] = None
    finding_id: int = 0
    role: str = "user"  # 'user' | 'assistant'
    content: str = ""
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> ClaudeConversationTurn:
        """Create ClaudeConversationTurn from database row."""
        return cls(
            id=row["id"],
            finding_id=row["finding_id"],
            role=row["role"],
            content=row["content"],
            created_at=row["created_at"],
        )

    @classmethod
    def get_by_finding(
        cls,
        conn: sqlite3.Connection,
        finding_id: int,
    ) -> list[ClaudeConversationTurn]:
        """Return all turns for a finding, ordered by creation time.

        Args:
            conn: Database connection
            finding_id: Finding ID to query

        Returns:
            List of ClaudeConversationTurn instances (may be empty)
        """
        rows = query_all(
            conn,
            "SELECT * FROM claude_conversations WHERE finding_id = ? ORDER BY id ASC",
            (finding_id,),
        )
        return [cls.from_row(row) for row in rows]

    @classmethod
    def add(
        cls,
        conn: sqlite3.Connection,
        finding_id: int,
        role: str,
        content: str,
    ) -> int:
        """Insert a new conversation turn.

        Args:
            conn: Database connection
            finding_id: Finding ID this turn belongs to
            role: 'user' or 'assistant'
            content: Text content of the turn

        Returns:
            Row ID of the inserted turn
        """
        with db_transaction(conn) as c:
            cursor = c.execute(
                "INSERT INTO claude_conversations (finding_id, role, content) VALUES (?, ?, ?)",
                (finding_id, role, content),
            )
            return cursor.lastrowid or 0

    @classmethod
    def clear(cls, conn: sqlite3.Connection, finding_id: int) -> int:
        """Delete all conversation turns for a finding.

        Args:
            conn: Database connection
            finding_id: Finding ID to clear history for

        Returns:
            Number of rows deleted
        """
        with db_transaction(conn) as c:
            cursor = c.execute(
                "DELETE FROM claude_conversations WHERE finding_id = ?",
                (finding_id,),
            )
            return cursor.rowcount

    @classmethod
    def finding_has_history(
        cls,
        conn: sqlite3.Connection,
        finding_ids: list[int],
    ) -> set[int]:
        """Return the subset of finding_ids that have at least one conversation turn.

        Args:
            conn: Database connection
            finding_ids: List of finding IDs to check

        Returns:
            Set of finding_ids that have conversation history
        """
        if not finding_ids:
            return set()
        placeholders = ",".join("?" * len(finding_ids))
        rows = query_all(
            conn,
            f"SELECT DISTINCT finding_id FROM claude_conversations WHERE finding_id IN ({placeholders})",
            tuple(finding_ids),
        )
        return {row["finding_id"] for row in rows}


# ========== Model: ClaudeAggregateConversationTurn ==========


@dataclass
class ClaudeAggregateConversationTurn:
    """A single turn in a Claude Assistant aggregate conversation.

    Used for severity-menu and findings-list scope conversations.
    Keyed by a context_key string (not a finding FK) since scope spans many findings.
    """

    id: Optional[int] = None
    context_key: str = ""
    role: str = "user"  # 'user' | 'assistant'
    content: str = ""
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "ClaudeAggregateConversationTurn":
        """Create instance from database row."""
        return cls(
            id=row["id"],
            context_key=row["context_key"],
            role=row["role"],
            content=row["content"],
            created_at=row["created_at"],
        )

    @classmethod
    def get_by_context(
        cls,
        conn: sqlite3.Connection,
        context_key: str,
    ) -> "list[ClaudeAggregateConversationTurn]":
        """Return all turns for a context key, ordered by creation time."""
        rows = query_all(
            conn,
            "SELECT * FROM claude_aggregate_conversations WHERE context_key = ? ORDER BY id ASC",
            (context_key,),
        )
        return [cls.from_row(row) for row in rows]

    @classmethod
    def add(
        cls,
        conn: sqlite3.Connection,
        context_key: str,
        role: str,
        content: str,
    ) -> int:
        """Insert a new conversation turn. Returns the inserted row ID."""
        with db_transaction(conn) as c:
            cursor = c.execute(
                "INSERT INTO claude_aggregate_conversations (context_key, role, content) VALUES (?, ?, ?)",
                (context_key, role, content),
            )
            return cursor.lastrowid or 0

    @classmethod
    def clear(cls, conn: sqlite3.Connection, context_key: str) -> int:
        """Delete all turns for a context key. Returns number of rows deleted."""
        with db_transaction(conn) as c:
            cursor = c.execute(
                "DELETE FROM claude_aggregate_conversations WHERE context_key = ?",
                (context_key,),
            )
            return cursor.rowcount

    @classmethod
    def has_history(cls, conn: sqlite3.Connection, context_key: str) -> bool:
        """Return True if any turns exist for this context key."""
        row = query_one(
            conn,
            "SELECT 1 FROM claude_aggregate_conversations WHERE context_key = ? LIMIT 1",
            (context_key,),
        )
        return row is not None


# ========== Execution -> Data Loop models (schema v4) ==========


class InvalidVerdict(ValueError):
    """Raised when a verdict label is not a known verdict type."""


def _lookup_id_by_label(
    table: str, id_col: str, label: str, conn: Optional[sqlite3.Connection] = None
) -> Optional[int]:
    """Resolve a lookup-table row id from its label (case-sensitive)."""
    with db_transaction(conn) as c:
        row = query_one(c, f"SELECT {id_col} FROM {table} WHERE label = ?", (label,))
        return cast(int, row[id_col]) if row else None


class VerdictType:
    """Accessor for the verdict_types lookup table."""

    @staticmethod
    def id_for_label(
        label: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[int]:
        return _lookup_id_by_label("verdict_types", "verdict_type_id", label, conn)

    @staticmethod
    def all_labels(conn: Optional[sqlite3.Connection] = None) -> list[str]:
        with db_transaction(conn) as c:
            rows = query_all(
                c, "SELECT label FROM verdict_types ORDER BY verdict_type_id"
            )
            return [r["label"] for r in rows]


class NseVerdict:
    """Accessor for the nse_verdicts lookup table."""

    @staticmethod
    def id_for_label(
        label: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[int]:
        return _lookup_id_by_label("nse_verdicts", "nse_verdict_id", label, conn)


class PortState:
    """Accessor for the port_states lookup table."""

    @staticmethod
    def id_for_label(
        label: str, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[int]:
        return _lookup_id_by_label("port_states", "port_state_id", label, conn)


@dataclass
class VerifiedPort:
    """A live-verified open port from a tool run (provenance = execution_id)."""

    verified_port_id: Optional[int] = None
    execution_id: int = 0
    host_id: int = 0
    port_number: Optional[int] = None
    protocol: str = "tcp"
    port_state_id: Optional[int] = None
    service_name: Optional[str] = None
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> VerifiedPort:
        return cls(
            verified_port_id=row["verified_port_id"],
            execution_id=row["execution_id"],
            host_id=row["host_id"],
            port_number=row["port_number"],
            protocol=row["protocol"],
            port_state_id=row["port_state_id"],
            service_name=row["service_name"],
            created_at=row["created_at"],
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        with db_transaction(conn) as c:
            cursor = c.execute(
                """
                INSERT OR REPLACE INTO verified_ports (
                    execution_id, host_id, port_number, protocol,
                    port_state_id, service_name, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.execution_id,
                    self.host_id,
                    self.port_number,
                    self.protocol,
                    self.port_state_id,
                    self.service_name,
                    self.created_at or now_iso(),
                ),
            )
            if self.verified_port_id is None:
                self.verified_port_id = cursor.lastrowid
        return self.verified_port_id

    @classmethod
    def delete_by_execution(
        cls, execution_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> int:
        with db_transaction(conn) as c:
            cursor = c.execute(
                "DELETE FROM verified_ports WHERE execution_id = ?", (execution_id,)
            )
            return cursor.rowcount

    @classmethod
    def get_by_execution(
        cls, execution_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[VerifiedPort]:
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                "SELECT * FROM verified_ports WHERE execution_id = ?",
                (execution_id,),
            )
            return [cls.from_row(r) for r in rows]


@dataclass
class NseScriptResult:
    """An NSE script result (vuln verdict) from a tool run (provenance = execution_id).

    port_number is None for a host script (vs a port script).
    """

    nse_result_id: Optional[int] = None
    execution_id: int = 0
    host_id: int = 0
    port_number: Optional[int] = None
    script_id: str = ""
    nse_verdict_id: Optional[int] = None
    output: Optional[str] = None
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> NseScriptResult:
        return cls(
            nse_result_id=row["nse_result_id"],
            execution_id=row["execution_id"],
            host_id=row["host_id"],
            port_number=row["port_number"],
            script_id=row["script_id"],
            nse_verdict_id=row["nse_verdict_id"],
            output=row["output"],
            created_at=row["created_at"],
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        with db_transaction(conn) as c:
            cursor = c.execute(
                """
                INSERT OR REPLACE INTO nse_script_results (
                    execution_id, host_id, port_number, script_id,
                    nse_verdict_id, output, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.execution_id,
                    self.host_id,
                    self.port_number,
                    self.script_id,
                    self.nse_verdict_id,
                    self.output,
                    self.created_at or now_iso(),
                ),
            )
            if self.nse_result_id is None:
                self.nse_result_id = cursor.lastrowid
        return self.nse_result_id

    @classmethod
    def delete_by_execution(
        cls, execution_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> int:
        with db_transaction(conn) as c:
            cursor = c.execute(
                "DELETE FROM nse_script_results WHERE execution_id = ?", (execution_id,)
            )
            return cursor.rowcount

    @classmethod
    def get_by_execution(
        cls, execution_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[NseScriptResult]:
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                "SELECT * FROM nse_script_results WHERE execution_id = ?",
                (execution_id,),
            )
            return [cls.from_row(r) for r in rows]


@dataclass
class NucleiMatchObservation:
    """One nuclei template match from a tool run (provenance = execution_id).

    Evidence, not a finding: `cerno import nuclei` is what creates `findings`
    rows. `port_number` is None where nuclei reported no usable port (a dns
    template, say), and both `matcher_name` and `extracted` are frequently
    None -- which is why `ingest` reconciles these rows in Python rather than
    relying on a UNIQUE index, where SQLite treats NULLs as distinct.
    """

    observation_id: Optional[int] = None
    execution_id: int = 0
    host_id: int = 0
    port_number: Optional[int] = None
    template_ref: str = ""
    template_name: Optional[str] = None
    severity_int: int = 0
    matched_at: Optional[str] = None
    matcher_name: Optional[str] = None
    template_url: Optional[str] = None
    extracted: Optional[str] = None
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> NucleiMatchObservation:
        return cls(
            observation_id=row["observation_id"],
            execution_id=row["execution_id"],
            host_id=row["host_id"],
            port_number=row["port_number"],
            template_ref=row["template_ref"],
            template_name=row["template_name"],
            severity_int=row["severity_int"],
            matched_at=row["matched_at"],
            matcher_name=row["matcher_name"],
            template_url=row["template_url"],
            extracted=row["extracted"],
            created_at=row["created_at"],
        )

    @classmethod
    def get_by_execution(
        cls, execution_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[NucleiMatchObservation]:
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                "SELECT * FROM nuclei_match_observations WHERE execution_id = ? "
                "ORDER BY observation_id",
                (execution_id,),
            )
            return [cls.from_row(r) for r in rows]

    @classmethod
    def get_by_finding(
        cls, finding_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[NucleiMatchObservation]:
        """Every match from any execution attributed to this finding."""
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT nmo.* FROM nuclei_match_observations nmo
                JOIN tool_executions te ON nmo.execution_id = te.execution_id
                WHERE te.finding_id = ?
                ORDER BY nmo.observation_id
                """,
                (finding_id,),
            )
            return [cls.from_row(r) for r in rows]


@dataclass
class NxcFlagObservation:
    """A point-in-time snapshot of one nxc security flag (provenance = execution_id)."""

    nxc_flag_id: Optional[int] = None
    execution_id: int = 0
    host_id: int = 0
    protocol: str = ""
    flag_name: str = ""
    flag_value: int = 0
    created_at: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> NxcFlagObservation:
        return cls(
            nxc_flag_id=row["nxc_flag_id"],
            execution_id=row["execution_id"],
            host_id=row["host_id"],
            protocol=row["protocol"],
            flag_name=row["flag_name"],
            flag_value=row["flag_value"],
            created_at=row["created_at"],
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        with db_transaction(conn) as c:
            cursor = c.execute(
                """
                INSERT OR REPLACE INTO nxc_flag_observations (
                    execution_id, host_id, protocol, flag_name, flag_value, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    self.execution_id,
                    self.host_id,
                    self.protocol,
                    self.flag_name,
                    1 if self.flag_value else 0,
                    self.created_at or now_iso(),
                ),
            )
            if self.nxc_flag_id is None:
                self.nxc_flag_id = cursor.lastrowid
        return self.nxc_flag_id

    @classmethod
    def delete_by_execution(
        cls, execution_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> int:
        with db_transaction(conn) as c:
            cursor = c.execute(
                "DELETE FROM nxc_flag_observations WHERE execution_id = ?",
                (execution_id,),
            )
            return cursor.rowcount

    @classmethod
    def get_by_execution(
        cls, execution_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[NxcFlagObservation]:
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                "SELECT * FROM nxc_flag_observations WHERE execution_id = ?",
                (execution_id,),
            )
            return [cls.from_row(r) for r in rows]


@dataclass
class VerdictEvidence:
    """A piece of evidence backing a verdict (links to execution/artifact/NSE result)."""

    evidence_id: Optional[int] = None
    verdict_id: Optional[int] = None
    execution_id: Optional[int] = None
    artifact_id: Optional[int] = None
    nse_result_id: Optional[int] = None
    note: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> VerdictEvidence:
        return cls(
            evidence_id=row["evidence_id"],
            verdict_id=row["verdict_id"],
            execution_id=row["execution_id"],
            artifact_id=row["artifact_id"],
            nse_result_id=row["nse_result_id"],
            note=row["note"],
        )

    def save(self, conn: Optional[sqlite3.Connection] = None) -> Optional[int]:
        with db_transaction(conn) as c:
            cursor = c.execute(
                """
                INSERT INTO verdict_evidence (
                    verdict_id, execution_id, artifact_id, nse_result_id, note
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    self.verdict_id,
                    self.execution_id,
                    self.artifact_id,
                    self.nse_result_id,
                    self.note,
                ),
            )
            if self.evidence_id is None:
                self.evidence_id = cursor.lastrowid
        return self.evidence_id

    @classmethod
    def get_by_verdict(
        cls, verdict_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[VerdictEvidence]:
        with db_transaction(conn) as c:
            rows = query_all(
                c, "SELECT * FROM verdict_evidence WHERE verdict_id = ?", (verdict_id,)
            )
            return [cls.from_row(r) for r in rows]


@dataclass
class FindingVerdict:
    """A verification verdict for a finding (truth, distinct from review_state).

    Append-only history: each ``set()`` inserts a new row. The current verdict
    for a finding is the latest one (see ``get_current`` / v_finding_current_verdict).
    """

    verdict_id: Optional[int] = None
    finding_id: int = 0
    verdict_type_id: int = 0
    verdict_label: str = ""
    note: Optional[str] = None
    created_at: Optional[str] = None
    #: ``finding_sources.source_id`` of the channel that recorded this verdict
    #: -- 4 (operator/TUI) or 5 (agent/MCP). Derived from the channel, never
    #: supplied by a caller.
    created_by: Optional[int] = None
    #: Resolved ``finding_sources.source_name`` for :attr:`created_by`, present
    #: when read through ``v_finding_current_verdict``.
    created_by_name: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> FindingVerdict:
        keys = row.keys()
        return cls(
            verdict_id=row["verdict_id"],
            finding_id=row["finding_id"],
            verdict_type_id=row["verdict_type_id"],
            verdict_label=row["verdict_label"] if "verdict_label" in keys else "",
            note=row["note"],
            created_at=row["created_at"],
            created_by=row["created_by"] if "created_by" in keys else None,
            created_by_name=(
                row["created_by_name"] if "created_by_name" in keys else None
            ),
        )

    @classmethod
    def set(
        cls,
        finding_id: int,
        verdict_label: str,
        actor: str,
        note: Optional[str] = None,
        evidence: Optional[list[VerdictEvidence]] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> FindingVerdict:
        """Record a new verdict (and optional evidence) for a finding.

        Args:
            finding_id: Finding the verdict is about.
            verdict_label: One of the ``verdict_types`` labels.
            actor: Channel recording the verdict -- ``SOURCE_OPERATOR`` from the
                TUI or ``SOURCE_AGENT`` from an MCP client. Required and
                derived from the channel, never accepted from a caller: a
                self-reported actor is worse than none, because it reads as
                evidence while carrying no guarantee.
            note: Optional free-text note.
            evidence: Optional supporting evidence rows.
            conn: Database connection.

        Raises:
            InvalidVerdict: if ``verdict_label`` is not a known verdict type.
            ValueError: if ``actor`` is not an authored (channel) source.
        """
        created_by = channel_source_id(actor)
        with db_transaction(conn) as c:
            type_id = VerdictType.id_for_label(verdict_label, c)
            if type_id is None:
                valid = ", ".join(VerdictType.all_labels(c))
                raise InvalidVerdict(
                    f"Unknown verdict '{verdict_label}'. Valid verdicts: {valid}"
                )
            created = now_iso()
            cursor = c.execute(
                """
                INSERT INTO finding_verdicts (
                    finding_id, verdict_type_id, note, created_at, created_by
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (finding_id, type_id, note, created, created_by),
            )
            verdict_id = cursor.lastrowid
            for ev in evidence or []:
                ev.verdict_id = verdict_id
                ev.save(c)
            return cls(
                verdict_id=verdict_id,
                finding_id=finding_id,
                verdict_type_id=type_id,
                verdict_label=verdict_label,
                note=note,
                created_at=created,
                created_by=created_by,
            )

    @classmethod
    def get_current(
        cls, finding_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> Optional[FindingVerdict]:
        with db_transaction(conn) as c:
            row = query_one(
                c,
                "SELECT * FROM v_finding_current_verdict WHERE finding_id = ?",
                (finding_id,),
            )
            return cls.from_row(row) if row else None

    @classmethod
    def get_history(
        cls, finding_id: int, conn: Optional[sqlite3.Connection] = None
    ) -> list[FindingVerdict]:
        with db_transaction(conn) as c:
            rows = query_all(
                c,
                """
                SELECT fv.*, vt.label AS verdict_label
                FROM finding_verdicts fv
                JOIN verdict_types vt ON fv.verdict_type_id = vt.verdict_type_id
                WHERE fv.finding_id = ?
                ORDER BY fv.created_at DESC, fv.verdict_id DESC
                """,
                (finding_id,),
            )
            return [cls.from_row(r) for r in rows]
