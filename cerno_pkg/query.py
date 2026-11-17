"""Composite finding query — one safe, parameterized predicate set.

This is the shared query layer behind the MCP ``query_findings`` tool (and, in
time, the TUI's finding-list filtering). It builds AND-combined predicates on top
of the same ``findings INNER JOIN v_finding_types_with_severity`` shape used by
``models.Finding.get_by_dataset_with_finding_type`` and the normalized host/port/service
tables and verdict view. Every predicate is a fixed, bound-parameter clause — no
free-form SQL ever crosses the boundary.

Two predicates are deliberately NOT pure SQL:

* ``cve`` — ``finding_types.cves`` is a JSON array column, so a SQL ``LIKE`` only
  pre-filters the candidate set; an exact, case-insensitive element match is then
  confirmed in Python (``LIKE`` cannot anchor to an array element, e.g.
  ``CVE-2021-1`` must not match ``CVE-2021-10``).
* ``has_workflow`` — workflow mappings live in ``workflow_mappings.yaml`` via
  :class:`cerno_pkg.workflow_mapper.WorkflowMapper`, not the database, so this is a
  Python post-filter consulting the mapper (which already resolves grouped,
  comma-separated finding_type keys to each member finding_type).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from .constants import REVIEW_STATES, SOURCE_IDS, VERDICT_LABELS
from .database import db_transaction, finding_type_id_order_sql, query_all
from .models import Finding, FindingType
from .workflow_mapper import WorkflowMapper, build_workflow_mapper

if TYPE_CHECKING:
    from .config import CernoConfig


@dataclass
class FindingQuery:
    """A set of AND-combined finding predicates. Unset (None) fields are ignored."""

    dataset_ids: Optional[list[int]] = None  # None = every dataset
    severity_int: Optional[int] = None  # exact severity (0..4)
    severity_min: Optional[int] = None  # severity >= N
    review_state: Optional[str] = None  # unreviewed|in_progress|done
    verdict: Optional[str] = None  # confirmed|false_positive|unable|none
    cve: Optional[str] = None  # exact CVE id (case-insensitive)
    port: Optional[int] = None  # affected on this port
    service: Optional[str] = None  # host_services.svc_name substring
    host: Optional[str] = None  # scan_target / ip_address substring
    finding_type_name: Optional[str] = (
        None  # finding_type name substring (case-insensitive)
    )
    source: Optional[str] = None  # nessus|nuclei|burp|operator|agent
    has_metasploit: Optional[bool] = None
    has_workflow: Optional[bool] = None  # consults the workflow mapper, not the DB
    # Dedup by finding_type across every dataset in scope, including the
    # all-datasets default (TUI multi-dataset semantics).
    merged: bool = False
    limit: int = 500
    offset: int = 0


# Column order for the shared SELECT — matches Finding.get_by_dataset_with_finding_type so
# the same row-to-object conversion applies.
_SELECT_COLS = """
    f.finding_id, f.dataset_id, f.finding_type_id,
    f.review_state, f.reviewed_at, f.completed_by, f.review_notes,
    p.finding_type_id as p_finding_type_id, p.finding_type_name, p.severity_int, p.severity_label,
    p.has_metasploit, p.cvss3_score, p.cvss2_score, p.cves,
    p.details_url, p.metasploit_names
"""


def _row_to_finding_type(row: Any) -> tuple[Finding, FindingType]:
    """Build a (Finding, FindingType) pair from a shared-SELECT row."""
    finding = Finding(
        finding_id=row[0],
        dataset_id=row[1],
        finding_type_id=row[2],
        review_state=row[3],
        reviewed_at=row[4],
        completed_by=row[5],
        review_notes=row[6],
    )
    cves = json.loads(row[14]) if row[14] else None
    msf_names = json.loads(row[16]) if row[16] else None
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
    return finding, finding_type


def _bad_value(field: str, got: str, valid: Any) -> str:
    """Message for a predicate whose value is not one of its valid values.

    An unrecognised ``source`` used to compile to a false clause, so a typo
    returned an empty result indistinguishable from "no findings match". An
    external MCP audit duly concluded that three real sources did not exist,
    because an out-of-date description said so and the empty result agreed.
    A filter the caller got wrong has to say so.
    """
    return f"unknown {field} {got!r}; valid values are: " + ", ".join(sorted(valid))


def _build_where(q: FindingQuery) -> tuple[str, list[Any], bool]:
    """Compile the SQL-expressible predicates into a WHERE clause.

    Returns ``(where_sql, params, needs_verdict_join)``. The verdict join is only
    added when a verdict predicate is present.

    Raises:
        ValueError: if ``source``, ``review_state`` or ``verdict`` is not one of
            its valid values (from ``SOURCE_IDS`` / ``REVIEW_STATES`` /
            ``VERDICT_LABELS``). An empty ``dataset_ids`` is **not** an error:
            an explicitly empty scope legitimately matches nothing.
    """
    clauses: list[str] = []
    params: list[Any] = []
    needs_verdict_join = False

    if q.dataset_ids is not None:
        if not q.dataset_ids:
            # An explicit empty scope matches nothing.
            clauses.append("0")
        else:
            placeholders = ",".join("?" * len(q.dataset_ids))
            clauses.append(f"f.dataset_id IN ({placeholders})")
            params.extend(q.dataset_ids)

    if q.severity_int is not None:
        clauses.append("p.severity_int = ?")
        params.append(q.severity_int)

    if q.severity_min is not None:
        clauses.append("p.severity_int >= ?")
        params.append(q.severity_min)

    if q.source is not None:
        # Filter on the stored, indexed source_id rather than a LIKE on the
        # finding_type_id prefix.
        source_id = SOURCE_IDS.get(q.source.strip().lower())
        if source_id is None:
            raise ValueError(_bad_value("source", q.source, SOURCE_IDS))
        clauses.append("p.source_id = ?")
        params.append(source_id)

    if q.review_state is not None:
        if q.review_state not in REVIEW_STATES:
            raise ValueError(_bad_value("review_state", q.review_state, REVIEW_STATES))
        clauses.append("f.review_state = ?")
        params.append(q.review_state)

    if q.finding_type_name is not None:
        clauses.append("p.finding_type_name LIKE ?")
        params.append(f"%{q.finding_type_name}%")

    if q.has_metasploit is not None:
        clauses.append("p.has_metasploit = ?")
        params.append(1 if q.has_metasploit else 0)

    if q.port is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM finding_affected_hosts fah "
            "WHERE fah.finding_id = f.finding_id AND fah.port_number = ?)"
        )
        params.append(q.port)

    if q.service is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM finding_affected_hosts fah "
            "JOIN host_services hs ON hs.host_id = fah.host_id "
            "AND hs.port_number = fah.port_number "
            "WHERE fah.finding_id = f.finding_id AND hs.svc_name LIKE ?)"
        )
        params.append(f"%{q.service}%")

    if q.host is not None:
        clauses.append(
            "EXISTS (SELECT 1 FROM finding_affected_hosts fah "
            "JOIN hosts h ON h.host_id = fah.host_id "
            "WHERE fah.finding_id = f.finding_id "
            "AND (h.scan_target LIKE ? OR h.ip_address LIKE ?))"
        )
        params.extend([f"%{q.host}%", f"%{q.host}%"])

    if q.verdict is not None:
        if q.verdict != "none" and q.verdict not in VERDICT_LABELS:
            raise ValueError(
                _bad_value("verdict", q.verdict, (*VERDICT_LABELS, "none"))
            )
        needs_verdict_join = True
        if q.verdict == "none":
            clauses.append("cv.finding_id IS NULL")
        else:
            clauses.append("cv.verdict_label = ?")
            params.append(q.verdict)

    # SQL pre-filter for CVE (shrinks the set; Python confirms exactness below).
    if q.cve is not None:
        clauses.append("p.cves LIKE ?")
        params.append(f"%{q.cve}%")

    where = " AND ".join(clauses) if clauses else "1"
    return where, params, needs_verdict_join


def _candidate_rows(q: FindingQuery, conn: sqlite3.Connection) -> list:
    where, params, needs_verdict_join = _build_where(q)
    verdict_join = (
        "LEFT JOIN v_finding_current_verdict cv ON cv.finding_id = f.finding_id"
        if needs_verdict_join
        else ""
    )
    sql = f"""
        SELECT {_SELECT_COLS}
        FROM findings f
        INNER JOIN v_finding_types_with_severity p ON f.finding_type_id = p.finding_type_id
        {verdict_join}
        WHERE {where}
        -- Worst first, so a page cut short by ``limit`` keeps the highest
        -- severities whatever their source. Ordering by finding_type_id alone
        -- sorted by source prefix, so a truncated page returned Nessus rows and
        -- silently discarded every nuclei, Burp and hand-authored finding --
        -- which is how a limit of 6 over the criticals lost a Critical Log4j
        -- RCE. The remaining keys keep the order fully deterministic, so
        -- limit/offset paging stays stable.
        ORDER BY p.severity_int DESC,
                 {finding_type_id_order_sql('p.finding_type_id')}, f.dataset_id ASC
    """
    return query_all(conn, sql, tuple(params))


def _cve_matches(finding_type: FindingType, target: str) -> bool:
    """Exact, case-insensitive membership of ``target`` in a finding_type's CVE list."""
    needle = target.strip().lower()
    return any(str(x).strip().lower() == needle for x in (finding_type.cves or []))


def _merge_by_finding_type(
    rows: list[tuple[Finding, FindingType]],
    dataset_ids: Optional[list[int]],
    conn: sqlite3.Connection,
) -> list[tuple[Finding, FindingType]]:
    """Dedup matched rows to one representative per finding_type, attaching siblings.

    The representative is the matched finding with the lowest dataset_id;
    ``extra_finding_ids`` is set to every other finding for that finding_type within the
    selected datasets, so downstream host/port lookups span all datasets (matching
    ``Finding.get_by_dataset_ids_merged``).

    ``dataset_ids`` None means every dataset, so the sibling lookup drops its
    scope clause rather than resolving the full id list.
    """
    by_finding_type: dict[str, tuple[Finding, FindingType]] = {}
    for finding, finding_type in rows:
        pid = finding_type.finding_type_id
        existing = by_finding_type.get(pid)
        if existing is None or (finding.dataset_id or 0) < (
            existing[0].dataset_id or 0
        ):
            by_finding_type[pid] = (finding, finding_type)

    scope_sql = ""
    scope_params: tuple[int, ...] = ()
    if dataset_ids is not None:
        placeholders = ",".join("?" * len(dataset_ids))
        scope_sql = f" AND dataset_id IN ({placeholders})"
        scope_params = tuple(dataset_ids)

    result: list[tuple[Finding, FindingType]] = []
    for pid, (rep, finding_type) in by_finding_type.items():
        sibling_rows = query_all(
            conn,
            "SELECT finding_id FROM findings WHERE finding_type_id = ?" + scope_sql,
            (pid, *scope_params),
        )
        rep.extra_finding_ids = [
            r[0] for r in sibling_rows if r[0] is not None and r[0] != rep.finding_id
        ]
        result.append((rep, finding_type))
    return result


def run_finding_query(
    q: FindingQuery,
    conn: Optional[sqlite3.Connection] = None,
    *,
    workflow_mapper: Optional[WorkflowMapper] = None,
    config: Optional[CernoConfig] = None,
) -> list[tuple[Finding, FindingType]]:
    """Run a composite finding query, returning (Finding, FindingType) pairs.

    Args:
        q: The predicate set (AND-combined; unset fields ignored).
        conn: Database connection (opened/closed by the caller or db_transaction).
        workflow_mapper: Mapper used for the ``has_workflow`` predicate; a default
            one (bundled + custom workflows) is built when omitted.
        config: Config for the default mapper's ``custom_workflows_path``;
            loaded when None. Ignored when ``workflow_mapper`` is given.
    """
    with db_transaction(conn) as c:
        rows = [_row_to_finding_type(r) for r in _candidate_rows(q, c)]

        # Python confirm for CVE exactness (SQL LIKE only pre-filtered).
        if q.cve is not None:
            rows = [rp for rp in rows if _cve_matches(rp[1], q.cve)]

        # has_workflow is not a DB fact — consult the workflow mapper.
        if q.has_workflow is not None:
            mapper = workflow_mapper or build_workflow_mapper(config)
            rows = [
                rp
                for rp in rows
                if mapper.has_workflow(str(rp[1].finding_type_id)) == q.has_workflow
            ]

        # ``merged`` with no explicit scope means every dataset, which is where
        # there is the most to merge. None is also falsy, so treating a falsy
        # scope as "nothing to merge" discarded the flag in exactly that case:
        # query_findings(merged=True) returned duplicates, and
        # list_workflow_gaps() -- which hardcodes merged=True and defaults to
        # no scope -- broke the one-row-per-finding-type promise in its own
        # published description. An explicit single dataset still short-circuits:
        # UNIQUE (dataset_id, finding_type_id) makes dedup a no-op there.
        if q.merged and (q.dataset_ids is None or len(q.dataset_ids) > 1):
            rows = _merge_by_finding_type(rows, q.dataset_ids, c)

    if q.offset:
        rows = rows[q.offset :]
    if q.limit is not None and q.limit >= 0:
        rows = rows[: q.limit]
    return rows
