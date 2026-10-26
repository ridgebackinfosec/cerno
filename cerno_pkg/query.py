"""Composite finding query — one safe, parameterized predicate set.

This is the shared query layer behind the MCP ``query_findings`` tool (and, in
time, the TUI's finding-list filtering). It builds AND-combined predicates on top
of the same ``findings INNER JOIN v_plugins_with_severity`` shape used by
``models.Finding.get_by_scan_with_plugin`` and the normalized host/port/service
tables and verdict view. Every predicate is a fixed, bound-parameter clause — no
free-form SQL ever crosses the boundary.

Two predicates are deliberately NOT pure SQL:

* ``cve`` — ``plugins.cves`` is a JSON array column, so a SQL ``LIKE`` only
  pre-filters the candidate set; an exact, case-insensitive element match is then
  confirmed in Python (``LIKE`` cannot anchor to an array element, e.g.
  ``CVE-2021-1`` must not match ``CVE-2021-10``).
* ``has_workflow`` — workflow mappings live in ``workflow_mappings.yaml`` via
  :class:`cerno_pkg.workflow_mapper.WorkflowMapper`, not the database, so this is a
  Python post-filter consulting the mapper (which already resolves grouped,
  comma-separated plugin keys to each member plugin).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from .database import db_transaction, query_all
from .models import Finding, Plugin
from .workflow_mapper import WorkflowMapper, build_workflow_mapper

if TYPE_CHECKING:
    from .config import CernoConfig


@dataclass
class FindingQuery:
    """A set of AND-combined finding predicates. Unset (None) fields are ignored."""

    scan_ids: Optional[list[int]] = None  # None = every scan
    severity_int: Optional[int] = None  # exact severity (0..4)
    severity_min: Optional[int] = None  # severity >= N
    review_state: Optional[str] = None  # unreviewed|in_progress|done
    verdict: Optional[str] = None  # confirmed|false_positive|unable|none
    cve: Optional[str] = None  # exact CVE id (case-insensitive)
    port: Optional[int] = None  # affected on this port
    service: Optional[str] = None  # host_services.svc_name substring
    host: Optional[str] = None  # scan_target / ip_address substring
    plugin_name: Optional[str] = None  # plugin name substring (case-insensitive)
    has_metasploit: Optional[bool] = None
    has_workflow: Optional[bool] = None  # consults the workflow mapper, not the DB
    merged: bool = False  # dedup by plugin across >1 scan (TUI multi-scan semantics)
    limit: int = 500
    offset: int = 0


# Column order for the shared SELECT — matches Finding.get_by_scan_with_plugin so
# the same row-to-object conversion applies.
_SELECT_COLS = """
    f.finding_id, f.scan_id, f.plugin_id,
    f.review_state, f.reviewed_at, f.reviewed_by, f.review_notes,
    p.plugin_id as p_plugin_id, p.plugin_name, p.severity_int, p.severity_label,
    p.has_metasploit, p.cvss3_score, p.cvss2_score, p.cves,
    p.plugin_url, p.metadata_fetched_at, p.metasploit_names
"""


def _row_to_finding_plugin(row: Any) -> tuple[Finding, Plugin]:
    """Build a (Finding, Plugin) pair from a shared-SELECT row."""
    finding = Finding(
        finding_id=row[0],
        scan_id=row[1],
        plugin_id=row[2],
        review_state=row[3],
        reviewed_at=row[4],
        reviewed_by=row[5],
        review_notes=row[6],
    )
    cves = json.loads(row[14]) if row[14] else None
    msf_names = json.loads(row[17]) if row[17] else None
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
        metadata_fetched_at=row[16],
        metasploit_names=msf_names,
    )
    return finding, plugin


def _build_where(q: FindingQuery) -> tuple[str, list[Any], bool]:
    """Compile the SQL-expressible predicates into a WHERE clause.

    Returns ``(where_sql, params, needs_verdict_join)``. The verdict join is only
    added when a verdict predicate is present.
    """
    clauses: list[str] = []
    params: list[Any] = []
    needs_verdict_join = False

    if q.scan_ids is not None:
        if not q.scan_ids:
            # An explicit empty scope matches nothing.
            clauses.append("0")
        else:
            placeholders = ",".join("?" * len(q.scan_ids))
            clauses.append(f"f.scan_id IN ({placeholders})")
            params.extend(q.scan_ids)

    if q.severity_int is not None:
        clauses.append("p.severity_int = ?")
        params.append(q.severity_int)

    if q.severity_min is not None:
        clauses.append("p.severity_int >= ?")
        params.append(q.severity_min)

    if q.review_state is not None:
        clauses.append("f.review_state = ?")
        params.append(q.review_state)

    if q.plugin_name is not None:
        clauses.append("p.plugin_name LIKE ?")
        params.append(f"%{q.plugin_name}%")

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
        INNER JOIN v_plugins_with_severity p ON f.plugin_id = p.plugin_id
        {verdict_join}
        WHERE {where}
        ORDER BY p.plugin_id ASC, f.scan_id ASC
    """
    return query_all(conn, sql, tuple(params))


def _cve_matches(plugin: Plugin, target: str) -> bool:
    """Exact, case-insensitive membership of ``target`` in a plugin's CVE list."""
    needle = target.strip().lower()
    return any(str(x).strip().lower() == needle for x in (plugin.cves or []))


def _merge_by_plugin(
    rows: list[tuple[Finding, Plugin]],
    scan_ids: list[int],
    conn: sqlite3.Connection,
) -> list[tuple[Finding, Plugin]]:
    """Dedup matched rows to one representative per plugin, attaching siblings.

    The representative is the matched finding with the lowest scan_id;
    ``extra_finding_ids`` is set to every other finding for that plugin within the
    selected scans, so downstream host/port lookups span all scans (matching
    ``Finding.get_by_scan_ids_merged``).
    """
    by_plugin: dict[int, tuple[Finding, Plugin]] = {}
    for finding, plugin in rows:
        pid = plugin.plugin_id
        existing = by_plugin.get(pid)
        if existing is None or (finding.scan_id or 0) < (existing[0].scan_id or 0):
            by_plugin[pid] = (finding, plugin)

    placeholders = ",".join("?" * len(scan_ids))
    result: list[tuple[Finding, Plugin]] = []
    for pid, (rep, plugin) in by_plugin.items():
        sibling_rows = query_all(
            conn,
            f"SELECT finding_id FROM findings "
            f"WHERE plugin_id = ? AND scan_id IN ({placeholders})",
            (pid, *scan_ids),
        )
        rep.extra_finding_ids = [
            r[0] for r in sibling_rows if r[0] is not None and r[0] != rep.finding_id
        ]
        result.append((rep, plugin))
    return result


def run_finding_query(
    q: FindingQuery,
    conn: Optional[sqlite3.Connection] = None,
    *,
    workflow_mapper: Optional[WorkflowMapper] = None,
    config: Optional[CernoConfig] = None,
) -> list[tuple[Finding, Plugin]]:
    """Run a composite finding query, returning (Finding, Plugin) pairs.

    Args:
        q: The predicate set (AND-combined; unset fields ignored).
        conn: Database connection (opened/closed by the caller or db_transaction).
        workflow_mapper: Mapper used for the ``has_workflow`` predicate; a default
            one (bundled + custom workflows) is built when omitted.
        config: Config for the default mapper's ``custom_workflows_path``;
            loaded when None. Ignored when ``workflow_mapper`` is given.
    """
    with db_transaction(conn) as c:
        rows = [_row_to_finding_plugin(r) for r in _candidate_rows(q, c)]

        # Python confirm for CVE exactness (SQL LIKE only pre-filtered).
        if q.cve is not None:
            rows = [rp for rp in rows if _cve_matches(rp[1], q.cve)]

        # has_workflow is not a DB fact — consult the workflow mapper.
        if q.has_workflow is not None:
            mapper = workflow_mapper or build_workflow_mapper(config)
            rows = [
                rp
                for rp in rows
                if mapper.has_workflow(str(rp[1].plugin_id)) == q.has_workflow
            ]

        if q.merged and q.scan_ids and len(q.scan_ids) > 1:
            rows = _merge_by_plugin(rows, q.scan_ids, c)

    if q.offset:
        rows = rows[q.offset :]
    if q.limit is not None and q.limit >= 0:
        rows = rows[: q.limit]
    return rows
