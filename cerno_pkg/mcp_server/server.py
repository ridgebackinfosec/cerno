"""Cerno MCP server implementation.

This module is intentionally structured in two layers:

1. **Pure adapter functions** (``tool_*``) that take an optional sqlite3
   connection plus plain arguments and return JSON-serializable dicts/lists.
   These contain no MCP-specific code and are unit-testable with the
   ``temp_db`` fixture by passing ``conn`` explicitly.
2. **``build_server``**, which wraps the adapters as ``FastMCP`` tools,
   opening a real database connection per call and registering the
   execution/mutation tools only when the corresponding config flag is on.

IMPORTANT: stdio transport uses stdout as the JSON-RPC channel. Nothing in the
adapter path may write to stdout. That is why execution goes through
``ops.run_command_captured`` (no Rich spinner, no interactive sudo) and scan
comparison/history use the pure-data ``cross_scan`` functions rather than the
console-printing helpers in ``analysis``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Generator, Optional, Sequence, cast

# Pydantic (via FastMCP output schemas) requires typing_extensions.TypedDict on
# Python < 3.12; typing_extensions ships with mcp/pydantic, so always use it.
from typing_extensions import TypedDict

from mcp.server.fastmcp import Context, FastMCP

from ..config import CernoConfig, load_config
from ..constants import REVIEW_STATES
from ..exec_chain import EXEC_WRAPPERS, command_chain, matches_any
from ..logging_setup import log_debug, log_error, log_info

# Valid review states (mirrors the findings.review_state CHECK constraint).
_VALID_REVIEW_STATES = set(REVIEW_STATES)


# Result shapes for the core read tools. Note: FastMCP serializes every
# declared key into structuredContent, emitting absent keys as null, and then
# validates against the generated schema. So any key an adapter may omit, or a
# DB column may leave NULL, must be typed Optional[...] -- and a TypedDict must
# not be shared between tools that return different key sets.
class ScanInfo(TypedDict, total=False):
    scan_id: int
    scan_name: str
    created_at: str
    last_reviewed_at: Optional[str]
    unique_hosts: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    done_count: int


class FindingSummary(TypedDict, total=False):
    finding_id: int
    scan_id: int
    plugin_id: int
    review_state: str
    plugin_name: str
    severity_int: int
    severity_label: str
    has_metasploit: bool
    cvss3_score: Optional[float]
    cvss2_score: Optional[float]
    cves: list[str]
    plugin_url: Optional[str]


class FindingDetail(FindingSummary, total=False):
    metasploit_names: list[str]
    affected: list[dict]
    affected_total: int
    affected_truncated: bool
    verdict: Optional[str]
    suggested_verdict: Optional[str]
    verified_port_count: int
    nse_result_count: int
    vulnerable_count: int


class FindingSearchResult(FindingSummary, total=False):
    scan_name: str


class QueryFindingResult(FindingSummary, total=False):
    scan_name: str
    has_workflow: bool


class WorkflowGapResult(FindingSummary, total=False):
    # Findings with NO mapped verification workflow; distinct TypedDict (not
    # QueryFindingResult) so the contract-test schema guard stays happy.
    scan_name: str


class NotesResult(TypedDict):
    finding_id: int
    entries: list[str]
    raw: Optional[str]


class FindingHosts(TypedDict, total=False):
    finding_id: int
    hosts: list[str]
    ports: str
    target_lines: list[str]


class ExecutionInfo(TypedDict, total=False):
    execution_id: int
    tool_name: str
    tool_protocol: Optional[str]
    command_text: str
    executed_at: str
    exit_code: Optional[int]
    duration_seconds: Optional[float]
    host_count: Optional[int]
    ports: Optional[str]
    used_sudo: bool


class ArtifactInfo(TypedDict, total=False):
    artifact_id: int
    execution_id: Optional[int]
    artifact_path: str
    artifact_type: Optional[str]
    file_extension: Optional[str]
    file_size_bytes: Optional[int]
    file_hash: Optional[str]
    created_at: str


class CveAffected(TypedDict, total=False):
    finding_id: int
    scan_id: int
    plugin_id: int
    plugin_name: str
    severity_int: int
    hosts: list[str]


class NmapCommand(TypedDict):
    command: list[str]
    ips_file: str
    output_base: str


class NetexecCommand(TypedDict):
    command: list[str]
    ips_file: str
    log_path: str
    relay_path: Optional[str]


class MsfSearchCommand(TypedDict):
    command: Optional[str]
    search_term: str
    has_metasploit: bool
    metasploit_names: list[str]


class Capabilities(TypedDict, total=False):
    execution_enabled: bool
    mutations_enabled: bool
    cred_injection_enabled: bool
    cred_reveal_enabled: bool
    batch_enabled: bool
    batch_concurrency: int
    exec_allowlist: list[str]
    exec_denylist: list[str]
    nxc_available: bool


class HostInfo(TypedDict, total=False):
    host_id: int
    ip_address: str
    scan_target: str
    scan_target_type: str
    netbios_name: Optional[str]
    fqdn: Optional[str]
    first_seen: str
    last_seen: str
    finding_count: int
    scan_count: int
    max_severity: Optional[int]


class ServiceInfo(TypedDict, total=False):
    host: str
    port: int
    protocol: str
    svc_name: str


class CveEntry(TypedDict, total=False):
    cve: str
    plugins: list[dict]


class IngestResult(TypedDict, total=False):
    execution_id: int
    tool_name: str
    verified_ports: int
    nse_results: int
    nxc_flags: int
    nse_verdicts: dict
    skipped_reason: Optional[str]


class VerdictInfo(TypedDict, total=False):
    verdict_id: int
    finding_id: int
    verdict: str
    note: Optional[str]
    created_at: Optional[str]
    created_by: Optional[str]


class WorkflowCandidateHint(TypedDict):
    # Workflow-contribution hint: available when a verified finding's execution
    # trail yields a new/enhanced workflow (reason "new" | "enhanced").
    available: bool
    reason: Optional[str]


class VerdictResult(TypedDict, total=False):
    finding_id: int
    current: Optional[VerdictInfo]
    suggested_verdict: Optional[str]
    history: list[VerdictInfo]
    evidence: list[dict]
    workflow_candidate: WorkflowCandidateHint


class WorkflowCandidateResult(TypedDict):
    finding_id: int
    plugin_id: int
    available: bool
    reason: Optional[str]
    verdict: Optional[str]
    exportable: bool
    workflow: Optional[dict]
    new_commands: list[str]
    possibly_superseded: list[str]
    review_hints: list[str]
    leak_warnings: list[str]
    excluded: list[dict]


class WorkflowExportResult(TypedDict):
    path: str
    reason: str
    plugin_id: int
    submission_instructions: str


@contextmanager
def _db(
    conn: Optional[sqlite3.Connection],
) -> Generator[sqlite3.Connection, None, None]:
    """Yield a connection, opening a fresh one only when none was supplied.

    A caller-supplied connection (tests, or an enclosing transaction) is never
    closed here; a connection opened here is always closed on exit.
    """
    from ..database import get_connection

    if conn is not None:
        yield conn
        return

    own = get_connection()
    try:
        yield own
    finally:
        own.close()


# ========== Serialization helpers ==========


def _finding_plugin_to_dict(finding: Any, plugin: Any) -> dict:
    """Flatten a (Finding, Plugin) tuple into a JSON-serializable dict."""
    return {
        "finding_id": finding.finding_id,
        "scan_id": finding.scan_id,
        "plugin_id": finding.plugin_id,
        "review_state": finding.review_state,
        "plugin_name": plugin.plugin_name,
        "severity_int": plugin.severity_int,
        "severity_label": plugin.severity_label,
        "has_metasploit": plugin.has_metasploit,
        "cvss3_score": plugin.cvss3_score,
        "cvss2_score": plugin.cvss2_score,
        "cves": plugin.cves or [],
        "plugin_url": plugin.plugin_url,
    }


# ========== Read tools ==========


def tool_list_scans(conn: Optional[sqlite3.Connection] = None) -> list[dict]:
    """List all imported scans with per-severity finding counts and progress."""
    from ..models import Scan

    with _db(conn) as c:
        return Scan.get_all_with_stats(c)


#: Row cap for list/query/search when neither the caller nor config sets one.
_DEFAULT_LIST_LIMIT = 500


def _resolve_limit(limit: Optional[int], config: Optional[CernoConfig]) -> int:
    """Resolve a listing's row cap: explicit ``limit`` > config > 500.

    The config value is ``default_page_size`` with the TUI's floor of 8
    (``fs.default_page_size``), so an operator's page size carries over to agents.
    """
    if limit is not None:
        return limit
    cfg = config or load_config()
    if cfg.default_page_size:
        return max(8, cfg.default_page_size)
    return _DEFAULT_LIST_LIMIT


def tool_list_findings(
    scan_ids: list[int],
    *,
    severity_int: Optional[int] = None,
    review_state: Optional[str] = None,
    has_metasploit: Optional[bool] = None,
    plugin_name: Optional[str] = None,
    merged: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """List findings across one or more scans, optionally filtered and paged.

    Args:
        scan_ids: Scan IDs to include.
        severity_int: Optional severity filter (0=Info .. 4=Critical).
        review_state: Optional review-state filter.
        has_metasploit: If set, keep only findings whose plugin has a MSF module.
        plugin_name: Optional case-insensitive substring match on plugin name.
        merged: When True and more than one scan is given, deduplicate by
            ``plugin_id`` (one representative finding per plugin, siblings tracked
            in ``extra_finding_ids``) — matching the TUI's multi-scan review.
            When False (default), findings are concatenated and deduplicated by
            ``finding_id``.
        limit: Maximum number of findings to return (applied after filtering/dedup).
            None uses config ``default_page_size`` (min 8) when set, else 500.
        offset: Number of findings to skip before ``limit`` (for paging).
        config: Config for the default ``limit``; loaded when None.
    """
    from ..models import Finding

    limit = _resolve_limit(limit, config)
    severity_dir = None if severity_int is None else f"{severity_int}_"
    results: list[dict] = []
    with _db(conn) as c:
        if merged and len(scan_ids) > 1:
            display_list, _ = Finding.get_by_scan_ids_merged(
                scan_ids,
                severity_dir=severity_dir,
                has_metasploit=has_metasploit,
                conn=c,
            )
            needle = plugin_name.lower() if plugin_name else None
            for finding, plugin in display_list:
                if review_state is not None and finding.review_state != review_state:
                    continue
                if (
                    needle is not None
                    and needle not in (plugin.plugin_name or "").lower()
                ):
                    continue
                results.append(_finding_plugin_to_dict(finding, plugin))
        else:
            seen: set[int] = set()
            for scan_id in scan_ids:
                pairs = Finding.get_by_scan_with_plugin(
                    scan_id,
                    severity_dir=severity_dir,
                    review_state=review_state,
                    plugin_name_filter=plugin_name,
                    has_metasploit=has_metasploit,
                    conn=c,
                )
                for finding, plugin in pairs:
                    fid = finding.finding_id
                    if fid is None or fid in seen:
                        continue
                    seen.add(fid)
                    results.append(_finding_plugin_to_dict(finding, plugin))
    if offset:
        results = results[offset:]
    if limit >= 0:
        results = results[:limit]
    return results


def tool_search_findings(
    *,
    plugin_name: Optional[str] = None,
    severity_int: Optional[int] = None,
    has_metasploit: Optional[bool] = None,
    limit: Optional[int] = None,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """Search findings across ALL scans (no scan_ids required).

    Answers questions like "every host with a critical SMB finding anywhere".
    Each result carries its ``scan_name`` for cross-scan context. Results are
    capped at ``limit`` (None: config ``default_page_size``, min 8, else 500).
    """
    from ..models import Finding, Scan

    limit = _resolve_limit(limit, config)
    severity_dir = None if severity_int is None else f"{severity_int}_"
    results: list[dict] = []
    with _db(conn) as c:
        for scan in Scan.get_all_with_stats(c):
            scan_id = scan["scan_id"]
            pairs = Finding.get_by_scan_with_plugin(
                scan_id,
                severity_dir=severity_dir,
                plugin_name_filter=plugin_name,
                has_metasploit=has_metasploit,
                conn=c,
            )
            for finding, plugin in pairs:
                row = _finding_plugin_to_dict(finding, plugin)
                row["scan_name"] = scan["scan_name"]
                results.append(row)
                if len(results) >= limit >= 0:
                    return results
    return results


def tool_query_findings(
    *,
    scan_ids: Optional[list[int]] = None,
    severity_int: Optional[int] = None,
    severity_min: Optional[int] = None,
    review_state: Optional[str] = None,
    verdict: Optional[str] = None,
    cve: Optional[str] = None,
    port: Optional[int] = None,
    service: Optional[str] = None,
    host: Optional[str] = None,
    plugin_name: Optional[str] = None,
    has_metasploit: Optional[bool] = None,
    has_workflow: Optional[bool] = None,
    merged: bool = False,
    limit: Optional[int] = None,
    offset: int = 0,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """Query findings with AND-combined predicates (the composite superset tool).

    Every predicate is optional and parameterized (no free-form SQL). ``scan_ids``
    None spans all scans; ``verdict`` accepts confirmed/false_positive/unable or
    "none" (no verdict yet); ``cve`` is an exact, case-insensitive CVE id;
    ``has_workflow`` consults the workflow mapper (bundled + ``custom_workflows_path``),
    not the DB. ``limit`` None uses config ``default_page_size`` (min 8), else 500.
    Each row carries its ``scan_name`` and ``has_workflow`` flag.
    """
    from ..models import Scan
    from ..query import FindingQuery, run_finding_query
    from ..workflow_mapper import build_workflow_mapper

    cfg = config or load_config()
    q = FindingQuery(
        scan_ids=scan_ids,
        severity_int=severity_int,
        severity_min=severity_min,
        review_state=review_state,
        verdict=verdict,
        cve=cve,
        port=port,
        service=service,
        host=host,
        plugin_name=plugin_name,
        has_metasploit=has_metasploit,
        has_workflow=has_workflow,
        merged=merged,
        limit=_resolve_limit(limit, cfg),
        offset=offset,
    )
    mapper = build_workflow_mapper(cfg)
    with _db(conn) as c:
        rows = run_finding_query(q, c, workflow_mapper=mapper)
        scan_names = {s["scan_id"]: s["scan_name"] for s in Scan.get_all_with_stats(c)}
        results: list[dict] = []
        for finding, plugin in rows:
            row = _finding_plugin_to_dict(finding, plugin)
            row["scan_name"] = scan_names.get(finding.scan_id)
            row["has_workflow"] = mapper.has_workflow(str(plugin.plugin_id))
            results.append(row)
    return results


def tool_list_workflow_gaps(
    *,
    scan_ids: Optional[list[int]] = None,
    severity_min: Optional[int] = None,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """List findings with NO mapped verification workflow (triage gaps).

    Reuses the composite query layer (``has_workflow=False``) and the workflow
    mapper (bundled + ``custom_workflows_path``); adds no new query logic. Returns one representative row per unmapped
    plugin (merged), worst-first (severity desc, then Metasploit-backed first).
    """
    from ..models import Scan
    from ..query import FindingQuery, run_finding_query
    from ..workflow_mapper import build_workflow_mapper

    q = FindingQuery(
        scan_ids=scan_ids,
        severity_min=severity_min,
        has_workflow=False,  # the gap predicate
        merged=True,  # one representative per unmapped plugin
    )
    mapper = build_workflow_mapper(config)
    with _db(conn) as c:
        rows = run_finding_query(q, c, workflow_mapper=mapper)
        scan_names = {s["scan_id"]: s["scan_name"] for s in Scan.get_all_with_stats(c)}
        results: list[dict] = []
        for finding, plugin in rows:
            row = _finding_plugin_to_dict(finding, plugin)
            row["scan_name"] = scan_names.get(finding.scan_id)
            results.append(row)
    # MSF-backed criticals first: severity desc, then has_metasploit desc.
    results.sort(
        key=lambda r: (r["severity_int"], bool(r["has_metasploit"])), reverse=True
    )
    return results


def tool_top_hosts(
    limit: int = 20, conn: Optional[sqlite3.Connection] = None
) -> list[dict]:
    """Return hosts ordered worst-severity-first for prioritization.

    Sorted by max severity (descending), then finding count (descending),
    sliced to ``limit``. Reuses the cross-scan host inventory.
    """
    from ..models import Host

    with _db(conn) as c:
        hosts = Host.get_all_with_stats(c)
    hosts.sort(
        key=lambda h: (h.get("max_severity") or -1, h.get("finding_count") or 0),
        reverse=True,
    )
    return hosts[:limit] if limit >= 0 else hosts


def tool_get_capabilities(config: Optional[CernoConfig] = None) -> dict:
    """Report which gated capabilities are live, so an agent can self-orient.

    TUI-only config keys (``config.MCP_NOT_APPLICABLE_KEYS``) are intentionally
    not applied by the MCP server and are not reported here.
    """
    from ..nxc_db import get_nxc_manager

    cfg = config or load_config()
    return {
        "execution_enabled": cfg.mcp_allow_execution,
        "mutations_enabled": cfg.mcp_allow_mutations,
        "cred_injection_enabled": cfg.mcp_allow_cred_injection,
        "cred_reveal_enabled": cfg.mcp_allow_cred_reveal,
        # execute_batch is registered only when BOTH flags are on.
        "batch_enabled": bool(cfg.mcp_allow_execution and cfg.mcp_allow_batch),
        "batch_concurrency": cfg.mcp_batch_concurrency,
        "exec_allowlist": list(cfg.mcp_exec_allowlist),
        "exec_denylist": list(cfg.mcp_exec_denylist),
        "nxc_available": get_nxc_manager() is not None,
    }


def tool_get_finding_artifacts(
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> list[dict]:
    """Return artifact files generated by executions attributed to a finding.

    Joins findings -> tool_executions (finding_id) -> artifacts so an agent can
    retrieve the evidence (e.g. nmap output) produced for a specific finding.
    """
    from ..database import query_all

    with _db(conn) as c:
        rows = query_all(
            c,
            """
            SELECT a.artifact_id, a.execution_id, a.artifact_path, a.artifact_type,
                   a.file_extension, a.file_size_bytes, a.file_hash, a.created_at
            FROM v_artifacts_with_types a
            JOIN tool_executions te ON a.execution_id = te.execution_id
            WHERE te.finding_id = ?
            ORDER BY a.created_at DESC
            """,
            (finding_id,),
        )
        return [dict(row) for row in rows]


def tool_get_finding_hosts(
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> dict:
    """Return the host list, port string, and ready-to-use target lines for a finding."""
    from ..models import Finding

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        hosts, ports_str = finding.get_hosts_and_ports(c)
        target_lines = finding.get_all_host_port_lines(c)
    return {
        "finding_id": finding_id,
        "hosts": hosts,
        "ports": ports_str,
        "target_lines": target_lines,
    }


def tool_get_web_targets(
    scan_id: int, conn: Optional[sqlite3.Connection] = None
) -> list[str]:
    """Return HTTP/HTTPS URLs discovered in a scan (ready for web testing)."""
    from ..models import get_http_urls_for_scan

    with _db(conn) as c:
        return get_http_urls_for_scan(scan_id, c)


def tool_host_history(
    host_ip: str, conn: Optional[sqlite3.Connection] = None
) -> Optional[dict]:
    """Return a host's vulnerability timeline across all scans, or None if unknown."""
    from ..cross_scan import get_host_vulnerability_history

    with _db(conn) as c:
        history = get_host_vulnerability_history(host_ip, conn=c)
    return dataclasses.asdict(history) if history is not None else None


def tool_compare_scans(
    scan1_name: str,
    scan2_name: str,
    *,
    min_severity: int = 0,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[dict]:
    """Compare two scans by name; returns new/resolved/persistent findings and hosts."""
    from ..cross_scan import compare_scans, get_scan_by_name

    with _db(conn) as c:
        s1 = get_scan_by_name(scan1_name, conn=c)
        s2 = get_scan_by_name(scan2_name, conn=c)
        if s1 is None:
            raise ValueError(f"Scan not found: {scan1_name}")
        if s2 is None:
            raise ValueError(f"Scan not found: {scan2_name}")
        result = compare_scans(
            scan_id_1=s1["scan_id"],
            scan_id_2=s2["scan_id"],
            min_severity=min_severity,
            conn=c,
        )
    return dataclasses.asdict(result) if result is not None else None


def tool_get_workflow(
    plugin_id: int, config: Optional[CernoConfig] = None
) -> Optional[dict]:
    """Return the verification workflow mapped to a plugin, or None if none exists.

    Looks up bundled workflows supplemented by config ``custom_workflows_path``.
    """
    from ..workflow_mapper import build_workflow_mapper

    workflow = build_workflow_mapper(config).get_workflow(str(plugin_id))
    return dataclasses.asdict(workflow) if workflow is not None else None


def tool_get_finding_detail(
    finding_id: int,
    max_hosts: int = 100,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Return full detail for one finding: plugin metadata + per-host plugin output.

    Note: Cerno does not store Nessus description/solution/synopsis text. The
    authoritative evidence is the per-host ``plugin_output`` plus the CVE list,
    Metasploit module names, and the Tenable ``plugin_url`` for further reading.

    The ``affected`` list is capped at ``max_hosts`` entries to protect the
    caller's context on large scans; ``affected_total`` gives the true count and
    ``affected_truncated`` flags when the list was cut.
    """
    from ..models import Finding, FindingVerdict, Plugin, SeverityLevel

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        plugin = Plugin.get_by_id(finding.plugin_id, c)
        if plugin is None:
            raise ValueError(f"No plugin with id {finding.plugin_id}")
        sev = SeverityLevel.get_by_int(plugin.severity_int, c)
        outputs = finding.get_plugin_outputs_by_host(c)
        current = FindingVerdict.get_current(finding_id, c)
        stats = _finding_verified_stats(finding_id, c)
        suggested = _suggested_verdict(finding_id, c)

    total = len(outputs)
    capped = outputs[:max_hosts] if max_hosts >= 0 else outputs
    return {
        "finding_id": finding_id,
        "scan_id": finding.scan_id,
        "plugin_id": plugin.plugin_id,
        "plugin_name": plugin.plugin_name,
        "severity_int": plugin.severity_int,
        "severity_label": sev.severity_label if sev is not None else None,
        "review_state": finding.review_state,
        "has_metasploit": plugin.has_metasploit,
        "metasploit_names": plugin.metasploit_names or [],
        "cvss3_score": plugin.cvss3_score,
        "cvss2_score": plugin.cvss2_score,
        "cves": plugin.cves or [],
        "plugin_url": plugin.plugin_url,
        "affected": [
            {"host": host, "port": port, "plugin_output": output}
            for host, port, output in capped
        ],
        "affected_total": total,
        "affected_truncated": max_hosts >= 0 and total > max_hosts,
        "verdict": current.verdict_label if current is not None else None,
        "suggested_verdict": suggested,
        "verified_port_count": stats["verified_port_count"],
        "nse_result_count": stats["nse_result_count"],
        "vulnerable_count": stats["vulnerable_count"],
    }


def _finding_verified_stats(finding_id: int, conn: sqlite3.Connection) -> dict:
    """Live-verified fact counts for a finding (from v_finding_verified_stats)."""
    from ..database import query_one

    row = query_one(
        conn,
        "SELECT * FROM v_finding_verified_stats WHERE finding_id = ?",
        (finding_id,),
    )
    if row is None:
        return {"verified_port_count": 0, "nse_result_count": 0, "vulnerable_count": 0}
    return {
        "verified_port_count": row["verified_port_count"],
        "nse_result_count": row["nse_result_count"],
        "vulnerable_count": row["vulnerable_count"],
    }


def _suggested_verdict(finding_id: int, conn: sqlite3.Connection) -> Optional[str]:
    """Non-binding verdict suggestion from NSE evidence (never auto-applied).

    VULNERABLE evidence suggests ``confirmed``; otherwise NOT_VULNERABLE-only
    evidence suggests ``false_positive``. No evidence -> no suggestion.
    """
    from ..database import query_all

    rows = query_all(
        conn,
        """
        SELECT nv.label AS label, COUNT(*) AS n
        FROM nse_script_results nsr
        JOIN tool_executions te ON nsr.execution_id = te.execution_id
        LEFT JOIN nse_verdicts nv ON nsr.nse_verdict_id = nv.nse_verdict_id
        WHERE te.finding_id = ?
        GROUP BY nv.label
        """,
        (finding_id,),
    )
    counts = {r["label"]: r["n"] for r in rows}
    if counts.get("VULNERABLE") or counts.get("LIKELY_VULNERABLE"):
        return "confirmed"
    if counts.get("NOT_VULNERABLE"):
        return "false_positive"
    return None


def _verdict_info(v: Any) -> dict:
    """Serialize a FindingVerdict to a JSON-friendly dict."""
    return {
        "verdict_id": v.verdict_id,
        "finding_id": v.finding_id,
        "verdict": v.verdict_label,
        "note": v.note,
        "created_at": v.created_at,
        "created_by": v.created_by,
    }


def tool_get_finding_verdict(
    finding_id: int,
    conn: Optional[sqlite3.Connection] = None,
    config: Optional[CernoConfig] = None,
) -> dict:
    """Return a finding's current verdict, full history, evidence, and a suggestion.

    The verdict is a verification truth value (confirmed / false_positive /
    unable), distinct from review_state. ``suggested_verdict`` is a non-binding
    hint derived from ingested NSE evidence; it is never applied automatically.
    ``workflow_candidate`` says whether a verified (confirmed / false_positive)
    finding's execution trail yields a new or enhanced workflow worth
    contributing (see get_workflow_candidate).
    """
    from ..models import Finding, FindingVerdict, VerdictEvidence

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        current = FindingVerdict.get_current(finding_id, c)
        history = FindingVerdict.get_history(finding_id, c)
        suggested = _suggested_verdict(finding_id, c)
        evidence: list[dict] = []
        for v in history:
            if v.verdict_id is None:
                continue
            for ev in VerdictEvidence.get_by_verdict(v.verdict_id, c):
                evidence.append(
                    {
                        "evidence_id": ev.evidence_id,
                        "verdict_id": ev.verdict_id,
                        "execution_id": ev.execution_id,
                        "artifact_id": ev.artifact_id,
                        "nse_result_id": ev.nse_result_id,
                        "note": ev.note,
                    }
                )
        hint = _workflow_candidate_hint(
            finding, current.verdict_label if current is not None else None, c, config
        )

    return {
        "finding_id": finding_id,
        "current": _verdict_info(current) if current is not None else None,
        "suggested_verdict": suggested,
        "history": [_verdict_info(v) for v in history],
        "evidence": evidence,
        "workflow_candidate": hint,
    }


# ---------------------------------------------------------------------------
# Workflow contribution feedback loop (draft -> review -> local export)
# ---------------------------------------------------------------------------


def _nxc_leak_material(
    config: CernoConfig,
) -> tuple[list[str], list[str], list[str]]:
    """NetExec ``(usernames, domains, secrets)`` for the contribution leak scan.

    Best effort: any failure (no workspace, enrichment disabled) yields empty
    lists. Secret values are resolved server-side only so the scan can refuse an
    export that contains one; they are compared in memory and never logged,
    returned or audited as a reveal.
    """
    usernames: list[str] = []
    domains: list[str] = []
    secrets: list[str] = []
    if not config.nxc_enrichment_enabled:
        return usernames, domains, secrets
    try:
        from ..nxc_db import list_credential_refs, resolve_credential_secret

        refs = list_credential_refs()
    except Exception as exc:  # enrichment is optional
        log_debug(f"workflow contrib: nxc identifiers unavailable: {exc}")
        return usernames, domains, secrets
    for ref in refs:
        if ref.username:
            usernames.append(ref.username)
        if ref.domain:
            domains.append(ref.domain)
        if not ref.secret_kind:
            continue
        try:
            resolved = resolve_credential_secret(ref.ref)
        except Exception:  # skip this ref; never log the value or the error text
            log_debug(f"workflow contrib: secret for {ref.ref} unavailable")
            continue
        if resolved is not None and resolved.secret_value:
            secrets.append(resolved.secret_value)
    return usernames, domains, secrets


def _contribution_assessment(
    finding: Any, conn: sqlite3.Connection, config: CernoConfig
) -> tuple[Any, Any, Any]:
    """Return ``(assessment, leak_context, mapper)`` for a finding."""
    from ..workflow_contrib import assess_candidate, build_leak_context
    from ..workflow_mapper import build_workflow_mapper

    mapper = build_workflow_mapper(config)
    usernames, domains, secrets = _nxc_leak_material(config)
    ctx = build_leak_context(
        finding, conn, extra=domains, usernames=usernames, secrets=secrets
    )
    return assess_candidate(finding, conn, mapper, ctx), ctx, mapper


def _workflow_candidate_hint(
    finding: Any,
    verdict: Optional[str],
    conn: sqlite3.Connection,
    config: Optional[CernoConfig],
) -> dict:
    """``{available, reason}`` for a verified finding; never raises.

    Drafting is best-effort: an error is logged and reported as unavailable so it
    can never break verdict reads/writes.
    """
    from ..workflow_contrib import CONTRIBUTABLE_VERDICTS

    unavailable = {"available": False, "reason": None}
    if verdict not in CONTRIBUTABLE_VERDICTS:
        return unavailable
    try:
        assessment, _, _ = _contribution_assessment(
            finding, conn, config or load_config()
        )
    except Exception as exc:
        log_error(
            f"workflow contrib: drafting failed for finding {finding.finding_id}: {exc}"
        )
        return unavailable
    candidate = assessment.candidate
    if candidate is None:
        return unavailable
    return {"available": True, "reason": candidate.reason}


def tool_get_workflow_candidate(
    finding_id: int,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Draft (regenerate) a workflow candidate from a finding's execution trail.

    Read-only. ``reason`` is "new" (plugin unmapped) or "enhanced" (non-baseline
    commands absent from the mapped workflow); ``available`` is False when there
    is nothing to contribute. ``workflow`` is the sanitized entry to review/edit;
    ``leak_warnings`` must be empty and the verdict confirmed/false_positive for
    ``exportable``. ``excluded`` lists runs dropped because they still held
    engagement data after sanitizing.
    """
    from ..models import Finding, FindingVerdict
    from ..workflow_contrib import CONTRIBUTABLE_VERDICTS, scan_candidate

    cfg = config or load_config()
    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        assessment, ctx, _ = _contribution_assessment(finding, c, cfg)
        current = FindingVerdict.get_current(finding_id, c)

    verdict = current.verdict_label if current is not None else None
    candidate = assessment.candidate
    leaks = scan_candidate(candidate, ctx) if candidate is not None else []
    return {
        "finding_id": finding_id,
        "plugin_id": finding.plugin_id,
        "available": candidate is not None,
        "reason": candidate.reason if candidate is not None else None,
        "verdict": verdict,
        "exportable": candidate is not None
        and verdict in CONTRIBUTABLE_VERDICTS
        and not leaks,
        "workflow": candidate.to_entry() if candidate is not None else None,
        "new_commands": list(candidate.new_commands) if candidate else [],
        "possibly_superseded": list(candidate.possibly_superseded) if candidate else [],
        "review_hints": list(candidate.review_hints) if candidate else [],
        "leak_warnings": leaks,
        "excluded": list(assessment.excluded),
    }


def _contribution_dir(config: CernoConfig) -> Path:
    """Export directory: ``contribution_export_dir`` or ``<results_root>/contributions``."""
    from ..constants import get_results_root

    if config.contribution_export_dir:
        return Path(config.contribution_export_dir).expanduser()
    return get_results_root(config) / "contributions"


def tool_export_workflow_contribution(
    finding_id: int,
    workflow: Optional[dict] = None,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Write a sanitized, PR-ready workflow YAML file for a verified finding.

    Local file only: no DB mutation, nothing sent anywhere. Uses the regenerated
    draft, or ``workflow`` (an edited entry: workflow_name, description, steps
    [{title, commands, notes}], references; plugin_id is always the finding's).
    Refuses unless the current verdict is confirmed/false_positive, and refuses
    (writing nothing) when the fail-closed leak scan finds any engagement data.
    """
    import contextlib
    import sys
    from datetime import datetime

    from ..models import Finding, FindingVerdict
    from ..workflow_contrib import (
        CONTRIBUTABLE_VERDICTS,
        SUBMISSION_INSTRUCTIONS,
        candidate_from_override,
        scan_candidate,
        to_yaml_fragment,
    )
    from ..workflow_mapper import WorkflowMapper

    cfg = config or load_config()
    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        current = FindingVerdict.get_current(finding_id, c)
        verdict = current.verdict_label if current is not None else None
        if verdict not in CONTRIBUTABLE_VERDICTS:
            raise ValueError(
                f"Finding {finding_id} has no confirmed/false_positive verdict "
                f"(current: {verdict}); only verified findings can be contributed. "
                "Record one with set_finding_verdict first."
            )
        assessment, ctx, mapper = _contribution_assessment(finding, c, cfg)
        if workflow is not None:
            candidate = candidate_from_override(
                finding, workflow, assessment.candidate, c, mapper
            )
        elif assessment.candidate is not None:
            candidate = assessment.candidate
        else:
            raise ValueError(
                f"No workflow candidate for finding {finding_id}: the mapped workflow "
                "already covers what was run (or no attributed successful runs exist). "
                "Pass an edited `workflow` to contribute one manually."
            )

    hits = scan_candidate(candidate, ctx)
    if hits:
        raise ValueError(
            "Refusing to export: leak scan found engagement data — "
            + "; ".join(hits)
            + ". No file was written."
        )

    text = to_yaml_fragment(candidate)
    out_dir = _contribution_dir(cfg)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{finding.plugin_id}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    path: Optional[Path] = None
    for n in range(100):
        attempt = out_dir / (f"{stem}.yaml" if n == 0 else f"{stem}-{n}.yaml")
        try:
            with open(attempt, "x", encoding="utf-8") as fh:  # never overwrite
                fh.write(text)
        except FileExistsError:
            continue
        path = attempt
        break
    if path is None:
        raise ValueError(f"Could not allocate a unique export file in {out_dir}")

    # Sanity check: the file must load as a workflow file mapping this plugin.
    with contextlib.redirect_stdout(sys.stderr):
        loaded = WorkflowMapper(yaml_path=path).get_workflow(str(finding.plugin_id))
    if loaded is None:
        path.unlink(missing_ok=True)
        raise ValueError("Exported YAML failed to re-load as a workflow; nothing kept.")

    return {
        "path": str(path),
        "reason": candidate.reason,
        "plugin_id": finding.plugin_id,
        "submission_instructions": SUBMISSION_INSTRUCTIONS,
    }


def tool_list_hosts(
    scan_id: Optional[int] = None, conn: Optional[sqlite3.Connection] = None
) -> list[dict]:
    """List hosts with finding counts and worst severity.

    With no ``scan_id``, returns the cross-scan host inventory. With a
    ``scan_id``, returns only hosts affected by findings in that scan.
    """
    from ..database import query_all
    from ..models import Host

    with _db(conn) as c:
        if scan_id is None:
            return Host.get_all_with_stats(c)
        rows = query_all(
            c,
            """
            SELECT
                h.host_id, h.ip_address, h.scan_target, h.scan_target_type,
                h.netbios_name, h.fqdn,
                COUNT(DISTINCT fah.finding_id) AS finding_count,
                MAX(p.severity_int) AS max_severity
            FROM hosts h
            JOIN finding_affected_hosts fah ON h.host_id = fah.host_id
            JOIN findings f ON fah.finding_id = f.finding_id
            JOIN plugins p ON f.plugin_id = p.plugin_id
            WHERE f.scan_id = ?
            GROUP BY h.host_id
            ORDER BY finding_count DESC
            """,
            (scan_id,),
        )
        return [dict(row) for row in rows]


def tool_check_tools() -> dict:
    """Report which security tools are installed and their detected versions."""
    from ..ops import get_tool_version, resolve_cmd

    specs = {
        "nmap": ["nmap"],
        "netexec": ["nxc", "netexec"],
        "msfconsole": ["msfconsole"],
        "proxychains4": ["proxychains4"],
    }
    result: dict[str, dict] = {}
    for name, candidates in specs.items():
        # Install status is PATH presence (matches the TUI); version is best-effort.
        installed = resolve_cmd(candidates) is not None
        version = get_tool_version(name, candidates)
        result[name] = {"installed": installed, "version": version}
    return result


def tool_list_executions(
    limit: int = 50, conn: Optional[sqlite3.Connection] = None
) -> list[dict]:
    """List recent tool executions (command, exit code, duration), newest first."""
    from ..database import query_all

    with _db(conn) as c:
        rows = query_all(
            c,
            """
            SELECT execution_id, tool_name, tool_protocol, command_text,
                   executed_at, exit_code, duration_seconds, host_count,
                   ports, used_sudo
            FROM tool_executions
            ORDER BY executed_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in rows]


def tool_list_artifacts(
    execution_id: Optional[int] = None,
    limit: int = 50,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """List generated artifact files, optionally scoped to one execution."""
    from ..database import query_all

    with _db(conn) as c:
        if execution_id is not None:
            rows = query_all(
                c,
                """
                SELECT artifact_id, execution_id, artifact_path, artifact_type,
                       file_extension, file_size_bytes, file_hash, created_at
                FROM v_artifacts_with_types
                WHERE execution_id = ?
                ORDER BY created_at DESC
                """,
                (execution_id,),
            )
        else:
            rows = query_all(
                c,
                """
                SELECT artifact_id, execution_id, artifact_path, artifact_type,
                       file_extension, file_size_bytes, file_hash, created_at
                FROM v_artifacts_with_types
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
        return [dict(row) for row in rows]


def tool_list_cves(
    scan_ids: list[int],
    *,
    severity_int: Optional[int] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """List unique CVEs across one or more scans, each mapped to its plugins.

    Uses the CVEs already cached in ``plugins.cves`` (no network calls). Useful
    for building an exploitation plan from a scan's findings.
    """
    import json as _json

    from ..database import query_all

    cve_map: dict[str, list[dict]] = {}
    with _db(conn) as c:
        for scan_id in scan_ids:
            params: list[Any] = [scan_id]
            query = """
                SELECT p.plugin_id, p.plugin_name, p.severity_int, p.cves
                FROM findings f
                JOIN plugins p ON f.plugin_id = p.plugin_id
                WHERE f.scan_id = ? AND p.cves IS NOT NULL
            """
            if severity_int is not None:
                query += " AND p.severity_int = ?"
                params.append(severity_int)
            for row in query_all(c, query, tuple(params)):
                try:
                    cves = _json.loads(row["cves"]) or []
                except (ValueError, TypeError):
                    continue
                for cve in cves:
                    entry = {
                        "plugin_id": row["plugin_id"],
                        "plugin_name": row["plugin_name"],
                        "severity_int": row["severity_int"],
                    }
                    bucket = cve_map.setdefault(cve, [])
                    if entry not in bucket:
                        bucket.append(entry)

    return [
        {"cve": cve, "plugins": plugins} for cve, plugins in sorted(cve_map.items())
    ]


def tool_list_services(
    scan_id: int, conn: Optional[sqlite3.Connection] = None
) -> list[dict]:
    """List discovered host/port/protocol/service-name tuples for a scan."""
    from ..database import query_all

    with _db(conn) as c:
        rows = query_all(
            c,
            """
            SELECT h.scan_target AS host, hs.port_number AS port,
                   hs.protocol, hs.svc_name
            FROM host_services hs
            JOIN hosts h ON hs.host_id = h.host_id
            WHERE hs.scan_id = ?
            ORDER BY h.scan_target, hs.port_number
            """,
            (scan_id,),
        )
        return [dict(row) for row in rows]


def tool_find_affected_by_cve(
    cve: str,
    scan_ids: Optional[list[int]] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """Find findings/hosts affected by a specific CVE, across scans.

    The reverse of ``list_cves``: given a CVE, return every plugin whose cached
    ``cves`` list contains it (exact element match, case-insensitive) plus the
    scan and affected host:port lines. Optional ``scan_ids`` narrows the search.
    """
    from ..database import query_all
    from ..models import Finding

    target = cve.strip().lower()
    results: list[dict] = []
    with _db(conn) as c:
        rows = query_all(
            c,
            """
            SELECT f.finding_id, f.scan_id, p.plugin_id, p.plugin_name,
                   p.severity_int, p.cves
            FROM findings f
            JOIN plugins p ON f.plugin_id = p.plugin_id
            WHERE p.cves IS NOT NULL
            """,
        )
        for row in rows:
            if scan_ids is not None and row["scan_id"] not in scan_ids:
                continue
            try:
                cves = json.loads(row["cves"]) or []
            except (ValueError, TypeError):
                continue
            if not any(str(x).strip().lower() == target for x in cves):
                continue
            finding = Finding(
                finding_id=row["finding_id"],
                scan_id=row["scan_id"],
                plugin_id=row["plugin_id"],
            )
            hosts = finding.get_all_host_port_lines(c)
            results.append(
                {
                    "finding_id": row["finding_id"],
                    "scan_id": row["scan_id"],
                    "plugin_id": row["plugin_id"],
                    "plugin_name": row["plugin_name"],
                    "severity_int": row["severity_int"],
                    "hosts": hosts,
                }
            )
    return results


def tool_read_artifact(
    artifact_id: int,
    max_bytes: int = 100_000,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Read the contents of a generated artifact file by its id.

    Only reads paths recorded in the artifacts table (never arbitrary paths).
    Text is capped at ``max_bytes`` with a ``truncated`` flag.
    """
    from ..database import query_one

    with _db(conn) as c:
        row = query_one(
            c,
            """
            SELECT artifact_id, artifact_path, artifact_type, file_size_bytes
            FROM v_artifacts_with_types
            WHERE artifact_id = ?
            """,
            (artifact_id,),
        )
    if row is None:
        raise ValueError(f"No artifact with id {artifact_id}")

    path = Path(row["artifact_path"])
    meta = {
        "artifact_id": row["artifact_id"],
        "artifact_path": str(path),
        "artifact_type": row["artifact_type"],
        "file_size_bytes": row["file_size_bytes"],
    }
    if not path.exists():
        return {**meta, "exists": False, "content": None, "truncated": False}

    raw = path.read_bytes()
    truncated = len(raw) > max_bytes
    text = raw[:max_bytes].decode("utf-8", errors="replace")
    return {**meta, "exists": True, "content": text, "truncated": truncated}


def tool_get_config() -> dict:
    """Return all current Cerno config settings (read-only), with resolved paths.

    Every key is returned, including the TUI-only ones in
    ``config.MCP_NOT_APPLICABLE_KEYS`` that the MCP server intentionally ignores.
    """
    from ..constants import get_results_root

    config = load_config()
    data = dataclasses.asdict(config)
    data["results_root_resolved"] = str(get_results_root(config))
    data["log_path_resolved"] = config.log_path or str(
        Path.home() / ".cerno" / "cerno.log"
    )
    return data


# ========== NetExec enrichment (read-only; needs a configured workspace) ==========
# Availability follows nxc_db.get_nxc_manager(), which already honors the
# nxc_enrichment_enabled flag and workspace existence. When no workspace is
# available the tools return {"available": False, ...} rather than erroring.


def tool_get_host_nxc(host_ip: str) -> dict:
    """Return NetExec enrichment for one host: credentials, shares, security flags."""
    from ..nxc_db import get_nxc_manager

    mgr = get_nxc_manager()
    if mgr is None:
        return {
            "available": False,
            "reason": "No NetExec workspace configured/available "
            "(see nxc_workspace_path / nxc_enrichment_enabled).",
            "host": host_ip,
        }
    data = mgr.get_host_enrichment(host_ip)
    if data is None:
        return {"available": True, "host": host_ip, "found": False}
    return {"available": True, "found": True, **dataclasses.asdict(data)}


def tool_list_nxc_credentials(
    host_ips: Optional[list[str]] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Return deduplicated NetExec credentials. Defaults to all known hosts."""
    from ..models import Host
    from ..nxc_db import get_nxc_manager

    mgr = get_nxc_manager()
    if mgr is None:
        return {
            "available": False,
            "reason": "No NetExec workspace configured/available.",
            "credentials": [],
        }
    if host_ips is None:
        with _db(conn) as c:
            host_ips = [h["ip_address"] for h in Host.get_all_with_stats(c)]
    summary = mgr.get_hosts_enrichment(host_ips)
    # Attach a non-secret credential ref + secret_kind by matching on
    # (protocol, username, domain). The secret value itself is never included.
    ref_index = {
        (r.protocol, r.username, r.domain or ""): r for r in mgr.list_credential_refs()
    }
    credentials = []
    for cred, count in summary.unique_credentials:
        entry = {**dataclasses.asdict(cred), "host_count": count}
        match = ref_index.get((cred.protocol, cred.username, cred.domain or ""))
        entry["ref"] = match.ref if match else None
        entry["secret_kind"] = match.secret_kind if match else None
        credentials.append(entry)
    return {
        "available": True,
        "hosts_queried": summary.total_hosts_queried,
        "hosts_with_data": summary.hosts_with_data,
        "protocols_seen": summary.protocols_seen,
        "security_flag_counts": summary.security_flag_counts,
        "credentials": credentials,
    }


# ========== Command generation ==========


def _targets_dir(finding_id: int, config: Optional[CernoConfig]) -> Path:
    """Fresh, unique per-call run directory for a finding's target/output files.

    Each call creates a new ``_mcp/<finding_id>/run-XXXXXX/`` directory so that
    successive ``generate_*`` calls (and the runs built from them) never share an
    output base and cannot clobber each other on disk.
    """
    from ..constants import get_results_root

    parent = get_results_root(config) / "_mcp" / str(finding_id)
    parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="run-", dir=parent))


def _write_targets_file(
    finding_id: int, hosts: list[str], config: Optional[CernoConfig]
) -> tuple[Path, Path]:
    """Write a finding's hosts to an IPs file; return (ips_file, output_base)."""
    d = _targets_dir(finding_id, config)
    ips_file = d / "targets.txt"
    ips_file.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    return ips_file, d / "scan"


def tool_generate_nmap_cmd(
    finding_id: int,
    *,
    udp: Optional[bool] = None,
    nse_option: Optional[str] = None,
    use_sudo: bool = False,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Build (but do not run) an nmap command targeting a finding's hosts/ports.

    ``nse_option`` None falls back to the config ``nmap_default_profile`` (an
    ``NSE_PROFILES`` name, matched case-insensitively; unknown = no scripts);
    ``""`` explicitly means no scripts. ``udp`` None means the applied profile's
    UDP requirement (SNMP/IPMI), else False; an explicit value always wins.
    """
    from ..models import Finding
    from ..tools import build_nmap_cmd, find_nse_profile

    profile_udp = False
    if nse_option is None:
        cfg = config or load_config()
        profile = find_nse_profile(cfg.nmap_default_profile)
        if profile is not None:
            scripts, profile_udp = profile
            nse_option = ",".join(scripts)
        elif cfg.nmap_default_profile:
            log_debug(
                f"mcp: unknown nmap_default_profile {cfg.nmap_default_profile!r}; "
                "no NSE scripts applied"
            )
    if udp is None:
        udp = profile_udp

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        hosts, ports_str = finding.get_hosts_and_ports(c)

    ips_file, output_base = _write_targets_file(finding_id, hosts, config)
    cmd = build_nmap_cmd(udp, nse_option, ips_file, ports_str, use_sudo, output_base)
    return {"command": cmd, "ips_file": str(ips_file), "output_base": str(output_base)}


def _resolve_credential_ref(use_credential: Optional[str]) -> Optional[dict]:
    """Resolve a credential ref to a non-secret spec, or None when ref is falsy.

    Returns ``{username, domain, secret_kind, ref}`` (never a secret). Raises
    ValueError if the ref is unknown or lacks a usable password/hash. Shared by
    ``generate_netexec_cmd`` and ``prepare_workflow`` so credential handling and
    its error messages never drift.
    """
    if not use_credential:
        return None
    from ..nxc_db import get_nxc_manager

    mgr = get_nxc_manager()
    ref_obj = None
    if mgr is not None:
        ref_obj = next(
            (r for r in mgr.list_credential_refs() if r.ref == use_credential),
            None,
        )
    if ref_obj is None:
        raise ValueError(f"Unknown credential ref {use_credential!r}")
    if ref_obj.secret_kind not in ("password", "hash"):
        raise ValueError(
            f"Credential {use_credential!r} has no usable secret (password/hash)"
        )
    return {
        "username": ref_obj.username,
        "domain": ref_obj.domain,
        "secret_kind": ref_obj.secret_kind,
        "ref": ref_obj.ref,
    }


def tool_generate_netexec_cmd(
    finding_id: int,
    protocol: Optional[str] = None,
    *,
    use_credential: Optional[str] = None,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Build (but do not run) a netexec command targeting a finding's hosts.

    ``protocol`` is case-insensitive and normalized to lowercase; it must be one
    of ``constants.NETEXEC_PROTOCOLS`` (the source of truth), else ValueError.
    When omitted it falls back to the config ``default_netexec_protocol``, then
    ``"smb"`` (as the TUI's protocol prompt does).

    ``use_credential`` is a credential ``ref`` from ``list_nxc_credentials``. When
    given, auth flags are injected using a ``@cred:<ref>@`` PLACEHOLDER — the real
    secret is resolved server-side only at execution time, never placed in the
    returned command. The ref must exist and have a usable secret, else ValueError.
    """
    from ..constants import NETEXEC_PROTOCOLS
    from ..models import Finding
    from ..ops import resolve_cmd
    from ..tools import build_netexec_cmd

    source = ""
    if not protocol:
        cfg = config or load_config()
        if cfg.default_netexec_protocol:
            protocol = cfg.default_netexec_protocol
            source = " (from config default_netexec_protocol)"
        else:
            protocol = "smb"
    proto = protocol.strip().lower()
    if proto not in NETEXEC_PROTOCOLS:
        raise ValueError(
            f"Unknown netexec protocol {protocol!r}{source}; valid protocols: "
            f"{', '.join(NETEXEC_PROTOCOLS)}"
        )

    credential = _resolve_credential_ref(use_credential)

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        hosts, _ = finding.get_hosts_and_ports(c)

    exec_bin = resolve_cmd(["nxc", "netexec"]) or "nxc"
    ips_file, output_base = _write_targets_file(finding_id, hosts, config)
    cmd, log_path, relay_path = build_netexec_cmd(
        exec_bin, proto, ips_file, output_base, credential=credential
    )
    return {
        "command": cmd,
        "ips_file": str(ips_file),
        "log_path": log_path,
        "relay_path": relay_path,
    }


def tool_generate_msf_search(
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> dict:
    """Build an msfconsole search command for a finding's Metasploit modules.

    Uses the plugin's cached Metasploit module names when available, otherwise
    falls back to searching on the plugin name. Returns the command without
    running it.
    """
    from ..models import Finding, Plugin
    from ..tools import _build_msfconsole_commands

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        plugin = Plugin.get_by_id(finding.plugin_id, c)
        if plugin is None:
            raise ValueError(f"No plugin with id {finding.plugin_id}")

    names = plugin.metasploit_names or []
    term = names[0] if names else plugin.plugin_name
    commands = _build_msfconsole_commands(term)
    return {
        "command": commands[0] if commands else None,
        "search_term": term,
        "has_metasploit": plugin.has_metasploit,
        "metasploit_names": names,
    }


def tool_prepare_workflow(
    finding_id: int,
    *,
    use_credential: Optional[str] = None,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[dict]:
    """Fill the verification workflow mapped to a finding's plugin, marking each
    filled command executable-via-execute_command or manual-only.

    Placeholders (<TARGET>/<PORT>/<USERNAME>/<PASSWORD>/<INTERFACE>, plus
    historical variants) are filled from the finding's real hosts/ports. When
    ``use_credential`` (a ref from ``list_nxc_credentials``) is given, <USERNAME>
    is filled and <PASSWORD> becomes a ``@cred:<ref>@`` placeholder (resolved
    server-side only at run time, never a real secret here). Each command reports
    ``executable`` + ``manual_reason`` (allowlist/denylist + installed check), so
    non-cerno-runnable steps (responder, ssh-audit, uninstalled tools, prose) are
    clearly flagged. Returns None if no workflow is mapped to the plugin.
    """
    from ..workflow_prep import prepare_workflow

    cfg = config or load_config()
    credential = _resolve_credential_ref(use_credential)
    with _db(conn) as c:
        prepared = prepare_workflow(
            finding_id, credential=credential, config=cfg, conn=c
        )
    return dataclasses.asdict(prepared) if prepared is not None else None


def _batch_query(
    *,
    scan_ids: Optional[list[int]],
    severity_int: Optional[int],
    severity_min: Optional[int],
    review_state: Optional[str],
    verdict: Optional[str],
    cve: Optional[str],
    port: Optional[int],
    service: Optional[str],
    host: Optional[str],
    plugin_name: Optional[str],
    has_metasploit: Optional[bool],
    has_workflow: Optional[bool],
    limit: int,
) -> Any:
    """Build a FindingQuery for a batch from the MCP predicate kwargs."""
    from ..query import FindingQuery

    return FindingQuery(
        scan_ids=scan_ids,
        severity_int=severity_int,
        severity_min=severity_min,
        review_state=review_state,
        verdict=verdict,
        cve=cve,
        port=port,
        service=service,
        host=host,
        plugin_name=plugin_name,
        has_metasploit=has_metasploit,
        has_workflow=has_workflow,
        limit=limit,
    )


def tool_plan_batch(
    strategy: str,
    *,
    scan_ids: Optional[list[int]] = None,
    severity_int: Optional[int] = None,
    severity_min: Optional[int] = None,
    review_state: Optional[str] = None,
    verdict: Optional[str] = None,
    cve: Optional[str] = None,
    port: Optional[int] = None,
    service: Optional[str] = None,
    host: Optional[str] = None,
    plugin_name: Optional[str] = None,
    has_metasploit: Optional[bool] = None,
    has_workflow: Optional[bool] = None,
    limit: int = 500,
    use_credential: Optional[str] = None,
    skip_done: bool = True,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Build a reviewable batch plan (read-only dry run) over a finding query.

    For each matched finding, generates the command for ``strategy`` ("nmap",
    "netexec:<proto>", "msf", "workflow"; bare "netexec" uses the config
    ``default_netexec_protocol``, else smb) and classifies it executable vs manual.
    Already-resolved findings (done, or confirmed/false_positive verdict) are
    skipped when ``skip_done``. Nothing is executed.
    """
    from ..batch import plan_batch

    q = _batch_query(
        scan_ids=scan_ids,
        severity_int=severity_int,
        severity_min=severity_min,
        review_state=review_state,
        verdict=verdict,
        cve=cve,
        port=port,
        service=service,
        host=host,
        plugin_name=plugin_name,
        has_metasploit=has_metasploit,
        has_workflow=has_workflow,
        limit=limit,
    )
    with _db(conn) as c:
        return plan_batch(
            q,
            strategy,
            use_credential=use_credential,
            skip_done=skip_done,
            config=config,
            conn=c,
        ).as_dict()


# ========== Execution (gated by mcp_allow_execution) ==========


#: Hard ceiling on execute_command timeouts (seconds).
_MAX_EXEC_TIMEOUT = 3600


# Command → target-binary resolution lives in the shared ``exec_chain`` module so
# the exec policy here, ingestion dispatch, and auth-flag masking never drift.
# ``_command_chain``/``_EXEC_WRAPPERS`` are kept as aliases for existing callers.
_command_chain = command_chain
_EXEC_WRAPPERS = EXEC_WRAPPERS


# Shared with workflow_prep/batch via exec_chain so allow/deny glob matching
# cannot drift between the execute_command policy and the eligibility checks.
_matches_any = matches_any


def _check_exec_policy(
    command: Sequence[Any], allowlist: Sequence[str], denylist: Sequence[str]
) -> str:
    """Enforce the execute_command allow/deny policy; return the target binary.

    Every binary in the (unwrapped) chain is checked against the denylist, which
    always wins. The target must then match the allowlist; wrappers need no
    allowlist entry. An empty allowlist denies everything.
    """
    chain = _command_chain(command)
    for name in chain:
        if _matches_any(name, denylist):
            raise ValueError(
                f"Binary {name!r} is in the execute_command denylist "
                f"{sorted(denylist)}. Adjust with "
                "'cerno config set mcp_exec_denylist ...' then reconnect."
            )
    target = chain[-1]
    if not allowlist:
        raise ValueError(
            "The execute_command allowlist is empty, so all commands are denied. "
            "Set it with 'cerno config set mcp_exec_allowlist \"nmap,nxc\"' "
            '(or "*") then reconnect.'
        )
    if not _matches_any(target, allowlist):
        raise ValueError(
            f"Binary {target!r} is not in the execute_command allowlist "
            f"{sorted(allowlist)}. Adjust with "
            "'cerno config set mcp_exec_allowlist ...' then reconnect."
        )
    return target


def _flag_value(command: Sequence[Any], flag: str) -> Optional[str]:
    """Return the token following ``flag`` in ``command``, or None."""
    argv = [str(x) for x in command]
    for i, tok in enumerate(argv):
        if tok == flag and i + 1 < len(argv):
            return argv[i + 1]
    return None


def _parse_nmap_output(
    command: Sequence[Any],
) -> tuple[Optional[Path], Optional[int], Optional[str]]:
    """Extract nmap output metadata from an argv list.

    Returns ``(oabase, host_count, ports)``. ``oabase`` is the ``-oA`` base path
    (the signal that this is an nmap run whose outputs should be registered);
    ``host_count`` is the non-empty line count of the ``-iL`` targets file when
    readable; ``ports`` is the ``-p`` value. All are None when absent.
    """
    oa = _flag_value(command, "-oA")
    if oa is None:
        return None, None, None

    host_count: Optional[int] = None
    ips = _flag_value(command, "-iL")
    if ips:
        try:
            with open(ips, encoding="utf-8") as fh:
                host_count = sum(1 for line in fh if line.strip())
        except OSError:
            host_count = None

    return Path(oa), host_count, _flag_value(command, "-p")


def _parse_log_flag(command: Sequence[Any]) -> Optional[str]:
    """Return the ``--log <path>`` value from an argv list (e.g. netexec), or None."""
    return _flag_value(command, "--log")


#: Matches a credential placeholder token ``@cred:<ref>@`` emitted by generation.
_CRED_PLACEHOLDER_RE = re.compile(r"@cred:([^@]+)@")

_SECRET_MASK = "********"


def _has_cred_placeholder(command: Sequence[Any]) -> bool:
    return any(_CRED_PLACEHOLDER_RE.search(str(arg)) for arg in command)


def _resolve_cred_placeholders(command: Sequence[Any]) -> tuple[list[str], list[str]]:
    """Substitute ``@cred:<ref>@`` tokens with real secrets, server-side.

    Returns ``(resolved_argv, secret_values)``. ``resolved_argv`` is for
    ``subprocess`` only; ``secret_values`` are collected so they can be scrubbed
    from any logged/returned output. Raises ValueError if a ref cannot be
    resolved to a usable secret.
    """
    from ..nxc_db import resolve_credential_secret

    resolved: list[str] = []
    secrets: list[str] = []
    for arg in command:
        text = str(arg)
        match = _CRED_PLACEHOLDER_RE.fullmatch(text)
        if match is None:
            resolved.append(text)
            continue
        ref = match.group(1)
        secret = resolve_credential_secret(ref)
        if secret is None:
            raise ValueError(f"Could not resolve credential {ref!r} to a usable secret")
        resolved.append(secret.secret_value)
        secrets.append(secret.secret_value)
    return resolved, secrets


def _mask_command_text(command: Sequence[Any]) -> str:
    """Build a loggable command string with only the @cred:<ref>@ placeholder masked.

    The real secret is never present in the pre-resolution command (generation
    emits a placeholder, resolution happens later for subprocess only), so masking
    the placeholder is sufficient and correct. Flag-value masking is deliberately
    NOT done here: ``-p`` is nxc's password flag but also nmap's ports flag, and
    blanket masking corrupted ``nmap -p 445``. Belt-and-suspenders masking of a
    literal secret is applied downstream in ``ops`` scoped to nxc/netexec only.
    """
    return " ".join(_CRED_PLACEHOLDER_RE.sub(_SECRET_MASK, str(arg)) for arg in command)


def _scrub_secrets(text: str, secrets: Sequence[str]) -> str:
    """Replace any occurrence of a resolved secret in text with the mask."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, _SECRET_MASK)
    return text


def _scrub_file_secrets(path: Path, secrets: Sequence[str]) -> bool:
    """Rewrite ``path`` in place with every resolved secret masked.

    A cred-injected tool (e.g. nxc with ``--log``) writes its own argv — including
    the resolved ``-H <hash>`` — to its output file, which Cerno registers as an
    artifact. This masks those before registration so the persisted file (and its
    stored hash/size) never carries the cleartext secret. Fail-closed: returns
    False on any error so the caller skips registering a file it couldn't scrub (a
    missing artifact beats a leaked one).
    """
    if not secrets:
        return True
    try:
        original = path.read_text(errors="surrogateescape")
        scrubbed = _scrub_secrets(original, secrets)
        if scrubbed != original:
            path.write_text(scrubbed, errors="surrogateescape")
        return True
    except OSError as exc:
        log_error(f"failed to scrub secrets from {path}: {exc}")
        return False


# A runner executes the resolved argv and returns (ExecutionMetadata, stdout,
# stderr). The sync path uses ops.run_command_captured; the async job path
# injects a cancellable spawn+communicate runner (see mcp_server/jobs.py), so
# both share the identical policy / cred-masking / logging / ingest body below.
_Runner = Callable[[list, int, "Optional[Any]"], "tuple[Any, str, str]"]


def _default_runner(
    run_command: list, timeout: int, proxy: Any
) -> tuple[Any, str, str]:
    from ..ops import run_command_captured

    return run_command_captured(run_command, timeout=timeout, proxy_config=proxy)


def _preflight_exec(command: list[str], config: Optional[CernoConfig]) -> None:
    """Validate a command before launching an async job (fail fast at start).

    Runs the same empty-command check, allow/deny policy, and cred-injection gate
    that ``_run_and_record`` enforces, so ``start_execution`` rejects a bad command
    immediately rather than reporting it only once the job has been scheduled.
    """
    if not command:
        raise ValueError("command must be a non-empty list of arguments")
    cfg = config or load_config()
    _check_exec_policy(command, cfg.mcp_exec_allowlist, cfg.mcp_exec_denylist)
    if _has_cred_placeholder(command) and not cfg.mcp_allow_cred_injection:
        raise ValueError(
            "command contains a @cred:...@ placeholder but credential injection "
            "is disabled; set mcp_allow_cred_injection to allow it."
        )


def _run_and_record(
    command: list[str],
    *,
    tool_name: str,
    use_proxy: bool,
    timeout: int,
    finding_id: Optional[int],
    config: Optional[CernoConfig],
    conn: Optional[sqlite3.Connection],
    runner: _Runner,
) -> dict:
    """Policy-check, run (via ``runner``), log, register artifacts, and auto-ingest.

    The single shared implementation behind synchronous ``execute_command`` and
    the async job model: everything except the actual subprocess call, which is
    the injected ``runner`` (so cancellation can wrap the spawn without
    duplicating the masking/logging/ingest logic).
    """
    from ..ops import (
        ProxyConfig,
        log_artifact,
        log_artifacts_for_nmap,
        log_tool_execution,
    )

    if not command:
        raise ValueError("command must be a non-empty list of arguments")

    cfg = config or load_config()

    _check_exec_policy(command, cfg.mcp_exec_allowlist, cfg.mcp_exec_denylist)

    timeout = max(1, min(int(timeout), _MAX_EXEC_TIMEOUT))

    oabase, host_count, ports = _parse_nmap_output(command)
    if oabase is not None:
        existing = [
            str(p)
            for ext in (".xml", ".nmap", ".gnmap")
            if (p := Path(str(oabase) + ext)).exists()
        ]
        if existing:
            raise ValueError(
                f"nmap output already exists at {oabase!r} ({', '.join(existing)}); "
                "refusing to overwrite a prior run. Call generate_nmap_cmd to get a "
                "fresh output path."
            )

    # Resolve credential placeholders server-side (gated, separate from execution).
    # run_command carries the real secret for subprocess; `command` keeps the
    # placeholder so nothing secret is ever logged or returned.
    run_command = list(command)
    secrets: list[str] = []
    if _has_cred_placeholder(command):
        if not cfg.mcp_allow_cred_injection:
            raise ValueError(
                "command contains a @cred:...@ placeholder but credential injection "
                "is disabled; set mcp_allow_cred_injection to allow it."
            )
        run_command, secrets = _resolve_cred_placeholders(command)

    proxy = None
    if use_proxy and cfg.proxychains_enabled:
        proxy = ProxyConfig(
            enabled=True,
            host=cfg.proxychains_host,
            port=cfg.proxychains_port,
            quiet=True,
        )

    meta, stdout, stderr = runner(run_command, timeout, proxy)

    # Never persist or return a resolved secret: log the masked placeholder form
    # and scrub any secret value that leaked into captured output.
    command_text = _mask_command_text(command)
    if secrets:
        stdout = _scrub_secrets(stdout, secrets)
        stderr = _scrub_secrets(stderr, secrets)
    with _db(conn) as c:
        execution_id = log_tool_execution(
            tool_name,
            command_text,
            meta,
            host_count=host_count,
            ports=ports,
            finding_id=finding_id,
            conn=c,
        )
        if oabase is not None and execution_id is not None:
            # Defensive: scrub any resolved secret from the -oA outputs before
            # registering (nmap runs carry no @cred today, so this is usually a
            # no-op, but never register a file we couldn't scrub).
            if not secrets or all(
                _scrub_file_secrets(p, secrets)
                for ext in (".xml", ".nmap", ".gnmap")
                if (p := Path(str(oabase) + ext)).exists()
            ):
                log_artifacts_for_nmap(execution_id, oabase, conn=c)
        # Generic single-file outputs (e.g. netexec --log) → 'log' artifact type.
        # nxc writes the resolved -H/-p into this file, so scrub before registering.
        log_file = _parse_log_flag(command)
        if log_file and execution_id is not None and Path(log_file).exists():
            if _scrub_file_secrets(Path(log_file), secrets):
                log_artifact(execution_id, Path(log_file), "log", conn=c)

    result: dict = {
        "exit_code": meta.exit_code,
        "duration_seconds": round(meta.duration_seconds, 3),
        "used_sudo": meta.used_sudo,
        "execution_id": execution_id,
        "stdout": stdout,
        "stderr": stderr,
    }

    # Best-effort auto-ingest: only when mutations are also allowed (writing
    # structured facts is a mutation). Never fail the exec over ingestion.
    if execution_id is not None:
        if cfg.mcp_allow_mutations:
            try:
                from ..ingest import ingest_execution

                result["ingested"] = ingest_execution(execution_id, conn=conn).as_dict()
            except Exception as exc:  # ingestion must never break the run
                log_error(f"auto-ingest failed for execution {execution_id}: {exc}")
                result["ingested"] = None
        else:
            result["ingest_hint"] = (
                "Enable mcp_allow_mutations and call ingest_results"
                f"({execution_id}) to persist structured results."
            )

    return result


def tool_execute_command(
    command: list[str],
    *,
    tool_name: str = "mcp",
    use_proxy: bool = False,
    timeout: int = 300,
    finding_id: Optional[int] = None,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Execute a command non-interactively, capture output, and log the run.

    The command is run with ``shell=False`` (argv list). Leading ``sudo`` /
    ``proxychains4`` wrappers are unwrapped; no binary in the chain may match
    ``mcp_exec_denylist``, and the target must match ``mcp_exec_allowlist``
    (glob patterns, ``*`` = anything; empty = deny all). ``timeout``
    is clamped to [1, 3600] seconds. Output is captured and returned; nothing is
    written to stdout. The run is recorded in ``tool_executions`` via
    ``ops.log_tool_execution``, attributed to ``finding_id`` when supplied.

    For an nmap command (``-oA <base>`` present), the ``-oA`` output files are
    registered as artifacts after the run (even when no hosts were up), and
    ``host_count`` (from ``-iL``) / ``ports`` (from ``-p``) are recorded. To avoid
    silently overwriting a prior logged run, the call is refused if those output
    files already exist; call ``generate_nmap_cmd`` for a fresh output path.
    """
    return _run_and_record(
        command,
        tool_name=tool_name,
        use_proxy=use_proxy,
        timeout=timeout,
        finding_id=finding_id,
        config=config,
        conn=conn,
        runner=_default_runner,
    )


def tool_get_notes(finding_id: int, conn: Optional[sqlite3.Connection] = None) -> dict:
    """Read a finding's review notes as timestamped entries plus raw text.

    ``review_notes`` is append-only (see ``add_note`` / ``set_review_state``);
    ``entries`` are its non-empty lines, ``raw`` the full stored string.
    """
    from ..models import Finding

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        raw = finding.review_notes
        entries = [ln for ln in (raw or "").splitlines() if ln.strip()]
    return {"finding_id": finding_id, "entries": entries, "raw": raw}


# ========== Mutations (gated by mcp_allow_mutations) ==========


def tool_set_review_state(
    finding_id: int,
    new_state: str,
    *,
    notes: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Move a finding to a new review state, enforcing the workflow.

    Allowed: unreviewed -> in_progress -> done, and done -> unreviewed.
    Raises ValueError (InvalidReviewTransition) for any other change.
    """
    from ..models import Finding

    if new_state not in _VALID_REVIEW_STATES:
        raise ValueError(
            f"Invalid review state {new_state!r}; must be one of "
            f"{sorted(_VALID_REVIEW_STATES)}"
        )

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        finding.transition_review_state(new_state, notes=notes, conn=c)
        c.commit()
    return {"finding_id": finding_id, "review_state": new_state}


def tool_add_note(
    finding_id: int, note: str, conn: Optional[sqlite3.Connection] = None
) -> dict:
    """Append a timestamped note to a finding, then return all its notes.

    Non-destructive: existing notes (from prior ``add_note`` or
    ``set_review_state`` calls) are preserved. Returns the fresh ``get_notes``
    read so callers see the accumulated list.
    """
    from ..models import Finding

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        finding.append_note(note, c)
        c.commit()
        return tool_get_notes(finding_id, conn=c)


def tool_ingest_results(
    execution_id: int, conn: Optional[sqlite3.Connection] = None
) -> dict:
    """Parse a completed execution's output into structured facts (idempotent).

    Reads the execution's nmap XML artifact (open ports + NSE vuln verdicts) or
    re-reads the NetExec workspace (security flags), persisting the results keyed
    to ``execution_id``. Re-running on the same execution never duplicates rows.
    Returns counts plus ``skipped_reason`` for empty/partial/unknown runs.
    """
    from ..ingest import ingest_execution

    with _db(conn) as c:
        summary = ingest_execution(execution_id, conn=c)
    return summary.as_dict()


def tool_set_finding_verdict(
    finding_id: int,
    verdict: str,
    *,
    note: Optional[str] = None,
    execution_id: Optional[int] = None,
    artifact_id: Optional[int] = None,
    nse_result_id: Optional[int] = None,
    created_by: Optional[str] = None,
    conn: Optional[sqlite3.Connection] = None,
    config: Optional[CernoConfig] = None,
) -> dict:
    """Record a verification verdict for a finding (truth, not workflow state).

    ``verdict`` must be one of confirmed / false_positive / unable. Optional
    evidence (execution_id / artifact_id / nse_result_id) links the proof. This
    appends to the finding's verdict history; the latest becomes current. The
    returned verdict carries the ``workflow_candidate`` contribution hint.
    """
    from ..models import Finding, FindingVerdict, VerdictEvidence

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        evidence: list[VerdictEvidence] = []
        if (
            execution_id is not None
            or artifact_id is not None
            or nse_result_id is not None
        ):
            evidence.append(
                VerdictEvidence(
                    execution_id=execution_id,
                    artifact_id=artifact_id,
                    nse_result_id=nse_result_id,
                )
            )
        # FindingVerdict.set validates the label (raises InvalidVerdict/ValueError).
        FindingVerdict.set(
            finding_id,
            verdict,
            note=note,
            created_by=created_by,
            evidence=evidence or None,
            conn=c,
        )
        c.commit()
    return tool_get_finding_verdict(finding_id, conn=conn, config=config)


def tool_import_nessus(nessus_path: str) -> dict:
    """Import a .nessus file into the database. Returns import statistics."""
    from ..constants import SCANS_ROOT
    from ..nessus_import import import_nessus_file

    path = Path(nessus_path).expanduser()
    if not path.exists():
        raise ValueError(f"No such file: {nessus_path}")

    result = import_nessus_file(path, SCANS_ROOT)
    return {
        "scan_name": result.scan_name,
        "plugins_exported": result.plugins_exported,
        "total_hosts": result.total_hosts,
        "severities": result.severities,
    }


def tool_reveal_credential(ref: str, conn: Optional[sqlite3.Connection] = None) -> dict:
    """Return a credential's CLEARTEXT secret (audited). SENSITIVE — do not persist.

    Resolves ``ref`` (from ``list_nxc_credentials``) to its real password/hash via
    the shared ``creds.reveal_credential`` (which records a ``cred_reveal`` audit
    row with the ref, never the value). Raises ValueError when the ref has no
    usable secret. Only registered when ``mcp_allow_cred_reveal`` is enabled.
    """
    from ..creds import reveal_credential

    with _db(conn) as c:
        secret = reveal_credential(ref, conn=c)
    if secret is None:
        raise ValueError(f"No usable secret for credential ref {ref!r}")
    return {
        "username": secret.username,
        "domain": secret.domain,
        "secret_kind": secret.secret_kind,
        "secret_value": secret.secret_value,
        "warning": "SENSITIVE — do not persist this value or write it to a file/log.",
    }


# ========== Resources (read-only, operator-pinnable context) ==========
# Resources re-expose existing read data under cerno:// URIs so an MCP client
# can attach it to context. They return text/JSON strings and never print.


def resource_scans(conn: Optional[sqlite3.Connection] = None) -> str:
    """`cerno://scans` — JSON index of all scans with stats."""
    return json.dumps(tool_list_scans(conn=conn), indent=2)


def resource_config() -> str:
    """`cerno://config` — JSON of all current (read-only) config settings."""
    return json.dumps(tool_get_config(), indent=2)


def resource_host_nxc(host_ip: str) -> str:
    """`cerno://host/{host_ip}/nxc` — JSON NetExec enrichment for a host."""
    return json.dumps(tool_get_host_nxc(host_ip), indent=2)


def resource_scan_hosts(scan_id: int, conn: Optional[sqlite3.Connection] = None) -> str:
    """`cerno://scan/{scan_id}/hosts` — discovered host:port lines, one per line."""
    services = tool_list_services(scan_id, conn=conn)
    return "\n".join(f"{s['host']}:{s['port']}" for s in services)


def resource_scan_cves(scan_id: int, conn: Optional[sqlite3.Connection] = None) -> str:
    """`cerno://scan/{scan_id}/cves` — JSON of unique CVEs mapped to plugins."""
    import json as _json

    return _json.dumps(tool_list_cves([scan_id], conn=conn), indent=2)


def resource_finding_output(
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> str:
    """`cerno://finding/{finding_id}/output` — raw per-host plugin output."""
    detail = tool_get_finding_detail(finding_id, conn=conn)
    header = f"# {detail['plugin_name']} (plugin {detail['plugin_id']})"
    blocks = [header]
    for a in detail["affected"]:
        host = a["host"]
        port = a["port"]
        loc = f"{host}:{port}" if port is not None else str(host)
        output = a["plugin_output"] or "(no plugin output)"
        blocks.append(f"[{loc}]\n{output}")
    return "\n\n".join(blocks)


def resource_finding_workflow(
    finding_id: int,
    conn: Optional[sqlite3.Connection] = None,
    config: Optional[CernoConfig] = None,
) -> str:
    """`cerno://finding/{finding_id}/workflow` — verification workflow, or a notice."""
    from ..models import Finding

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        plugin_id = finding.plugin_id
    workflow = tool_get_workflow(plugin_id, config=config)
    if workflow is None:
        return f"No verification workflow mapped for plugin {plugin_id}."

    lines = [f"# {workflow['workflow_name']}", workflow["description"], ""]
    for i, step in enumerate(workflow["steps"], 1):
        lines.append(f"## Step {i}: {step['title']}")
        for cmd in step["commands"]:
            lines.append(f"    {cmd}")
        if step.get("notes"):
            lines.append(f"Notes: {step['notes']}")
        lines.append("")
    if workflow.get("references"):
        lines.append("References:")
        lines.extend(f"  - {ref}" for ref in workflow["references"])
    return "\n".join(lines).rstrip()


def resource_finding_verdict(
    finding_id: int,
    conn: Optional[sqlite3.Connection] = None,
    config: Optional[CernoConfig] = None,
) -> str:
    """`cerno://finding/{finding_id}/verdict` — JSON verification verdict + evidence."""
    return json.dumps(
        tool_get_finding_verdict(finding_id, conn=conn, config=config), indent=2
    )


def resource_finding_results(
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> str:
    """`cerno://finding/{finding_id}/results` — JSON live-verified ports + NSE verdicts."""
    from ..database import query_all

    with _db(conn) as c:
        ports = query_all(
            c,
            """
            SELECT h.ip_address AS host, vp.port_number, vp.protocol,
                   ps.label AS state, vp.service_name, vp.execution_id
            FROM verified_ports vp
            JOIN tool_executions te ON vp.execution_id = te.execution_id
            JOIN hosts h ON vp.host_id = h.host_id
            LEFT JOIN port_states ps ON vp.port_state_id = ps.port_state_id
            WHERE te.finding_id = ?
            ORDER BY h.ip_address, vp.port_number
            """,
            (finding_id,),
        )
        scripts = query_all(
            c,
            """
            SELECT h.ip_address AS host, nsr.port_number, nsr.script_id,
                   nv.label AS verdict, nsr.output, nsr.execution_id
            FROM nse_script_results nsr
            JOIN tool_executions te ON nsr.execution_id = te.execution_id
            JOIN hosts h ON nsr.host_id = h.host_id
            LEFT JOIN nse_verdicts nv ON nsr.nse_verdict_id = nv.nse_verdict_id
            WHERE te.finding_id = ?
            ORDER BY h.ip_address, nsr.script_id
            """,
            (finding_id,),
        )
    payload = {
        "finding_id": finding_id,
        "verified_ports": [dict(r) for r in ports],
        "nse_results": [dict(r) for r in scripts],
    }
    return json.dumps(payload, indent=2)


# ========== Prompts (read-only triage/report templates) ==========
# Prompts reuse the same context builders as the in-TUI [A] assistant so the
# TUI and MCP produce consistent briefs.


def _finding_context(
    finding_id: int,
    conn: Optional[sqlite3.Connection],
    config: Optional[CernoConfig] = None,
) -> str:
    """Assemble the shared finding context block (plugin + hosts + output + workflow)."""
    from ..claude_assistant import build_finding_context
    from ..models import Finding, Plugin
    from ..workflow_mapper import build_workflow_mapper

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        plugin = Plugin.get_by_id(finding.plugin_id, c)
        if plugin is None:
            raise ValueError(f"No plugin with id {finding.plugin_id}")
        hosts, _ = finding.get_hosts_and_ports(c)
        outputs = finding.get_plugin_outputs_by_host(c)
    workflow = build_workflow_mapper(config).get_workflow(str(finding.plugin_id))
    return build_finding_context(plugin, finding, hosts, outputs, workflow)


def _execution_attribution_note(finding_id: int) -> str:
    """Prompt guidance so runs are attributed and contributions surface."""
    return (
        "If you run any verification command through Cerno (execute_command / "
        f"start_execution), always pass finding_id={finding_id} so the run is "
        "attributed to this finding. After recording a verdict, if "
        "workflow_candidate.available is true, offer to review the drafted workflow "
        "with get_workflow_candidate before exporting it."
    )


def prompt_triage_finding(
    finding_id: int,
    conn: Optional[sqlite3.Connection] = None,
    config: Optional[CernoConfig] = None,
) -> str:
    """Report-brief prompt for a single finding."""
    from ..claude_assistant import REPORT_BRIEF_QUERY

    return (
        f"{_finding_context(finding_id, conn, config)}\n\n{REPORT_BRIEF_QUERY}"
        f"\n\n{_execution_attribution_note(finding_id)}"
    )


def prompt_exploit_plan(
    finding_id: int,
    conn: Optional[sqlite3.Connection] = None,
    config: Optional[CernoConfig] = None,
) -> str:
    """Exploitation-planning prompt for a single finding."""
    instruction = (
        "Based on the context above, outline the fastest viable path to exploit or "
        "verify this finding. Name any Metasploit modules listed; identify which "
        "affected hosts are most promising and why; and give the concrete next "
        "verification step (an nmap, netexec, or msfconsole command). Be concise and "
        "flag uncertainty. Always verify before acting."
    )
    return (
        f"{_finding_context(finding_id, conn, config)}\n\n{instruction}"
        f"\n\n{_execution_attribution_note(finding_id)}"
    )


def prompt_triage_scope(
    scan_ids: list[int] | int,
    severity_int: Optional[int] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> str:
    """Report-brief prompt for a scan scope spanning one or more scans.

    Accepts a single ``scan_id`` or a list. Multiple scans are merged and
    deduplicated by plugin_id (``Finding.get_by_scan_ids_merged``), matching the
    TUI's scope-level aggregate assistant.
    """
    from ..claude_assistant import REPORT_BRIEF_QUERY, build_aggregate_context
    from ..models import Finding, Scan

    ids = [scan_ids] if isinstance(scan_ids, int) else list(scan_ids)
    if not ids:
        raise ValueError("scan_ids must contain at least one scan id")

    severity_dir = None if severity_int is None else f"{severity_int}_"
    with _db(conn) as c:
        names: list[str] = []
        for sid in ids:
            scan = Scan.get_by_id(sid, c)
            if scan is None:
                raise ValueError(f"No scan with id {sid}")
            names.append(scan.scan_name)

        if len(ids) > 1:
            pairs, _ = Finding.get_by_scan_ids_merged(
                ids, severity_dir=severity_dir, conn=c
            )
        else:
            pairs = Finding.get_by_scan_with_plugin(
                ids[0], severity_dir=severity_dir, conn=c
            )
        sev_note = "" if severity_int is None else f" (severity {severity_int})"
        scope_label = ", ".join(names)
        scope_description = f"{scope_label}{sev_note}: {len(pairs)} finding(s)"
        # Pass conn so host/port lookups use the injected connection (not the
        # default DB) — keeps the prompt hermetic under tests.
        context = build_aggregate_context(names, scope_description, pairs, conn=c)
    return f"{context}\n\n{REPORT_BRIEF_QUERY}"


# ========== Server assembly ==========


def build_server(config: Optional[CernoConfig] = None) -> Any:
    """Build and return a FastMCP server with tools registered per config flags.

    Read and command-generation tools are always registered. Execution and
    mutation tools are registered only when their config flag is enabled.
    """
    cfg = config or load_config()
    mcp = FastMCP("cerno")

    # --- Read tools (always on) ---
    @mcp.tool()
    def list_scans() -> list[ScanInfo]:
        """List all imported scans with severity counts and review progress."""
        return cast("list[ScanInfo]", tool_list_scans())

    @mcp.tool()
    def list_findings(
        scan_ids: list[int],
        severity_int: Optional[int] = None,
        review_state: Optional[str] = None,
        has_metasploit: Optional[bool] = None,
        plugin_name: Optional[str] = None,
        merged: bool = False,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[FindingSummary]:
        """List findings across scans, filtered and paged.

        merged=True dedups multi-scan results by plugin (TUI semantics); limit/
        offset page the result. limit defaults to the configured default_page_size
        (min 8) when set, else 500; use offset to page past it.
        """
        return cast(
            "list[FindingSummary]",
            tool_list_findings(
                scan_ids,
                severity_int=severity_int,
                review_state=review_state,
                has_metasploit=has_metasploit,
                plugin_name=plugin_name,
                merged=merged,
                limit=limit,
                offset=offset,
                config=cfg,
            ),
        )

    @mcp.tool()
    def search_findings(
        plugin_name: Optional[str] = None,
        severity_int: Optional[int] = None,
        has_metasploit: Optional[bool] = None,
        limit: Optional[int] = None,
    ) -> list[FindingSearchResult]:
        """Search findings across ALL scans (no scan_ids needed); each carries scan_name.

        limit defaults to the configured default_page_size (min 8) when set, else 500.
        """
        return cast(
            "list[FindingSearchResult]",
            tool_search_findings(
                plugin_name=plugin_name,
                severity_int=severity_int,
                has_metasploit=has_metasploit,
                limit=limit,
                config=cfg,
            ),
        )

    @mcp.tool()
    def query_findings(
        scan_ids: Optional[list[int]] = None,
        severity_int: Optional[int] = None,
        severity_min: Optional[int] = None,
        review_state: Optional[str] = None,
        verdict: Optional[str] = None,
        cve: Optional[str] = None,
        port: Optional[int] = None,
        service: Optional[str] = None,
        host: Optional[str] = None,
        plugin_name: Optional[str] = None,
        has_metasploit: Optional[bool] = None,
        has_workflow: Optional[bool] = None,
        merged: bool = False,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[QueryFindingResult]:
        """Query findings with AND-combined predicates (composite superset of list/search).

        All predicates optional. scan_ids=None spans all scans. verdict is
        confirmed/false_positive/unable or "none" (no verdict yet). cve is an exact
        CVE id (case-insensitive). has_workflow consults the workflow mapper. Each
        row carries scan_name and has_workflow. merged dedups by plugin across scans.
        limit defaults to the configured default_page_size (min 8) when set, else
        500; use offset to page past it.
        """
        return cast(
            "list[QueryFindingResult]",
            tool_query_findings(
                scan_ids=scan_ids,
                severity_int=severity_int,
                severity_min=severity_min,
                review_state=review_state,
                verdict=verdict,
                cve=cve,
                port=port,
                service=service,
                host=host,
                plugin_name=plugin_name,
                has_metasploit=has_metasploit,
                has_workflow=has_workflow,
                merged=merged,
                limit=limit,
                offset=offset,
                config=cfg,
            ),
        )

    @mcp.tool()
    def get_finding_hosts(finding_id: int) -> FindingHosts:
        """Get host list, ports, and ready-to-use host:port target lines for a finding."""
        return cast("FindingHosts", tool_get_finding_hosts(finding_id))

    @mcp.tool()
    def get_web_targets(scan_id: int) -> list[str]:
        """Get HTTP/HTTPS URLs discovered in a scan."""
        return tool_get_web_targets(scan_id)

    @mcp.tool()
    def host_history(host_ip: str) -> Optional[dict]:
        """Get a host's vulnerability timeline across all scans."""
        return tool_host_history(host_ip)

    @mcp.tool()
    def compare_scans(
        scan1_name: str, scan2_name: str, min_severity: int = 0
    ) -> Optional[dict]:
        """Compare two scans by name (new/resolved/persistent findings and hosts)."""
        return tool_compare_scans(scan1_name, scan2_name, min_severity=min_severity)

    @mcp.tool()
    def get_workflow(plugin_id: int) -> Optional[dict]:
        """Get the verification workflow mapped to a plugin, if any."""
        return tool_get_workflow(plugin_id, config=cfg)

    @mcp.tool()
    def list_workflow_gaps(
        scan_ids: list[int], severity_min: Optional[int] = None
    ) -> list[WorkflowGapResult]:
        """List findings with no mapped verification workflow (triage gaps), worst first.

        The complement of query_findings(has_workflow=True): MSF-backed criticals
        appear first. Use it to see what still needs a manual verification path.
        """
        return cast(
            "list[WorkflowGapResult]",
            tool_list_workflow_gaps(
                scan_ids=scan_ids, severity_min=severity_min, config=cfg
            ),
        )

    @mcp.tool()
    def get_notes(finding_id: int) -> NotesResult:
        """Read a finding's review notes (timestamped entries + raw text).

        Notes are append-only; written via add_note or set_review_state(notes=...).
        """
        return cast("NotesResult", tool_get_notes(finding_id))

    @mcp.tool()
    def get_finding_detail(finding_id: int, max_hosts: int = 100) -> FindingDetail:
        """Get full detail for a finding: plugin metadata + per-host plugin output (capped).

        Also carries the current verification verdict, a non-binding
        suggested_verdict from ingested NSE evidence, and live-verified fact counts.
        """
        return cast(
            "FindingDetail", tool_get_finding_detail(finding_id, max_hosts=max_hosts)
        )

    @mcp.tool()
    def get_finding_verdict(finding_id: int) -> VerdictResult:
        """Get a finding's verification verdict (current + history + evidence + suggestion).

        The verdict (confirmed / false_positive / unable) is a truth value, distinct
        from review_state. suggested_verdict is a non-binding hint from ingested NSE
        evidence and is never applied automatically.
        """
        return cast("VerdictResult", tool_get_finding_verdict(finding_id, config=cfg))

    @mcp.tool()
    def get_workflow_candidate(finding_id: int) -> WorkflowCandidateResult:
        """Draft a workflow contribution from the commands run against a finding.

        reason "new" = plugin has no mapped workflow; "enhanced" = non-baseline
        commands absent from the mapped one; available=false = nothing new.
        Hosts/ports/creds are templated (<TARGET>/<PORT>/<USERNAME>/<PASSWORD>/
        <DOMAIN>). Review/edit per review_hints, then export_workflow_contribution.
        """
        return cast(
            "WorkflowCandidateResult",
            tool_get_workflow_candidate(finding_id, config=cfg),
        )

    @mcp.tool()
    def export_workflow_contribution(
        finding_id: int, workflow: Optional[dict] = None
    ) -> WorkflowExportResult:
        """Export a sanitized, PR-ready workflow YAML file (local file only).

        Uses the draft, or `workflow` (edited entry: workflow_name, description,
        steps [{title, commands, notes}], references). Requires a confirmed/
        false_positive verdict; refuses and writes nothing if the leak scan finds
        real IPs/hostnames/paths. Returns the path + PR-against-develop steps.
        Never submits anything.
        """
        return cast(
            "WorkflowExportResult",
            tool_export_workflow_contribution(finding_id, workflow, config=cfg),
        )

    @mcp.tool()
    def list_hosts(scan_id: Optional[int] = None) -> list[HostInfo]:
        """List hosts with finding counts and worst severity (all scans, or one scan)."""
        return cast("list[HostInfo]", tool_list_hosts(scan_id))

    @mcp.tool()
    def top_hosts(limit: int = 20) -> list[HostInfo]:
        """List hosts worst-severity-first for prioritization (cross-scan)."""
        return cast("list[HostInfo]", tool_top_hosts(limit))

    @mcp.tool()
    def check_tools() -> dict:
        """Report which security tools (nmap/netexec/msf/proxychains4) are installed."""
        return tool_check_tools()

    @mcp.tool()
    def list_executions(limit: int = 50) -> list[ExecutionInfo]:
        """List recent tool executions recorded in the database."""
        return cast("list[ExecutionInfo]", tool_list_executions(limit))

    @mcp.tool()
    def list_artifacts(
        execution_id: Optional[int] = None, limit: int = 50
    ) -> list[ArtifactInfo]:
        """List generated artifact files, optionally for one execution."""
        return cast("list[ArtifactInfo]", tool_list_artifacts(execution_id, limit))

    @mcp.tool()
    def get_finding_artifacts(finding_id: int) -> list[ArtifactInfo]:
        """List artifact files generated by executions attributed to a finding."""
        return cast("list[ArtifactInfo]", tool_get_finding_artifacts(finding_id))

    @mcp.tool()
    def list_cves(
        scan_ids: list[int], severity_int: Optional[int] = None
    ) -> list[CveEntry]:
        """List unique CVEs across scans, each mapped to its plugins."""
        return cast(
            "list[CveEntry]", tool_list_cves(scan_ids, severity_int=severity_int)
        )

    @mcp.tool()
    def list_services(scan_id: int) -> list[ServiceInfo]:
        """List discovered host/port/protocol/service-name tuples for a scan."""
        return cast("list[ServiceInfo]", tool_list_services(scan_id))

    @mcp.tool()
    def find_affected_by_cve(
        cve: str, scan_ids: Optional[list[int]] = None
    ) -> list[CveAffected]:
        """Find findings/hosts affected by a CVE across scans (reverse of list_cves)."""
        return cast(
            "list[CveAffected]", tool_find_affected_by_cve(cve, scan_ids=scan_ids)
        )

    @mcp.tool()
    def read_artifact(artifact_id: int, max_bytes: int = 100_000) -> dict:
        """Read the contents of a generated artifact file by id (capped)."""
        return tool_read_artifact(artifact_id, max_bytes=max_bytes)

    @mcp.tool()
    def get_config() -> dict:
        """Return all current Cerno config settings (read-only)."""
        return tool_get_config()

    @mcp.tool()
    def get_capabilities() -> Capabilities:
        """Report which gated capabilities are live.

        Covers execution, mutations, batch, credential injection/reveal, the
        exec allow/deny lists and NetExec availability.
        """
        return cast("Capabilities", tool_get_capabilities(cfg))

    @mcp.tool()
    def get_host_nxc(host_ip: str) -> dict:
        """NetExec enrichment for a host: credentials, shares, security flags."""
        return tool_get_host_nxc(host_ip)

    @mcp.tool()
    def list_nxc_credentials(host_ips: Optional[list[str]] = None) -> dict:
        """Deduplicated NetExec credentials across hosts (default: all known hosts)."""
        return tool_list_nxc_credentials(host_ips)

    # --- Command generation (always on; no execution) ---
    @mcp.tool()
    def generate_nmap_cmd(
        finding_id: int,
        udp: Optional[bool] = None,
        nse_option: Optional[str] = None,
        use_sudo: bool = False,
    ) -> NmapCommand:
        """Build an nmap command for a finding's hosts/ports (does not run it).

        nse_option: NSE script names or categories, comma-separated (e.g.
        "smb-security-mode,smb2-security-mode" or "vuln"); a "--script=" prefix
        is optional. Other nmap flags are rejected. Omitted: the configured
        nmap_default_profile's scripts (if set); "" means no scripts.
        udp: omitted = the applied default profile's UDP need (SNMP/IPMI), else
        False.
        """
        return cast(
            "NmapCommand",
            tool_generate_nmap_cmd(
                finding_id,
                udp=udp,
                nse_option=nse_option,
                use_sudo=use_sudo,
                config=cfg,
            ),
        )

    @mcp.tool()
    def generate_netexec_cmd(
        finding_id: int,
        protocol: Optional[str] = None,
        use_credential: Optional[str] = None,
    ) -> NetexecCommand:
        """Build a netexec command for a finding's hosts (does not run it).

        protocol is case-insensitive; valid values: mssql, smb, ftp, ldap, nfs,
        rdp, ssh, vnc, winrm, wmi. An unknown protocol is rejected with an error.
        Omitted: the configured default_netexec_protocol, else smb.

        use_credential is a credential ref from list_nxc_credentials; when given,
        auth is injected via a @cred:<ref>@ placeholder (the secret is resolved
        server-side at run time, never placed in the returned command). Running
        the command requires mcp_allow_cred_injection to also be enabled.
        """
        return cast(
            "NetexecCommand",
            tool_generate_netexec_cmd(
                finding_id, protocol, use_credential=use_credential, config=cfg
            ),
        )

    @mcp.tool()
    def generate_msf_search(finding_id: int) -> MsfSearchCommand:
        """Build an msfconsole search command for a finding's Metasploit modules."""
        return cast("MsfSearchCommand", tool_generate_msf_search(finding_id))

    @mcp.tool()
    def prepare_workflow(
        finding_id: int, use_credential: Optional[str] = None
    ) -> Optional[dict]:
        """Fill the finding's mapped verification workflow and flag runnable commands.

        Substitutes <TARGET>/<PORT>/<USERNAME>/<PASSWORD>/<INTERFACE> (and historical
        variants) with the finding's real hosts/ports; use_credential (a ref from
        list_nxc_credentials) fills <USERNAME> and turns <PASSWORD> into a
        @cred:<ref>@ placeholder (secret resolved only at run time). Each command
        reports executable + manual_reason so non-runnable steps are clear. Returns
        None when no workflow is mapped to the plugin.
        """
        return tool_prepare_workflow(
            finding_id, use_credential=use_credential, config=cfg
        )

    @mcp.tool()
    def plan_batch(
        strategy: str,
        scan_ids: Optional[list[int]] = None,
        severity_int: Optional[int] = None,
        severity_min: Optional[int] = None,
        review_state: Optional[str] = None,
        verdict: Optional[str] = None,
        cve: Optional[str] = None,
        port: Optional[int] = None,
        service: Optional[str] = None,
        host: Optional[str] = None,
        plugin_name: Optional[str] = None,
        has_metasploit: Optional[bool] = None,
        has_workflow: Optional[bool] = None,
        limit: int = 500,
        use_credential: Optional[str] = None,
        skip_done: bool = True,
    ) -> dict:
        """Build a reviewable batch plan (dry run) over a finding query (no execution).

        strategy is "nmap", "netexec:<proto>" (bare "netexec" = configured default
        protocol, else smb), "msf", or "workflow". Predicates are
        the same AND-combined set as query_findings. Each item reports the generated
        command and whether it is executable-via-execute_command or manual; already-
        resolved findings are skipped when skip_done. Review this, then execute_batch.
        """
        return tool_plan_batch(
            strategy,
            scan_ids=scan_ids,
            severity_int=severity_int,
            severity_min=severity_min,
            review_state=review_state,
            verdict=verdict,
            cve=cve,
            port=port,
            service=service,
            host=host,
            plugin_name=plugin_name,
            has_metasploit=has_metasploit,
            has_workflow=has_workflow,
            limit=limit,
            use_credential=use_credential,
            skip_done=skip_done,
            config=cfg,
        )

    # --- Resources (always on; operator-pinnable context) ---
    @mcp.resource("cerno://scans", mime_type="application/json")
    def scans_resource() -> str:
        """Index of all imported scans with statistics."""
        return resource_scans()

    @mcp.resource("cerno://scan/{scan_id}/hosts", mime_type="text/plain")
    def scan_hosts_resource(scan_id: int) -> str:
        """Discovered host:port lines for a scan."""
        return resource_scan_hosts(scan_id)

    @mcp.resource("cerno://scan/{scan_id}/cves", mime_type="application/json")
    def scan_cves_resource(scan_id: int) -> str:
        """Unique CVEs across a scan, mapped to their plugins."""
        return resource_scan_cves(scan_id)

    @mcp.resource("cerno://finding/{finding_id}/output", mime_type="text/plain")
    def finding_output_resource(finding_id: int) -> str:
        """Raw per-host plugin output for a finding."""
        return resource_finding_output(finding_id)

    @mcp.resource("cerno://finding/{finding_id}/workflow", mime_type="text/plain")
    def finding_workflow_resource(finding_id: int) -> str:
        """Verification workflow for a finding's plugin, if one is mapped."""
        return resource_finding_workflow(finding_id, config=cfg)

    @mcp.resource("cerno://config", mime_type="application/json")
    def config_resource() -> str:
        """All current Cerno config settings (read-only)."""
        return resource_config()

    @mcp.resource("cerno://host/{host_ip}/nxc", mime_type="application/json")
    def host_nxc_resource(host_ip: str) -> str:
        """NetExec enrichment for a host (credentials, shares, security flags)."""
        return resource_host_nxc(host_ip)

    @mcp.resource("cerno://finding/{finding_id}/verdict", mime_type="application/json")
    def finding_verdict_resource(finding_id: int) -> str:
        """Verification verdict + evidence for a finding."""
        return resource_finding_verdict(finding_id, config=cfg)

    @mcp.resource("cerno://finding/{finding_id}/results", mime_type="application/json")
    def finding_results_resource(finding_id: int) -> str:
        """Live-verified ports + NSE verdicts ingested for a finding."""
        return resource_finding_results(finding_id)

    # --- Prompts (always on; triage/report templates) ---
    @mcp.prompt()
    def triage_finding(finding_id: int) -> str:
        """Draft a pentest-report brief for a single finding."""
        return prompt_triage_finding(finding_id, config=cfg)

    @mcp.prompt()
    def exploit_plan(finding_id: int) -> str:
        """Outline the fastest viable exploitation/verification path for a finding."""
        return prompt_exploit_plan(finding_id, config=cfg)

    @mcp.prompt()
    def triage_scope(scan_ids: str, severity_int: Optional[int] = None) -> str:
        """Draft a report brief across one or more scans (optionally one severity).

        scan_ids is a comma-separated list of scan IDs (e.g. "1" or "1,3"); multiple
        scans are merged and deduplicated by plugin, matching the TUI scope assistant.
        """
        ids = [int(s) for s in str(scan_ids).split(",") if s.strip()]
        return prompt_triage_scope(ids, severity_int)

    # --- Execution (gated) ---
    if cfg.mcp_allow_execution:

        @mcp.tool()
        async def execute_command(
            command: list[str],
            tool_name: str = "mcp",
            use_proxy: bool = False,
            timeout: int = 300,
            finding_id: Optional[int] = None,
            ctx: Optional[Context] = None,
        ) -> dict:
            """Execute a command (argv list), capture output, and log the run.

            sudo/proxychains4 prefixes are allowed and unwrapped. No binary in the
            chain may match mcp_exec_denylist, and the target binary's basename
            must match mcp_exec_allowlist (globs; "*" = anything not denied; an
            empty allowlist denies all). Call get_capabilities to see both lists.
            use_proxy=true routes the run through proxychains4 (requires the
            proxychains_enabled config key; Cerno's ~/.cerno/proxychains4.conf).
            timeout is clamped to [1, 3600]s. ALWAYS pass finding_id when the run
            verifies a finding: it attributes the run (get_finding_artifacts,
            verdict evidence, verified stats, workflow contributions).

            Runs the blocking command in a worker thread and emits periodic
            progress heartbeats so long scans (e.g. nmap) show liveness in
            progress-capable clients.
            """
            task = asyncio.create_task(
                asyncio.to_thread(
                    tool_execute_command,
                    command,
                    tool_name=tool_name,
                    use_proxy=use_proxy,
                    timeout=timeout,
                    finding_id=finding_id,
                    config=cfg,
                )
            )
            start = time.time()
            while not task.done():
                done, _ = await asyncio.wait({task}, timeout=2.0)
                if not done and ctx is not None:
                    elapsed = time.time() - start
                    try:
                        await ctx.report_progress(
                            progress=elapsed,
                            message=f"running {tool_name}… {elapsed:.0f}s",
                        )
                    except Exception:  # progress is best-effort
                        pass
            return task.result()

        @mcp.tool()
        async def start_execution(
            command: list[str],
            tool_name: str = "mcp",
            use_proxy: bool = False,
            timeout: int = 300,
            finding_id: Optional[int] = None,
        ) -> dict:
            """Start a command as a background job and return its job_id immediately.

            For long scans/batches that should not block the tool call. The exec
            policy (allow/denylist) and cred-injection gate are checked up front, so
            a disallowed command fails here. Poll get_execution_status(job_id) and
            cancel_execution(job_id). Jobs are in-memory and lost on server restart,
            but every completed run is still logged to tool_executions. ALWAYS pass
            finding_id when the run verifies a finding (attribution, verdict
            evidence, workflow contributions).
            """
            from .jobs import get_registry

            job = get_registry().start(
                command=command,
                tool_name=tool_name,
                config=cfg,
                finding_id=finding_id,
                use_proxy=use_proxy,
                timeout=timeout,
            )
            return {"job_id": job.job_id, "status": job.status}

        @mcp.tool()
        def get_execution_status(job_id: str) -> dict:
            """Return a background job's status (running/done/failed/cancelled) + tail."""
            from .jobs import get_registry

            job = get_registry().get(job_id)
            if job is None:
                raise ValueError(f"No job with id {job_id!r}")
            return job.status_dict()

        @mcp.tool()
        def cancel_execution(job_id: str) -> dict:
            """Cancel a running job, killing its process group (no-op if finished)."""
            from .jobs import get_registry

            job = get_registry().cancel(job_id)
            return {"job_id": job.job_id, "status": job.status}

        @mcp.tool()
        def list_jobs(limit: int = 50) -> list[dict]:
            """List background jobs (newest first) for this server process."""
            from .jobs import get_registry

            return [j.status_dict() for j in get_registry().list_jobs(limit)]

    else:
        log_info("mcp: execute_command not registered (mcp_allow_execution=false)")

    # --- Scoped batch execution (gated by execution AND batch) ---
    if cfg.mcp_allow_execution and cfg.mcp_allow_batch:

        @mcp.tool()
        async def execute_batch(
            strategy: str,
            scan_ids: Optional[list[int]] = None,
            severity_int: Optional[int] = None,
            severity_min: Optional[int] = None,
            review_state: Optional[str] = None,
            verdict: Optional[str] = None,
            cve: Optional[str] = None,
            port: Optional[int] = None,
            service: Optional[str] = None,
            host: Optional[str] = None,
            plugin_name: Optional[str] = None,
            has_metasploit: Optional[bool] = None,
            has_workflow: Optional[bool] = None,
            limit: int = 500,
            use_credential: Optional[str] = None,
            skip_done: bool = True,
            concurrency: Optional[int] = None,
            per_command_timeout: Optional[int] = None,
        ) -> dict:
            """Run the runnable commands of a batch plan over a finding query.

            Builds the same plan as plan_batch, then runs each runnable, non-skipped
            item as a tracked, cancellable job attributed to its finding (and auto-
            ingested), capped at mcp_batch_concurrency (default 3; concurrency is
            clamped to [1, 8]) with an mcp_batch_timeout per command. Every command is re-validated against the exec policy at run
            time. Returns the plan plus per-item results. Registered only when both
            mcp_allow_execution and mcp_allow_batch are set.
            """
            from ..batch import execute_batch as _execute_batch

            q = _batch_query(
                scan_ids=scan_ids,
                severity_int=severity_int,
                severity_min=severity_min,
                review_state=review_state,
                verdict=verdict,
                cve=cve,
                port=port,
                service=service,
                host=host,
                plugin_name=plugin_name,
                has_metasploit=has_metasploit,
                has_workflow=has_workflow,
                limit=limit,
            )
            return await _execute_batch(
                q,
                strategy,
                use_credential=use_credential,
                skip_done=skip_done,
                concurrency=concurrency,
                per_command_timeout=per_command_timeout,
                config=cfg,
            )

    else:
        log_info(
            "mcp: execute_batch not registered "
            "(requires mcp_allow_execution and mcp_allow_batch)"
        )

    # --- Mutations (gated) ---
    if cfg.mcp_allow_mutations:

        @mcp.tool()
        def set_review_state(
            finding_id: int, new_state: str, notes: Optional[str] = None
        ) -> dict:
            """Move a finding's review state: unreviewed -> in_progress -> done; done -> unreviewed."""
            return tool_set_review_state(finding_id, new_state, notes=notes)

        @mcp.tool()
        def add_note(finding_id: int, note: str) -> NotesResult:
            """Append a timestamped note to a finding (non-destructive); returns all notes."""
            return cast("NotesResult", tool_add_note(finding_id, note))

        @mcp.tool()
        def import_nessus(nessus_path: str) -> dict:
            """Import a .nessus file into the database."""
            return tool_import_nessus(nessus_path)

        @mcp.tool()
        def ingest_results(execution_id: int) -> IngestResult:
            """Parse a completed execution's output into structured facts (idempotent).

            nmap: open ports + NSE vuln verdicts; nxc: security-flag snapshot. Safe
            to re-run; empty/partial runs return a skipped_reason instead of erroring.
            """
            return cast("IngestResult", tool_ingest_results(execution_id))

        @mcp.tool()
        def set_finding_verdict(
            finding_id: int,
            verdict: str,
            note: Optional[str] = None,
            execution_id: Optional[int] = None,
            artifact_id: Optional[int] = None,
            nse_result_id: Optional[int] = None,
        ) -> VerdictResult:
            """Record a verification verdict (confirmed / false_positive / unable) for a finding.

            This is the truth value, distinct from review_state. Optional
            execution_id/artifact_id/nse_result_id link the evidence that proves it.
            The result's workflow_candidate says whether the commands run yield a
            workflow worth contributing (then call get_workflow_candidate).
            """
            return cast(
                "VerdictResult",
                tool_set_finding_verdict(
                    finding_id,
                    verdict,
                    note=note,
                    execution_id=execution_id,
                    artifact_id=artifact_id,
                    nse_result_id=nse_result_id,
                    config=cfg,
                ),
            )

    else:
        log_info(
            "mcp: set_review_state/add_note/import_nessus/ingest_results/"
            "set_finding_verdict not registered (mcp_allow_mutations=false)"
        )

    # --- Credential reveal (gated separately; strictly more sensitive) ---
    if cfg.mcp_allow_cred_reveal:

        @mcp.tool()
        def reveal_credential(ref: str) -> dict:
            """Return a NetExec credential's CLEARTEXT secret. SENSITIVE — do not persist.

            ref comes from list_nxc_credentials. Returns username/domain/secret_kind/
            secret_value; the reveal is audited (ref only, never the value). Available
            only because mcp_allow_cred_reveal is enabled.
            """
            return tool_reveal_credential(ref)

    else:
        log_info("mcp: reveal_credential not registered (mcp_allow_cred_reveal=false)")

    return mcp


def gating_summary(config: CernoConfig) -> str:
    """One-line description of the server's active capability gating.

    Covers execution (with allow/deny list sizes), mutations, batch (which needs
    execution too), credential injection and credential reveal.

    Logged at startup so operators can see which capabilities are live. Because
    the flags are read only when the server boots, it also reminds the operator
    to reconnect after changing them.
    """
    execution = "off"
    if config.mcp_allow_execution:
        allow = config.mcp_exec_allowlist
        if not allow:
            allow_desc = "empty=deny-all"
        elif "*" in allow:
            allow_desc = "*"
        else:
            allow_desc = f"{len(allow)} entries"
        execution = (
            f"on [allowlist={allow_desc}, "
            f"denylist={len(config.mcp_exec_denylist)} entries]"
        )

    def _onoff(flag: bool) -> str:
        return "on" if flag else "off"

    mutations = _onoff(config.mcp_allow_mutations)
    batch = _onoff(config.mcp_allow_execution and config.mcp_allow_batch)
    return (
        f"mcp: serving over stdio (execution={execution}, mutations={mutations}, "
        f"batch={batch}, cred_injection={_onoff(config.mcp_allow_cred_injection)}, "
        f"cred_reveal={_onoff(config.mcp_allow_cred_reveal)}); "
        "edit with 'cerno config set mcp_allow_<flag> ...' then reconnect to apply"
    )


def main() -> None:
    """Entry point for ``cerno mcp``: build the server and serve over stdio."""
    config = load_config()
    try:
        server = build_server(config)
    except Exception as exc:  # pragma: no cover - startup failure
        log_error(f"mcp: failed to build server: {exc}")
        raise
    # Safe: log_info writes to the log file / stderr, never stdout (the JSON-RPC channel).
    log_info(gating_summary(config))
    server.run(transport="stdio")
