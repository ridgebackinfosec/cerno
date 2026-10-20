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
import fnmatch
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional, Sequence, cast

# Pydantic (via FastMCP output schemas) requires typing_extensions.TypedDict on
# Python < 3.12; typing_extensions ships with mcp/pydantic, so always use it.
from typing_extensions import TypedDict

from mcp.server.fastmcp import Context, FastMCP

from ..config import CernoConfig, load_config
from ..constants import REVIEW_STATES
from ..logging_setup import log_error, log_info

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


class FindingSearchResult(FindingSummary, total=False):
    scan_name: str


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


def tool_list_findings(
    scan_ids: list[int],
    *,
    severity_int: Optional[int] = None,
    review_state: Optional[str] = None,
    has_metasploit: Optional[bool] = None,
    plugin_name: Optional[str] = None,
    merged: bool = False,
    limit: int = 500,
    offset: int = 0,
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
        offset: Number of findings to skip before ``limit`` (for paging).
    """
    from ..models import Finding

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
    if limit is not None and limit >= 0:
        results = results[:limit]
    return results


def tool_search_findings(
    *,
    plugin_name: Optional[str] = None,
    severity_int: Optional[int] = None,
    has_metasploit: Optional[bool] = None,
    limit: int = 500,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """Search findings across ALL scans (no scan_ids required).

    Answers questions like "every host with a critical SMB finding anywhere".
    Each result carries its ``scan_name`` for cross-scan context. Results are
    capped at ``limit``.
    """
    from ..models import Finding, Scan

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
    """Report which gated capabilities are live, so an agent can self-orient."""
    from ..nxc_db import get_nxc_manager

    cfg = config or load_config()
    return {
        "execution_enabled": cfg.mcp_allow_execution,
        "mutations_enabled": cfg.mcp_allow_mutations,
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


def tool_get_workflow(plugin_id: int) -> Optional[dict]:
    """Return the verification workflow mapped to a plugin, or None if none exists."""
    from ..workflow_mapper import WorkflowMapper

    workflow = WorkflowMapper().get_workflow(str(plugin_id))
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
    from ..models import Finding, Plugin, SeverityLevel

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        plugin = Plugin.get_by_id(finding.plugin_id, c)
        if plugin is None:
            raise ValueError(f"No plugin with id {finding.plugin_id}")
        sev = SeverityLevel.get_by_int(plugin.severity_int, c)
        outputs = finding.get_plugin_outputs_by_host(c)

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
    from ..ops import get_tool_version

    specs = {
        "nmap": ["nmap"],
        "netexec": ["nxc", "netexec"],
        "msfconsole": ["msfconsole"],
        "proxychains4": ["proxychains4"],
    }
    result: dict[str, dict] = {}
    for name, candidates in specs.items():
        version = get_tool_version(name, candidates)
        result[name] = {"installed": version is not None, "version": version}
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
    """Return all current Cerno config settings (read-only), with resolved paths."""
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
    credentials = [
        {**dataclasses.asdict(cred), "host_count": count}
        for cred, count in summary.unique_credentials
    ]
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
    """Directory under results_root where a finding's target/output files live."""
    from ..constants import get_results_root

    d = get_results_root(config) / "_mcp" / str(finding_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


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
    udp: bool = False,
    nse_option: Optional[str] = None,
    use_sudo: bool = False,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Build (but do not run) an nmap command targeting a finding's hosts/ports."""
    from ..models import Finding
    from ..tools import build_nmap_cmd

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        hosts, ports_str = finding.get_hosts_and_ports(c)

    ips_file, output_base = _write_targets_file(finding_id, hosts, config)
    cmd = build_nmap_cmd(udp, nse_option, ips_file, ports_str, use_sudo, output_base)
    return {"command": cmd, "ips_file": str(ips_file), "output_base": str(output_base)}


def tool_generate_netexec_cmd(
    finding_id: int,
    protocol: str,
    *,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> dict:
    """Build (but do not run) a netexec command targeting a finding's hosts."""
    from ..models import Finding
    from ..ops import resolve_cmd
    from ..tools import build_netexec_cmd

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        hosts, _ = finding.get_hosts_and_ports(c)

    exec_bin = resolve_cmd(["nxc", "netexec"]) or "nxc"
    ips_file, output_base = _write_targets_file(finding_id, hosts, config)
    cmd, log_path, relay_path = build_netexec_cmd(
        exec_bin, protocol, ips_file, output_base
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


# ========== Execution (gated by mcp_allow_execution) ==========


#: Hard ceiling on execute_command timeouts (seconds).
_MAX_EXEC_TIMEOUT = 3600


@dataclasses.dataclass(frozen=True)
class _WrapperSpec:
    """How to step past a wrapper binary's own arguments to its wrapped command.

    ``short_val`` are short option letters that consume a value; ``long_val`` are
    ``--long`` options whose value is a separate argument. ``skip_positionals``
    is the count of positional arguments before the command (e.g. ``timeout``'s
    DURATION), and ``assignments`` skips leading ``NAME=VALUE`` tokens (``env``).
    """

    short_val: frozenset[str] = frozenset()
    long_val: frozenset[str] = frozenset()
    skip_positionals: int = 0
    assignments: bool = False


#: Wrapper binaries that run another command. The wrapped target is unwrapped so
#: policy applies to what actually runs — e.g. ``env rm`` or ``timeout 5 rm``
#: must expose ``rm`` to the denylist, not hide it behind the wrapper. The
#: positional-mask wrappers ``taskset`` / ``chrt`` are deliberately omitted (their
#: grammar is ambiguous to parse without running them).
_EXEC_WRAPPERS: dict[str, _WrapperSpec] = {
    "sudo": _WrapperSpec(
        short_val=frozenset("ugCDhprtUT"),
        long_val=frozenset(
            {
                "--user",
                "--group",
                "--close-from",
                "--chdir",
                "--host",
                "--prompt",
                "--role",
                "--type",
                "--other-user",
                "--command-timeout",
            }
        ),
    ),
    # doas takes a subset of sudo's value options; overmatching is harmless here.
    "doas": _WrapperSpec(short_val=frozenset("uCa")),
    "proxychains4": _WrapperSpec(short_val=frozenset("f")),
    "proxychains": _WrapperSpec(short_val=frozenset("f")),
    "env": _WrapperSpec(
        short_val=frozenset("uCS"),
        long_val=frozenset({"--unset", "--chdir", "--split-string"}),
        assignments=True,
    ),
    "nice": _WrapperSpec(short_val=frozenset("n")),
    "timeout": _WrapperSpec(
        short_val=frozenset("sk"),
        long_val=frozenset({"--signal", "--kill-after"}),
        skip_positionals=1,  # DURATION
    ),
    "stdbuf": _WrapperSpec(short_val=frozenset("ioe")),
    "ionice": _WrapperSpec(short_val=frozenset("cnp")),
    "setsid": _WrapperSpec(),
    "nohup": _WrapperSpec(),
    # /usr/bin/time (the shell builtin never reaches an argv list).
    "time": _WrapperSpec(
        short_val=frozenset("of"),
        long_val=frozenset({"--output", "--format"}),
    ),
}


def _skip_wrapper_options(command: Sequence[Any], i: int, spec: _WrapperSpec) -> int:
    """Return the index of the wrapper's command, stepping past its arguments.

    Handles getopt-style options (short flags may be clustered as ``-Eu root`` or
    carry an attached value as ``-uroot``; ``--`` ends option parsing), then any
    ``NAME=VALUE`` assignments (``env``), then ``skip_positionals`` positionals
    (``timeout`` DURATION).
    """
    short_vals, long_vals = spec.short_val, spec.long_val
    while i < len(command):
        arg = str(command[i])
        if arg == "--":
            i += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        if arg.startswith("--"):
            i += 2 if arg in long_vals else 1
            continue
        i += 1
        for pos, letter in enumerate(arg[1:], start=1):
            if letter in short_vals:
                if pos == len(arg) - 1:  # value is the next argument
                    i += 1
                break  # anything after the letter is its attached value

    if spec.assignments:
        while i < len(command):
            arg = str(command[i])
            if "=" in arg and not arg.startswith("-"):
                i += 1
            else:
                break

    i += spec.skip_positionals
    return i


def _command_chain(command: Sequence[Any]) -> list[str]:
    """Basenames of every binary in ``command``, unwrapping known wrappers.

    ``["sudo", "-u", "root", "proxychains4", "-q", "nmap", ...]`` yields
    ``["sudo", "proxychains4", "nmap"]``; the last entry is the real target. Known
    wrappers (``_EXEC_WRAPPERS``) such as sudo, env, timeout and nice are stepped
    past so the wrapped command is exposed. Raises ValueError if a wrapper is left
    with no command to run (fail closed).
    """
    chain: list[str] = []
    i = 0
    while i < len(command):
        name = Path(str(command[i])).name
        chain.append(name)
        spec = _EXEC_WRAPPERS.get(name)
        if spec is None:
            return chain
        i = _skip_wrapper_options(command, i + 1, spec)
    raise ValueError(
        f"{chain[-1]!r} does not wrap a command to run"
        if chain
        else "command must be a non-empty list of arguments"
    )


def _matches_any(name: str, patterns: Sequence[str]) -> bool:
    """True if ``name`` matches any glob pattern (``*`` matches everything)."""
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


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
    """
    from ..ops import ProxyConfig, log_tool_execution, run_command_captured

    if not command:
        raise ValueError("command must be a non-empty list of arguments")

    cfg = config or load_config()

    _check_exec_policy(command, cfg.mcp_exec_allowlist, cfg.mcp_exec_denylist)

    timeout = max(1, min(int(timeout), _MAX_EXEC_TIMEOUT))

    proxy = None
    if use_proxy and cfg.proxychains_enabled:
        proxy = ProxyConfig(
            enabled=True,
            host=cfg.proxychains_host,
            port=cfg.proxychains_port,
            quiet=True,
        )

    meta, stdout, stderr = run_command_captured(
        command, timeout=timeout, proxy_config=proxy
    )

    command_text = " ".join(str(x) for x in command)
    with _db(conn) as c:
        execution_id = log_tool_execution(
            tool_name,
            command_text,
            meta,
            finding_id=finding_id,
            conn=c,
        )

    return {
        "exit_code": meta.exit_code,
        "duration_seconds": round(meta.duration_seconds, 3),
        "used_sudo": meta.used_sudo,
        "execution_id": execution_id,
        "stdout": stdout,
        "stderr": stderr,
    }


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
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> str:
    """`cerno://finding/{finding_id}/workflow` — verification workflow, or a notice."""
    from ..models import Finding

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        plugin_id = finding.plugin_id
    workflow = tool_get_workflow(plugin_id)
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


# ========== Prompts (read-only triage/report templates) ==========
# Prompts reuse the same context builders as the in-TUI [A] assistant so the
# TUI and MCP produce consistent briefs.


def _finding_context(finding_id: int, conn: Optional[sqlite3.Connection]) -> str:
    """Assemble the shared finding context block (plugin + hosts + output + workflow)."""
    from ..claude_assistant import build_finding_context
    from ..models import Finding, Plugin
    from ..workflow_mapper import WorkflowMapper

    with _db(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        plugin = Plugin.get_by_id(finding.plugin_id, c)
        if plugin is None:
            raise ValueError(f"No plugin with id {finding.plugin_id}")
        hosts, _ = finding.get_hosts_and_ports(c)
        outputs = finding.get_plugin_outputs_by_host(c)
    workflow = WorkflowMapper().get_workflow(str(finding.plugin_id))
    return build_finding_context(plugin, finding, hosts, outputs, workflow)


def prompt_triage_finding(
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> str:
    """Report-brief prompt for a single finding."""
    from ..claude_assistant import REPORT_BRIEF_QUERY

    return f"{_finding_context(finding_id, conn)}\n\n{REPORT_BRIEF_QUERY}"


def prompt_exploit_plan(
    finding_id: int, conn: Optional[sqlite3.Connection] = None
) -> str:
    """Exploitation-planning prompt for a single finding."""
    instruction = (
        "Based on the context above, outline the fastest viable path to exploit or "
        "verify this finding. Name any Metasploit modules listed; identify which "
        "affected hosts are most promising and why; and give the concrete next "
        "verification step (an nmap, netexec, or msfconsole command). Be concise and "
        "flag uncertainty. Always verify before acting."
    )
    return f"{_finding_context(finding_id, conn)}\n\n{instruction}"


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
        limit: int = 500,
        offset: int = 0,
    ) -> list[FindingSummary]:
        """List findings across scans, filtered and paged.

        merged=True dedups multi-scan results by plugin (TUI semantics); limit/
        offset page the result.
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
            ),
        )

    @mcp.tool()
    def search_findings(
        plugin_name: Optional[str] = None,
        severity_int: Optional[int] = None,
        has_metasploit: Optional[bool] = None,
        limit: int = 500,
    ) -> list[FindingSearchResult]:
        """Search findings across ALL scans (no scan_ids needed); each carries scan_name."""
        return cast(
            "list[FindingSearchResult]",
            tool_search_findings(
                plugin_name=plugin_name,
                severity_int=severity_int,
                has_metasploit=has_metasploit,
                limit=limit,
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
        return tool_get_workflow(plugin_id)

    @mcp.tool()
    def get_finding_detail(finding_id: int, max_hosts: int = 100) -> FindingDetail:
        """Get full detail for a finding: plugin metadata + per-host plugin output (capped)."""
        return cast(
            "FindingDetail", tool_get_finding_detail(finding_id, max_hosts=max_hosts)
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
        """Report which gated capabilities (execution/mutations/nxc) are live."""
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
        udp: bool = False,
        nse_option: Optional[str] = None,
        use_sudo: bool = False,
    ) -> NmapCommand:
        """Build an nmap command for a finding's hosts/ports (does not run it)."""
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
    def generate_netexec_cmd(finding_id: int, protocol: str) -> NetexecCommand:
        """Build a netexec command for a finding's hosts (does not run it)."""
        return cast(
            "NetexecCommand",
            tool_generate_netexec_cmd(finding_id, protocol, config=cfg),
        )

    @mcp.tool()
    def generate_msf_search(finding_id: int) -> MsfSearchCommand:
        """Build an msfconsole search command for a finding's Metasploit modules."""
        return cast("MsfSearchCommand", tool_generate_msf_search(finding_id))

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
        return resource_finding_workflow(finding_id)

    @mcp.resource("cerno://config", mime_type="application/json")
    def config_resource() -> str:
        """All current Cerno config settings (read-only)."""
        return resource_config()

    @mcp.resource("cerno://host/{host_ip}/nxc", mime_type="application/json")
    def host_nxc_resource(host_ip: str) -> str:
        """NetExec enrichment for a host (credentials, shares, security flags)."""
        return resource_host_nxc(host_ip)

    # --- Prompts (always on; triage/report templates) ---
    @mcp.prompt()
    def triage_finding(finding_id: int) -> str:
        """Draft a pentest-report brief for a single finding."""
        return prompt_triage_finding(finding_id)

    @mcp.prompt()
    def exploit_plan(finding_id: int) -> str:
        """Outline the fastest viable exploitation/verification path for a finding."""
        return prompt_exploit_plan(finding_id)

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
            timeout is clamped to [1, 3600]s. Pass finding_id to attribute the run
            to a finding (so get_finding_artifacts can later find its output).

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

    else:
        log_info("mcp: execute_command not registered (mcp_allow_execution=false)")

    # --- Mutations (gated) ---
    if cfg.mcp_allow_mutations:

        @mcp.tool()
        def set_review_state(
            finding_id: int, new_state: str, notes: Optional[str] = None
        ) -> dict:
            """Move a finding's review state: unreviewed -> in_progress -> done; done -> unreviewed."""
            return tool_set_review_state(finding_id, new_state, notes=notes)

        @mcp.tool()
        def import_nessus(nessus_path: str) -> dict:
            """Import a .nessus file into the database."""
            return tool_import_nessus(nessus_path)

    else:
        log_info(
            "mcp: set_review_state/import_nessus not registered (mcp_allow_mutations=false)"
        )

    return mcp


def gating_summary(config: CernoConfig) -> str:
    """One-line description of the server's active execution/mutation gating.

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
    mutations = "on" if config.mcp_allow_mutations else "off"
    return (
        f"mcp: serving over stdio (execution={execution}, mutations={mutations}); "
        "edit with 'cerno config set mcp_allow_execution/mcp_allow_mutations ...' "
        "then reconnect to apply"
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
