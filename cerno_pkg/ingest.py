"""Ingest tool output back into the database as structured, provenance-stamped facts.

This is the shared implementation behind the MCP ``ingest_results`` tool and the
best-effort auto-ingest inside ``execute_command``; it is also usable directly by
the TUI. Everything written here is keyed to an ``execution_id`` (which carries
``executed_at`` and ``finding_id``), so live-verified facts are distinguishable
from Nessus-imported data and ingestion is fully attributable.

Ingestion is **idempotent**: re-ingesting the same ``execution_id`` deletes that
execution's prior rows and rewrites them, so it never duplicates. It is also
forgiving of partial/failed/empty runs — nothing to parse yields a summary with
``skipped_reason`` set rather than an error.

- nmap: parses the execution's ``nmap_xml`` artifact into ``verified_ports`` and
  ``nse_script_results`` (reusing :mod:`cerno_pkg.nmap_parse`).
- nxc/netexec: re-reads the NetExec workspace (via :mod:`cerno_pkg.nxc_db`) for
  the execution's finding hosts and snapshots security flags into
  ``nxc_flag_observations``. Credentials/shares are **not** duplicated here; they
  stay live-read via ``nxc_db`` to avoid a divergent second store.
"""

from __future__ import annotations

import shlex
import sqlite3
from dataclasses import dataclass, field
from typing import Optional

from . import exec_chain, nxc_db
from .database import db_transaction, query_all, query_one
from .logging_setup import log_debug, log_info
from .models import (
    Artifact,
    ArtifactType,
    Host,
    NseVerdict,
    Port,
    PortState,
)
from .nmap_parse import parse_nmap_xml
from .parsing import detect_host_type

_NMAP_TOOLS = {"nmap"}
_NXC_TOOLS = {"nxc", "netexec"}


def _resolve_effective_tool(command_text: Optional[str]) -> Optional[str]:
    """Resolve the ingester tool ('nmap'|'nxc') from a logged command string.

    Delegates to the shared :func:`exec_chain.effective_tool` so dispatch matches
    the exec-policy's view of the target binary. Returns None on an empty or
    unparseable command.
    """
    if not command_text:
        return None
    try:
        argv = shlex.split(command_text)
    except ValueError:
        return None
    return exec_chain.effective_tool(argv)


# nxc security flags to snapshot, as (attribute on NxcSecurityFlags, stored flag_name)
_SMB_FLAG_FIELDS = (
    ("signing_required", "signing_required"),
    ("smbv1_enabled", "smbv1"),
    ("zerologon_vulnerable", "zerologon"),
    ("petitpotam_vulnerable", "petitpotam"),
)


@dataclass
class IngestSummary:
    """Outcome of ingesting one execution."""

    execution_id: int
    tool_name: str
    verified_ports: int = 0
    nse_results: int = 0
    nxc_flags: int = 0
    nse_verdicts: dict[str, int] = field(default_factory=dict)
    skipped_reason: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "execution_id": self.execution_id,
            "tool_name": self.tool_name,
            "verified_ports": self.verified_ports,
            "nse_results": self.nse_results,
            "nxc_flags": self.nxc_flags,
            "nse_verdicts": dict(self.nse_verdicts),
            "skipped_reason": self.skipped_reason,
        }


def _scan_target_type(address: str) -> str:
    """Map a host address to a valid hosts.scan_target_type value."""
    detected = detect_host_type(address)
    return "fqdn" if detected == "hostname" else detected


def _resolve_host_id(address: str, conn: sqlite3.Connection) -> int:
    """Find an existing host_id for an IP, else create one keyed by (ip, ip)."""
    existing = Host.get_by_ip(address, conn)
    if existing:
        host_id = existing[0].host_id
        if host_id is not None:
            return host_id
    return Host.get_or_create(address, address, _scan_target_type(address), conn=conn)


def _reconcile_execution_rows(
    conn: sqlite3.Connection,
    *,
    table: str,
    pk_col: str,
    execution_id: int,
    key_cols: tuple[str, ...],
    mutable_cols: tuple[str, ...],
    rows: list[dict],
) -> list[int]:
    """Idempotently write this execution's rows, preserving unchanged rows' PKs.

    Matches parsed ``rows`` against existing rows by ``key_cols`` **in Python**
    (so a NULL key part matches — SQLite treats NULLs as distinct in a UNIQUE
    index, which would otherwise duplicate NSE host-script rows): an existing
    match is UPDATEd in place (PK kept), a new key is INSERTed, and any existing
    row for this execution whose key is absent from ``rows`` is pruned. This keeps
    ``verdict_evidence`` FKs (ON DELETE SET NULL) intact across re-ingest.

    ``table``/``pk_col``/column names are internal constants, never user input.
    """
    existing: dict[tuple, int] = {
        tuple(r[k] for k in key_cols): r[pk_col]
        for r in query_all(
            conn,
            f"SELECT {pk_col}, {', '.join(key_cols)} FROM {table} WHERE execution_id = ?",
            (execution_id,),
        )
    }

    kept: list[int] = []
    for row in rows:
        key = tuple(row[k] for k in key_cols)
        pk = existing.get(key)
        if pk is not None:
            if mutable_cols:
                set_clause = ", ".join(f"{c} = ?" for c in mutable_cols)
                conn.execute(
                    f"UPDATE {table} SET {set_clause} WHERE {pk_col} = ?",
                    (*(row[c] for c in mutable_cols), pk),
                )
        else:
            cols = list(row.keys())
            cursor = conn.execute(
                f"INSERT INTO {table} ({', '.join(cols)}) "
                f"VALUES ({', '.join('?' * len(cols))})",
                tuple(row[c] for c in cols),
            )
            new_pk = cursor.lastrowid
            assert new_pk is not None  # INSERT always sets lastrowid
            pk = new_pk
            existing[key] = pk  # register so a duplicate key in this batch updates
        kept.append(pk)

    # Prune rows that disappeared from this execution's current output.
    if kept:
        placeholders = ", ".join("?" * len(kept))
        conn.execute(
            f"DELETE FROM {table} WHERE execution_id = ? AND {pk_col} NOT IN ({placeholders})",
            (execution_id, *kept),
        )
    else:
        conn.execute(f"DELETE FROM {table} WHERE execution_id = ?", (execution_id,))
    return kept


def _ingest_nmap(
    execution_id: int, conn: sqlite3.Connection, summary: IngestSummary
) -> None:
    artifacts = Artifact.get_by_execution(execution_id, conn)
    xml_type = ArtifactType.get_by_name("nmap_xml", conn)
    xml_type_id = xml_type.artifact_type_id if xml_type else None
    xml_artifact = next(
        (
            a
            for a in artifacts
            if a.artifact_type_id == xml_type_id and xml_type_id is not None
        ),
        None,
    )
    if xml_artifact is None:
        summary.skipped_reason = "no nmap_xml artifact registered for this execution"
        return

    parsed = parse_nmap_xml(xml_artifact.artifact_path)
    if parsed.is_empty:
        summary.skipped_reason = "nmap XML contained no hosts/ports/scripts"
        return

    host_id_cache: dict[str, int] = {}

    def host_id_for(address: str) -> int:
        if address not in host_id_cache:
            host_id_cache[address] = _resolve_host_id(address, conn)
        return host_id_cache[address]

    port_rows: list[dict] = []
    for port in parsed.ports:
        if port.state != "open":
            continue
        Port.get_or_create(port.port, port.service_name, conn=conn)
        port_rows.append(
            {
                "execution_id": execution_id,
                "host_id": host_id_for(port.host),
                "port_number": port.port,
                "protocol": port.protocol,
                "port_state_id": PortState.id_for_label(port.state, conn),
                "service_name": port.service_name,
            }
        )
    summary.verified_ports = len(port_rows)
    _reconcile_execution_rows(
        conn,
        table="verified_ports",
        pk_col="verified_port_id",
        execution_id=execution_id,
        key_cols=("host_id", "port_number", "protocol"),
        mutable_cols=("port_state_id", "service_name"),
        rows=port_rows,
    )

    nse_rows: list[dict] = []
    for script in parsed.scripts:
        if script.port is not None:
            Port.get_or_create(script.port, None, conn=conn)
        nse_rows.append(
            {
                "execution_id": execution_id,
                "host_id": host_id_for(script.host),
                "port_number": script.port,
                "script_id": script.script_id,
                "nse_verdict_id": NseVerdict.id_for_label(script.verdict, conn),
                "output": script.raw_output,
            }
        )
        summary.nse_verdicts[script.verdict] = (
            summary.nse_verdicts.get(script.verdict, 0) + 1
        )
    summary.nse_results = len(nse_rows)
    _reconcile_execution_rows(
        conn,
        table="nse_script_results",
        pk_col="nse_result_id",
        execution_id=execution_id,
        key_cols=("host_id", "port_number", "script_id"),
        mutable_cols=("nse_verdict_id", "output"),
        rows=nse_rows,
    )

    if summary.verified_ports == 0 and summary.nse_results == 0:
        summary.skipped_reason = "no open ports or NSE results in nmap output"


def _finding_host_map(finding_id: int, conn: sqlite3.Connection) -> dict[str, int]:
    """Return {ip_address: host_id} for all hosts affected by a finding."""
    rows = query_all(
        conn,
        """
        SELECT DISTINCT h.host_id, h.ip_address
        FROM finding_affected_hosts fah
        JOIN hosts h ON fah.host_id = h.host_id
        WHERE fah.finding_id = ?
        """,
        (finding_id,),
    )
    return {r["ip_address"]: r["host_id"] for r in rows if r["ip_address"]}


def _ingest_nxc(
    execution_id: int,
    finding_id: Optional[int],
    conn: sqlite3.Connection,
    summary: IngestSummary,
) -> None:
    if finding_id is None:
        summary.skipped_reason = "execution has no finding_id to resolve nxc hosts"
        return

    manager = nxc_db.get_nxc_manager()
    if manager is None:
        summary.skipped_reason = "NetExec workspace unavailable or disabled"
        return

    host_map = _finding_host_map(finding_id, conn)
    if not host_map:
        summary.skipped_reason = "finding has no affected hosts"
        return

    enrichment = manager.get_hosts_enrichment(list(host_map.keys()))

    flag_rows: list[dict] = []
    for ip, host_data in enrichment.per_host_data.items():
        host_id = host_map.get(ip)
        if host_id is None:
            continue

        if host_data.security_flags is not None:
            for attr, flag_name in _SMB_FLAG_FIELDS:
                value = getattr(host_data.security_flags, attr)
                flag_rows.append(
                    {
                        "execution_id": execution_id,
                        "host_id": host_id,
                        "protocol": "smb",
                        "flag_name": flag_name,
                        "flag_value": 1 if value else 0,
                    }
                )

        # Boolean flags surfaced per-protocol (e.g. ldap signing_required, rdp nla)
        for protocol, details in host_data.protocol_details.items():
            for key, value in details.items():
                if isinstance(value, bool):
                    flag_rows.append(
                        {
                            "execution_id": execution_id,
                            "host_id": host_id,
                            "protocol": protocol,
                            "flag_name": key,
                            "flag_value": 1 if value else 0,
                        }
                    )

    summary.nxc_flags = len(flag_rows)
    _reconcile_execution_rows(
        conn,
        table="nxc_flag_observations",
        pk_col="nxc_flag_id",
        execution_id=execution_id,
        key_cols=("host_id", "protocol", "flag_name"),
        mutable_cols=("flag_value",),
        rows=flag_rows,
    )


def ingest_execution(
    execution_id: int, *, conn: Optional[sqlite3.Connection] = None
) -> IngestSummary:
    """Parse a completed execution's output into structured facts (idempotent).

    Args:
        execution_id: The tool_executions row to ingest.
        conn: Optional connection (the whole ingest runs in one transaction).

    Returns:
        An :class:`IngestSummary` (counts + optional ``skipped_reason``). Never
        raises on empty/partial/unknown runs.
    """
    with db_transaction(conn) as c:
        row = query_one(
            c,
            "SELECT execution_id, tool_name, command_text, finding_id "
            "FROM tool_executions WHERE execution_id = ?",
            (execution_id,),
        )
        if row is None:
            return IngestSummary(
                execution_id, "", skipped_reason="unknown execution_id"
            )

        tool_name = (row["tool_name"] or "").strip().lower()
        finding_id = row["finding_id"]
        summary = IngestSummary(execution_id=execution_id, tool_name=tool_name)

        # Dispatch on the real target binary, not the free-text tool_name label:
        # the MCP server records every run as tool_name="mcp", so the actual tool
        # must be resolved from command_text (unwrapping sudo/proxychains4/etc.).
        effective = tool_name if tool_name in (_NMAP_TOOLS | _NXC_TOOLS) else None
        if effective is None:
            effective = _resolve_effective_tool(row["command_text"])

        if effective in _NMAP_TOOLS:
            _ingest_nmap(execution_id, c, summary)
        elif effective in _NXC_TOOLS:
            _ingest_nxc(execution_id, finding_id, c, summary)
        else:
            summary.skipped_reason = f"no ingester for tool '{tool_name}'"

        if summary.skipped_reason:
            log_debug(f"ingest_execution({execution_id}): {summary.skipped_reason}")
        else:
            log_info(
                f"ingest_execution({execution_id}): {summary.verified_ports} ports, "
                f"{summary.nse_results} NSE results, {summary.nxc_flags} nxc flags"
            )
        return summary
