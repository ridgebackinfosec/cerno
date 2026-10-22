"""Tests for result ingestion (cerno_pkg.ingest)."""

import sqlite3
from pathlib import Path

import pytest

from cerno_pkg import ingest
from cerno_pkg.models import (
    Artifact,
    ArtifactType,
    FindingVerdict,
    NseScriptResult,
    VerdictEvidence,
    VerifiedPort,
)

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


def _seed_nmap_execution(
    conn: sqlite3.Connection,
    xml_name: str,
    *,
    tool_name: str = "nmap",
    command_text: str = "nmap -oA x",
) -> int:
    """Seed a scan/plugin/finding + nmap execution with an nmap_xml artifact.

    ``tool_name``/``command_text`` let a test mimic how the MCP server logs runs
    (every run as tool_name="mcp", the real binary only in command_text).

    Returns the execution_id.
    """
    conn.execute("INSERT INTO scans (scan_name, export_root) VALUES ('s', '/tmp')")
    scan_id = conn.execute("SELECT scan_id FROM scans").fetchone()["scan_id"]
    conn.execute(
        "INSERT INTO plugins (plugin_id, plugin_name, severity_int) VALUES (100, 'SMB', 3)"
    )
    conn.execute(
        "INSERT INTO findings (scan_id, plugin_id) VALUES (?, 100)", (scan_id,)
    )
    finding_id = conn.execute("SELECT finding_id FROM findings").fetchone()[
        "finding_id"
    ]
    conn.execute(
        "INSERT INTO tool_executions (tool_name, command_text, finding_id) "
        "VALUES (?, ?, ?)",
        (tool_name, command_text, finding_id),
    )
    execution_id = conn.execute("SELECT execution_id FROM tool_executions").fetchone()[
        "execution_id"
    ]
    type_id = ArtifactType.get_by_name("nmap_xml", conn).artifact_type_id
    Artifact(
        execution_id=execution_id,
        artifact_path=str(FIXTURES / xml_name),
        artifact_type_id=type_id,
    ).save(conn)
    conn.commit()
    return execution_id


@pytest.mark.integration
class TestIngestNmap:
    def test_ingests_ports_and_nse_verdicts(self, temp_db: sqlite3.Connection) -> None:
        eid = _seed_nmap_execution(temp_db, "ms17_vulnerable.xml")
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.skipped_reason is None
        assert summary.verified_ports == 2  # 445 + 139
        assert summary.nse_results == 2
        assert summary.nse_verdicts.get("VULNERABLE") == 1
        rows = VerifiedPort.get_by_execution(eid, temp_db)
        assert {r.port_number for r in rows} == {445, 139}

    def test_idempotent_reingest(self, temp_db: sqlite3.Connection) -> None:
        eid = _seed_nmap_execution(temp_db, "ms17_vulnerable.xml")
        ingest.ingest_execution(eid, conn=temp_db)
        ingest.ingest_execution(eid, conn=temp_db)
        assert len(VerifiedPort.get_by_execution(eid, temp_db)) == 2
        assert len(NseScriptResult.get_by_execution(eid, temp_db)) == 2

    def test_empty_run_sets_skipped_reason(self, temp_db: sqlite3.Connection) -> None:
        eid = _seed_nmap_execution(temp_db, "no_hosts_up.xml")
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.verified_ports == 0
        assert summary.nse_results == 0
        assert summary.skipped_reason is not None

    def test_missing_artifact_skips_gracefully(
        self, temp_db: sqlite3.Connection
    ) -> None:
        temp_db.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES ('s', '/tmp')"
        )
        sid = temp_db.execute("SELECT scan_id FROM scans").fetchone()["scan_id"]
        temp_db.execute(
            "INSERT INTO plugins (plugin_id, plugin_name, severity_int) VALUES (1,'P',1)"
        )
        temp_db.execute(
            "INSERT INTO findings (scan_id, plugin_id) VALUES (?,1)", (sid,)
        )
        fid = temp_db.execute("SELECT finding_id FROM findings").fetchone()[
            "finding_id"
        ]
        temp_db.execute(
            "INSERT INTO tool_executions (tool_name, command_text, finding_id) VALUES ('nmap','x',?)",
            (fid,),
        )
        eid = temp_db.execute("SELECT execution_id FROM tool_executions").fetchone()[
            "execution_id"
        ]
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.skipped_reason is not None
        assert summary.verified_ports == 0


@pytest.mark.integration
class TestIngestDispatch:
    """Dispatch must follow the real binary in command_text, not the free-text
    tool_name label — the MCP server logs every run as tool_name='mcp'."""

    def test_mcp_labelled_nmap_dispatches_to_nmap(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nmap_execution(
            temp_db,
            "ms17_vulnerable.xml",
            tool_name="mcp",
            command_text="nmap -A -p 445 -oA out -iL ips.txt",
        )
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.skipped_reason is None
        assert summary.verified_ports == 2
        assert "no ingester" not in (summary.skipped_reason or "")

    def test_mcp_labelled_nmap_with_wrapper_dispatches(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nmap_execution(
            temp_db,
            "ms17_vulnerable.xml",
            tool_name="mcp",
            command_text="sudo proxychains4 -q nmap -A -oA out",
        )
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.verified_ports == 2

    def test_mcp_labelled_nxc_dispatches_to_nxc(
        self, temp_db: sqlite3.Connection
    ) -> None:
        # No finding hosts / no nxc workspace -> benign nxc-specific skip, and
        # crucially NOT "no ingester for tool 'mcp'".
        temp_db.execute(
            "INSERT INTO tool_executions (tool_name, command_text) "
            "VALUES ('mcp', 'nxc smb targets --shares')"
        )
        eid = temp_db.execute("SELECT execution_id FROM tool_executions").fetchone()[
            "execution_id"
        ]
        temp_db.commit()
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert "no ingester" not in (summary.skipped_reason or "")

    def test_mcp_labelled_empty_nmap_is_benign(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nmap_execution(
            temp_db,
            "no_hosts_up.xml",
            tool_name="mcp",
            command_text="nmap -A -oA out",
        )
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.verified_ports == 0
        assert summary.skipped_reason is not None
        assert "no ingester" not in summary.skipped_reason

    def test_mcp_labelled_unknown_binary_skips(
        self, temp_db: sqlite3.Connection
    ) -> None:
        temp_db.execute(
            "INSERT INTO tool_executions (tool_name, command_text) "
            "VALUES ('mcp', 'curl http://x')"
        )
        eid = temp_db.execute("SELECT execution_id FROM tool_executions").fetchone()[
            "execution_id"
        ]
        temp_db.commit()
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert "no ingester" in (summary.skipped_reason or "")


@pytest.mark.integration
class TestReingestStability:
    """Re-ingest must preserve fact-row PKs so verdict evidence FKs survive."""

    def _pks(self, conn: sqlite3.Connection, eid: int) -> tuple[list[int], list[int]]:
        vp = [r.verified_port_id for r in VerifiedPort.get_by_execution(eid, conn)]
        nse = [r.nse_result_id for r in NseScriptResult.get_by_execution(eid, conn)]
        return sorted(vp), sorted(nse)

    def test_pks_stable_across_reingest(self, temp_db: sqlite3.Connection) -> None:
        eid = _seed_nmap_execution(temp_db, "ms17_vulnerable.xml")
        ingest.ingest_execution(eid, conn=temp_db)
        vp1, nse1 = self._pks(temp_db, eid)
        ingest.ingest_execution(eid, conn=temp_db)
        vp2, nse2 = self._pks(temp_db, eid)
        assert vp1 == vp2 and nse1 == nse2
        assert len(vp2) == 2 and len(nse2) == 2  # no duplicates

    def test_verdict_evidence_survives_reingest(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nmap_execution(temp_db, "ms17_vulnerable.xml")
        ingest.ingest_execution(eid, conn=temp_db)
        finding_id = temp_db.execute("SELECT finding_id FROM findings").fetchone()[
            "finding_id"
        ]
        nse_pk = NseScriptResult.get_by_execution(eid, temp_db)[0].nse_result_id
        FindingVerdict.set(
            finding_id,
            "confirmed",
            evidence=[VerdictEvidence(execution_id=eid, nse_result_id=nse_pk)],
            conn=temp_db,
        )
        ingest.ingest_execution(eid, conn=temp_db)  # re-ingest same artifact
        row = temp_db.execute("SELECT nse_result_id FROM verdict_evidence").fetchone()
        assert row["nse_result_id"] == nse_pk  # not nulled

    def test_content_change_prunes_stale_keeps_survivor(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nmap_execution(temp_db, "ms17_vulnerable.xml")  # ports 445 + 139
        ingest.ingest_execution(eid, conn=temp_db)
        pk_445 = next(
            r.verified_port_id
            for r in VerifiedPort.get_by_execution(eid, temp_db)
            if r.port_number == 445
        )
        # Point the same execution's artifact at a trimmed scan (only 445).
        temp_db.execute(
            "UPDATE artifacts SET artifact_path = ? WHERE execution_id = ?",
            (str(FIXTURES / "ms17_one_port.xml"), eid),
        )
        temp_db.commit()
        ingest.ingest_execution(eid, conn=temp_db)
        ports = VerifiedPort.get_by_execution(eid, temp_db)
        assert {p.port_number for p in ports} == {445}  # 139 pruned
        assert ports[0].verified_port_id == pk_445  # survivor kept its PK


@pytest.mark.integration
class TestIngestEdgeCases:
    def test_unknown_execution_id(self, temp_db: sqlite3.Connection) -> None:
        summary = ingest.ingest_execution(999, conn=temp_db)
        assert summary.skipped_reason == "unknown execution_id"

    def test_unknown_tool_no_op(self, temp_db: sqlite3.Connection) -> None:
        temp_db.execute(
            "INSERT INTO tool_executions (tool_name, command_text) VALUES ('curl', 'curl x')"
        )
        eid = temp_db.execute("SELECT execution_id FROM tool_executions").fetchone()[
            "execution_id"
        ]
        temp_db.commit()
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert "no ingester" in (summary.skipped_reason or "")
