"""Tests for finding verdicts + evidence (models + MCP adapters)."""

import sqlite3

import pytest

from cerno_pkg.models import (
    FindingVerdict,
    InvalidVerdict,
    NseScriptResult,
    NseVerdict,
    VerdictEvidence,
)
from cerno_pkg.mcp_server import server as mcp


def _seed_finding(conn: sqlite3.Connection) -> int:
    conn.execute("INSERT INTO scans (scan_name, export_root) VALUES ('s', '/tmp')")
    sid = conn.execute("SELECT scan_id FROM scans").fetchone()["scan_id"]
    conn.execute(
        "INSERT INTO plugins (plugin_id, plugin_name, severity_int) VALUES (100,'SMB',3)"
    )
    conn.execute("INSERT INTO findings (scan_id, plugin_id) VALUES (?,100)", (sid,))
    fid = conn.execute("SELECT finding_id FROM findings").fetchone()["finding_id"]
    conn.commit()
    return fid


@pytest.mark.integration
class TestFindingVerdictModel:
    def test_set_and_get_current(self, temp_db: sqlite3.Connection) -> None:
        fid = _seed_finding(temp_db)
        FindingVerdict.set(
            fid, "confirmed", note="ms17 fired", created_by="agent", conn=temp_db
        )
        current = FindingVerdict.get_current(fid, temp_db)
        assert current is not None
        assert current.verdict_label == "confirmed"
        assert current.note == "ms17 fired"

    def test_history_latest_is_current(self, temp_db: sqlite3.Connection) -> None:
        fid = _seed_finding(temp_db)
        FindingVerdict.set(fid, "unable", conn=temp_db)
        FindingVerdict.set(fid, "confirmed", conn=temp_db)
        history = FindingVerdict.get_history(fid, temp_db)
        assert len(history) == 2
        current = FindingVerdict.get_current(fid, temp_db)
        assert current is not None and current.verdict_label == "confirmed"

    def test_invalid_verdict_raises(self, temp_db: sqlite3.Connection) -> None:
        fid = _seed_finding(temp_db)
        with pytest.raises(InvalidVerdict):
            FindingVerdict.set(fid, "bogus", conn=temp_db)

    def test_evidence_linked(self, temp_db: sqlite3.Connection) -> None:
        fid = _seed_finding(temp_db)
        temp_db.execute(
            "INSERT INTO tool_executions (tool_name, command_text, finding_id) VALUES ('nmap','x',?)",
            (fid,),
        )
        eid = temp_db.execute("SELECT execution_id FROM tool_executions").fetchone()[
            "execution_id"
        ]
        v = FindingVerdict.set(
            fid, "confirmed", evidence=[VerdictEvidence(execution_id=eid)], conn=temp_db
        )
        assert v.verdict_id is not None
        ev = VerdictEvidence.get_by_verdict(v.verdict_id, temp_db)
        assert len(ev) == 1 and ev[0].execution_id == eid


@pytest.mark.integration
class TestVerdictMcpAdapters:
    def test_set_and_get_through_adapter(self, temp_db: sqlite3.Connection) -> None:
        fid = _seed_finding(temp_db)
        result = mcp.tool_set_finding_verdict(fid, "confirmed", note="n", conn=temp_db)
        assert result["current"]["verdict"] == "confirmed"
        got = mcp.tool_get_finding_verdict(fid, conn=temp_db)
        assert got["current"]["verdict"] == "confirmed"
        assert got["finding_id"] == fid

    def test_suggested_verdict_from_nse_evidence(
        self, temp_db: sqlite3.Connection
    ) -> None:
        fid = _seed_finding(temp_db)
        temp_db.execute(
            "INSERT INTO tool_executions (tool_name, command_text, finding_id) VALUES ('nmap','x',?)",
            (fid,),
        )
        eid = temp_db.execute("SELECT execution_id FROM tool_executions").fetchone()[
            "execution_id"
        ]
        temp_db.execute(
            "INSERT INTO hosts (ip_address, scan_target, scan_target_type) VALUES ('10.0.0.1','10.0.0.1','ipv4')"
        )
        hid = temp_db.execute("SELECT host_id FROM hosts").fetchone()["host_id"]
        NseScriptResult(
            execution_id=eid,
            host_id=hid,
            port_number=None,
            script_id="smb-vuln-ms17-010",
            nse_verdict_id=NseVerdict.id_for_label("VULNERABLE", temp_db),
            output="State: VULNERABLE",
        ).save(temp_db)
        temp_db.commit()
        # suggestion present, but verdict not auto-applied
        got = mcp.tool_get_finding_verdict(fid, conn=temp_db)
        assert got["suggested_verdict"] == "confirmed"
        assert got["current"] is None

    def test_detail_surfaces_verdict_and_counts(
        self, temp_db: sqlite3.Connection
    ) -> None:
        fid = _seed_finding(temp_db)
        mcp.tool_set_finding_verdict(fid, "false_positive", conn=temp_db)
        detail = mcp.tool_get_finding_detail(fid, conn=temp_db)
        assert detail["verdict"] == "false_positive"
        assert detail["verified_port_count"] == 0
