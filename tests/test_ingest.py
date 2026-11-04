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
        "INSERT INTO plugins (plugin_id, plugin_name, severity_int) VALUES ('nessus:100', 'SMB', 3)"
    )
    conn.execute(
        "INSERT INTO findings (scan_id, plugin_id) VALUES (?, 'nessus:100')", (scan_id,)
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
            "INSERT INTO plugins (plugin_id, plugin_name, severity_int) VALUES ('nessus:1','P',1)"
        )
        temp_db.execute(
            "INSERT INTO findings (scan_id, plugin_id) VALUES (?,'nessus:1')", (sid,)
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


NUCLEI_FIXTURES = Path(__file__).parent / "fixtures" / "nuclei"


def _seed_nuclei_execution(
    conn: sqlite3.Connection,
    json_name: str,
    *,
    tool_name: str = "nuclei",
    command_text: str = "nuclei -l t.txt -jle out.jsonl",
    artifact_type: str = "nuclei_json",
) -> int:
    """Seed a scan/plugin/finding + nuclei execution with a nuclei_json artifact."""
    conn.execute("INSERT INTO scans (scan_name, export_root) VALUES ('s', '/tmp')")
    scan_id = conn.execute("SELECT scan_id FROM scans").fetchone()["scan_id"]
    conn.execute(
        "INSERT INTO plugins (plugin_id, plugin_name, severity_int) "
        "VALUES ('nessus:100', 'HTTP', 2)"
    )
    conn.execute(
        "INSERT INTO findings (scan_id, plugin_id) VALUES (?, 'nessus:100')", (scan_id,)
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
    type_row = ArtifactType.get_by_name(artifact_type, conn)
    assert type_row is not None, f"{artifact_type} must be a seeded artifact type"
    Artifact(
        execution_id=execution_id,
        artifact_path=str(NUCLEI_FIXTURES / json_name),
        artifact_type_id=type_row.artifact_type_id,
    ).save(conn)
    conn.commit()
    return execution_id


def _observations(conn: sqlite3.Connection, execution_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM nuclei_match_observations WHERE execution_id = ? "
        "ORDER BY observation_id",
        (execution_id,),
    ).fetchall()


@pytest.mark.integration
class TestIngestNuclei:
    """A nuclei run's matches land as evidence, not as new findings."""

    def test_ingests_matches_from_the_json_artifact(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nuclei_execution(temp_db, "web_scan.json")
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.skipped_reason is None
        assert summary.nuclei_matches == 28  # every match in the fixture
        rows = _observations(temp_db, eid)
        assert len(rows) == 28
        assert all(r["template_ref"] for r in rows)
        # Severity comes from the template, resolved against severity_levels.
        assert all(0 <= r["severity_int"] <= 4 for r in rows)

    def test_keeps_matches_that_differ_only_by_extracted_results(
        self, temp_db: sqlite3.Connection
    ) -> None:
        """Both matcher_name and extracted must be part of the identity key.

        http-missing-security-headers reports several matches on one host:port
        differing only by matcher_name; tls-version carries no matcher name at
        all and differs only by extracted-results. Keying on either alone
        silently collapses rows and loses evidence -- which is exactly what
        happened before `extracted` joined the key.
        """
        eid = _seed_nuclei_execution(temp_db, "web_scan.json")
        ingest.ingest_execution(eid, conn=temp_db)

        tls = temp_db.execute(
            "SELECT matcher_name, extracted FROM nuclei_match_observations "
            "WHERE template_ref = 'tls-version' AND execution_id = ?",
            (eid,),
        ).fetchall()
        assert len(tls) > 1, "tls-version's multiple matches must all survive"
        assert all(r["matcher_name"] is None for r in tls)
        assert len({r["extracted"] for r in tls}) == len(tls)

    def test_creates_no_findings(self, temp_db: sqlite3.Connection) -> None:
        """Ingest is evidence; `cerno import nuclei` is what creates findings."""
        eid = _seed_nuclei_execution(temp_db, "web_scan.json")
        before = temp_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        ingest.ingest_execution(eid, conn=temp_db)
        after = temp_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        assert after == before

    def test_reingest_is_idempotent(self, temp_db: sqlite3.Connection) -> None:
        eid = _seed_nuclei_execution(temp_db, "web_scan.json")
        first = ingest.ingest_execution(eid, conn=temp_db)
        ids_first = [r["observation_id"] for r in _observations(temp_db, eid)]
        second = ingest.ingest_execution(eid, conn=temp_db)
        ids_second = [r["observation_id"] for r in _observations(temp_db, eid)]
        assert second.nuclei_matches == first.nuclei_matches
        # Rows are reconciled in place, so primary keys survive a re-ingest.
        assert ids_second == ids_first

    def test_jsonl_shape_agrees_with_array(self, temp_db: sqlite3.Connection) -> None:
        eid = _seed_nuclei_execution(temp_db, "web_scan.jsonl")
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.nuclei_matches == 28

    def test_dispatches_on_the_binary_not_the_tool_name(
        self, temp_db: sqlite3.Connection
    ) -> None:
        """MCP logs every run as tool_name='mcp'; the binary is in command_text."""
        eid = _seed_nuclei_execution(
            temp_db,
            "web_scan.json",
            tool_name="mcp",
            command_text="proxychains4 nuclei -l t.txt -jle out.jsonl",
        )
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.skipped_reason is None
        assert summary.nuclei_matches == 28

    def test_missing_artifact_is_skipped_not_raised(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nuclei_execution(temp_db, "web_scan.json", artifact_type="log")
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.nuclei_matches == 0
        assert "nuclei_json" in (summary.skipped_reason or "")

    def test_empty_output_is_skipped_not_raised(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nuclei_execution(temp_db, "empty.jsonl")
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.nuclei_matches == 0
        assert summary.skipped_reason is not None

    def test_malformed_output_is_skipped_not_raised(
        self, temp_db: sqlite3.Connection
    ) -> None:
        """parse_nuclei_file never raises, so a truncated run must not either."""
        eid = _seed_nuclei_execution(temp_db, "malformed.json")
        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.nuclei_matches >= 0  # no exception is the assertion

    def test_view_resolves_the_severity_label(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nuclei_execution(temp_db, "web_scan.json")
        ingest.ingest_execution(eid, conn=temp_db)
        row = temp_db.execute(
            "SELECT severity_label, ip_address FROM v_nuclei_observations LIMIT 1"
        ).fetchone()
        assert row is not None and row["severity_label"]
        assert row["ip_address"]

    def test_observations_cascade_with_the_execution(
        self, temp_db: sqlite3.Connection
    ) -> None:
        eid = _seed_nuclei_execution(temp_db, "web_scan.json")
        ingest.ingest_execution(eid, conn=temp_db)
        temp_db.execute("DELETE FROM tool_executions WHERE execution_id = ?", (eid,))
        temp_db.commit()
        assert _observations(temp_db, eid) == []


@pytest.mark.integration
class TestTuiRunArtifactsIngest:
    """The TUI's run loop must register what ingest_execution needs.

    Artifact registration used to be gated on `selected_tool.name == "nmap"`,
    so a `[T]` nuclei run logged an execution with no artifact and
    ingest_results reported "no nuclei_json artifact registered". These tests
    pin that the two halves agree on the output path.
    """

    def _seed_execution(self, conn: sqlite3.Connection, tool_name: str) -> int:
        conn.execute("INSERT INTO scans (scan_name, export_root) VALUES ('s', '/tmp')")
        scan_id = conn.execute("SELECT scan_id FROM scans").fetchone()["scan_id"]
        conn.execute(
            "INSERT INTO plugins (plugin_id, plugin_name, severity_int) "
            "VALUES ('nessus:100', 'HTTP', 2)"
        )
        conn.execute(
            "INSERT INTO findings (scan_id, plugin_id) VALUES (?, 'nessus:100')",
            (scan_id,),
        )
        finding_id = conn.execute("SELECT finding_id FROM findings").fetchone()[
            "finding_id"
        ]
        conn.execute(
            "INSERT INTO tool_executions (tool_name, command_text, finding_id) "
            "VALUES (?, 'x', ?)",
            (tool_name, finding_id),
        )
        conn.commit()
        return conn.execute(
            "SELECT MAX(execution_id) e FROM tool_executions"
        ).fetchone()["e"]

    def test_nuclei_run_registers_its_json(
        self, temp_db: sqlite3.Connection, tmp_path
    ) -> None:
        from cerno_pkg.ops import log_artifacts_for_run
        from cerno_pkg.tools import nuclei_scan_output

        eid = self._seed_execution(temp_db, "nuclei")
        oabase = tmp_path / "run"
        # The command builder and the artifact logger must agree on this path.
        Path(nuclei_scan_output(oabase)).write_text(
            (NUCLEI_FIXTURES / "web_scan.jsonl").read_text(), encoding="utf-8"
        )

        ids = log_artifacts_for_run("nuclei", eid, oabase, conn=temp_db)
        assert len(ids) == 1
        row = temp_db.execute(
            "SELECT t.type_name FROM artifacts a "
            "JOIN artifact_types t ON a.artifact_type_id = t.artifact_type_id "
            "WHERE a.execution_id = ?",
            (eid,),
        ).fetchone()
        assert row["type_name"] == "nuclei_json"

    def test_registered_run_then_ingests(
        self, temp_db: sqlite3.Connection, tmp_path
    ) -> None:
        """The whole point: register the way the TUI does, then ingest."""
        from cerno_pkg.ops import log_artifacts_for_run
        from cerno_pkg.tools import nuclei_scan_output

        eid = self._seed_execution(temp_db, "nuclei")
        oabase = tmp_path / "run"
        Path(nuclei_scan_output(oabase)).write_text(
            (NUCLEI_FIXTURES / "web_scan.jsonl").read_text(), encoding="utf-8"
        )
        log_artifacts_for_run("nuclei", eid, oabase, conn=temp_db)

        summary = ingest.ingest_execution(eid, conn=temp_db)
        assert summary.skipped_reason is None
        assert summary.nuclei_matches == 28

    def test_missing_output_is_not_an_error(
        self, temp_db: sqlite3.Connection, tmp_path
    ) -> None:
        """A nuclei run that matched nothing writes no file."""
        from cerno_pkg.ops import log_artifacts_for_run

        eid = self._seed_execution(temp_db, "nuclei")
        assert (
            log_artifacts_for_run("nuclei", eid, tmp_path / "run", conn=temp_db) == []
        )

    def test_tool_with_no_artifacts_is_a_noop(
        self, temp_db: sqlite3.Connection, tmp_path
    ) -> None:
        from cerno_pkg.ops import log_artifacts_for_run

        eid = self._seed_execution(temp_db, "metasploit")
        for tool in ("metasploit", "Custom command", ""):
            assert (
                log_artifacts_for_run(tool, eid, tmp_path / "run", conn=temp_db) == []
            )

    def test_nmap_still_registers_its_triple(
        self, temp_db: sqlite3.Connection, tmp_path
    ) -> None:
        from cerno_pkg.ops import log_artifacts_for_run

        eid = self._seed_execution(temp_db, "nmap")
        oabase = tmp_path / "run"
        for ext in (".xml", ".nmap", ".gnmap"):
            Path(str(oabase) + ext).write_text("x", encoding="utf-8")
        assert len(log_artifacts_for_run("nmap", eid, oabase, conn=temp_db)) == 3
