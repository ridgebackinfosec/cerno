"""Tests for the bundled demo nuclei fixtures.

These pin what `cerno demo` loads, mirroring the demo `.nessus` coverage in
`test_nessus_import.py`. The important one is
`test_nuclei_import_reuses_nessus_hosts`: the whole point of the demo nuclei
data is that it lands on the *same* host rows as the Nessus scans, so the two
sources can be reviewed side by side. If the fixture's `host`/`ip` values drift
away from the `.nessus` `ReportHost@name`/`host-ip` values, that silently stops
being true and the demo quietly loses its reason to exist.
"""

import sqlite3
from pathlib import Path

import pytest

from cerno_pkg.nessus_import import import_nessus_file
from cerno_pkg.nuclei_import import import_nuclei_file

DEMO = Path(__file__).parent.parent / "docs" / "demo"
INITIAL_NUCLEI = DEMO / "cerno-demo-nuclei-initial.json"
EXPANDED_NUCLEI = DEMO / "cerno-demo-nuclei-expanded.json"
EXPANDED_NESSUS = DEMO / "cerno-demo-expanded.nessus"


@pytest.mark.integration
class TestDemoNucleiFixtures:
    @pytest.fixture(autouse=True)
    def mock_db(self, monkeypatch, temp_db):
        import cerno_pkg.database

        class UnclosableConnection:
            def __init__(self, conn):
                self._conn = conn

            def __getattr__(self, name):
                if name == "close":
                    return lambda: None
                return getattr(self._conn, name)

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                return False

        monkeypatch.setattr(
            cerno_pkg.database,
            "get_connection",
            lambda database_path=None: UnclosableConnection(temp_db),
        )

    # ---------- shape ----------

    def test_initial_fixture_imports_expected_baseline(self, temp_db, temp_dir):
        result = import_nuclei_file(
            INITIAL_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Initial_Scan"
        )
        assert result.plugins_exported == 9
        # Quiet baseline: 8 info templates plus weak-cipher-suites (low).
        # Counts are per template, not per match, so a template matching two
        # targets still contributes one finding.
        assert result.severities == {0: 8, 1: 1}
        assert result.total_hosts == 13

    def test_expanded_fixture_imports_expected_data(self, temp_db, temp_dir):
        result = import_nuclei_file(
            EXPANDED_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Expanded_Scan"
        )
        assert result.plugins_exported == 17
        # A real severity spread, so the demo exercises severity filtering.
        assert result.severities[4] == 1  # Log4Shell
        assert result.severities[3] == 2  # path traversal + Tomcat default login
        assert sum(result.severities.values()) == 17

    def test_expanded_carries_the_nuclei_only_findings(self, temp_db, temp_dir):
        """The point of a second scanner: things Nessus did not report."""
        import_nuclei_file(
            EXPANDED_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Expanded_Scan"
        )
        ids = {
            r[0] for r in temp_db.execute("SELECT plugin_id FROM plugins").fetchall()
        }
        assert "nuclei:CVE-2021-44228" in ids  # critical, Log4Shell
        assert "nuclei:CVE-2021-41773" in ids  # high, Apache path traversal
        assert "nuclei:tomcat-default-login" in ids  # high, default credentials

    def test_all_plugin_ids_are_namespaced(self, temp_db, temp_dir):
        import_nuclei_file(
            EXPANDED_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Expanded_Scan"
        )
        ids = [
            r[0] for r in temp_db.execute("SELECT plugin_id FROM plugins").fetchall()
        ]
        assert ids and all(pid.startswith("nuclei:") for pid in ids)

    # ---------- the correlation that makes the demo worth shipping ----------

    def test_nuclei_import_reuses_nessus_hosts(self, temp_db, temp_dir):
        """Importing the nuclei half must not create a single new host row."""
        import_nessus_file(
            EXPANDED_NESSUS,
            temp_dir,
            scan_name="Cerno_Demo_Expanded_Scan",
            include_ports=True,
        )
        hosts_after_nessus = temp_db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        assert hosts_after_nessus == 42

        import_nuclei_file(
            EXPANDED_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Expanded_Scan"
        )
        hosts_after_nuclei = temp_db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        assert hosts_after_nuclei == hosts_after_nessus

    def test_fqdn_named_hosts_correlate_too(self, temp_db, temp_dir):
        """Six demo hosts are named by FQDN, not IP -- the easy case to get wrong."""
        import_nessus_file(
            EXPANDED_NESSUS,
            temp_dir,
            scan_name="Cerno_Demo_Expanded_Scan",
            include_ports=True,
        )
        import_nuclei_file(
            EXPANDED_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Expanded_Scan"
        )
        rows = temp_db.execute(
            "SELECT host_id, ip_address FROM hosts WHERE scan_target = ?",
            ("vpn.demo.example",),
        ).fetchall()
        assert len(rows) == 1, "FQDN-named host was duplicated by the nuclei import"
        assert rows[0][1] == "203.0.113.60"

    def test_both_sources_share_a_host_row(self, temp_db, temp_dir):
        """A shop host carries findings from both scanners on the same host_id."""
        import_nessus_file(
            EXPANDED_NESSUS,
            temp_dir,
            scan_name="Cerno_Demo_Expanded_Scan",
            include_ports=True,
        )
        import_nuclei_file(
            EXPANDED_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Expanded_Scan"
        )
        sources = {r[0] for r in temp_db.execute("""
                SELECT p.source_id
                FROM finding_affected_hosts fah
                JOIN findings f ON f.finding_id = fah.finding_id
                JOIN plugins p ON p.plugin_id = f.plugin_id
                JOIN hosts h ON h.host_id = fah.host_id
                WHERE h.scan_target = '203.0.113.80' AND fah.port_number = 443
                """).fetchall()}
        assert sources == {1, 2}

    # ---------- the merged-evidence centrepiece ----------

    def test_missing_headers_merge_into_one_finding(self, temp_db, temp_dir):
        """Nessus splits these into 3 plugins; nuclei reports 3 matchers on 1."""
        import_nuclei_file(
            EXPANDED_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Expanded_Scan"
        )
        rows = temp_db.execute("""
            SELECT fah.plugin_output
            FROM finding_affected_hosts fah
            JOIN findings f ON f.finding_id = fah.finding_id
            JOIN hosts h ON h.host_id = fah.host_id
            WHERE f.plugin_id = 'nuclei:http-missing-security-headers'
              AND h.scan_target = '203.0.113.80'
            """).fetchall()
        assert len(rows) == 1, "the three matches must merge into one row"
        output = rows[0][0]
        for matcher in (
            "strict-transport-security",
            "x-frame-options",
            "content-security-policy",
        ):
            assert matcher in output, matcher

    def test_corroborating_findings_land_on_the_nessus_host_port(
        self, temp_db, temp_dir
    ):
        """self-signed-ssl must sit on the same host:port as Nessus plugin 11219."""
        import_nuclei_file(
            EXPANDED_NUCLEI, temp_dir, scan_name="Cerno_Demo_Nuclei_Expanded_Scan"
        )
        target, port = temp_db.execute("""
            SELECT h.scan_target, fah.port_number
            FROM finding_affected_hosts fah
            JOIN findings f ON f.finding_id = fah.finding_id
            JOIN hosts h ON h.host_id = fah.host_id
            WHERE f.plugin_id = 'nuclei:self-signed-ssl'
            """).fetchone()
        assert (target, port) == ("198.51.100.12", 443)

    # ---------- fixture hygiene ----------

    def test_fixtures_carry_no_local_paths(self):
        """template-path must not leak a real home directory."""
        for fixture in (INITIAL_NUCLEI, EXPANDED_NUCLEI):
            text = fixture.read_text()
            assert "/home/" not in text, fixture.name
            assert "/Users/" not in text, fixture.name

    def test_fixtures_omit_raw_request_response(self):
        """Generated as if with -or; Cerno discards them and they bloat the file."""
        import json

        for fixture in (INITIAL_NUCLEI, EXPANDED_NUCLEI):
            for record in json.loads(fixture.read_text()):
                assert "request" not in record
                assert "response" not in record

    def test_fixtures_only_use_documentation_addresses(self):
        """RFC 5737 / RFC 3849 ranges and .example names only."""
        import json
        import re

        allowed = re.compile(r"^(198\.51\.100\.|203\.0\.113\.|2001:db8:)")
        for fixture in (INITIAL_NUCLEI, EXPANDED_NUCLEI):
            for record in json.loads(fixture.read_text()):
                ip = record.get("ip")
                if ip:
                    assert allowed.match(ip), f"{fixture.name}: {ip}"
                assert record["host"].endswith(".example") or allowed.match(
                    record["host"]
                ), f"{fixture.name}: {record['host']}"
