"""Tests for the Burp Suite importer (cerno_pkg.burp_import).

The fixture holds 11 ``<issue>`` elements: 8 usable instances over 6 issue
types, one dismissed issue and one with an unusable type.
"""

from pathlib import Path

import pytest

from cerno_pkg.burp_import import import_burp_file

FIXTURES = Path(__file__).parent / "fixtures" / "burp"
WEB_SCAN = FIXTURES / "web_scan.xml"


@pytest.mark.integration
class TestBurpImport:
    @pytest.fixture(autouse=True)
    def mock_db_for_import(self, monkeypatch, temp_db):
        """Route the importer at the in-memory test DB (see test_nessus_import)."""
        import cerno_pkg.database

        class UnclosableConnection:
            """Keeps the :memory: DB alive across the importer's open/close."""

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

    @staticmethod
    def _dataset_id(temp_db, dataset_name: str) -> int:
        return temp_db.execute(
            "SELECT dataset_id FROM datasets WHERE dataset_name = ?", (dataset_name,)
        ).fetchone()[0]

    # ---------- shape ----------

    def test_one_finding_per_issue_type(self, temp_db, temp_dir):
        result = import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        assert result.finding_types_exported == 6
        assert temp_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 6

    def test_dataset_name_defaults_to_the_file_stem(self, temp_db, temp_dir):
        result = import_burp_file(WEB_SCAN, temp_dir)
        assert result.dataset_name == "web_scan"

    def test_severity_breakdown_has_no_critical(self, temp_db, temp_dir):
        result = import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        assert 4 not in result.severities
        assert result.severities[3] >= 1

    # ---------- finding_type identity ----------

    def test_finding_type_ids_are_namespaced_with_the_hex_type(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        ids = {
            row[0]
            for row in temp_db.execute(
                "SELECT finding_type_id FROM finding_types"
            ).fetchall()
        }
        assert "burp:00200300" in ids
        assert all(pid.startswith("burp:") for pid in ids)

    def test_source_id_is_recorded(self, temp_db, temp_dir):
        from cerno_pkg.constants import SOURCE_BURP, SOURCE_IDS

        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        sources = {
            row[0]
            for row in temp_db.execute("SELECT DISTINCT source_id FROM finding_types")
        }
        assert sources == {SOURCE_IDS[SOURCE_BURP]}

    def test_source_name_resolves_through_the_lookup_table(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        row = temp_db.execute(
            "SELECT fs.source_name FROM finding_types p "
            "JOIN finding_sources fs ON p.source_id = fs.source_id LIMIT 1"
        ).fetchone()
        assert row[0] == "burp"

    def test_findings_query_by_source(self, temp_db, temp_dir):
        from cerno_pkg.query import FindingQuery, run_finding_query

        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        dataset_id = self._dataset_id(temp_db, "web")
        matched = run_finding_query(
            FindingQuery(dataset_ids=[dataset_id], source="burp"), temp_db
        )
        assert len(matched) == 6

    def test_details_url_points_at_the_knowledge_base(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        row = temp_db.execute(
            "SELECT details_url FROM finding_types WHERE finding_type_id = 'burp:00200300'"
        ).fetchone()
        assert row[0] == "https://portswigger.net/kb/issues/00200300"

    def test_extension_issues_do_not_share_a_finding_type_row(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        rows = temp_db.execute(
            "SELECT finding_type_id, finding_type_name, details_url FROM finding_types "
            "WHERE finding_type_id LIKE 'burp:08000000%' ORDER BY finding_type_id"
        ).fetchall()
        assert len(rows) == 2
        assert {r[1] for r in rows} == {
            "JWT none algorithm accepted",
            "Hardcoded API key in JavaScript",
        }
        # PortSwigger publishes no page for an extension-generated issue.
        assert all(r[2] is None for r in rows)

    def test_cves_found_in_prose_are_stored(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        row = temp_db.execute(
            "SELECT cves FROM finding_types WHERE finding_type_id = 'burp:01000100'"
        ).fetchone()
        assert "CVE-2021-44228" in row[0]

    # ---------- hosts, ports, evidence ----------

    def test_instances_on_one_host_port_merge_into_one_row(self, temp_db, temp_dir):
        """finding_affected_hosts is UNIQUE per (finding_id, host_id, port)."""
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        rows = temp_db.execute(
            "SELECT fah.port_number, fah.evidence "
            "FROM finding_affected_hosts fah "
            "JOIN findings f ON f.finding_id = fah.finding_id "
            "WHERE f.finding_type_id = 'burp:00200300' ORDER BY fah.port_number"
        ).fetchall()
        assert [r[0] for r in rows] == [443, 8080]
        merged = rows[0][1]
        assert "[q parameter]" in merged
        assert "[lang parameter]" in merged

    def test_evidence_includes_the_decoded_exchange(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        output = temp_db.execute(
            "SELECT fah.evidence FROM finding_affected_hosts fah "
            "JOIN findings f ON f.finding_id = fah.finding_id "
            "WHERE f.finding_type_id = 'burp:00200300' AND fah.port_number = 443"
        ).fetchone()[0]
        assert "GET /search?q=" in output
        assert "HTTP/1.1 200 OK" in output
        assert "confidence: Certain" in output

    def test_host_without_an_ip_attribute_is_keyed_by_its_hostname(
        self, temp_db, temp_dir
    ):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        row = temp_db.execute(
            "SELECT ip_address, scan_target, scan_target_type FROM hosts "
            "WHERE scan_target = 'web02.corp.local'"
        ).fetchone()
        assert tuple(row) == ("web02.corp.local", "web02.corp.local", "fqdn")

    def test_ipv6_host_is_stored_unbracketed(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        row = temp_db.execute(
            "SELECT ip_address, scan_target_type FROM hosts "
            "WHERE scan_target = '2001:db8::21'"
        ).fetchone()
        assert tuple(row) == ("2001:db8::21", "ipv6")

    def test_ports_are_registered(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        ports = {row[0] for row in temp_db.execute("SELECT port_number FROM ports")}
        assert {443, 8080, 8443} <= ports

    # ---------- host_services (Burp-only datasets) ----------

    def test_services_come_from_the_url_scheme(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        rows = temp_db.execute(
            "SELECT svc_name, protocol FROM host_services"
        ).fetchall()
        assert {r[0] for r in rows} == {"http", "https"}
        assert {r[1] for r in rows} == {"tcp"}

    def test_burp_only_dataset_reports_web_services(self, temp_db, temp_dir):
        """A web-app engagement may import nothing but a Burp report."""
        from cerno_pkg.models import get_http_urls_for_dataset

        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        dataset_id = self._dataset_id(temp_db, "web")
        assert (
            temp_db.execute(
                "SELECT COUNT(*) FROM v_http_services WHERE dataset_id = ?",
                (dataset_id,),
            ).fetchone()[0]
            > 0
        )
        assert get_http_urls_for_dataset(dataset_id, temp_db)

    # ---------- filtering ----------

    def test_min_severity_drops_lower_issues(self, temp_db, temp_dir):
        result = import_burp_file(
            WEB_SCAN, temp_dir, dataset_name="web", min_severity=3
        )
        assert result.finding_types_exported == 3
        names = {
            row[0]
            for row in temp_db.execute("SELECT finding_type_name FROM finding_types")
        }
        assert "Robots.txt file" not in names

    def test_min_severity_above_everything_writes_nothing(self, temp_db, temp_dir):
        result = import_burp_file(
            WEB_SCAN, temp_dir, dataset_name="web", min_severity=4
        )
        assert result.finding_types_exported == 0
        assert temp_db.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 0

    def test_dismissed_issue_is_not_imported(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        names = {
            row[0]
            for row in temp_db.execute("SELECT finding_type_name FROM finding_types")
        }
        assert "Frameable response (potential Clickjacking)" not in names

    # ---------- re-import ----------

    def test_reimport_replaces_rather_than_duplicating(self, temp_db, temp_dir):
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        counts = lambda: (  # noqa: E731
            temp_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            temp_db.execute("SELECT COUNT(*) FROM finding_affected_hosts").fetchone()[
                0
            ],
            temp_db.execute("SELECT COUNT(*) FROM host_services").fetchone()[0],
            temp_db.execute("SELECT COUNT(*) FROM datasets").fetchone()[0],
        )
        first = counts()
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        assert counts() == first

    # ---------- forgiving inputs ----------

    def test_missing_file_writes_nothing(self, temp_db, temp_dir):
        result = import_burp_file(temp_dir / "nope.xml", temp_dir, dataset_name="web")
        assert result.finding_types_exported == 0
        assert temp_db.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 0

    def test_non_burp_xml_writes_nothing(self, temp_db, temp_dir):
        path = temp_dir / "scan.xml"
        path.write_text('<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>')
        result = import_burp_file(path, temp_dir, dataset_name="web")
        assert result.finding_types_exported == 0
        assert temp_db.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 0

    # ---------- the review loop sees them ----------

    def test_findings_render_through_the_normal_review_path(self, temp_db, temp_dir):
        from cerno_pkg.models import Finding

        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        dataset_id = self._dataset_id(temp_db, "web")
        pairs = Finding.get_by_dataset_with_finding_type(dataset_id, conn=temp_db)
        assert len(pairs) == 6
        finding, finding_type = pairs[0]
        assert finding.review_state == "unreviewed"
        assert finding_type.source == "burp"

    def test_finding_panel_label_is_burps(self, temp_db, temp_dir):
        from cerno_pkg.constants import FINDING_TYPE_ID_LABELS
        from cerno_pkg.models import Finding

        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")
        dataset_id = self._dataset_id(temp_db, "web")
        _finding, finding_type = Finding.get_by_dataset_with_finding_type(
            dataset_id, conn=temp_db
        )[0]
        assert FINDING_TYPE_ID_LABELS[finding_type.source] == "Burp Issue Type"


@pytest.mark.integration
class TestBurpToolSuggestions:
    """The post-import suggestions are shared with nuclei, so they must name Burp."""

    @pytest.fixture(autouse=True)
    def mock_db_for_import(self, monkeypatch, temp_db):
        import cerno_pkg.database

        class Unclosable:
            def __init__(self, conn):
                self._conn = conn

            def __getattr__(self, name):
                if name == "close":
                    return lambda: None
                return getattr(self._conn, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr(
            cerno_pkg.database,
            "get_connection",
            lambda database_path=None: Unclosable(temp_db),
        )

    def test_suggestions_name_burp_not_nuclei(
        self, temp_db, temp_dir, tmp_path, monkeypatch, capsys
    ):
        import cerno
        import cerno_pkg.constants

        monkeypatch.setattr(cerno_pkg.constants, "DATASETS_ROOT", tmp_path / "datasets")
        import_burp_file(WEB_SCAN, temp_dir, dataset_name="web")

        cerno.show_web_tool_suggestions("web", source_label="Burp")
        out = capsys.readouterr().out
        assert "Burp matched" in out
        assert "nuclei matched" not in out
        # The onward steps themselves are still the nuclei/nmap sweep.
        assert "nmap -sV -iL" in out
        assert "cerno import nuclei" in out
