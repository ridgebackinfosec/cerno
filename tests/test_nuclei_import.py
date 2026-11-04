"""Tests for the nuclei importer (cerno_pkg.nuclei_import).

The fixtures are derived from a real ``nuclei -je`` export, so the counts here
pin genuine behaviour: 28 result records over 20 templates, with three
templates matching the same host:port more than once.
"""

import sqlite3
from pathlib import Path

import pytest

from cerno_pkg.nuclei_import import import_nuclei_file

FIXTURES = Path(__file__).parent / "fixtures" / "nuclei"


@pytest.mark.integration
class TestNucleiImport:
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

    # ---------- host_services (nuclei-only scans) ----------

    def test_import_records_services_from_the_matched_url_scheme(
        self, temp_db, temp_dir
    ):
        """nuclei reports a URL, so the scheme is the service."""
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        rows = temp_db.execute(
            "SELECT svc_name, COUNT(*) FROM host_services GROUP BY svc_name"
        ).fetchall()
        services = {r[0]: r[1] for r in rows}
        assert services, "a nuclei import must record host_services"
        assert "http" in services or "https" in services
        assert all(
            p == "tcp"
            for (p,) in temp_db.execute("SELECT DISTINCT protocol FROM host_services")
        )

    def test_nuclei_only_scan_reports_web_services(self, temp_db, temp_dir):
        """The whole point: a web-app engagement may import nothing but nuclei.

        Before this, v_http_services / get_web_targets / list_services /
        FindingQuery.service / the scan hosts resource were all empty for such
        a scan.
        """
        from cerno_pkg.models import get_http_urls_for_scan

        result = import_nuclei_file(
            FIXTURES / "web_scan.json", temp_dir, scan_name="web"
        )
        scan_id = temp_db.execute(
            "SELECT scan_id FROM scans WHERE scan_name = ?", (result.scan_name,)
        ).fetchone()[0]

        assert (
            temp_db.execute(
                "SELECT COUNT(*) FROM v_http_services WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
            > 0
        )
        assert get_http_urls_for_scan(scan_id, temp_db)

    def test_service_query_predicate_matches_nuclei_findings(self, temp_db, temp_dir):
        from cerno_pkg.query import FindingQuery, run_finding_query

        result = import_nuclei_file(
            FIXTURES / "web_scan.json", temp_dir, scan_name="web"
        )
        scan_id = temp_db.execute(
            "SELECT scan_id FROM scans WHERE scan_name = ?", (result.scan_name,)
        ).fetchone()[0]
        matched = run_finding_query(
            FindingQuery(scan_ids=[scan_id], service="http"), temp_db
        )
        assert matched, "FindingQuery.service must reach nuclei findings"

    def test_reimport_resets_services_rather_than_duplicating(self, temp_db, temp_dir):
        """host_services has no FK to findings, so it does not cascade."""
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        first = temp_db.execute("SELECT COUNT(*) FROM host_services").fetchone()[0]
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        second = temp_db.execute("SELECT COUNT(*) FROM host_services").fetchone()[0]
        assert first == second > 0

    def test_ssl_match_is_not_claimed_as_a_web_service(self, temp_db, temp_dir):
        """An ssl match has no URL scheme, so its `type` is the service.

        Mapping ssl to https would be convenient but wrong: an ssl template
        firing on 3389 is RDP, not a web service, and would land in
        get_web_targets. The view's port arm still classifies 443 as https
        without svc_name having to claim it.
        """
        from cerno_pkg.nuclei_parse import parse_nuclei_file

        parsed = parse_nuclei_file(FIXTURES / "web_scan.json")
        ssl_matches = [
            m for t in parsed.templates for m in t.matches if m.result_type == "ssl"
        ]
        assert ssl_matches, "fixture must carry ssl-type records"
        assert {m.service_name for m in ssl_matches} == {"ssl"}

    def test_url_scheme_outranks_a_bare_record_type(self, temp_db, temp_dir):
        """One row per host:port, so the winner must be chosen deliberately.

        example.com:443 is reported by both an https template (scheme) and ssl
        templates (type only). `https` is the more informative answer, and
        which one lands must not depend on insertion order.
        """
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        row = temp_db.execute(
            "SELECT svc_name FROM host_services WHERE port_number = 443"
        ).fetchone()
        assert row is not None and row[0] == "https"

    def test_service_preference_is_order_independent(self):
        """The fixture alone cannot prove this: 'https' < 'ssl' alphabetically,
        so insertion order would have produced the right answer by accident.
        """
        from cerno_pkg.nuclei_import import _prefer_service

        assert _prefer_service(None, "ssl") == "ssl"
        assert _prefer_service("ssl", "https") == "https"
        assert _prefer_service("https", "ssl") == "https"
        # Two schemes: first one wins, nothing to prefer between them.
        assert _prefer_service("http", "https") == "http"

    # ---------- shape ----------

    def test_collapses_28_records_into_20_findings(self, temp_db, temp_dir):
        result = import_nuclei_file(
            FIXTURES / "web_scan.json", temp_dir, scan_name="web"
        )
        assert result.plugins_exported == 20
        assert result.scan_name == "web"
        assert temp_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 20
        assert temp_db.execute("SELECT COUNT(*) FROM plugins").fetchone()[0] == 20

    def test_jsonl_and_array_shapes_agree(self, temp_db, temp_dir):
        array = import_nuclei_file(
            FIXTURES / "web_scan.json", temp_dir, scan_name="as-array"
        )
        jsonl = import_nuclei_file(
            FIXTURES / "web_scan.jsonl", temp_dir, scan_name="as-jsonl"
        )
        assert jsonl.plugins_exported == array.plugins_exported
        assert jsonl.total_hosts == array.total_hosts
        assert jsonl.severities == array.severities

    def test_plugin_ids_are_namespaced(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        ids = [
            r[0] for r in temp_db.execute("SELECT plugin_id FROM plugins").fetchall()
        ]
        assert all(pid.startswith("nuclei:") for pid in ids)
        assert "nuclei:ssl-dns-names" in ids

    def test_source_id_is_recorded(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        sources = {
            r[0] for r in temp_db.execute("SELECT source_id FROM plugins").fetchall()
        }
        assert sources == {2}

    def test_severity_breakdown(self, temp_db, temp_dir):
        result = import_nuclei_file(
            FIXTURES / "web_scan.json", temp_dir, scan_name="web"
        )
        # The real sample is entirely Info severity.
        assert result.severities == {0: 20}

    def test_template_source_url_is_stored(self, temp_db, temp_dir):
        """The stored details URL points at the template's source, not a viewer."""
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        url = temp_db.execute(
            "SELECT plugin_url FROM plugins WHERE plugin_id = ?",
            ("nuclei:ssl-dns-names",),
        ).fetchone()[0]
        assert url == (
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
            "ssl/ssl-dns-names.yaml"
        )

    def test_nuclei_findings_carry_no_metasploit_flag(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        flags = {
            r[0]
            for r in temp_db.execute("SELECT has_metasploit FROM plugins").fetchall()
        }
        assert flags == {0}

    # ---------- the collision, which is the whole point ----------

    def test_colliding_matches_merge_into_one_row(self, temp_db, temp_dir):
        """6 security-header matches on one host:port = 1 row, not 6, not 1-of-6."""
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        rows = temp_db.execute(
            """
            SELECT fah.plugin_output
            FROM finding_affected_hosts fah
            JOIN findings f ON f.finding_id = fah.finding_id
            WHERE f.plugin_id = ?
            """,
            ("nuclei:http-missing-security-headers",),
        ).fetchall()
        assert len(rows) == 1
        output = rows[0][0]
        for matcher in (
            "content-security-policy",
            "strict-transport-security",
            "cross-origin-resource-policy",
            "cross-origin-embedder-policy",
            "cross-origin-opener-policy",
            "x-permitted-cross-domain-policies",
        ):
            assert matcher in output, matcher

    def test_collision_without_matcher_name_keeps_both_extractions(
        self, temp_db, temp_dir
    ):
        """tls-version has no matcher-name; only extracted-results differ."""
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        output = temp_db.execute(
            """
            SELECT fah.plugin_output
            FROM finding_affected_hosts fah
            JOIN findings f ON f.finding_id = fah.finding_id
            WHERE f.plugin_id = ?
            """,
            ("nuclei:tls-version",),
        ).fetchone()[0]
        assert "tls12" in output
        assert "tls13" in output

    # ---------- hosts and ports ----------

    def test_dns_findings_have_null_port_and_host_as_ip(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        rows = temp_db.execute(
            """
            SELECT fah.port_number, h.ip_address, h.scan_target
            FROM finding_affected_hosts fah
            JOIN findings f ON f.finding_id = fah.finding_id
            JOIN hosts h ON h.host_id = fah.host_id
            WHERE f.plugin_id = ?
            """,
            ("nuclei:soa-detect",),
        ).fetchall()
        assert len(rows) == 1
        port, ip, target = rows[0]
        assert port is None
        # nuclei reports no `ip` for dns templates and hosts.ip_address is NOT NULL.
        assert ip == "example.com"
        assert target == "example.com"

    def test_web_findings_use_resolved_ip_and_port(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        port, ip = temp_db.execute(
            """
            SELECT fah.port_number, h.ip_address
            FROM finding_affected_hosts fah
            JOIN findings f ON f.finding_id = fah.finding_id
            JOIN hosts h ON h.host_id = fah.host_id
            WHERE f.plugin_id = ?
            """,
            ("nuclei:ssl-dns-names",),
        ).fetchone()
        assert port == 443
        assert ip == "192.0.2.10"

    def test_port_row_is_created(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        assert (
            temp_db.execute(
                "SELECT COUNT(*) FROM ports WHERE port_number = 443"
            ).fetchone()[0]
            == 1
        )

    def test_scan_row_records_the_source_file(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        path, file_hash = temp_db.execute(
            "SELECT source_file_path, source_file_hash FROM scans WHERE scan_name = ?",
            ("web",),
        ).fetchone()
        assert path.endswith("web_scan.json")
        assert file_hash and len(file_hash) == 64

    # ---------- re-import ----------

    def test_reimport_does_not_duplicate(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        assert temp_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 20
        assert temp_db.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1
        assert (
            temp_db.execute("SELECT COUNT(*) FROM finding_affected_hosts").fetchone()[0]
            == 20
        )

    # ---------- filtering ----------

    def test_min_severity_filters_everything_out(self, temp_db, temp_dir):
        result = import_nuclei_file(
            FIXTURES / "web_scan.json", temp_dir, scan_name="web", min_severity=2
        )
        # The whole real sample is Info, so nothing survives a medium floor.
        assert result.plugins_exported == 0
        assert temp_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0

    def test_min_severity_zero_keeps_everything(self, temp_db, temp_dir):
        result = import_nuclei_file(
            FIXTURES / "web_scan.json", temp_dir, scan_name="web", min_severity=0
        )
        assert result.plugins_exported == 20

    # ---------- adversarial input ----------

    def test_adversarial_fixture_imports(self, temp_db, temp_dir):
        result = import_nuclei_file(
            FIXTURES / "adversarial.jsonl", temp_dir, scan_name="edge"
        )
        assert result.plugins_exported == 15
        ids = {
            r[0] for r in temp_db.execute("SELECT plugin_id FROM plugins").fetchall()
        }
        assert "nuclei:non-match-must-be-filtered" not in ids

    def test_adversarial_cves_and_cvss(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "adversarial.jsonl", temp_dir, scan_name="edge")
        cves, c3, c2 = temp_db.execute(
            "SELECT cves, cvss3_score, cvss2_score FROM plugins WHERE plugin_id = ?",
            ("nuclei:scalar-stringslices",),
        ).fetchone()
        assert "CVE-2021-44228" in cves
        assert c2 == 7.5
        assert c3 is None

    def test_adversarial_null_cve_stores_no_cves(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "adversarial.jsonl", temp_dir, scan_name="edge")
        cves = temp_db.execute(
            "SELECT cves FROM plugins WHERE plugin_id = ?",
            ("nuclei:cve-null-classification",),
        ).fetchone()[0]
        assert cves is None

    def test_adversarial_out_of_range_port_is_null(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "adversarial.jsonl", temp_dir, scan_name="edge")
        port = temp_db.execute(
            """
            SELECT fah.port_number FROM finding_affected_hosts fah
            JOIN findings f ON f.finding_id = fah.finding_id
            WHERE f.plugin_id = ?
            """,
            ("nuclei:port-out-of-range",),
        ).fetchone()[0]
        assert port is None

    def test_escapes_are_stored_verbatim(self, temp_db, temp_dir):
        """The DB holds what the scanner said; sanitizing happens at render."""
        import_nuclei_file(FIXTURES / "adversarial.jsonl", temp_dir, scan_name="edge")
        name = temp_db.execute(
            "SELECT plugin_name FROM plugins WHERE plugin_id = ?",
            ("nuclei:esc-in-untrusted-text",),
        ).fetchone()[0]
        assert "\x1b" in name

    # ---------- failure modes ----------

    def test_missing_file_is_not_fatal(self, temp_db, temp_dir):
        result = import_nuclei_file(
            FIXTURES / "nope.json", temp_dir, scan_name="missing"
        )
        assert result.plugins_exported == 0
        assert temp_db.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0

    def test_malformed_file_is_not_fatal(self, temp_db, temp_dir):
        result = import_nuclei_file(
            FIXTURES / "malformed.json", temp_dir, scan_name="bad"
        )
        assert result.plugins_exported == 0

    def test_empty_file_is_not_fatal(self, temp_db, temp_dir):
        result = import_nuclei_file(
            FIXTURES / "empty.jsonl", temp_dir, scan_name="empty"
        )
        assert result.plugins_exported == 0

    def test_scan_name_defaults_to_filename_stem(self, temp_db, temp_dir):
        result = import_nuclei_file(FIXTURES / "web_scan.json", temp_dir)
        assert result.scan_name == "web_scan"


@pytest.mark.integration
class TestNucleiFindingsAreReviewable:
    """A nuclei finding must flow through the same review surfaces as Nessus."""

    @pytest.fixture(autouse=True)
    def mock_db_for_import(self, monkeypatch, temp_db):
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

    def test_findings_default_to_unreviewed(self, temp_db, temp_dir):
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        states = {
            r[0]
            for r in temp_db.execute("SELECT review_state FROM findings").fetchall()
        }
        assert states == {"unreviewed"}

    def test_findings_load_through_the_review_query(self, temp_db, temp_dir):
        from cerno_pkg.models import Finding, Scan

        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        scan = Scan.get_by_name("web", temp_db)
        assert scan is not None and scan.scan_id is not None
        rows = Finding.get_by_scan_with_plugin(scan.scan_id, conn=temp_db)
        assert len(rows) == 20
        # severity_label comes from the v_plugins_with_severity INNER JOIN, so a
        # mis-mapped severity would silently drop the finding here.
        assert all(plugin.severity_label == "Info" for _f, plugin in rows)
        assert all(plugin.source == "nuclei" for _f, plugin in rows)

    def test_details_url_points_at_the_template_viewer(self, temp_db, temp_dir):
        from cerno_pkg.models import Plugin

        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")
        plugin = Plugin.get_by_id("nuclei:tech-detect", conn=temp_db)
        assert plugin is not None
        assert plugin.details_url is not None
        assert "tenable.com" not in plugin.details_url


@pytest.mark.integration
class TestNucleiImportSuggestions:
    """A nuclei-first operator needs an onward step too.

    `show_nessus_tool_suggestions` is only reachable from a Nessus import, so
    before this a nuclei-only engagement got no follow-up suggestions at all.
    """

    @pytest.fixture(autouse=True)
    def _db(self, monkeypatch, temp_db):
        import cerno_pkg.database

        class Unclosable:
            def __init__(self, conn):
                self._conn = conn

            def __getattr__(self, name):
                return (lambda: None) if name == "close" else getattr(self._conn, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        monkeypatch.setattr(
            cerno_pkg.database,
            "get_connection",
            lambda database_path=None: Unclosable(temp_db),
        )

    def test_suggestions_reference_the_discovered_urls(
        self, temp_db, temp_dir, tmp_path, monkeypatch, capsys
    ):
        import cerno
        import cerno_pkg.constants

        monkeypatch.setattr(cerno_pkg.constants, "SCANS_ROOT", tmp_path / "scans")
        import_nuclei_file(FIXTURES / "web_scan.json", temp_dir, scan_name="web")

        cerno.show_nuclei_tool_suggestions("web")
        out = capsys.readouterr().out
        assert "Suggested Next Steps" in out
        assert "nmap -sV -iL" in out
        assert "cerno import nuclei" in out
        # The re-run command must write JSON, the only shape the importer reads.
        assert "-je " in out

    def test_silent_when_no_web_services(self, temp_db, tmp_path, monkeypatch, capsys):
        """No URLs is not an error, and must not print an empty section."""
        import cerno
        import cerno_pkg.constants

        monkeypatch.setattr(cerno_pkg.constants, "SCANS_ROOT", tmp_path / "scans")
        cerno.show_nuclei_tool_suggestions("no-such-scan")
        assert "Suggested Next Steps" not in capsys.readouterr().out
