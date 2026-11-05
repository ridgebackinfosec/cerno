"""Tests for cerno_pkg.cross_scan module."""

import pytest

from cerno_pkg.cross_scan import (
    compare_scans,
    get_host_vulnerability_history,
    get_scan_by_name,
    ScanComparisonResult,
    HostVulnerabilityHistory,
    ScanSnapshot,
)
from cerno_pkg.models import Scan, Plugin, Finding, Host


def _create_test_scan(conn, scan_name: str, plugins_data: list[dict]) -> int:
    """Helper to create a scan with plugins, findings, and hosts.

    Args:
        conn: Database connection
        scan_name: Name for the scan
        plugins_data: List of dicts with plugin_id, plugin_name, severity_int, hosts

    Returns:
        scan_id
    """
    # Create scan
    scan = Scan(scan_name=scan_name, export_root="/tmp/test")
    scan_id = scan.save(conn)
    assert scan_id is not None

    for pd in plugins_data:
        # Create or get plugin
        plugin = Plugin(
            plugin_id=pd["plugin_id"],
            plugin_name=pd["plugin_name"],
            severity_int=pd["severity_int"],
        )
        plugin.save(conn)

        # Create finding
        finding = Finding(scan_id=scan_id, plugin_id=pd["plugin_id"])
        finding_id = finding.save(conn)
        assert finding_id is not None

        # Create hosts and link to finding
        for host_ip in pd.get("hosts", []):
            # Get or create host
            host_id = Host.get_or_create(
                ip_address=host_ip,
                scan_target=host_ip,
                scan_target_type="ipv4",
                conn=conn,
            )

            # Link host to finding
            conn.execute(
                """
                INSERT OR IGNORE INTO finding_affected_hosts
                (finding_id, host_id, port_number, plugin_output)
                VALUES (?, ?, NULL, 'Test output')
                """,
                (finding_id, host_id),
            )

    conn.commit()
    return scan_id


class TestCompareScan:
    """Tests for compare_scans function."""

    def test_compare_identical_scans(self, temp_db):
        """Comparing same scan should show all persistent."""
        scan_id = _create_test_scan(
            temp_db,
            "test_scan",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "Plugin B",
                    "severity_int": 2,
                    "hosts": ["192.168.1.2"],
                },
            ],
        )

        result = compare_scans(scan_id, scan_id, conn=temp_db)

        assert result is not None
        assert result.total_new == 0
        assert result.total_resolved == 0
        assert result.total_persistent == 2

    def test_compare_finds_new_findings(self, temp_db):
        """New findings in scan2 detected correctly."""
        # Scan 1: plugins 100, 101
        scan1_id = _create_test_scan(
            temp_db,
            "scan1",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "Plugin B",
                    "severity_int": 2,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        # Scan 2: plugins 100, 101, 102 (102 is new)
        scan2_id = _create_test_scan(
            temp_db,
            "scan2",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "Plugin B",
                    "severity_int": 2,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:102",
                    "plugin_name": "Plugin C",
                    "severity_int": 4,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        result = compare_scans(scan1_id, scan2_id, conn=temp_db)

        assert result is not None
        assert result.total_new == 1
        assert result.total_resolved == 0
        assert result.total_persistent == 2

        # Check the new finding
        new_plugin_ids = [f["plugin_id"] for f in result.new_findings]
        assert "nessus:102" in new_plugin_ids

    def test_compare_finds_resolved_findings(self, temp_db):
        """Resolved findings (in scan1 only) detected correctly."""
        # Scan 1: plugins 100, 101, 102
        scan1_id = _create_test_scan(
            temp_db,
            "scan1",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "Plugin B",
                    "severity_int": 2,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:102",
                    "plugin_name": "Plugin C",
                    "severity_int": 4,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        # Scan 2: plugins 100, 101 (102 is resolved)
        scan2_id = _create_test_scan(
            temp_db,
            "scan2",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "Plugin B",
                    "severity_int": 2,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        result = compare_scans(scan1_id, scan2_id, conn=temp_db)

        assert result is not None
        assert result.total_new == 0
        assert result.total_resolved == 1
        assert result.total_persistent == 2

        # Check the resolved finding
        resolved_plugin_ids = [f["plugin_id"] for f in result.resolved_findings]
        assert "nessus:102" in resolved_plugin_ids

    def test_compare_severity_filter(self, temp_db):
        """Minimum severity filter works correctly."""
        # Scan 1: plugins at various severities
        scan1_id = _create_test_scan(
            temp_db,
            "scan1",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Low Plugin",
                    "severity_int": 1,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "Medium Plugin",
                    "severity_int": 2,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:102",
                    "plugin_name": "High Plugin",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        # Scan 2: same plugins
        scan2_id = _create_test_scan(
            temp_db,
            "scan2",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Low Plugin",
                    "severity_int": 1,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "Medium Plugin",
                    "severity_int": 2,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:102",
                    "plugin_name": "High Plugin",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        # Filter to High and above (severity >= 3)
        result = compare_scans(scan1_id, scan2_id, min_severity=3, conn=temp_db)

        assert result is not None
        assert result.total_persistent == 1  # Only the High plugin
        persistent_plugin_ids = [f["plugin_id"] for f in result.persistent_findings]
        assert "nessus:102" in persistent_plugin_ids
        assert 100 not in persistent_plugin_ids
        assert 101 not in persistent_plugin_ids

    def test_compare_host_changes(self, temp_db):
        """Host changes detected correctly."""
        # Scan 1: hosts 1.1, 1.2
        scan1_id = _create_test_scan(
            temp_db,
            "scan1",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1", "192.168.1.2"],
                },
            ],
        )

        # Scan 2: hosts 1.1, 1.3 (1.2 removed, 1.3 new)
        scan2_id = _create_test_scan(
            temp_db,
            "scan2",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1", "192.168.1.3"],
                },
            ],
        )

        result = compare_scans(scan1_id, scan2_id, conn=temp_db)

        assert result is not None
        assert len(result.new_hosts) == 1
        assert len(result.removed_hosts) == 1
        assert len(result.persistent_hosts) == 1

        new_host_ips = [h["ip_address"] for h in result.new_hosts]
        removed_host_ips = [h["ip_address"] for h in result.removed_hosts]
        persistent_host_ips = [h["ip_address"] for h in result.persistent_hosts]

        assert "192.168.1.3" in new_host_ips
        assert "192.168.1.2" in removed_host_ips
        assert "192.168.1.1" in persistent_host_ips

    def test_compare_nonexistent_scan_returns_none(self, temp_db):
        """Comparing with non-existent scan returns None."""
        scan_id = _create_test_scan(
            temp_db,
            "test_scan",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                }
            ],
        )

        result = compare_scans(scan_id, 99999, conn=temp_db)
        assert result is None

        result = compare_scans(99999, scan_id, conn=temp_db)
        assert result is None


class TestHostVulnerabilityHistory:
    """Tests for host vulnerability history functions."""

    def test_host_history_single_scan(self, temp_db):
        """Host history for single scan returns one entry."""
        _create_test_scan(
            temp_db,
            "scan1",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Critical",
                    "severity_int": 4,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "High",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        history = get_host_vulnerability_history("192.168.1.1", conn=temp_db)

        assert history is not None
        assert history.ip_address == "192.168.1.1"
        assert history.scan_count == 1
        assert len(history.scans) == 1
        assert history.scans[0].finding_count == 2
        assert history.scans[0].critical_count == 1
        assert history.scans[0].high_count == 1

    def test_host_history_multiple_scans(self, temp_db):
        """Host history spans multiple scans correctly."""
        # Scan 1: 3 findings
        _create_test_scan(
            temp_db,
            "scan1",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Critical",
                    "severity_int": 4,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "High",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:102",
                    "plugin_name": "Medium",
                    "severity_int": 2,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        # Scan 2: 2 findings (one resolved)
        _create_test_scan(
            temp_db,
            "scan2",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Critical",
                    "severity_int": 4,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "High",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        history = get_host_vulnerability_history("192.168.1.1", conn=temp_db)

        assert history is not None
        assert history.scan_count == 2
        assert len(history.scans) == 2
        assert history.scans[0].finding_count == 3
        assert history.scans[1].finding_count == 2

    def test_host_not_found_returns_none(self, temp_db):
        """Non-existent host returns None."""
        _create_test_scan(
            temp_db,
            "scan1",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                }
            ],
        )

        history = get_host_vulnerability_history("10.0.0.99", conn=temp_db)
        assert history is None

    def test_host_history_plugin_ids(self, temp_db):
        """Host history includes plugin IDs."""
        _create_test_scan(
            temp_db,
            "scan1",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "Plugin A",
                    "severity_int": 4,
                    "hosts": ["192.168.1.1"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "Plugin B",
                    "severity_int": 3,
                    "hosts": ["192.168.1.1"],
                },
            ],
        )

        history = get_host_vulnerability_history("192.168.1.1", conn=temp_db)

        assert history is not None
        assert len(history.scans[0].plugin_ids) == 2
        assert "nessus:100" in history.scans[0].plugin_ids
        assert "nessus:101" in history.scans[0].plugin_ids


class TestGetScanByName:
    """Tests for get_scan_by_name helper."""

    def test_get_scan_by_name_found(self, temp_db):
        """Returns scan data when found."""
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan.save(temp_db)
        temp_db.commit()

        result = get_scan_by_name("test_scan", conn=temp_db)

        assert result is not None
        assert result["scan_name"] == "test_scan"

    def test_get_scan_by_name_not_found(self, temp_db):
        """Returns None when scan not found."""
        result = get_scan_by_name("nonexistent", conn=temp_db)
        assert result is None


class TestDataclasses:
    """Tests for dataclass properties and methods."""

    def test_scan_comparison_result_properties(self):
        """ScanComparisonResult properties calculate correctly."""
        result = ScanComparisonResult(
            scan1_id=1,
            scan1_name="scan1",
            scan1_date="2024-01-01",
            scan2_id=2,
            scan2_name="scan2",
            scan2_date="2024-02-01",
            new_findings=[{"plugin_id": "nessus:100"}, {"plugin_id": "nessus:101"}],
            resolved_findings=[{"plugin_id": "nessus:102"}],
            persistent_findings=[
                {"plugin_id": "nessus:103"},
                {"plugin_id": "nessus:104"},
                {"plugin_id": "nessus:105"},
            ],
        )

        assert result.total_new == 2
        assert result.total_resolved == 1
        assert result.total_persistent == 3

    def test_host_vulnerability_history_scan_count(self):
        """HostVulnerabilityHistory.scan_count property."""
        history = HostVulnerabilityHistory(
            host_id=1,
            ip_address="192.168.1.1",
            scan_target="192.168.1.1",
            scan_target_type="ipv4",
            first_seen="2024-01-01",
            last_seen="2024-03-01",
            scans=[
                ScanSnapshot(
                    scan_id=1,
                    scan_name="scan1",
                    scan_date="2024-01-01",
                    finding_count=5,
                    max_severity=4,
                    critical_count=1,
                    high_count=2,
                    medium_count=1,
                    low_count=1,
                    info_count=0,
                ),
                ScanSnapshot(
                    scan_id=2,
                    scan_name="scan2",
                    scan_date="2024-02-01",
                    finding_count=3,
                    max_severity=3,
                    critical_count=0,
                    high_count=2,
                    medium_count=1,
                    low_count=0,
                    info_count=0,
                ),
            ],
        )

        assert history.scan_count == 2


@pytest.mark.integration
class TestMixedSourceComparisonRefused:
    """A Nessus scan and a nuclei scan share no plugin ids, so comparing them
    would report every finding as both new and resolved."""

    @staticmethod
    def _seed(temp_db):
        from cerno_pkg.models import Finding, Plugin, Scan

        nessus_scan = Scan(scan_name="nessus-scan", export_root="/tmp").save(temp_db)
        nuclei_scan = Scan(scan_name="nuclei-scan", export_root="/tmp").save(temp_db)
        Plugin(
            plugin_id="nessus:57608", plugin_name="SMB Signing", severity_int=3
        ).save(temp_db)
        Plugin(
            plugin_id="nuclei:tech-detect",
            plugin_name="Technology Detection",
            severity_int=3,
        ).save(temp_db)
        Finding(scan_id=nessus_scan, plugin_id="nessus:57608").save(temp_db)
        Finding(scan_id=nuclei_scan, plugin_id="nuclei:tech-detect").save(temp_db)
        return nessus_scan, nuclei_scan

    def test_cross_source_comparison_raises(self, temp_db):
        from cerno_pkg.cross_scan import MixedSourceComparisonError, compare_scans

        nessus_scan, nuclei_scan = self._seed(temp_db)
        with pytest.raises(MixedSourceComparisonError) as exc:
            compare_scans(nessus_scan, nuclei_scan, conn=temp_db)
        message = str(exc.value)
        assert "nessus-scan" in message and "nuclei-scan" in message
        assert "same source" in message

    def test_error_is_a_valueerror_so_mcp_surfaces_it(self, temp_db):
        from cerno_pkg.cross_scan import MixedSourceComparisonError

        assert issubclass(MixedSourceComparisonError, ValueError)

    def test_same_source_comparison_still_works(self, temp_db):
        from cerno_pkg.cross_scan import compare_scans
        from cerno_pkg.models import Finding, Plugin, Scan

        a = Scan(scan_name="nuclei-a", export_root="/tmp").save(temp_db)
        b = Scan(scan_name="nuclei-b", export_root="/tmp").save(temp_db)
        Plugin(plugin_id="nuclei:x", plugin_name="X", severity_int=2).save(temp_db)
        Plugin(plugin_id="nuclei:y", plugin_name="Y", severity_int=2).save(temp_db)
        Finding(scan_id=a, plugin_id="nuclei:x").save(temp_db)
        Finding(scan_id=b, plugin_id="nuclei:y").save(temp_db)

        result = compare_scans(a, b, conn=temp_db)
        assert result is not None
        assert [f["plugin_id"] for f in result.new_findings] == ["nuclei:y"]
        assert [f["plugin_id"] for f in result.resolved_findings] == ["nuclei:x"]


@pytest.mark.unit
class TestScanSnapshotSource:
    """A snapshot knows its scanner, derived from its namespaced plugin ids."""

    def _snap(self, plugin_ids):
        return ScanSnapshot(
            scan_id=1,
            scan_name="s",
            scan_date="2026-01-01",
            finding_count=len(plugin_ids),
            max_severity=2,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            plugin_ids=list(plugin_ids),
        )

    def test_single_source(self):
        assert self._snap(["nessus:1", "nessus:2"]).source == "nessus"
        assert self._snap(["nuclei:tech-detect"]).source == "nuclei"

    def test_empty_snapshot_is_unknown_not_a_guess(self):
        assert self._snap([]).source == "unknown"

    def test_mixed_sources_reported_as_mixed(self):
        assert self._snap(["nessus:1", "nuclei:x"]).source == "mixed"


@pytest.mark.integration
class TestHostHistoryTrendAcrossSources:
    """`scan history` must not claim remediation across two scanners.

    A 30-finding Nessus scan followed by a 3-finding nuclei scan is not 27
    findings fixed -- the two tools count different things. Before this, the
    Trend column and the overall summary both reported the difference as if it
    were progress.
    """

    def _history(self, conn):
        _create_test_scan(
            conn,
            "nessus-scan",
            [
                {
                    "plugin_id": f"nessus:{100 + i}",
                    "plugin_name": f"N{i}",
                    "severity_int": 3,
                    "hosts": ["10.0.0.1"],
                }
                for i in range(5)
            ],
        )
        _create_test_scan(
            conn,
            "nuclei-scan",
            [
                {
                    "plugin_id": "nuclei:tech-detect",
                    "plugin_name": "Tech Detect",
                    "severity_int": 0,
                    "hosts": ["10.0.0.1"],
                }
            ],
        )
        return get_host_vulnerability_history("10.0.0.1", conn)

    def test_snapshots_report_their_own_source(self, temp_db):
        history = self._history(temp_db)
        assert {s.source for s in history.scans} == {"nessus", "nuclei"}

    def test_no_overall_trend_claim_across_sources(self, temp_db, capsys):
        from cerno_pkg.render import render_host_history

        history = self._history(temp_db)
        render_host_history(history)
        out = capsys.readouterr().out
        # The misleading claim: 5 findings then 1 reads as "-4 findings".
        assert "-4 findings" not in out
        assert "since first scan" not in out
        assert "different sources" in out

    def test_source_column_is_rendered(self, temp_db, capsys):
        from cerno_pkg.render import render_host_history

        render_host_history(self._history(temp_db))
        out = capsys.readouterr().out
        assert "Source" in out and "nessus" in out and "nuclei" in out

    def test_single_source_history_still_reports_a_trend(self, temp_db, capsys):
        from cerno_pkg.render import render_host_history

        _create_test_scan(
            temp_db,
            "first",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "N",
                    "severity_int": 3,
                    "hosts": ["10.9.9.9"],
                },
                {
                    "plugin_id": "nessus:101",
                    "plugin_name": "N2",
                    "severity_int": 3,
                    "hosts": ["10.9.9.9"],
                },
            ],
        )
        _create_test_scan(
            temp_db,
            "second",
            [
                {
                    "plugin_id": "nessus:100",
                    "plugin_name": "N",
                    "severity_int": 3,
                    "hosts": ["10.9.9.9"],
                }
            ],
        )
        render_host_history(get_host_vulnerability_history("10.9.9.9", temp_db))
        out = capsys.readouterr().out
        assert "since first scan" in out
        # info() does not parse Rich markup, so these must not leak tags.
        assert "[green]" not in out and "[red]" not in out
