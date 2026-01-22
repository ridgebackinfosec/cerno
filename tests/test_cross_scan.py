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
                {"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 3, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "Plugin B", "severity_int": 2, "hosts": ["192.168.1.2"]},
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
                {"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 3, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "Plugin B", "severity_int": 2, "hosts": ["192.168.1.1"]},
            ],
        )

        # Scan 2: plugins 100, 101, 102 (102 is new)
        scan2_id = _create_test_scan(
            temp_db,
            "scan2",
            [
                {"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 3, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "Plugin B", "severity_int": 2, "hosts": ["192.168.1.1"]},
                {"plugin_id": 102, "plugin_name": "Plugin C", "severity_int": 4, "hosts": ["192.168.1.1"]},
            ],
        )

        result = compare_scans(scan1_id, scan2_id, conn=temp_db)

        assert result is not None
        assert result.total_new == 1
        assert result.total_resolved == 0
        assert result.total_persistent == 2

        # Check the new finding
        new_plugin_ids = [f["plugin_id"] for f in result.new_findings]
        assert 102 in new_plugin_ids

    def test_compare_finds_resolved_findings(self, temp_db):
        """Resolved findings (in scan1 only) detected correctly."""
        # Scan 1: plugins 100, 101, 102
        scan1_id = _create_test_scan(
            temp_db,
            "scan1",
            [
                {"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 3, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "Plugin B", "severity_int": 2, "hosts": ["192.168.1.1"]},
                {"plugin_id": 102, "plugin_name": "Plugin C", "severity_int": 4, "hosts": ["192.168.1.1"]},
            ],
        )

        # Scan 2: plugins 100, 101 (102 is resolved)
        scan2_id = _create_test_scan(
            temp_db,
            "scan2",
            [
                {"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 3, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "Plugin B", "severity_int": 2, "hosts": ["192.168.1.1"]},
            ],
        )

        result = compare_scans(scan1_id, scan2_id, conn=temp_db)

        assert result is not None
        assert result.total_new == 0
        assert result.total_resolved == 1
        assert result.total_persistent == 2

        # Check the resolved finding
        resolved_plugin_ids = [f["plugin_id"] for f in result.resolved_findings]
        assert 102 in resolved_plugin_ids

    def test_compare_severity_filter(self, temp_db):
        """Minimum severity filter works correctly."""
        # Scan 1: plugins at various severities
        scan1_id = _create_test_scan(
            temp_db,
            "scan1",
            [
                {"plugin_id": 100, "plugin_name": "Low Plugin", "severity_int": 1, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "Medium Plugin", "severity_int": 2, "hosts": ["192.168.1.1"]},
                {"plugin_id": 102, "plugin_name": "High Plugin", "severity_int": 3, "hosts": ["192.168.1.1"]},
            ],
        )

        # Scan 2: same plugins
        scan2_id = _create_test_scan(
            temp_db,
            "scan2",
            [
                {"plugin_id": 100, "plugin_name": "Low Plugin", "severity_int": 1, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "Medium Plugin", "severity_int": 2, "hosts": ["192.168.1.1"]},
                {"plugin_id": 102, "plugin_name": "High Plugin", "severity_int": 3, "hosts": ["192.168.1.1"]},
            ],
        )

        # Filter to High and above (severity >= 3)
        result = compare_scans(scan1_id, scan2_id, min_severity=3, conn=temp_db)

        assert result is not None
        assert result.total_persistent == 1  # Only the High plugin
        persistent_plugin_ids = [f["plugin_id"] for f in result.persistent_findings]
        assert 102 in persistent_plugin_ids
        assert 100 not in persistent_plugin_ids
        assert 101 not in persistent_plugin_ids

    def test_compare_host_changes(self, temp_db):
        """Host changes detected correctly."""
        # Scan 1: hosts 1.1, 1.2
        scan1_id = _create_test_scan(
            temp_db,
            "scan1",
            [
                {"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 3, "hosts": ["192.168.1.1", "192.168.1.2"]},
            ],
        )

        # Scan 2: hosts 1.1, 1.3 (1.2 removed, 1.3 new)
        scan2_id = _create_test_scan(
            temp_db,
            "scan2",
            [
                {"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 3, "hosts": ["192.168.1.1", "192.168.1.3"]},
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
            [{"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 3, "hosts": ["192.168.1.1"]}],
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
                {"plugin_id": 100, "plugin_name": "Critical", "severity_int": 4, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "High", "severity_int": 3, "hosts": ["192.168.1.1"]},
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
                {"plugin_id": 100, "plugin_name": "Critical", "severity_int": 4, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "High", "severity_int": 3, "hosts": ["192.168.1.1"]},
                {"plugin_id": 102, "plugin_name": "Medium", "severity_int": 2, "hosts": ["192.168.1.1"]},
            ],
        )

        # Scan 2: 2 findings (one resolved)
        _create_test_scan(
            temp_db,
            "scan2",
            [
                {"plugin_id": 100, "plugin_name": "Critical", "severity_int": 4, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "High", "severity_int": 3, "hosts": ["192.168.1.1"]},
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
            [{"plugin_id": 100, "plugin_name": "Plugin", "severity_int": 3, "hosts": ["192.168.1.1"]}],
        )

        history = get_host_vulnerability_history("10.0.0.99", conn=temp_db)
        assert history is None

    def test_host_history_plugin_ids(self, temp_db):
        """Host history includes plugin IDs."""
        _create_test_scan(
            temp_db,
            "scan1",
            [
                {"plugin_id": 100, "plugin_name": "Plugin A", "severity_int": 4, "hosts": ["192.168.1.1"]},
                {"plugin_id": 101, "plugin_name": "Plugin B", "severity_int": 3, "hosts": ["192.168.1.1"]},
            ],
        )

        history = get_host_vulnerability_history("192.168.1.1", conn=temp_db)

        assert history is not None
        assert len(history.scans[0].plugin_ids) == 2
        assert 100 in history.scans[0].plugin_ids
        assert 101 in history.scans[0].plugin_ids


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
            new_findings=[{"plugin_id": 100}, {"plugin_id": 101}],
            resolved_findings=[{"plugin_id": 102}],
            persistent_findings=[{"plugin_id": 103}, {"plugin_id": 104}, {"plugin_id": 105}],
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
