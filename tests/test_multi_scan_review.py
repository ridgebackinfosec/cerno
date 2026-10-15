"""Tests for multi-scan review feature.

Covers:
- parse_scan_selection() input parsing (unit)
- Finding.get_by_scan_ids_merged() cross-scan deduplication (integration)
- Scan label logic for "All N" vs "M of N" coverage display (unit)
- Review state updates across multiple findings (integration)
"""

import pytest

from cerno_pkg.models import Finding, Host, Plugin, Scan
from cerno_pkg.tui import parse_scan_selection
from cerno_pkg.database import query_all


# ========== TestParseScanSelection ==========


@pytest.mark.unit
class TestParseScanSelection:
    """Unit tests for parse_scan_selection() input parsing."""

    def test_single_number(self):
        result = parse_scan_selection("1", 5)
        assert result == [1]

    def test_range(self):
        result = parse_scan_selection("1-3", 5)
        assert result == [1, 2, 3]

    def test_comma_separated(self):
        result = parse_scan_selection("1,3", 5)
        assert result == [1, 3]

    def test_mixed_range_and_comma(self):
        result = parse_scan_selection("1-2,4", 5)
        assert result == [1, 2, 4]

    def test_invalid_returns_none(self):
        assert parse_scan_selection("abc", 5) is None

    def test_out_of_range_returns_none(self):
        assert parse_scan_selection("6", 5) is None

    def test_zero_returns_none(self):
        assert parse_scan_selection("0", 5) is None

    def test_inverted_range_returns_none(self):
        assert parse_scan_selection("3-1", 5) is None

    def test_empty_returns_none(self):
        assert parse_scan_selection("", 5) is None

    def test_max_boundary(self):
        result = parse_scan_selection("5", 5)
        assert result == [5]

    def test_full_range(self):
        result = parse_scan_selection("1-5", 5)
        assert result == [1, 2, 3, 4, 5]


# ========== TestGetByScanIdsMerged ==========


@pytest.mark.integration
class TestGetByScanIdsMerged:
    """Integration tests for Finding.get_by_scan_ids_merged()."""

    def _setup_two_scans(self, conn):
        """Helper: two scans with one shared plugin and one unique plugin each."""
        # Scans
        scan_a = Scan(scan_name="scan_a", export_root="/tmp", nessus_file_path="/tmp/a.nessus")
        scan_a_id = scan_a.save(conn)
        scan_b = Scan(scan_name="scan_b", export_root="/tmp", nessus_file_path="/tmp/b.nessus")
        scan_b_id = scan_b.save(conn)

        # Shared plugin (appears in both scans)
        shared_plugin = Plugin(plugin_id=11111, plugin_name="Shared Plugin", severity_int=3, severity_label="High")
        shared_plugin.save(conn)

        # Unique plugin for scan_a only
        plugin_a = Plugin(plugin_id=22222, plugin_name="Plugin A Only", severity_int=2, severity_label="Medium")
        plugin_a.save(conn)

        # Unique plugin for scan_b only
        plugin_b = Plugin(plugin_id=33333, plugin_name="Plugin B Only", severity_int=1, severity_label="Low")
        plugin_b.save(conn)

        # Findings
        finding_shared_a = Finding(scan_id=scan_a_id, plugin_id=11111)
        finding_shared_a.save(conn)
        finding_shared_b = Finding(scan_id=scan_b_id, plugin_id=11111)
        finding_shared_b.save(conn)
        finding_a_only = Finding(scan_id=scan_a_id, plugin_id=22222)
        finding_a_only.save(conn)
        finding_b_only = Finding(scan_id=scan_b_id, plugin_id=33333)
        finding_b_only.save(conn)

        conn.commit()
        return scan_a_id, scan_b_id

    def test_empty_scan_ids_returns_empty(self, temp_db):
        display_list, all_instances = Finding.get_by_scan_ids_merged([], conn=temp_db)
        assert display_list == []
        assert all_instances == {}

    def test_merged_returns_one_per_plugin(self, temp_db):
        scan_a_id, scan_b_id = self._setup_two_scans(temp_db)
        display_list, all_instances = Finding.get_by_scan_ids_merged(
            [scan_a_id, scan_b_id], conn=temp_db
        )
        # Should have 3 unique plugins
        assert len(display_list) == 3
        plugin_ids = [p.plugin_id for _, p in display_list]
        assert set(plugin_ids) == {11111, 22222, 33333}

    def test_all_instances_maps_plugin_to_findings(self, temp_db):
        scan_a_id, scan_b_id = self._setup_two_scans(temp_db)
        _, all_instances = Finding.get_by_scan_ids_merged(
            [scan_a_id, scan_b_id], conn=temp_db
        )
        # Shared plugin should have 2 instances (one per scan)
        assert len(all_instances[11111]) == 2
        # Plugin a only has 1 instance
        assert len(all_instances[22222]) == 1
        # Plugin b only has 1 instance
        assert len(all_instances[33333]) == 1

    def test_representative_has_lowest_scan_id(self, temp_db):
        scan_a_id, scan_b_id = self._setup_two_scans(temp_db)
        display_list, _ = Finding.get_by_scan_ids_merged(
            [scan_a_id, scan_b_id], conn=temp_db
        )
        # For shared plugin, representative should be from scan_a (lower scan_id)
        for finding, plugin in display_list:
            if plugin.plugin_id == 11111:
                assert finding.scan_id == scan_a_id
                break

    def test_representative_has_extra_finding_ids(self, temp_db):
        scan_a_id, scan_b_id = self._setup_two_scans(temp_db)
        display_list, all_instances = Finding.get_by_scan_ids_merged(
            scan_ids=[scan_a_id, scan_b_id], conn=temp_db
        )
        reps = {f.plugin_id: f for f, _p in display_list}
        assert reps[11111].extra_finding_ids == [all_instances[11111][1].finding_id]
        assert reps[22222].extra_finding_ids == []
        assert reps[33333].extra_finding_ids == []

    def test_single_scan_id_works(self, temp_db):
        scan_a_id, scan_b_id = self._setup_two_scans(temp_db)
        display_list, _ = Finding.get_by_scan_ids_merged(
            [scan_a_id], conn=temp_db
        )
        # Only scan_a findings: shared + plugin_a_only
        assert len(display_list) == 2

    def test_severity_filter_applied(self, temp_db):
        scan_a_id, scan_b_id = self._setup_two_scans(temp_db)
        display_list, _ = Finding.get_by_scan_ids_merged(
            [scan_a_id, scan_b_id],
            severity_dirs=["3_High"],
            conn=temp_db
        )
        # Only High severity plugin (11111)
        assert len(display_list) == 1
        assert display_list[0][1].plugin_id == 11111


# ========== TestScanLabels ==========


@pytest.mark.unit
class TestScanLabels:
    """Unit tests for scan coverage label logic."""

    def test_all_label_when_in_all_scans(self):
        """When a plugin appears in all selected scans, label is 'All N'."""
        all_instances = {111: ["f1", "f2", "f3"]}  # 3 findings
        total = 3
        label = f"All {total}" if len(all_instances[111]) == total else f"{len(all_instances[111])} of {total}"
        assert label == "All 3"

    def test_partial_label_when_subset(self):
        """When a plugin appears in subset of selected scans, label is 'M of N'."""
        all_instances = {222: ["f1", "f2"]}  # 2 findings
        total = 4
        label = f"All {total}" if len(all_instances[222]) == total else f"{len(all_instances[222])} of {total}"
        assert label == "2 of 4"


# ========== TestReviewStateBroadcast ==========


@pytest.mark.integration
class TestReviewStateBroadcast:
    """Integration tests for updating review state across multiple scan findings."""

    def test_update_review_state(self, temp_db):
        """Test that update_review_state() works for individual findings."""
        scan_a = Scan(scan_name="scan_a", export_root="/tmp", nessus_file_path="/tmp/a.nessus")
        scan_a_id = scan_a.save(temp_db)
        scan_b = Scan(scan_name="scan_b", export_root="/tmp", nessus_file_path="/tmp/b.nessus")
        scan_b_id = scan_b.save(temp_db)

        plugin = Plugin(plugin_id=44444, plugin_name="Test Plugin", severity_int=3, severity_label="High")
        plugin.save(temp_db)

        finding_a = Finding(scan_id=scan_a_id, plugin_id=44444)
        finding_a.save(temp_db)
        finding_b = Finding(scan_id=scan_b_id, plugin_id=44444)
        finding_b.save(temp_db)

        temp_db.commit()

        # Reload to get finding_ids via merged query
        _, all_instances = Finding.get_by_scan_ids_merged(
            [scan_a_id, scan_b_id], conn=temp_db
        )
        assert len(all_instances[44444]) == 2

        # Update both findings to completed (simulating broadcast)
        for f in all_instances[44444]:
            f.update_review_state("completed", conn=temp_db)

        temp_db.commit()

        # Verify both findings have been updated to completed
        rows = query_all(temp_db, "SELECT review_state FROM findings WHERE plugin_id = ?", (44444,))
        states = [r["review_state"] for r in rows]
        assert all(s == "completed" for s in states)


# ========== TestHostPluginIdsMultiScan ==========


@pytest.mark.integration
class TestHostPluginIdsMultiScan:
    """Integration tests for Host.get_plugin_ids_for_scan() across multiple scans."""

    def _link(self, conn, scan_id, plugin_id, host_ip):
        """Helper: create finding for plugin in scan and link host to it."""
        Plugin(plugin_id=plugin_id, plugin_name=f"Plugin {plugin_id}", severity_int=2).save(conn)
        finding_id = Finding(scan_id=scan_id, plugin_id=plugin_id).save(conn)
        host_id = Host.get_or_create(
            ip_address=host_ip, scan_target=host_ip, scan_target_type="ipv4", conn=conn
        )
        conn.execute(
            "INSERT OR IGNORE INTO finding_affected_hosts "
            "(finding_id, host_id, port_number, plugin_output) VALUES (?, ?, NULL, 'x')",
            (finding_id, host_id),
        )

    def _setup(self, conn):
        """Two scans: 10.0.0.5 has plugin 100 in A, 200 in B, 300 in both; 10.0.0.9 only in B."""
        scan_a_id = Scan(scan_name="scan_a", export_root="/tmp").save(conn)
        scan_b_id = Scan(scan_name="scan_b", export_root="/tmp").save(conn)
        self._link(conn, scan_a_id, 100, "10.0.0.5")
        self._link(conn, scan_b_id, 200, "10.0.0.5")
        self._link(conn, scan_a_id, 300, "10.0.0.5")
        self._link(conn, scan_b_id, 300, "10.0.0.5")
        self._link(conn, scan_b_id, 400, "10.0.0.9")
        conn.commit()
        return scan_a_id, scan_b_id

    def test_returns_union_across_scans(self, temp_db):
        a, b = self._setup(temp_db)
        result = Host.get_plugin_ids_for_scan(
            ip_address="10.0.0.5", scan_id=a, scan_ids=[a, b], conn=temp_db
        )
        assert result == [100, 200, 300]

    def test_host_only_in_secondary_scan(self, temp_db):
        a, b = self._setup(temp_db)
        result = Host.get_plugin_ids_for_scan(
            ip_address="10.0.0.9", scan_id=a, scan_ids=[a, b], conn=temp_db
        )
        assert result == [400]

    def test_single_scan_unchanged(self, temp_db):
        a, _b = self._setup(temp_db)
        result = Host.get_plugin_ids_for_scan(ip_address="10.0.0.5", scan_id=a, conn=temp_db)
        assert result == [100, 300]

    def test_partial_match_across_scans(self, temp_db):
        a, b = self._setup(temp_db)
        result = Host.get_plugin_ids_for_scan(
            ip_address="10.0.0", scan_id=a, scan_ids=[a, b], partial_match=True, conn=temp_db
        )
        assert result == [100, 200, 300, 400]
