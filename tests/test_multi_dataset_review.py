"""Tests for multi-dataset review feature.

Covers:
- parse_dataset_selection() input parsing (unit)
- Finding.get_by_dataset_ids_merged() cross-dataset deduplication (integration)
- Dataset label logic for "All N" vs "M of N" coverage display (unit)
- Review state updates across multiple findings (integration)
"""

from cerno_pkg.constants import SOURCE_OPERATOR

import pytest

from cerno_pkg.models import Finding, Host, FindingType, Dataset
from cerno_pkg.tui import parse_dataset_selection
from cerno_pkg.database import query_all

# ========== TestParseScanSelection ==========


@pytest.mark.unit
class TestParseScanSelection:
    """Unit tests for parse_dataset_selection() input parsing."""

    def test_single_number(self):
        result = parse_dataset_selection("1", 5)
        assert result == [1]

    def test_range(self):
        result = parse_dataset_selection("1-3", 5)
        assert result == [1, 2, 3]

    def test_comma_separated(self):
        result = parse_dataset_selection("1,3", 5)
        assert result == [1, 3]

    def test_mixed_range_and_comma(self):
        result = parse_dataset_selection("1-2,4", 5)
        assert result == [1, 2, 4]

    def test_invalid_returns_none(self):
        assert parse_dataset_selection("abc", 5) is None

    def test_out_of_range_returns_none(self):
        assert parse_dataset_selection("6", 5) is None

    def test_zero_returns_none(self):
        assert parse_dataset_selection("0", 5) is None

    def test_inverted_range_returns_none(self):
        assert parse_dataset_selection("3-1", 5) is None

    def test_empty_returns_none(self):
        assert parse_dataset_selection("", 5) is None

    def test_max_boundary(self):
        result = parse_dataset_selection("5", 5)
        assert result == [5]

    def test_full_range(self):
        result = parse_dataset_selection("1-5", 5)
        assert result == [1, 2, 3, 4, 5]


# ========== TestGetByScanIdsMerged ==========


@pytest.mark.integration
class TestGetByScanIdsMerged:
    """Integration tests for Finding.get_by_dataset_ids_merged()."""

    def _setup_two_datasets(self, conn):
        """Helper: two datasets with one shared finding_type and one unique finding_type each."""
        # Datasets
        dataset_a = Dataset(
            dataset_name="dataset_a",
            export_root="/tmp",
            source_file_path="/tmp/a.nessus",
        )
        dataset_a_id = dataset_a.save(conn)
        dataset_b = Dataset(
            dataset_name="dataset_b",
            export_root="/tmp",
            source_file_path="/tmp/b.nessus",
        )
        dataset_b_id = dataset_b.save(conn)

        # Shared finding_type (appears in both datasets)
        shared_finding_type = FindingType(
            finding_type_id="nessus:11111",
            finding_type_name="Shared FindingType",
            severity_int=3,
            severity_label="High",
        )
        shared_finding_type.save(conn)

        # Unique finding_type for dataset_a only
        finding_type_a = FindingType(
            finding_type_id="nessus:22222",
            finding_type_name="FindingType A Only",
            severity_int=2,
            severity_label="Medium",
        )
        finding_type_a.save(conn)

        # Unique finding_type for dataset_b only
        finding_type_b = FindingType(
            finding_type_id="nessus:33333",
            finding_type_name="FindingType B Only",
            severity_int=1,
            severity_label="Low",
        )
        finding_type_b.save(conn)

        # Findings
        finding_shared_a = Finding(
            dataset_id=dataset_a_id, finding_type_id="nessus:11111"
        )
        finding_shared_a.save(conn)
        finding_shared_b = Finding(
            dataset_id=dataset_b_id, finding_type_id="nessus:11111"
        )
        finding_shared_b.save(conn)
        finding_a_only = Finding(
            dataset_id=dataset_a_id, finding_type_id="nessus:22222"
        )
        finding_a_only.save(conn)
        finding_b_only = Finding(
            dataset_id=dataset_b_id, finding_type_id="nessus:33333"
        )
        finding_b_only.save(conn)

        conn.commit()
        return dataset_a_id, dataset_b_id

    def test_empty_dataset_ids_returns_empty(self, temp_db):
        display_list, all_instances = Finding.get_by_dataset_ids_merged(
            [], conn=temp_db
        )
        assert display_list == []
        assert all_instances == {}

    def test_merged_returns_one_per_finding_type(self, temp_db):
        dataset_a_id, dataset_b_id = self._setup_two_datasets(temp_db)
        display_list, all_instances = Finding.get_by_dataset_ids_merged(
            [dataset_a_id, dataset_b_id], conn=temp_db
        )
        # Should have 3 unique finding_types
        assert len(display_list) == 3
        finding_type_ids = [p.finding_type_id for _, p in display_list]
        assert set(finding_type_ids) == {"nessus:11111", "nessus:22222", "nessus:33333"}

    def test_all_instances_maps_finding_type_to_findings(self, temp_db):
        dataset_a_id, dataset_b_id = self._setup_two_datasets(temp_db)
        _, all_instances = Finding.get_by_dataset_ids_merged(
            [dataset_a_id, dataset_b_id], conn=temp_db
        )
        # Shared finding_type should have 2 instances (one per dataset)
        assert len(all_instances["nessus:11111"]) == 2
        # FindingType a only has 1 instance
        assert len(all_instances["nessus:22222"]) == 1
        # FindingType b only has 1 instance
        assert len(all_instances["nessus:33333"]) == 1

    def test_representative_has_lowest_dataset_id(self, temp_db):
        dataset_a_id, dataset_b_id = self._setup_two_datasets(temp_db)
        display_list, _ = Finding.get_by_dataset_ids_merged(
            [dataset_a_id, dataset_b_id], conn=temp_db
        )
        # For shared finding_type, representative should be from dataset_a (lower dataset_id)
        for finding, finding_type in display_list:
            if finding_type.finding_type_id == "nessus:11111":
                assert finding.dataset_id == dataset_a_id
                break

    def test_representative_has_extra_finding_ids(self, temp_db):
        dataset_a_id, dataset_b_id = self._setup_two_datasets(temp_db)
        display_list, all_instances = Finding.get_by_dataset_ids_merged(
            dataset_ids=[dataset_a_id, dataset_b_id], conn=temp_db
        )
        reps = {f.finding_type_id: f for f, _p in display_list}
        assert reps["nessus:11111"].extra_finding_ids == [
            all_instances["nessus:11111"][1].finding_id
        ]
        assert reps["nessus:22222"].extra_finding_ids == []
        assert reps["nessus:33333"].extra_finding_ids == []

    def test_single_dataset_id_works(self, temp_db):
        dataset_a_id, dataset_b_id = self._setup_two_datasets(temp_db)
        display_list, _ = Finding.get_by_dataset_ids_merged(
            [dataset_a_id], conn=temp_db
        )
        # Only dataset_a findings: shared + finding_type_a_only
        assert len(display_list) == 2

    def test_severity_filter_applied(self, temp_db):
        dataset_a_id, dataset_b_id = self._setup_two_datasets(temp_db)
        display_list, _ = Finding.get_by_dataset_ids_merged(
            [dataset_a_id, dataset_b_id], severity_dirs=["3_High"], conn=temp_db
        )
        # Only High severity finding_type (11111)
        assert len(display_list) == 1
        assert display_list[0][1].finding_type_id == "nessus:11111"


# ========== TestScanLabels ==========


@pytest.mark.unit
class TestScanLabels:
    """Unit tests for scan coverage label logic."""

    def test_all_label_when_in_all_datasets(self):
        """When a finding_type appears in all selected datasets, label is 'All N'."""
        all_instances = {111: ["f1", "f2", "f3"]}  # 3 findings
        total = 3
        label = (
            f"All {total}"
            if len(all_instances[111]) == total
            else f"{len(all_instances[111])} of {total}"
        )
        assert label == "All 3"

    def test_partial_label_when_subset(self):
        """When a finding_type appears in subset of selected datasets, label is 'M of N'."""
        all_instances = {222: ["f1", "f2"]}  # 2 findings
        total = 4
        label = (
            f"All {total}"
            if len(all_instances[222]) == total
            else f"{len(all_instances[222])} of {total}"
        )
        assert label == "2 of 4"


# ========== TestReviewStateBroadcast ==========


@pytest.mark.integration
class TestReviewStateBroadcast:
    """Integration tests for updating review state across multiple scan findings."""

    def test_update_review_state(self, temp_db):
        """Test that update_review_state() works for individual findings."""
        dataset_a = Dataset(
            dataset_name="dataset_a",
            export_root="/tmp",
            source_file_path="/tmp/a.nessus",
        )
        dataset_a_id = dataset_a.save(temp_db)
        dataset_b = Dataset(
            dataset_name="dataset_b",
            export_root="/tmp",
            source_file_path="/tmp/b.nessus",
        )
        dataset_b_id = dataset_b.save(temp_db)

        finding_type = FindingType(
            finding_type_id="nessus:44444",
            finding_type_name="Test FindingType",
            severity_int=3,
            severity_label="High",
        )
        finding_type.save(temp_db)

        finding_a = Finding(dataset_id=dataset_a_id, finding_type_id="nessus:44444")
        finding_a.save(temp_db)
        finding_b = Finding(dataset_id=dataset_b_id, finding_type_id="nessus:44444")
        finding_b.save(temp_db)

        temp_db.commit()

        # Reload to get finding_ids via merged query
        _, all_instances = Finding.get_by_dataset_ids_merged(
            [dataset_a_id, dataset_b_id], conn=temp_db
        )
        assert len(all_instances["nessus:44444"]) == 2

        # Update both findings to completed (simulating broadcast)
        for f in all_instances["nessus:44444"]:
            f.update_review_state("done", SOURCE_OPERATOR, conn=temp_db)

        temp_db.commit()

        # Verify both findings have been updated to completed
        rows = query_all(
            temp_db,
            "SELECT review_state FROM findings WHERE finding_type_id = ?",
            (44444,),
        )
        states = [r["review_state"] for r in rows]
        assert all(s == "done" for s in states)


# ========== TestHostPluginIdsMultiScan ==========


@pytest.mark.integration
class TestHostPluginIdsMultiScan:
    """Integration tests for Host.get_finding_type_ids_for_dataset() across multiple datasets."""

    def _link(self, conn, dataset_id, finding_type_id, host_ip):
        """Helper: create finding for finding_type in scan and link host to it."""
        FindingType(
            finding_type_id=finding_type_id,
            finding_type_name=f"FindingType {finding_type_id}",
            severity_int=2,
        ).save(conn)
        finding_id = Finding(
            dataset_id=dataset_id, finding_type_id=finding_type_id
        ).save(conn)
        host_id = Host.get_or_create(
            ip_address=host_ip, scan_target=host_ip, scan_target_type="ipv4", conn=conn
        )
        conn.execute(
            "INSERT OR IGNORE INTO finding_affected_hosts "
            "(finding_id, host_id, port_number, evidence) VALUES (?, ?, NULL, 'x')",
            (finding_id, host_id),
        )

    def _setup(self, conn):
        """Two datasets: 10.0.0.5 has finding_type 100 in A, 200 in B, 300 in both; 10.0.0.9 only in B."""
        dataset_a_id = Dataset(dataset_name="dataset_a", export_root="/tmp").save(conn)
        dataset_b_id = Dataset(dataset_name="dataset_b", export_root="/tmp").save(conn)
        self._link(conn, dataset_a_id, "nessus:100", "10.0.0.5")
        self._link(conn, dataset_b_id, "nessus:200", "10.0.0.5")
        self._link(conn, dataset_a_id, "nessus:300", "10.0.0.5")
        self._link(conn, dataset_b_id, "nessus:300", "10.0.0.5")
        self._link(conn, dataset_b_id, "nessus:400", "10.0.0.9")
        conn.commit()
        return dataset_a_id, dataset_b_id

    def test_returns_union_across_datasets(self, temp_db):
        a, b = self._setup(temp_db)
        result = Host.get_finding_type_ids_for_dataset(
            ip_address="10.0.0.5", dataset_id=a, dataset_ids=[a, b], conn=temp_db
        )
        assert result == ["nessus:100", "nessus:200", "nessus:300"]

    def test_host_only_in_secondary_dataset(self, temp_db):
        a, b = self._setup(temp_db)
        result = Host.get_finding_type_ids_for_dataset(
            ip_address="10.0.0.9", dataset_id=a, dataset_ids=[a, b], conn=temp_db
        )
        assert result == ["nessus:400"]

    def test_single_dataset_unchanged(self, temp_db):
        a, _b = self._setup(temp_db)
        result = Host.get_finding_type_ids_for_dataset(
            ip_address="10.0.0.5", dataset_id=a, conn=temp_db
        )
        assert result == ["nessus:100", "nessus:300"]

    def test_partial_match_across_datasets(self, temp_db):
        a, b = self._setup(temp_db)
        result = Host.get_finding_type_ids_for_dataset(
            ip_address="10.0.0",
            dataset_id=a,
            dataset_ids=[a, b],
            partial_match=True,
            conn=temp_db,
        )
        assert result == ["nessus:100", "nessus:200", "nessus:300", "nessus:400"]
