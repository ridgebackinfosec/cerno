"""Tests for cerno_pkg.models module."""

from cerno_pkg.constants import SOURCE_OPERATOR

import json
from datetime import datetime

import pytest

from cerno_pkg.models import (
    Dataset,
    FindingType,
    Finding,
    ToolExecution,
    Artifact,
    now_iso,
)


class TestScanModel:
    """Tests for Scan model."""

    def test_dataset_save_creates_record(self, temp_db):
        """Test saving a new scan."""
        dataset = Dataset(
            dataset_name="test_dataset",
            source_file_path="/tmp/test.nessus",
            export_root="/tmp/exports",
        )

        dataset_id = dataset.save(temp_db)

        assert dataset_id is not None
        assert dataset_id > 0

    def test_dataset_get_by_name(self, temp_db):
        """Test retrieving scan by name."""
        # Create scan
        dataset = Dataset(
            dataset_name="test_dataset",
            source_file_path="/tmp/test.nessus",
            export_root="/tmp/exports",
        )
        dataset.save(temp_db)

        # Retrieve it
        retrieved = Dataset.get_by_name("test_dataset", temp_db)

        assert retrieved is not None
        assert retrieved.dataset_name == "test_dataset"
        assert retrieved.source_file_path == "/tmp/test.nessus"

    def test_dataset_get_by_name_nonexistent(self, temp_db):
        """Test retrieving nonexistent scan returns None."""
        result = Dataset.get_by_name("nonexistent", temp_db)
        assert result is None

    def test_dataset_get_by_id(self, temp_db):
        """Test retrieving scan by ID."""
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)

        retrieved = Dataset.get_by_id(dataset_id, temp_db)

        assert retrieved is not None
        assert retrieved.dataset_id == dataset_id
        assert retrieved.dataset_name == "test_dataset"

    def test_dataset_get_all_empty(self, temp_db):
        """Test get_all returns empty list when no datasets."""
        datasets = Dataset.get_all(temp_db)
        assert datasets == []

    def test_dataset_get_all_orders_by_last_reviewed(self, temp_db):
        """Test get_all returns datasets ordered by last_reviewed_at DESC."""
        from datetime import datetime, timedelta

        # Create 3 datasets with different last_reviewed_at
        dataset1 = Dataset(dataset_name="old_dataset", export_root="/tmp/old")
        dataset1_id = dataset1.save(temp_db)
        assert dataset1_id is not None

        dataset2 = Dataset(dataset_name="recent_dataset", export_root="/tmp/recent")
        dataset2_id = dataset2.save(temp_db)
        assert dataset2_id is not None

        scan3 = Dataset(dataset_name="never_reviewed", export_root="/tmp/never")
        scan3_id = scan3.save(temp_db)
        assert scan3_id is not None

        # Update last_reviewed_at for scan1 and scan2
        old_time = (datetime.now() - timedelta(days=7)).isoformat()
        recent_time = (datetime.now() - timedelta(hours=1)).isoformat()

        temp_db.execute(
            "UPDATE datasets SET last_reviewed_at = ? WHERE dataset_id = ?",
            (old_time, dataset1_id),
        )
        temp_db.execute(
            "UPDATE datasets SET last_reviewed_at = ? WHERE dataset_id = ?",
            (recent_time, dataset2_id),
        )
        temp_db.commit()

        # Get all datasets
        datasets = Dataset.get_all(temp_db)

        # Should be ordered: recent_dataset, old_dataset, never_reviewed (NULLS LAST)
        assert len(datasets) == 3
        assert datasets[0].dataset_name == "recent_dataset"
        assert datasets[1].dataset_name == "old_dataset"
        assert datasets[2].dataset_name == "never_reviewed"

    def test_dataset_update_existing(self, temp_db):
        """Test updating existing scan."""
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None

        # Update
        dataset.dataset_id = dataset_id
        dataset.source_file_hash = "abc123"
        dataset.save(temp_db)

        # Retrieve and verify
        retrieved = Dataset.get_by_id(dataset_id, temp_db)
        assert retrieved is not None
        assert retrieved.source_file_hash == "abc123"

    def test_dataset_unique_constraint(self, temp_db):
        """Test that dataset names must be unique."""
        dataset1 = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset1.save(temp_db)

        dataset2 = Dataset(dataset_name="test_dataset", export_root="/tmp2")

        with pytest.raises(Exception):  # Should raise IntegrityError
            dataset2.save(temp_db)


class TestPluginModel:
    """Tests for FindingType model."""

    def test_finding_type_save_creates_record(self, temp_db):
        """Test saving a new finding_type."""
        finding_type = FindingType(
            finding_type_id="nessus:12345",
            finding_type_name="Test FindingType",
            severity_int=2,
            cvss3_score=5.3,
        )

        finding_type.save(temp_db)

        # Verify saved
        cursor = temp_db.execute(
            "SELECT finding_type_name FROM finding_types WHERE finding_type_id = ?",
            ("nessus:12345",),
        )
        result = cursor.fetchone()
        assert result["finding_type_name"] == "Test FindingType"

    def test_finding_type_get_by_id(self, temp_db):
        """Test retrieving finding_type by ID."""
        finding_type = FindingType(
            finding_type_id="nessus:12345",
            finding_type_name="Test FindingType",
            severity_int=2,
        )
        finding_type.save(temp_db)

        retrieved = FindingType.get_by_id("nessus:12345", temp_db)

        assert retrieved is not None
        assert retrieved.finding_type_id == "nessus:12345"
        assert retrieved.finding_type_name == "Test FindingType"

    def test_finding_type_cve_list_serialization(self, temp_db):
        """Test CVE list is serialized to JSON."""
        finding_type = FindingType(
            finding_type_id="nessus:12345",
            finding_type_name="Test FindingType",
            severity_int=2,
            cves=["CVE-2024-0001", "CVE-2024-0002"],
        )
        finding_type.save(temp_db)

        # Check stored as JSON
        cursor = temp_db.execute(
            "SELECT cves FROM finding_types WHERE finding_type_id = ?",
            ("nessus:12345",),
        )
        result = cursor.fetchone()
        cves = json.loads(result["cves"])
        assert cves == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_finding_type_update_with_cves(self, temp_db):
        """Test updating finding_type with CVE list."""
        finding_type = FindingType(
            finding_type_id="nessus:12345",
            finding_type_name="Test FindingType",
            severity_int=2,
        )
        finding_type.save(temp_db)

        # Update with CVEs
        finding_type.cves = ["CVE-2024-0001"]
        finding_type.save(temp_db)

        retrieved = FindingType.get_by_id("nessus:12345", temp_db)
        assert retrieved is not None
        assert retrieved.cves == ["CVE-2024-0001"]


class TestFindingModel:
    """Tests for Finding model."""

    def test_finding_save_creates_record(self, temp_db):
        """Test saving a new finding_type file."""
        # Create dependencies
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None

        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        # Create finding_type file (host_count computed by view, not stored)
        pf = Finding(dataset_id=dataset_id, finding_type_id="nessus:12345")

        finding_id = pf.save(temp_db)

        assert finding_id is not None
        assert finding_id > 0

    @pytest.mark.skip(reason="file_path column not present in current schema")
    def test_finding_get_by_path(self):
        """Test retrieving finding_type file by path."""
        # This test is skipped because Finding.get_by_path() was removed when
        # The file_path column is not present in the current schema.
        # Database now uses dataset_id + finding_type_id as the primary lookup method.
        pytest.skip("get_by_path method no longer exists")

    def test_finding_update_review_state(self, temp_db):
        """Test updating finding_type file review state."""
        # Setup
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
            review_state="unreviewed",
        )
        finding_id = pf.save(temp_db)
        assert finding_id is not None

        # Update review state
        pf.finding_id = finding_id
        pf.update_review_state("done", SOURCE_OPERATOR, notes="All fixed", conn=temp_db)

        # Verify
        retrieved = Finding.get_by_id(finding_id, temp_db)
        assert retrieved is not None
        assert retrieved.review_state == "done"
        assert retrieved.reviewed_at is not None

    def test_finding_default_review_state(self, temp_db):
        """Test default review state is 'unreviewed'."""
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
        )
        finding_id = pf.save(temp_db)
        assert finding_id is not None

        retrieved = Finding.get_by_id(finding_id, temp_db)
        assert retrieved is not None
        assert retrieved.review_state == "unreviewed"

    def test_get_severity_dirs_for_dataset_empty(self, temp_db):
        """Test get_severity_names_for_dataset returns empty list when no files exist."""
        # Create scan without any finding_type files
        dataset = Dataset(dataset_name="empty_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None

        # Query severity directories
        severity_dirs = Finding.get_severity_names_for_dataset(dataset_id, temp_db)

        assert severity_dirs == []

    def test_get_severity_dirs_for_dataset_with_data(self, temp_db):
        """Test get_severity_names_for_dataset returns sorted severity directories."""
        # Setup scan
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None

        # Create finding_types with different severities
        finding_type1 = FindingType(
            finding_type_id="nessus:1001",
            finding_type_name="Critical FindingType",
            severity_int=4,
        )
        finding_type1.save(temp_db)
        finding_type2 = FindingType(
            finding_type_id="nessus:1002",
            finding_type_name="High FindingType",
            severity_int=3,
        )
        finding_type2.save(temp_db)
        finding_type3 = FindingType(
            finding_type_id="nessus:1003",
            finding_type_name="Medium FindingType",
            severity_int=2,
        )
        finding_type3.save(temp_db)
        finding_type4 = FindingType(
            finding_type_id="nessus:1004",
            finding_type_name="Info FindingType",
            severity_int=0,
        )
        finding_type4.save(temp_db)

        # Create finding_type files with severity directories
        assert isinstance(dataset_id, int)
        pf1 = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:1001",
        )
        pf1.save(temp_db)

        pf2 = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:1002",
        )
        pf2.save(temp_db)

        pf3 = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:1003",
        )
        pf3.save(temp_db)

        pf4 = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:1004",
        )
        pf4.save(temp_db)

        # Query severity directories
        severity_dirs = Finding.get_severity_names_for_dataset(dataset_id, temp_db)

        # Should be sorted from highest to lowest severity
        assert severity_dirs == ["4_Critical", "3_High", "2_Medium", "0_Info"]

    @pytest.mark.skip(
        reason="Cannot create duplicate dataset_id+finding_type_id due to UNIQUE constraint"
    )
    def test_get_severity_dirs_for_dataset_deduplicates(self, temp_db):
        """Test get_severity_names_for_dataset deduplicates severity directories."""
        # Setup scan
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)

        # Create finding_type
        finding_type = FindingType(
            finding_type_id="nessus:1001",
            finding_type_name="High FindingType",
            severity_int=3,
        )
        finding_type.save(temp_db)

        # Create multiple finding_type files with same severity
        pf1 = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:1001",
        )
        pf1.save(temp_db)

        pf2 = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:1001",
        )
        pf2.save(temp_db)

        # Query severity directories
        severity_dirs = Finding.get_severity_names_for_dataset(dataset_id, temp_db)

        # Should only return one instance of "3_High"
        assert severity_dirs == ["3_High"]

    def test_get_hosts_and_ports_empty(self, temp_db):
        """Test get_hosts_and_ports returns empty when no hosts exist."""
        # Setup
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Query hosts
        hosts, ports_str = pf.get_hosts_and_ports(temp_db)

        assert hosts == []
        assert ports_str == ""

    def test_get_hosts_and_ports_with_data(self, temp_db):
        """Test get_hosts_and_ports retrieves hosts and ports from database."""
        # Setup
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(dataset_id=dataset_id, finding_type_id="nessus:12345")
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert test data into finding_affected_hosts using normalized schema
        from cerno_pkg.models import Host, Port

        # Insert 192.168.1.1:80
        host_id_1 = Host.get_or_create(
            "192.168.1.1", "192.168.1.1", "ipv4", conn=temp_db
        )
        port_id_80 = Port.get_or_create(80, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_1, port_id_80, None),
        )

        # Insert 192.168.1.1:443
        port_id_443 = Port.get_or_create(443, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_1, port_id_443, None),
        )

        # Insert 192.168.1.2:80
        host_id_2 = Host.get_or_create(
            "192.168.1.2", "192.168.1.2", "ipv4", conn=temp_db
        )
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_2, port_id_80, None),
        )

        # Insert example.com:443 (FQDN-targeted scan - use example.com as both IP and target for test)
        host_id_3 = Host.get_or_create(
            "93.184.216.34", "example.com", "fqdn", conn=temp_db
        )
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_3, port_id_443, None),
        )
        temp_db.commit()

        # Query hosts
        hosts, ports_str = pf.get_hosts_and_ports(temp_db)

        # Verify hosts (should be unique, IPs first)
        # Note: hosts contains scan_target values (original scan targets)
        # example.com was created with scan_target=example.com
        assert len(hosts) == 3
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts
        assert hosts.count("example.com") == 1  # Original scan target (FQDN)

        # IPv4s come first (ordered by scan_target), then FQDNs
        assert hosts[0] == "192.168.1.1"
        assert hosts[1] == "192.168.1.2"
        assert hosts[2] == "example.com"

        # Verify ports (sorted numerically)
        assert ports_str == "80,443"

    def test_get_hosts_and_ports_ipv6(self, temp_db):
        """Test get_hosts_and_ports handles IPv6 addresses."""
        # Setup
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert IPv6 data using normalized schema
        from cerno_pkg.models import Host, Port

        # Insert 2001:db8::1:80 (IPv6)
        host_id_ipv6 = Host.get_or_create(
            "2001:db8::1", "2001:db8::1", "ipv6", conn=temp_db
        )
        port_id_80 = Port.get_or_create(80, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_ipv6, port_id_80, None),
        )

        # Insert 192.168.1.1:80 (IPv4)
        host_id_ipv4 = Host.get_or_create(
            "192.168.1.1", "192.168.1.1", "ipv4", conn=temp_db
        )
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_ipv4, port_id_80, None),
        )
        temp_db.commit()

        # Query hosts
        hosts, ports_str = pf.get_hosts_and_ports(temp_db)

        # IPv4 should come first due to ORDER BY is_ipv4 DESC
        assert len(hosts) == 2
        assert hosts[0] == "192.168.1.1"
        assert hosts[1] == "2001:db8::1"
        assert ports_str == "80"

    def test_get_all_host_port_lines_empty(self, temp_db):
        """Test get_all_host_port_lines returns empty list when no hosts."""
        # Setup
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Query lines
        lines = pf.get_all_host_port_lines(temp_db)

        assert lines == []

    def test_get_all_host_port_lines_with_data(self, temp_db):
        """Test get_all_host_port_lines returns formatted host:port strings."""
        # Setup
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert test data using normalized schema
        from cerno_pkg.models import Host, Port

        # Insert 192.168.1.1:80
        host_id_1 = Host.get_or_create(
            "192.168.1.1", "192.168.1.1", "ipv4", conn=temp_db
        )
        port_id_80 = Port.get_or_create(80, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_1, port_id_80, None),
        )

        # Insert 192.168.1.1:443
        port_id_443 = Port.get_or_create(443, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_1, port_id_443, None),
        )

        # Insert example.com:80 (FQDN-targeted scan)
        host_id_2 = Host.get_or_create(
            "93.184.216.34", "example.com", "fqdn", conn=temp_db
        )
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_2, port_id_80, None),
        )
        temp_db.commit()

        # Query lines
        lines = pf.get_all_host_port_lines(temp_db)

        # Verify format and sorting
        # Note: lines contain scan_target:port (original scan targets)
        # example.com was created with scan_target=example.com
        assert len(lines) == 3
        assert "192.168.1.1:80" in lines
        assert "192.168.1.1:443" in lines
        assert lines.count("example.com:80") == 1  # Original scan target (FQDN)

        # IPv4s first (ordered by scan_target), then FQDNs
        assert lines == ["192.168.1.1:80", "192.168.1.1:443", "example.com:80"]

    def test_get_all_host_port_lines_ipv6_bracketed(self, temp_db):
        """Test get_all_host_port_lines adds brackets to IPv6 addresses."""
        # Setup
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert IPv6 data using normalized schema
        from cerno_pkg.models import Host, Port

        # Insert 2001:db8::1:80 (IPv6)
        host_id = Host.get_or_create("2001:db8::1", "2001:db8::1", "ipv6", conn=temp_db)
        port_id = Port.get_or_create(80, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id, port_id, None),
        )
        temp_db.commit()

        # Query lines
        lines = pf.get_all_host_port_lines(temp_db)

        # Should add brackets for IPv6
        assert len(lines) == 1
        assert lines[0] == "[2001:db8::1]:80"

    def test_get_all_host_port_lines_no_port(self, temp_db):
        """Test get_all_host_port_lines handles entries without ports."""
        # Setup
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)
        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert data without port using normalized schema
        from cerno_pkg.models import Host

        # Insert 192.168.1.1 with no port
        host_id = Host.get_or_create("192.168.1.1", "192.168.1.1", "ipv4", conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) VALUES (?, ?, ?, ?)",
            (finding_id, host_id, None, None),
        )
        temp_db.commit()

        # Query lines
        lines = pf.get_all_host_port_lines(temp_db)

        # Should just return host without port
        assert len(lines) == 1
        assert lines[0] == "192.168.1.1"

    def test_get_hosts_and_ports_no_finding_id(self, temp_db):
        """Test get_hosts_and_ports handles unsaved Finding gracefully."""
        pf = Finding()  # No finding_id

        hosts, ports_str = pf.get_hosts_and_ports(temp_db)

        # Should return empty results and log error
        assert hosts == []
        assert ports_str == ""

    def test_get_all_host_port_lines_no_finding_id(self, temp_db):
        """Test get_all_host_port_lines handles unsaved Finding gracefully."""
        pf = Finding()  # No finding_id

        lines = pf.get_all_host_port_lines(temp_db)

        # Should return empty list and log error
        assert lines == []


class TestToolExecutionModel:
    """Tests for ToolExecution model."""

    def test_tool_execution_save(self, temp_db):
        """Test saving tool execution."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            exit_code=0,
            duration_seconds=12.5,
        )

        exec_id = execution.save(temp_db)

        assert exec_id is not None
        assert exec_id > 0

    def test_tool_execution_with_session_link(self, temp_db):
        """Test tool execution linked to session."""
        # Create session
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)

        cursor = temp_db.execute(
            "INSERT INTO sessions (dataset_id, session_start) VALUES (?, datetime('now'))",
            (dataset_id,),
        )
        session_id = cursor.lastrowid
        temp_db.commit()

        # Create execution
        execution = ToolExecution(
            session_id=session_id,
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            exit_code=0,
            duration_seconds=12.5,
        )
        exec_id = execution.save(temp_db)

        # Verify link
        cursor = temp_db.execute(
            "SELECT session_id FROM tool_executions WHERE execution_id = ?", (exec_id,)
        )
        result = cursor.fetchone()
        assert result["session_id"] == session_id

    def test_tool_execution_metadata_fields(self, temp_db):
        """Test tool execution captures all metadata."""
        execution = ToolExecution(
            tool_name="nmap",
            tool_protocol=None,
            command_text="sudo nmap -sS 192.168.1.0/24",
            exit_code=0,
            duration_seconds=45.2,
            host_count=256,
            sampled=False,
            ports="1-1000",
            used_sudo=True,
        )

        exec_id = execution.save(temp_db)

        # Retrieve and verify
        cursor = temp_db.execute(
            """SELECT * FROM tool_executions WHERE execution_id = ?""", (exec_id,)
        )
        result = cursor.fetchone()

        assert result["tool_name"] == "nmap"
        assert result["host_count"] == 256
        assert result["ports"] == "1-1000"
        assert result["used_sudo"] == 1
        assert result["duration_seconds"] == 45.2


class TestArtifactModel:
    """Tests for Artifact model."""

    def test_artifact_save(self, temp_db):
        """Test saving artifact."""
        # Create execution first
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0,
        )
        exec_id = execution.save(temp_db)

        # Create artifact (artifact_type_id=1 is nmap_xml from migration 003)
        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type_id=1,  # nmap_xml
            file_size_bytes=1024,
            file_hash="abc123",
        )

        artifact_id = artifact.save(temp_db)

        assert artifact_id is not None
        assert artifact_id > 0

    def test_artifact_linked_to_execution(self, temp_db):
        """Test artifact is linked to tool execution."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0,
        )
        exec_id = execution.save(temp_db)

        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type_id=1,  # nmap_xml
        )
        artifact_id = artifact.save(temp_db)

        # Verify link via join using v_artifacts_with_types view
        cursor = temp_db.execute(
            """
            SELECT te.tool_name, a.artifact_type
            FROM v_artifacts_with_types a
            JOIN tool_executions te ON a.execution_id = te.execution_id
            WHERE a.artifact_id = ?
            """,
            (artifact_id,),
        )
        result = cursor.fetchone()
        assert result["tool_name"] == "nmap"
        assert result["artifact_type"] == "nmap_xml"

    def test_artifact_metadata_json(self, temp_db):
        """Test artifact metadata is stored as JSON."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0,
        )
        exec_id = execution.save(temp_db)

        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type_id=1,  # nmap_xml
            metadata={"dataset_type": "SYN", "hosts_up": 5},
        )
        artifact_id = artifact.save(temp_db)

        # Retrieve and verify
        cursor = temp_db.execute(
            "SELECT metadata FROM artifacts WHERE artifact_id = ?", (artifact_id,)
        )
        result = cursor.fetchone()
        metadata = json.loads(result["metadata"]) if result["metadata"] else None
        assert metadata == {"dataset_type": "SYN", "hosts_up": 5}


class TestTimestampFunctions:
    """Tests for timestamp helper functions."""

    def test_now_iso_format(self):
        """Test now_iso returns ISO format timestamp."""
        timestamp = now_iso()

        # Should parse as datetime
        dt = datetime.fromisoformat(timestamp)
        assert isinstance(dt, datetime)

    def test_now_iso_is_recent(self):
        """Test now_iso returns current time."""
        timestamp = now_iso()
        dt = datetime.fromisoformat(timestamp)

        # Should be within last minute
        now = datetime.now()
        diff = (now - dt).total_seconds()
        assert abs(diff) < 60


class TestModelRelationships:
    """Tests for model relationships and cascading."""

    @pytest.mark.integration
    def test_delete_dataset_cascades_to_files(self, temp_db):
        """Test deleting scan removes finding_type files."""
        # Create chain: scan -> finding_type -> finding
        dataset = Dataset(dataset_name="test_dataset", export_root="/tmp")
        dataset_id = dataset.save(temp_db)
        assert dataset_id is not None
        assert isinstance(dataset_id, int)

        finding_type = FindingType(
            finding_type_id="nessus:12345", finding_type_name="Test", severity_int=2
        )
        finding_type.save(temp_db)

        pf = Finding(
            dataset_id=dataset_id,
            finding_type_id="nessus:12345",
        )
        pf.save(temp_db)

        # Delete scan
        temp_db.execute("DELETE FROM datasets WHERE dataset_id = ?", (dataset_id,))
        temp_db.commit()

        # FindingType file should be gone
        cursor = temp_db.execute("SELECT COUNT(*) as count FROM findings")
        assert cursor.fetchone()["count"] == 0

    @pytest.mark.integration
    def test_delete_execution_cascades_to_artifacts(self, temp_db):
        """Test deleting tool execution removes artifacts."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0,
        )
        exec_id = execution.save(temp_db)

        # Get artifact_type_id for normalized schema
        from cerno_pkg.models import ArtifactType

        artifact_type = ArtifactType.get_by_name("nmap_xml", conn=temp_db)
        artifact_type_id = artifact_type.artifact_type_id if artifact_type else None

        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type_id=artifact_type_id,
            file_hash="abc123",
            file_size_bytes=1024,
        )
        artifact.save(temp_db)

        # Delete execution
        temp_db.execute(
            "DELETE FROM tool_executions WHERE execution_id = ?", (exec_id,)
        )
        temp_db.commit()

        # Artifact should still exist but execution_id should be NULL (ON DELETE SET NULL)
        cursor = temp_db.execute(
            "SELECT COUNT(*) as count FROM artifacts WHERE artifact_path = ?",
            ("/tmp/scan.xml",),
        )
        assert cursor.fetchone()["count"] == 1

        cursor = temp_db.execute(
            "SELECT execution_id FROM artifacts WHERE artifact_path = ?",
            ("/tmp/scan.xml",),
        )
        assert cursor.fetchone()["execution_id"] is None


# ---------------------------------------------------------------------------
# Host identity: machines vs scan targets
#
# A machine is hosts.ip_address. A scan target is hosts.scan_target -- what you
# point a tool at. host_id is the (ip_address, scan_target) pair and is
# therefore the right key for neither count: it double-counts a machine
# recorded under both its IP and its hostname, which is what made the
# [V] View hosts (N) footer read one higher than the host list it opens.
# Virtual hosting means one machine legitimately owns many targets.
# ---------------------------------------------------------------------------


@pytest.fixture
def vhost_finding(temp_db):
    """3 vhosts on one IP, plus a name that round-robins to two IPs.

    Machines: 10.0.0.9, 10.0.0.2, 10.0.0.3  -> 3
    Targets:  shop/blog/api.example, www.example -> 4
    host_ids: 3 vhosts + 2 round-robin rows -> 5
    """
    from cerno_pkg.models import Finding, Host, FindingType, Port, Dataset

    dataset_id = Dataset(dataset_name="vhosts", export_root="/tmp").save(temp_db)
    FindingType(
        finding_type_id="nuclei:tls-version", finding_type_name="TLS", severity_int=1
    ).save(temp_db)
    finding_id = Finding(
        dataset_id=dataset_id, finding_type_id="nuclei:tls-version"
    ).save(temp_db)
    Port.get_or_create(443, conn=temp_db)

    pairs = [
        ("10.0.0.9", "shop.example"),
        ("10.0.0.9", "blog.example"),
        ("10.0.0.9", "api.example"),
        ("10.0.0.2", "www.example"),
        ("10.0.0.3", "www.example"),
    ]
    for ip, target in pairs:
        host_id = Host.get_or_create(ip, target, "fqdn", conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number) "
            "VALUES (?, ?, ?)",
            (finding_id, host_id, 443),
        )
    temp_db.commit()
    return dataset_id, finding_id


@pytest.mark.integration
def test_count_targets_counts_every_vhost(vhost_finding, temp_db):
    """Each vhost is its own target, so all three on one IP count separately."""
    from cerno_pkg.models import Finding

    _dataset_id, finding_id = vhost_finding
    assert Finding.count_targets([finding_id], temp_db) == 4


@pytest.mark.integration
def test_count_targets_matches_host_list_length(vhost_finding, temp_db):
    """The footer count must equal the number of lines the [V] host list renders."""
    from cerno_pkg.models import Finding

    _dataset_id, finding_id = vhost_finding
    finding = Finding.get_by_id(finding_id, temp_db)
    hosts, _ports = finding.get_hosts_and_ports(temp_db)

    assert Finding.count_targets([finding_id], temp_db) == len(hosts)


@pytest.mark.integration
def test_count_targets_empty_for_no_ids(temp_db):
    """No finding ids means no targets, not an SQL error."""
    from cerno_pkg.models import Finding

    assert Finding.count_targets([], temp_db) == 0


@pytest.mark.integration
def test_dataset_unique_hosts_counts_machines_not_targets(vhost_finding, temp_db):
    """`cerno dataset list` reports machines by resolved IP, so vhosts collapse."""
    from cerno_pkg.models import Dataset

    datasets = {s["dataset_name"]: s for s in Dataset.get_all_with_stats(temp_db)}
    # 3 machines behind 4 targets / 5 (ip, target) pairs.
    assert datasets["vhosts"]["unique_hosts"] == 3


@pytest.mark.integration
def test_port_distribution_agrees_with_host_list(vhost_finding, temp_db):
    """Distribution counts targets, matching the "N across M port(s)" N above it."""
    from cerno_pkg.models import Finding

    _dataset_id, finding_id = vhost_finding
    finding = Finding.get_by_id(finding_id, temp_db)
    hosts, _ports = finding.get_hosts_and_ports(temp_db)
    distribution = finding.get_port_distribution(temp_db)

    assert distribution == {"443": len(hosts)}
