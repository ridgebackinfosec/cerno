"""Tests for cerno_pkg.models module."""

import json
from datetime import datetime

import pytest

from cerno_pkg.models import (
    Scan,
    Plugin,
    Finding,
    ToolExecution,
    Artifact,
    now_iso,
)


class TestScanModel:
    """Tests for Scan model."""

    def test_scan_save_creates_record(self, temp_db):
        """Test saving a new scan."""
        scan = Scan(
            scan_name="test_scan",
            nessus_file_path="/tmp/test.nessus",
            export_root="/tmp/exports"
        )

        scan_id = scan.save(temp_db)

        assert scan_id is not None
        assert scan_id > 0

    def test_scan_get_by_name(self, temp_db):
        """Test retrieving scan by name."""
        # Create scan
        scan = Scan(
            scan_name="test_scan",
            nessus_file_path="/tmp/test.nessus",
            export_root="/tmp/exports"
        )
        scan.save(temp_db)

        # Retrieve it
        retrieved = Scan.get_by_name("test_scan", temp_db)

        assert retrieved is not None
        assert retrieved.scan_name == "test_scan"
        assert retrieved.nessus_file_path == "/tmp/test.nessus"

    def test_scan_get_by_name_nonexistent(self, temp_db):
        """Test retrieving nonexistent scan returns None."""
        result = Scan.get_by_name("nonexistent", temp_db)
        assert result is None

    def test_scan_get_by_id(self, temp_db):
        """Test retrieving scan by ID."""
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)

        retrieved = Scan.get_by_id(scan_id, temp_db)

        assert retrieved is not None
        assert retrieved.scan_id == scan_id
        assert retrieved.scan_name == "test_scan"

    def test_scan_get_all_empty(self, temp_db):
        """Test get_all returns empty list when no scans."""
        scans = Scan.get_all(temp_db)
        assert scans == []

    def test_scan_get_all_orders_by_last_reviewed(self, temp_db):
        """Test get_all returns scans ordered by last_reviewed_at DESC."""
        from datetime import datetime, timedelta

        # Create 3 scans with different last_reviewed_at
        scan1 = Scan(scan_name="old_scan", export_root="/tmp/old")
        scan1_id = scan1.save(temp_db)
        assert scan1_id is not None

        scan2 = Scan(scan_name="recent_scan", export_root="/tmp/recent")
        scan2_id = scan2.save(temp_db)
        assert scan2_id is not None

        scan3 = Scan(scan_name="never_reviewed", export_root="/tmp/never")
        scan3_id = scan3.save(temp_db)
        assert scan3_id is not None

        # Update last_reviewed_at for scan1 and scan2
        old_time = (datetime.now() - timedelta(days=7)).isoformat()
        recent_time = (datetime.now() - timedelta(hours=1)).isoformat()

        temp_db.execute(
            "UPDATE scans SET last_reviewed_at = ? WHERE scan_id = ?",
            (old_time, scan1_id)
        )
        temp_db.execute(
            "UPDATE scans SET last_reviewed_at = ? WHERE scan_id = ?",
            (recent_time, scan2_id)
        )
        temp_db.commit()

        # Get all scans
        scans = Scan.get_all(temp_db)

        # Should be ordered: recent_scan, old_scan, never_reviewed (NULLS LAST)
        assert len(scans) == 3
        assert scans[0].scan_name == "recent_scan"
        assert scans[1].scan_name == "old_scan"
        assert scans[2].scan_name == "never_reviewed"

    def test_scan_update_existing(self, temp_db):
        """Test updating existing scan."""
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Update
        scan.scan_id = scan_id
        scan.nessus_file_hash = "abc123"
        scan.save(temp_db)

        # Retrieve and verify
        retrieved = Scan.get_by_id(scan_id, temp_db)
        assert retrieved is not None
        assert retrieved.nessus_file_hash == "abc123"

    def test_scan_unique_constraint(self, temp_db):
        """Test that scan names must be unique."""
        scan1 = Scan(scan_name="test_scan", export_root="/tmp")
        scan1.save(temp_db)

        scan2 = Scan(scan_name="test_scan", export_root="/tmp2")

        with pytest.raises(Exception):  # Should raise IntegrityError
            scan2.save(temp_db)


class TestPluginModel:
    """Tests for Plugin model."""

    def test_plugin_save_creates_record(self, temp_db):
        """Test saving a new plugin."""
        plugin = Plugin(
            plugin_id=12345,
            plugin_name="Test Plugin",
            severity_int=2,
            cvss3_score=5.3
        )

        plugin.save(temp_db)

        # Verify saved
        cursor = temp_db.execute(
            "SELECT plugin_name FROM plugins WHERE plugin_id = ?",
            (12345,)
        )
        result = cursor.fetchone()
        assert result["plugin_name"] == "Test Plugin"

    def test_plugin_get_by_id(self, temp_db):
        """Test retrieving plugin by ID."""
        plugin = Plugin(
            plugin_id=12345,
            plugin_name="Test Plugin",
            severity_int=2
        )
        plugin.save(temp_db)

        retrieved = Plugin.get_by_id(12345, temp_db)

        assert retrieved is not None
        assert retrieved.plugin_id == 12345
        assert retrieved.plugin_name == "Test Plugin"

    def test_plugin_cve_list_serialization(self, temp_db):
        """Test CVE list is serialized to JSON."""
        plugin = Plugin(
            plugin_id=12345,
            plugin_name="Test Plugin",
            severity_int=2,
            cves=["CVE-2024-0001", "CVE-2024-0002"]
        )
        plugin.save(temp_db)

        # Check stored as JSON
        cursor = temp_db.execute(
            "SELECT cves FROM plugins WHERE plugin_id = ?",
            (12345,)
        )
        result = cursor.fetchone()
        cves = json.loads(result["cves"])
        assert cves == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_plugin_update_with_cves(self, temp_db):
        """Test updating plugin with CVE list."""
        plugin = Plugin(
            plugin_id=12345,
            plugin_name="Test Plugin",
            severity_int=2
        )
        plugin.save(temp_db)

        # Update with CVEs
        plugin.cves = ["CVE-2024-0001"]
        plugin.save(temp_db)

        retrieved = Plugin.get_by_id(12345, temp_db)
        assert retrieved is not None
        assert retrieved.cves == ["CVE-2024-0001"]


class TestFindingModel:
    """Tests for Finding model."""

    def test_finding_save_creates_record(self, temp_db):
        """Test saving a new plugin file."""
        # Create dependencies
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        # Create plugin file (host_count computed by view, not stored)
        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345
        )

        finding_id = pf.save(temp_db)

        assert finding_id is not None
        assert finding_id > 0

    @pytest.mark.skip(reason="file_path column not present in current schema")
    def test_finding_get_by_path(self):
        """Test retrieving plugin file by path."""
        # This test is skipped because Finding.get_by_path() was removed when
        # The file_path column is not present in the current schema.
        # Database now uses scan_id + plugin_id as the primary lookup method.
        pytest.skip("get_by_path method no longer exists")

    def test_finding_update_review_state(self, temp_db):
        """Test updating plugin file review state."""
        # Setup
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
            review_state="pending"
        )
        finding_id = pf.save(temp_db)
        assert finding_id is not None

        # Update review state
        pf.finding_id = finding_id
        pf.update_review_state("completed", notes="All fixed", conn=temp_db)

        # Verify
        retrieved = Finding.get_by_id(finding_id, temp_db)
        assert retrieved is not None
        assert retrieved.review_state == "completed"
        assert retrieved.reviewed_at is not None

    def test_finding_default_review_state(self, temp_db):
        """Test default review state is 'pending'."""
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
        )
        finding_id = pf.save(temp_db)
        assert finding_id is not None

        retrieved = Finding.get_by_id(finding_id, temp_db)
        assert retrieved is not None
        assert retrieved.review_state == "pending"

    def test_get_severity_dirs_for_scan_empty(self, temp_db):
        """Test get_severity_dirs_for_scan returns empty list when no files exist."""
        # Create scan without any plugin files
        scan = Scan(scan_name="empty_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Query severity directories
        severity_dirs = Finding.get_severity_dirs_for_scan(scan_id, temp_db)

        assert severity_dirs == []

    def test_get_severity_dirs_for_scan_with_data(self, temp_db):
        """Test get_severity_dirs_for_scan returns sorted severity directories."""
        # Setup scan
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Create plugins with different severities
        plugin1 = Plugin(plugin_id=1001, plugin_name="Critical Plugin", severity_int=4)
        plugin1.save(temp_db)
        plugin2 = Plugin(plugin_id=1002, plugin_name="High Plugin", severity_int=3)
        plugin2.save(temp_db)
        plugin3 = Plugin(plugin_id=1003, plugin_name="Medium Plugin", severity_int=2)
        plugin3.save(temp_db)
        plugin4 = Plugin(plugin_id=1004, plugin_name="Info Plugin", severity_int=0)
        plugin4.save(temp_db)

        # Create plugin files with severity directories
        assert isinstance(scan_id, int)
        pf1 = Finding(
            scan_id=scan_id,
            plugin_id=1001,
        )
        pf1.save(temp_db)

        pf2 = Finding(
            scan_id=scan_id,
            plugin_id=1002,
        )
        pf2.save(temp_db)

        pf3 = Finding(
            scan_id=scan_id,
            plugin_id=1003,
        )
        pf3.save(temp_db)

        pf4 = Finding(
            scan_id=scan_id,
            plugin_id=1004,
        )
        pf4.save(temp_db)

        # Query severity directories
        severity_dirs = Finding.get_severity_dirs_for_scan(scan_id, temp_db)

        # Should be sorted from highest to lowest severity
        assert severity_dirs == ["4_Critical", "3_High", "2_Medium", "0_Info"]

    @pytest.mark.skip(reason="Cannot create duplicate scan_id+plugin_id due to UNIQUE constraint")
    def test_get_severity_dirs_for_scan_deduplicates(self, temp_db):
        """Test get_severity_dirs_for_scan deduplicates severity directories."""
        # Setup scan
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)

        # Create plugin
        plugin = Plugin(plugin_id=1001, plugin_name="High Plugin", severity_int=3)
        plugin.save(temp_db)

        # Create multiple plugin files with same severity
        pf1 = Finding(
            scan_id=scan_id,
            plugin_id=1001,
        )
        pf1.save(temp_db)

        pf2 = Finding(
            scan_id=scan_id,
            plugin_id=1001,
        )
        pf2.save(temp_db)

        # Query severity directories
        severity_dirs = Finding.get_severity_dirs_for_scan(scan_id, temp_db)

        # Should only return one instance of "3_High"
        assert severity_dirs == ["3_High"]

    def test_get_hosts_and_ports_empty(self, temp_db):
        """Test get_hosts_and_ports returns empty when no hosts exist."""
        # Setup
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
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
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert test data into finding_affected_hosts using normalized schema
        from cerno_pkg.models import Host, Port

        # Insert 192.168.1.1:80
        host_id_1 = Host.get_or_create("192.168.1.1", "192.168.1.1", "ipv4", conn=temp_db)
        port_id_80 = Port.get_or_create(80, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_1, port_id_80, None)
        )

        # Insert 192.168.1.1:443
        port_id_443 = Port.get_or_create(443, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_1, port_id_443, None)
        )

        # Insert 192.168.1.2:80
        host_id_2 = Host.get_or_create("192.168.1.2", "192.168.1.2", "ipv4", conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_2, port_id_80, None)
        )

        # Insert example.com:443 (FQDN-targeted scan - use example.com as both IP and target for test)
        host_id_3 = Host.get_or_create("93.184.216.34", "example.com", "fqdn", conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_3, port_id_443, None)
        )
        temp_db.commit()

        # Query hosts
        hosts, ports_str = pf.get_hosts_and_ports(temp_db)

        # Verify hosts (should be unique, IPs first)
        # Note: With new schema, hosts contains ip_address values (resolved IPs)
        # example.com was created with ip_address=93.184.216.34
        assert len(hosts) == 3
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts
        assert "93.184.216.34" in hosts  # Resolved IP for example.com

        # All are now IP addresses, so ordering is by IP type then address
        # IPv4s come first, ordered by address
        assert hosts[0] == "192.168.1.1"
        assert hosts[1] == "192.168.1.2"
        assert hosts[2] == "93.184.216.34"

        # Verify ports (sorted numerically)
        assert ports_str == "80,443"

    def test_get_hosts_and_ports_ipv6(self, temp_db):
        """Test get_hosts_and_ports handles IPv6 addresses."""
        # Setup
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert IPv6 data using normalized schema
        from cerno_pkg.models import Host, Port

        # Insert 2001:db8::1:80 (IPv6)
        host_id_ipv6 = Host.get_or_create("2001:db8::1", "2001:db8::1", "ipv6", conn=temp_db)
        port_id_80 = Port.get_or_create(80, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_ipv6, port_id_80, None)
        )

        # Insert 192.168.1.1:80 (IPv4)
        host_id_ipv4 = Host.get_or_create("192.168.1.1", "192.168.1.1", "ipv4", conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_ipv4, port_id_80, None)
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
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Query lines
        lines = pf.get_all_host_port_lines(temp_db)

        assert lines == []

    def test_get_all_host_port_lines_with_data(self, temp_db):
        """Test get_all_host_port_lines returns formatted host:port strings."""
        # Setup
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert test data using normalized schema
        from cerno_pkg.models import Host, Port

        # Insert 192.168.1.1:80
        host_id_1 = Host.get_or_create("192.168.1.1", "192.168.1.1", "ipv4", conn=temp_db)
        port_id_80 = Port.get_or_create(80, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_1, port_id_80, None)
        )

        # Insert 192.168.1.1:443
        port_id_443 = Port.get_or_create(443, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_1, port_id_443, None)
        )

        # Insert example.com:80 (FQDN-targeted scan)
        host_id_2 = Host.get_or_create("93.184.216.34", "example.com", "fqdn", conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id_2, port_id_80, None)
        )
        temp_db.commit()

        # Query lines
        lines = pf.get_all_host_port_lines(temp_db)

        # Verify format and sorting
        # Note: With new schema, lines contain ip_address:port (resolved IPs)
        # example.com was created with ip_address=93.184.216.34
        assert len(lines) == 3
        assert "192.168.1.1:80" in lines
        assert "192.168.1.1:443" in lines
        assert "93.184.216.34:80" in lines  # Resolved IP for example.com

        # All are now IPs, verify ordering by IP address
        assert lines == ["192.168.1.1:80", "192.168.1.1:443", "93.184.216.34:80"]

    def test_get_all_host_port_lines_ipv6_bracketed(self, temp_db):
        """Test get_all_host_port_lines adds brackets to IPv6 addresses."""
        # Setup
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert IPv6 data using normalized schema
        from cerno_pkg.models import Host, Port

        # Insert 2001:db8::1:80 (IPv6)
        host_id = Host.get_or_create("2001:db8::1", "2001:db8::1", "ipv6", conn=temp_db)
        port_id = Port.get_or_create(80, conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id, port_id, None)
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
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)
        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
        )
        finding_id = pf.save(temp_db)
        pf.finding_id = finding_id

        # Insert data without port using normalized schema
        from cerno_pkg.models import Host

        # Insert 192.168.1.1 with no port
        host_id = Host.get_or_create("192.168.1.1", "192.168.1.1", "ipv4", conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, ?)",
            (finding_id, host_id, None, None)
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
            duration_seconds=12.5
        )

        exec_id = execution.save(temp_db)

        assert exec_id is not None
        assert exec_id > 0

    def test_tool_execution_with_session_link(self, temp_db):
        """Test tool execution linked to session."""
        # Create session
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)

        cursor = temp_db.execute(
            "INSERT INTO sessions (scan_id, session_start) VALUES (?, datetime('now'))",
            (scan_id,)
        )
        session_id = cursor.lastrowid
        temp_db.commit()

        # Create execution
        execution = ToolExecution(
            session_id=session_id,
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            exit_code=0,
            duration_seconds=12.5
        )
        exec_id = execution.save(temp_db)

        # Verify link
        cursor = temp_db.execute(
            "SELECT session_id FROM tool_executions WHERE execution_id = ?",
            (exec_id,)
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
            used_sudo=True
        )

        exec_id = execution.save(temp_db)

        # Retrieve and verify
        cursor = temp_db.execute(
            """SELECT * FROM tool_executions WHERE execution_id = ?""",
            (exec_id,)
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
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        # Create artifact (artifact_type_id=1 is nmap_xml from migration 003)
        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type_id=1,  # nmap_xml
            file_size_bytes=1024,
            file_hash="abc123"
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
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type_id=1  # nmap_xml
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
            (artifact_id,)
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
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)

        artifact = Artifact(
            execution_id=exec_id,
            artifact_path="/tmp/scan.xml",
            artifact_type_id=1,  # nmap_xml
            metadata={"scan_type": "SYN", "hosts_up": 5}
        )
        artifact_id = artifact.save(temp_db)

        # Retrieve and verify
        cursor = temp_db.execute(
            "SELECT metadata FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        result = cursor.fetchone()
        metadata = json.loads(result["metadata"]) if result["metadata"] else None
        assert metadata == {"scan_type": "SYN", "hosts_up": 5}


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
    def test_delete_scan_cascades_to_files(self, temp_db):
        """Test deleting scan removes plugin files."""
        # Create chain: scan -> plugin -> finding
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None
        assert isinstance(scan_id, int)

        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345,
        )
        pf.save(temp_db)

        # Delete scan
        temp_db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        temp_db.commit()

        # Plugin file should be gone
        cursor = temp_db.execute("SELECT COUNT(*) as count FROM findings")
        assert cursor.fetchone()["count"] == 0

    @pytest.mark.integration
    def test_delete_execution_cascades_to_artifacts(self, temp_db):
        """Test deleting tool execution removes artifacts."""
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            exit_code=0,
            duration_seconds=10.0
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
            file_size_bytes=1024
        )
        artifact.save(temp_db)

        # Delete execution
        temp_db.execute("DELETE FROM tool_executions WHERE execution_id = ?", (exec_id,))
        temp_db.commit()

        # Artifact should still exist but execution_id should be NULL (ON DELETE SET NULL)
        cursor = temp_db.execute("SELECT COUNT(*) as count FROM artifacts WHERE artifact_path = ?", ("/tmp/scan.xml",))
        assert cursor.fetchone()["count"] == 1

        cursor = temp_db.execute("SELECT execution_id FROM artifacts WHERE artifact_path = ?", ("/tmp/scan.xml",))
        assert cursor.fetchone()["execution_id"] is None
