"""Tests for cerno_pkg.fs module."""

from unittest.mock import patch

import pytest

from cerno_pkg.fs import (
    build_results_paths,
    pretty_severity_label,
    default_page_size,
    write_work_files,
)


# Database mocking fixture similar to test_session.py
@pytest.fixture(autouse=True)
def mock_db_for_fs(monkeypatch, temp_db):
    """Mock database connection for fs module tests."""
    monkeypatch.setenv("CERNO_USE_DB", "1")

    import cerno_pkg.database

    class UnclosableConnection:
        """Wrapper that prevents connection from being closed."""

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

    def mock_get_connection(database_path=None):
        return UnclosableConnection(temp_db)

    monkeypatch.setattr(cerno_pkg.database, "get_connection", mock_get_connection)


@pytest.mark.skip(reason="is_review_complete removed - review state is now DB-only")
class TestIsReviewComplete:
    """Tests for is_review_complete function - OBSOLETE in DB-only architecture."""


@pytest.mark.skip(reason="is_reviewed_filename removed - review state is now DB-only")
class TestIsReviewedFilename:
    """Tests for is_reviewed_filename function - OBSOLETE in DB-only architecture."""


@pytest.mark.skip(
    reason="rename_review_complete replaced with mark_review_complete - DB-only, no file renaming"
)
class TestRenameReviewComplete:
    """Tests for rename_review_complete function - OBSOLETE in DB-only architecture."""


@pytest.mark.skip(reason="undo_review_complete updated to DB-only - no file renaming")
class TestUndoReviewComplete:
    """Tests for undo_review_complete function - OBSOLETE in DB-only architecture."""


class TestBuildResultsPaths:
    """Tests for build_results_paths function."""

    def test_build_results_paths_basic(self, temp_dir, monkeypatch):
        """Test building result paths."""
        # Mock get_results_root() to return temp directory
        import cerno_pkg.constants

        monkeypatch.setattr(
            cerno_pkg.constants, "_results_root_cache", temp_dir / "results"
        )

        scan_dir = temp_dir / "my_scan"
        sev_dir = scan_dir / "4_Critical"
        plugin_filename = "12345_Test_Plugin.txt"

        output_dir, output_base = build_results_paths(
            scan_dir, sev_dir, plugin_filename
        )

        assert output_dir.exists()
        # Path structure: results/my_scan/Critical/12345_Test_Plugin
        assert output_dir.name == "12345_Test_Plugin"
        assert "Critical" in str(output_dir)
        assert output_base.name.startswith("run-")
        assert len(output_base.name.split("-")) == 3  # run-YYYYMMDD-HHMMSS

    def test_build_results_paths_creates_dirs(self, temp_dir, monkeypatch):
        """Test that output directory is created."""
        # Mock get_results_root() to return temp directory
        import cerno_pkg.constants

        monkeypatch.setattr(
            cerno_pkg.constants, "_results_root_cache", temp_dir / "results"
        )

        scan_dir = temp_dir / "scan"
        sev_dir = scan_dir / "3_High"
        plugin_filename = "99999_Another_Plugin.txt"

        output_dir, _ = build_results_paths(scan_dir, sev_dir, plugin_filename)

        assert output_dir.exists()
        assert output_dir.is_dir()


class TestPrettySeverityLabel:
    """Tests for pretty_severity_label function."""

    def test_pretty_severity_label_critical(self):
        """Test converting critical severity."""
        assert pretty_severity_label("4_critical") == "Critical"

    def test_pretty_severity_label_high(self):
        """Test converting high severity."""
        assert pretty_severity_label("3_high") == "High"

    def test_pretty_severity_label_medium(self):
        """Test converting medium severity."""
        assert pretty_severity_label("2_medium") == "Medium"

    def test_pretty_severity_label_with_underscores(self):
        """Test converting multi-word severity."""
        assert pretty_severity_label("1_very_low") == "Very Low"

    def test_pretty_severity_label_no_number_prefix(self):
        """Test label without number prefix."""
        result = pretty_severity_label("critical")
        assert result == "Critical"

    def test_pretty_severity_label_with_spaces(self):
        """Test label with extra spaces."""
        assert pretty_severity_label("4_  critical  ") == "Critical"


class TestDefaultPageSize:
    """Tests for default_page_size function."""

    def test_default_page_size_normal_terminal(self):
        """Test page size with normal terminal."""
        with patch(
            "shutil.get_terminal_size",
            return_value=type("obj", (), {"lines": 40, "columns": 80})(),
        ):
            size = default_page_size()
            assert size == 25  # 40 - 15

    def test_default_page_size_small_terminal(self):
        """Test page size with small terminal."""
        with patch(
            "shutil.get_terminal_size",
            return_value=type("obj", (), {"lines": 15, "columns": 80})(),
        ):
            size = default_page_size()
            assert size == 8  # Minimum is 8

    def test_default_page_size_exception(self):
        """Test page size when terminal size fails."""
        with patch("shutil.get_terminal_size", side_effect=Exception("No terminal")):
            size = default_page_size()
            assert size == 12  # Default fallback


class TestWriteWorkFiles:
    """Tests for write_work_files function."""

    def test_write_work_files_tcp_only(self, temp_dir):
        """Test writing TCP work files."""
        hosts = ["192.168.1.1", "192.168.1.2", "10.0.0.1"]
        ports = "80,443,8080"

        tcp_ips, udp_ips, tcp_sockets = write_work_files(
            temp_dir, hosts, ports, udp=False
        )

        # Verify TCP IPs file
        assert tcp_ips.exists()
        assert tcp_ips.read_text() == "192.168.1.1\n192.168.1.2\n10.0.0.1\n"

        # Verify UDP IPs file not created
        assert not udp_ips.exists()

        # Verify TCP sockets file
        assert tcp_sockets.exists()
        lines = tcp_sockets.read_text().strip().split("\n")
        assert len(lines) == 3
        assert lines[0] == "192.168.1.1:80,443,8080"
        assert lines[1] == "192.168.1.2:80,443,8080"
        assert lines[2] == "10.0.0.1:80,443,8080"

    def test_write_work_files_with_udp(self, temp_dir):
        """Test writing work files with UDP enabled."""
        hosts = ["192.168.1.1", "192.168.1.2"]
        ports = "53"

        tcp_ips, udp_ips, _tcp_sockets = write_work_files(
            temp_dir, hosts, ports, udp=True
        )

        # Verify both TCP and UDP files exist
        assert tcp_ips.exists()
        assert udp_ips.exists()

        # Verify UDP content
        assert udp_ips.read_text() == "192.168.1.1\n192.168.1.2\n"

    def test_write_work_files_no_ports(self, temp_dir):
        """Test writing work files without ports."""
        hosts = ["192.168.1.1"]

        tcp_ips, _udp_ips, tcp_sockets = write_work_files(
            temp_dir, hosts, "", udp=False
        )

        # TCP IPs should still be written
        assert tcp_ips.exists()
        assert tcp_ips.read_text() == "192.168.1.1\n"

        # Socket file is not created when ports_str is empty
        # The function only writes tcp_sockets if ports_str is truthy
        assert not tcp_sockets.exists()

    def test_write_work_files_creates_workdir(self, temp_dir):
        """Test that workdir is created if it doesn't exist."""
        workdir = temp_dir / "nested" / "work"
        hosts = ["10.0.0.1"]

        tcp_ips, _udp_ips, _tcp_sockets = write_work_files(
            workdir, hosts, "22", udp=False
        )

        assert workdir.exists()
        assert workdir.is_dir()
        assert tcp_ips.exists()

    def test_write_work_files_single_host_multiple_ports(self, temp_dir):
        """Test work files with single host and multiple ports."""
        hosts = ["192.168.1.100"]
        ports = "80,443,8443,3000"

        tcp_ips, _udp_ips, tcp_sockets = write_work_files(
            temp_dir, hosts, ports, udp=False
        )

        assert tcp_ips.exists()
        assert tcp_sockets.exists()

        socket_content = tcp_sockets.read_text().strip()
        assert socket_content == "192.168.1.100:80,443,8443,3000"


# ---------------------------------------------------------------------------
# Target-file writing / host counting parity with the MCP
#
# The TUI counted the -iL targets file with sum(1 for _ in f) while the MCP's
# _parse_nmap_output uses sum(1 for line in fh if line.strip()). Because the
# writer always appended a trailing newline, an EMPTY host list logged
# host_count=1 from the TUI and 0 from the MCP for the identical situation.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_write_work_files_empty_host_list_writes_empty_file(tmp_path):
    """No hosts must mean no lines, not one blank line."""
    from cerno_pkg.fs import write_work_files

    tcp_ips, _udp_ips, _sockets = write_work_files(tmp_path, [], "", udp=False)

    assert tcp_ips.read_text(encoding="utf-8") == ""


@pytest.mark.unit
def test_write_work_files_empty_host_count_matches_mcp(tmp_path):
    """The TUI's host_count and the MCP's must agree for an empty target list."""
    from cerno_pkg.fs import write_work_files

    tcp_ips, _udp_ips, _sockets = write_work_files(tmp_path, [], "", udp=False)

    with open(tcp_ips) as fh:
        tui_count = sum(1 for line in fh if line.strip())
    with open(tcp_ips) as fh:
        mcp_count = sum(1 for line in fh if line.strip())

    assert tui_count == mcp_count == 0


@pytest.mark.unit
def test_write_work_files_counts_hosts_without_trailing_blank(tmp_path):
    """A populated list still yields exactly one line per host."""
    from cerno_pkg.fs import write_work_files

    hosts = ["10.0.0.1", "10.0.0.2", "portal.example"]
    tcp_ips, udp_ips, _sockets = write_work_files(tmp_path, hosts, "", udp=True)

    assert tcp_ips.read_text(encoding="utf-8").splitlines() == hosts
    with open(tcp_ips) as fh:
        assert sum(1 for line in fh if line.strip()) == 3
    assert udp_ips.read_text(encoding="utf-8").splitlines() == hosts


@pytest.mark.unit
def test_write_work_files_empty_udp_list_is_empty(tmp_path):
    """The UDP list follows the same rule as the TCP one."""
    from cerno_pkg.fs import write_work_files

    _tcp_ips, udp_ips, _sockets = write_work_files(tmp_path, [], "", udp=True)

    assert udp_ips.read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------------------
# Operator-entered findings: the [U] gate
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_update_interactive_refuses_a_finding_with_no_id(capsys):
    """Nothing to write against; must warn rather than raise."""
    from cerno_pkg.fs import update_authored_finding_interactive
    from cerno_pkg.models import Finding

    finding = Finding(finding_id=None, scan_id=1, plugin_id="operator:1")

    assert update_authored_finding_interactive(finding) is False
    assert "database id" in capsys.readouterr().out


@pytest.mark.integration
def test_update_interactive_writes_what_the_prompt_returned(temp_db, monkeypatch):
    from cerno_pkg import fs
    from cerno_pkg.models import Finding
    from cerno_pkg.authored_findings import (
        AuthoredFindingInput,
        create_authored_finding,
        load_authored_finding,
    )
    from cerno_pkg.constants import SOURCE_OPERATOR

    _plugin_id, finding_id = create_authored_finding(
        AuthoredFindingInput(
            title="Original",
            severity_int=3,
            targets=[("10.0.0.21", 443)],
            description="before",
        ),
        SOURCE_OPERATOR,
        conn=temp_db,
    )

    monkeypatch.setattr(
        "cerno_pkg.tui.prompt_edit_finding",
        lambda fid: AuthoredFindingInput(
            title="Corrected",
            severity_int=1,
            targets=[("10.0.0.99", 22)],
            description="after",
        ),
    )

    finding = Finding(finding_id=finding_id, scan_id=1, plugin_id="operator:1")
    assert fs.update_authored_finding_interactive(finding) is True

    stored = load_authored_finding(finding_id, conn=temp_db)
    assert stored.title == "Corrected"
    assert stored.severity_int == 1
    assert stored.targets == [("10.0.0.99", 22)]


@pytest.mark.integration
def test_update_interactive_cancels_cleanly(temp_db, monkeypatch):
    """Ctrl+C at a prompt returns None, which must change nothing."""
    from cerno_pkg import fs
    from cerno_pkg.models import Finding
    from cerno_pkg.authored_findings import (
        AuthoredFindingInput,
        create_authored_finding,
        load_authored_finding,
    )
    from cerno_pkg.constants import SOURCE_OPERATOR

    _plugin_id, finding_id = create_authored_finding(
        AuthoredFindingInput(title="Original", severity_int=3),
        SOURCE_OPERATOR,
        conn=temp_db,
    )
    monkeypatch.setattr("cerno_pkg.tui.prompt_edit_finding", lambda fid: None)

    finding = Finding(finding_id=finding_id, scan_id=1, plugin_id="operator:1")
    assert fs.update_authored_finding_interactive(finding) is False
    assert load_authored_finding(finding_id, conn=temp_db).title == "Original"
