"""Tests for cerno_pkg.ops module."""

import tempfile
from pathlib import Path

import pytest

from cerno_pkg.ops import (
    ExecutionMetadata,
    ProxyConfig,
    write_proxychains_config,
    log_tool_execution,
    log_artifact,
    log_artifacts_for_nmap,
)
from cerno_pkg.tools import build_nmap_cmd


class TestExecutionMetadata:
    """Tests for ExecutionMetadata dataclass."""

    def test_execution_metadata_creation(self):
        """Test creating ExecutionMetadata."""
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=12.5,
            used_sudo=True
        )

        assert metadata.exit_code == 0
        assert metadata.duration_seconds == 12.5
        assert metadata.used_sudo is True

    def test_execution_metadata_with_failure(self):
        """Test metadata for failed execution."""
        metadata = ExecutionMetadata(
            exit_code=1,
            duration_seconds=5.2,
            used_sudo=False
        )

        assert metadata.exit_code == 1
        assert metadata.duration_seconds == 5.2
        assert metadata.used_sudo is False


class TestProxyConfig:
    """Tests for ProxyConfig dataclass and write_proxychains_config helper."""

    @pytest.mark.unit
    def test_proxy_config_defaults(self):
        proxy = ProxyConfig(enabled=False, host="127.0.0.1", port=9000)
        assert proxy.enabled is False
        assert proxy.host == "127.0.0.1"
        assert proxy.port == 9000

    @pytest.mark.unit
    def test_proxy_config_custom_values(self):
        proxy = ProxyConfig(enabled=True, host="10.10.0.1", port=1080)
        assert proxy.enabled is True
        assert proxy.host == "10.10.0.1"
        assert proxy.port == 1080

    @pytest.mark.unit
    def test_write_proxychains_config_content(self, tmp_path):
        proxy = ProxyConfig(enabled=True, host="10.10.0.1", port=1080)
        config_path = tmp_path / "proxychains4.conf"
        write_proxychains_config(proxy, config_path)
        content = config_path.read_text()
        assert "strict_chain" in content
        assert "proxy_dns" in content
        assert "socks5 10.10.0.1 1080" in content
        assert "[ProxyList]" in content

    @pytest.mark.unit
    def test_write_proxychains_config_creates_parent_dirs(self, tmp_path):
        proxy = ProxyConfig(enabled=True, host="127.0.0.1", port=9000)
        config_path = tmp_path / "nested" / "dir" / "proxychains4.conf"
        write_proxychains_config(proxy, config_path)
        assert config_path.exists()

    @pytest.mark.unit
    def test_write_proxychains_config_is_idempotent(self, tmp_path):
        proxy = ProxyConfig(enabled=True, host="127.0.0.1", port=9000)
        config_path = tmp_path / "proxychains4.conf"
        write_proxychains_config(proxy, config_path)
        write_proxychains_config(proxy, config_path)
        content = config_path.read_text()
        assert "socks5 127.0.0.1 9000" in content

    @pytest.mark.unit
    def test_write_proxychains_config_no_op_when_disabled(self, tmp_path):
        proxy = ProxyConfig(enabled=False, host="127.0.0.1", port=9000)
        config_path = tmp_path / "proxychains4.conf"
        write_proxychains_config(proxy, config_path)
        assert not config_path.exists()


class TestLogToolExecution:
    """Tests for log_tool_execution function."""

    def test_log_execution_basic(self, temp_db):
        """Test logging basic tool execution."""
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=10.5,
            used_sudo=False
        )

        execution_id = log_tool_execution(
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            execution_metadata=metadata,
            conn=temp_db
        )

        assert execution_id is not None
        assert execution_id > 0

        # Verify in database
        cursor = temp_db.execute(
            "SELECT * FROM tool_executions WHERE execution_id = ?",
            (execution_id,)
        )
        row = cursor.fetchone()

        assert row["tool_name"] == "nmap"
        assert row["command_text"] == "nmap -sV 192.168.1.1"
        assert row["exit_code"] == 0
        assert row["duration_seconds"] == 10.5
        assert row["used_sudo"] == 0

    def test_log_execution_with_metadata(self, temp_db):
        """Test logging execution with full metadata."""
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=45.2,
            used_sudo=True
        )

        execution_id = log_tool_execution(
            tool_name="nmap",
            command_text="sudo nmap -sS -p- 192.168.1.0/24",
            execution_metadata=metadata,
            host_count=256,
            sampled=False,
            ports="1-65535",
            conn=temp_db
        )

        assert execution_id is not None

        # Verify metadata
        cursor = temp_db.execute(
            "SELECT * FROM tool_executions WHERE execution_id = ?",
            (execution_id,)
        )
        row = cursor.fetchone()

        assert row["host_count"] == 256
        assert row["sampled"] == 0
        assert row["ports"] == "1-65535"
        assert row["used_sudo"] == 1

    def test_log_execution_with_protocol(self, temp_db):
        """Test logging netexec execution with protocol."""
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=15.3,
            used_sudo=False
        )

        execution_id = log_tool_execution(
            tool_name="netexec",
            command_text="netexec smb targets.txt -u admin -p password",
            execution_metadata=metadata,
            tool_protocol="smb",
            host_count=10,
            conn=temp_db
        )

        assert execution_id is not None

        cursor = temp_db.execute(
            "SELECT tool_protocol FROM tool_executions WHERE execution_id = ?",
            (execution_id,)
        )
        row = cursor.fetchone()
        assert row["tool_protocol"] == "smb"

    @pytest.mark.integration
    def test_log_execution_with_session_link(self, temp_db):
        """Test logging execution linked to a session."""
        from cerno_pkg.models import Scan

        # Create scan and session
        scan = Scan(scan_name="test_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Create session for linking test
        temp_db.execute(
            "INSERT INTO sessions (scan_id, session_start) VALUES (?, datetime('now'))",
            (scan_id,)
        )
        temp_db.commit()

        # Create scan directory for linking
        with tempfile.TemporaryDirectory() as tmpdir:
            scan_dir = Path(tmpdir) / "test_scan"
            scan_dir.mkdir()

            metadata = ExecutionMetadata(
                exit_code=0,
                duration_seconds=5.0,
                used_sudo=False
            )

            # Note: This won't actually link since scan_dir.name != scan_name in DB
            # but tests the code path
            execution_id = log_tool_execution(
                tool_name="nmap",
                command_text="nmap 192.168.1.1",
                execution_metadata=metadata,
                scan_dir=scan_dir,
                conn=temp_db
            )

            assert execution_id is not None

    @pytest.mark.integration
    @pytest.mark.skip(reason="file_path column not present, cannot link executions by path")
    def test_log_execution_with_file_link(self, temp_db, temp_dir):
        """Test logging execution linked to a plugin file."""
        from cerno_pkg.models import Scan, Plugin, Finding

        # Create dependencies
        scan = Scan(scan_name="test_scan", export_root="/tmp/test")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        plugin = Plugin(plugin_id=12345, plugin_name="Test", severity_int=2)
        plugin.save(temp_db)

        file_path = temp_dir / "test_plugin.txt"
        file_path.write_text("192.168.1.1:80\n")

        pf = Finding(
            scan_id=scan_id,
            plugin_id=12345
        )
        pf.save(temp_db)

        # Log execution
        metadata = ExecutionMetadata(
            exit_code=0,
            duration_seconds=8.5,
            used_sudo=False
        )

        execution_id = log_tool_execution(
            tool_name="nmap",
            command_text="nmap -sV 192.168.1.1",
            execution_metadata=metadata,
            file_path=file_path,
            conn=temp_db
        )

        assert execution_id is not None

        # Verify link
        cursor = temp_db.execute(
            "SELECT finding_id FROM tool_executions WHERE execution_id = ?",
            (execution_id,)
        )
        row = cursor.fetchone()
        assert row["finding_id"] is not None


class TestLogArtifact:
    """Tests for log_artifact function."""

    def test_log_artifact_basic(self, temp_db, temp_dir):
        """Test logging a basic artifact."""
        from cerno_pkg.models import ToolExecution, now_iso

        # Create tool execution first
        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)
        assert exec_id is not None

        # Create artifact file
        artifact_file = temp_dir / "scan.xml"
        artifact_file.write_text("<nmaprun>test</nmaprun>")

        # Log artifact
        artifact_id = log_artifact(
            execution_id=exec_id,
            artifact_path=artifact_file,
            artifact_type="nmap_xml",
            conn=temp_db
        )

        assert artifact_id is not None
        assert artifact_id > 0

        # Verify in database using v_artifacts_with_types view
        cursor = temp_db.execute(
            "SELECT * FROM v_artifacts_with_types WHERE artifact_id = ?",
            (artifact_id,)
        )
        row = cursor.fetchone()

        assert row["execution_id"] == exec_id
        assert row["artifact_type"] == "nmap_xml"
        assert row["file_size_bytes"] == len("<nmaprun>test</nmaprun>")
        assert row["file_hash"] is not None
        assert len(row["file_hash"]) == 64  # SHA256

    def test_log_artifact_with_metadata(self, temp_db, temp_dir):
        """Test logging artifact with metadata."""
        from cerno_pkg.models import ToolExecution, now_iso
        import json

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)
        assert exec_id is not None

        artifact_file = temp_dir / "scan.xml"
        artifact_file.write_text("test")

        metadata_dict = {"scan_type": "SYN", "hosts_up": 5}

        artifact_id = log_artifact(
            execution_id=exec_id,
            artifact_path=artifact_file,
            artifact_type="nmap_xml",
            metadata=metadata_dict,
            conn=temp_db
        )

        assert artifact_id is not None

        # Verify metadata
        cursor = temp_db.execute(
            "SELECT metadata FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        row = cursor.fetchone()
        stored_metadata = json.loads(row["metadata"]) if row["metadata"] else None
        assert stored_metadata == metadata_dict

    def test_log_artifact_nonexistent_file(self, temp_db, temp_dir):
        """Test logging artifact for nonexistent file."""
        from cerno_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)
        assert exec_id is not None

        nonexistent = temp_dir / "nonexistent.xml"

        # Should still log but with None for size/hash
        artifact_id = log_artifact(
            execution_id=exec_id,
            artifact_path=nonexistent,
            artifact_type="nmap_xml",
            conn=temp_db
        )

        assert artifact_id is not None

        cursor = temp_db.execute(
            "SELECT file_size_bytes, file_hash FROM artifacts WHERE artifact_id = ?",
            (artifact_id,)
        )
        row = cursor.fetchone()
        assert row["file_size_bytes"] is None
        assert row["file_hash"] is None


class TestLogArtifactsForNmap:
    """Tests for log_artifacts_for_nmap function."""

    def test_log_nmap_artifacts_all_formats(self, temp_db, temp_dir):
        """Test logging all nmap output formats."""
        from cerno_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)
        assert exec_id is not None

        # Create all three nmap output files
        oabase = temp_dir / "scan"
        (temp_dir / "scan.xml").write_text("<nmaprun/>")
        (temp_dir / "scan.nmap").write_text("Nmap scan")
        (temp_dir / "scan.gnmap").write_text("# Nmap scan")

        artifact_ids = log_artifacts_for_nmap(exec_id, oabase, conn=temp_db)

        assert len(artifact_ids) == 3

        # Verify all artifacts in database using v_artifacts_with_types view
        cursor = temp_db.execute(
            "SELECT artifact_type FROM v_artifacts_with_types WHERE execution_id = ? ORDER BY artifact_type",
            (exec_id,)
        )
        types = [row["artifact_type"] for row in cursor.fetchall()]
        assert types == ["nmap_gnmap", "nmap_nmap", "nmap_xml"]

    def test_log_nmap_artifacts_partial(self, temp_db, temp_dir):
        """Test logging when only some nmap files exist."""
        from cerno_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oX scan.xml 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)
        assert exec_id is not None

        # Create only XML file
        oabase = temp_dir / "scan"
        (temp_dir / "scan.xml").write_text("<nmaprun/>")

        artifact_ids = log_artifacts_for_nmap(exec_id, oabase, conn=temp_db)

        assert len(artifact_ids) == 1

        cursor = temp_db.execute(
            "SELECT artifact_type FROM v_artifacts_with_types WHERE execution_id = ?",
            (exec_id,)
        )
        row = cursor.fetchone()
        assert row["artifact_type"] == "nmap_xml"

    def test_log_nmap_artifacts_none_exist(self, temp_db, temp_dir):
        """Test logging when no nmap files exist."""
        from cerno_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)
        assert exec_id is not None

        oabase = temp_dir / "scan"

        artifact_ids = log_artifacts_for_nmap(exec_id, oabase, conn=temp_db)

        assert len(artifact_ids) == 0

    def test_log_nmap_artifacts_with_metadata(self, temp_db, temp_dir):
        """Test logging nmap artifacts with metadata."""
        from cerno_pkg.models import ToolExecution, now_iso

        execution = ToolExecution(
            tool_name="nmap",
            command_text="nmap -oA scan 192.168.1.1",
            executed_at=now_iso(),
            exit_code=0,
            duration_seconds=10.0
        )
        exec_id = execution.save(temp_db)
        assert exec_id is not None

        oabase = temp_dir / "scan"
        (temp_dir / "scan.xml").write_text("<nmaprun/>")

        metadata_dict = {"scan_type": "version_detection"}

        artifact_ids = log_artifacts_for_nmap(exec_id, oabase, metadata=metadata_dict, conn=temp_db)

        assert len(artifact_ids) == 1

        # Verify metadata was stored
        import json
        cursor = temp_db.execute(
            "SELECT metadata FROM artifacts WHERE artifact_id = ?",
            (artifact_ids[0],)
        )
        row = cursor.fetchone()
        stored_metadata = json.loads(row["metadata"]) if row["metadata"] else None
        assert stored_metadata == metadata_dict


class TestCommandAvailability:
    """Tests for command availability checking functions."""

    def test_require_cmd_available(self):
        """Test require_cmd with an available command."""
        from cerno_pkg.ops import require_cmd

        # Python should always be available in test environment
        require_cmd("python")  # Should not raise

    def test_require_cmd_unavailable(self):
        """Test require_cmd with unavailable command."""
        from cerno_pkg.ops import require_cmd

        # This should exit
        with pytest.raises(SystemExit) as exc_info:
            require_cmd("this-command-definitely-does-not-exist-12345")

        assert exc_info.value.code == 1

    def test_resolve_cmd_first_available(self):
        """Test resolve_cmd returns first available command."""
        from cerno_pkg.ops import resolve_cmd

        # Python should be available, fake command won't be
        result = resolve_cmd(["python", "fake-command-xyz"])
        assert result == "python"

    def test_resolve_cmd_second_available(self):
        """Test resolve_cmd returns second when first unavailable."""
        from cerno_pkg.ops import resolve_cmd

        result = resolve_cmd(["fake-command-xyz", "python"])
        assert result == "python"

    def test_resolve_cmd_none_available(self):
        """Test resolve_cmd returns None when no commands available."""
        from cerno_pkg.ops import resolve_cmd

        result = resolve_cmd(["fake-cmd-1", "fake-cmd-2", "fake-cmd-3"])
        assert result is None

    def test_resolve_cmd_empty_list(self):
        """Test resolve_cmd with empty list."""
        from cerno_pkg.ops import resolve_cmd

        result = resolve_cmd([])
        assert result is None

    def test_root_or_sudo_available(self):
        """Test checking for root/sudo availability."""
        from cerno_pkg.ops import root_or_sudo_available
        import shutil

        result = root_or_sudo_available()

        # Result depends on system, but should be bool
        assert isinstance(result, bool)

        # If sudo is available via which, function should return True
        if shutil.which("sudo"):
            assert result is True

    def test_get_tool_version_available(self):
        """Test getting version from an available tool."""
        from cerno_pkg.ops import get_tool_version
        from unittest.mock import Mock, patch

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "nmap version 7.92\n"
        mock_result.stderr = ""

        with patch('subprocess.run', return_value=mock_result) as mock_run:
            with patch('shutil.which', return_value='/usr/bin/nmap'):
                version = get_tool_version("nmap")

        assert version == "7.92"
        mock_run.assert_called_once()

    def test_get_tool_version_missing(self):
        """Test getting version from a missing tool."""
        from cerno_pkg.ops import get_tool_version
        from unittest.mock import patch

        with patch('shutil.which', return_value=None):
            version = get_tool_version("nonexistent_tool")

        assert version is None

    def test_get_tool_version_timeout(self):
        """Test handling timeout when getting version."""
        from cerno_pkg.ops import get_tool_version
        from unittest.mock import patch
        import subprocess

        with patch('shutil.which', return_value='/usr/bin/slow_tool'):
            with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('cmd', 5)):
                version = get_tool_version("slow_tool")

        assert version is None

    def test_get_tool_version_parsing_variations(self):
        """Test version parsing with various output formats."""
        from cerno_pkg.ops import get_tool_version
        from unittest.mock import Mock, patch

        test_cases = [
            ("Nmap version 7.92", "7.92"),
            ("version 1.2.1", "1.2.1"),
            ("tool 2.3.4.5", "2.3.4"),  # Only captures first 3 parts
            ("Version: 10.11", "10.11"),
            ("v3.14", "3.14"),
        ]

        for output, expected_version in test_cases:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = output
            mock_result.stderr = ""

            with patch('subprocess.run', return_value=mock_result):
                with patch('shutil.which', return_value='/usr/bin/tool'):
                    version = get_tool_version("tool")

            assert version == expected_version, f"Failed to parse '{output}' as '{expected_version}'"

    def test_get_tool_version_candidates(self):
        """Test version detection with multiple binary name candidates."""
        from cerno_pkg.ops import get_tool_version
        from unittest.mock import Mock, patch

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "netexec version 1.2.1\n"
        mock_result.stderr = ""

        def mock_which(cmd):
            # nxc is available, netexec is not
            return '/usr/bin/nxc' if cmd == 'nxc' else None

        with patch('subprocess.run', return_value=mock_result) as mock_run:
            with patch('shutil.which', side_effect=mock_which):
                version = get_tool_version("netexec", ["nxc", "netexec"])

        assert version == "1.2.1"
        # Should have called subprocess with the first available candidate
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0][0] == "nxc"

    def test_get_tool_version_stderr_output(self):
        """Test version parsing when version info is in stderr."""
        from cerno_pkg.ops import get_tool_version
        from unittest.mock import Mock, patch

        mock_result = Mock()
        mock_result.returncode = 1  # Non-zero exit
        mock_result.stdout = ""
        mock_result.stderr = "tool version 4.5.6\n"

        with patch('subprocess.run', return_value=mock_result):
            with patch('shutil.which', return_value='/usr/bin/tool'):
                version = get_tool_version("tool")

        assert version == "4.5.6"

    def test_render_tool_availability_table_basic(self):
        """Test rendering tool availability table (smoke test)."""
        from cerno_pkg.render import render_tool_availability_table
        from unittest.mock import patch

        # Mock the console output to capture what would be printed
        with patch('cerno_pkg.render._console_global') as mock_console:
            with patch('shutil.which', return_value='/usr/bin/nmap'):
                with patch('cerno_pkg.ops.get_tool_version', return_value="7.92"):
                    render_tool_availability_table(include_unavailable=True)

        # Verify console.print was called (table was rendered)
        assert mock_console.print.called

    def test_render_tool_availability_respects_config(self):
        """Test that render_tool_availability_table respects configuration."""
        from cerno_pkg.render import render_tool_availability_table
        from unittest.mock import patch, Mock

        # Mock the tool registry to return a predictable set of tools
        mock_tool = Mock()
        mock_tool.id = "nmap"
        mock_tool.name = "nmap"
        mock_tool.requires = ["nmap"]

        with patch('cerno_pkg.tool_registry.get_available_tools', return_value=[mock_tool]):
            with patch('shutil.which', return_value='/usr/bin/nmap'):
                with patch('cerno_pkg.ops.get_tool_version', return_value="7.92"):
                    # Should not raise exception
                    try:
                        # Just test that it doesn't crash
                        # Full output testing would require capturing Rich console output
                        render_tool_availability_table(include_unavailable=True)
                    except Exception as e:
                        pytest.fail(f"render_tool_availability_table() raised unexpected exception: {e}")


class TestBuildNmapCmd:
    """Tests for build_nmap_cmd command builder."""

    @pytest.mark.unit
    def test_basic_tcp_no_sudo(self, tmp_path):
        ips = tmp_path / "ips.txt"
        out = tmp_path / "output"
        cmd = build_nmap_cmd(False, None, ips, "80,443", False, out)
        assert cmd == ["nmap", "-A", "-iL", str(ips), "-p", "80,443", "-oA", str(out)]

    @pytest.mark.unit
    def test_sudo_without_proxy(self, tmp_path):
        ips = tmp_path / "ips.txt"
        out = tmp_path / "output"
        cmd = build_nmap_cmd(False, None, ips, "", True, out)
        assert cmd[0] == "sudo"
        assert "nmap" in cmd
        assert "-Pn" not in cmd

    @pytest.mark.unit
    def test_proxy_adds_pn_and_drops_sudo(self, tmp_path):
        ips = tmp_path / "ips.txt"
        out = tmp_path / "output"
        # use_sudo=True but use_proxy=True → sudo must be dropped, -Pn must be added
        cmd = build_nmap_cmd(False, None, ips, "80", True, out, use_proxy=True)
        assert "sudo" not in cmd
        assert "-Pn" in cmd
        assert cmd[0] == "nmap"

    @pytest.mark.unit
    def test_proxy_pn_position(self, tmp_path):
        """Verify -Pn appears immediately after 'nmap -A'."""
        ips = tmp_path / "ips.txt"
        out = tmp_path / "output"
        cmd = build_nmap_cmd(False, None, ips, "443", False, out, use_proxy=True)
        nmap_idx = cmd.index("nmap")
        pn_idx = cmd.index("-Pn")
        assert pn_idx == nmap_idx + 2  # nmap, -A, -Pn

    @pytest.mark.unit
    def test_nse_option_included(self, tmp_path):
        ips = tmp_path / "ips.txt"
        out = tmp_path / "output"
        cmd = build_nmap_cmd(False, "--script=smb-vuln-ms17-010", ips, "445", False, out)
        assert "--script=smb-vuln-ms17-010" in cmd

    @pytest.mark.unit
    def test_udp_flag(self, tmp_path):
        ips = tmp_path / "ips.txt"
        out = tmp_path / "output"
        cmd = build_nmap_cmd(True, None, ips, "161", False, out)
        assert "-sU" in cmd

    @pytest.mark.unit
    def test_no_ports_str(self, tmp_path):
        ips = tmp_path / "ips.txt"
        out = tmp_path / "output"
        cmd = build_nmap_cmd(False, None, ips, "", False, out)
        assert "-p" not in cmd


class TestRunCommandWithProgressProxy:
    """Tests for proxy wrapping in run_command_with_progress."""

    @pytest.mark.unit
    def test_proxy_config_wraps_list_command(self, tmp_path, monkeypatch):
        """Verify proxychains4 is prepended to list commands when proxy is enabled."""
        from cerno_pkg.ops import ProxyConfig, run_command_with_progress
        import subprocess

        captured = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            class FakeProc:
                returncode = 0
                stdout = iter([])
                def wait(self): pass
                def terminate(self): pass
            return FakeProc()

        monkeypatch.setattr(subprocess, "Popen", fake_popen)
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        proxy = ProxyConfig(enabled=True, host="127.0.0.1", port=9000)
        try:
            run_command_with_progress(["echo", "hello"], proxy_config=proxy)
        except Exception:
            pass

        assert captured.get("cmd", [])[:2] == ["proxychains4", "-f"]
        assert captured["cmd"][3:] == ["echo", "hello"]

    @pytest.mark.unit
    def test_no_proxy_leaves_command_unchanged(self, tmp_path, monkeypatch):
        """Verify command is not wrapped when proxy is disabled."""
        from cerno_pkg.ops import ProxyConfig, run_command_with_progress
        import subprocess

        captured = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            class FakeProc:
                returncode = 0
                stdout = iter([])
                def wait(self): pass
            return FakeProc()

        monkeypatch.setattr(subprocess, "Popen", fake_popen)

        proxy = ProxyConfig(enabled=False, host="127.0.0.1", port=9000)
        try:
            run_command_with_progress(["echo", "hello"], proxy_config=proxy)
        except Exception:
            pass

        assert captured.get("cmd") == ["echo", "hello"]

    @pytest.mark.unit
    def test_none_proxy_config_leaves_command_unchanged(self, tmp_path, monkeypatch):
        """Verify proxy_config=None does not wrap command (backward compat)."""
        from cerno_pkg.ops import run_command_with_progress
        import subprocess

        captured = {}

        def fake_popen(cmd, **kwargs):
            captured["cmd"] = cmd
            class FakeProc:
                returncode = 0
                stdout = iter([])
                def wait(self): pass
            return FakeProc()

        monkeypatch.setattr(subprocess, "Popen", fake_popen)

        try:
            run_command_with_progress(["echo", "hello"])
        except Exception:
            pass

        assert captured.get("cmd") == ["echo", "hello"]


class TestProxychainsRenderRow:
    """Tests for proxychains4 row in render_tool_availability_table."""

    @pytest.mark.unit
    def test_proxychains4_row_appears_when_disabled(self, monkeypatch, capsys):
        """proxychains4 row always appears (proxy disabled in config)."""
        from cerno_pkg.render import render_tool_availability_table
        from cerno_pkg.config import CernoConfig

        monkeypatch.setattr("cerno_pkg.render.load_config", lambda: CernoConfig(proxychains_enabled=False))
        # Don't need proxychains4 on PATH — just verify row name is rendered
        render_tool_availability_table(include_unavailable=True)
        captured = capsys.readouterr()
        assert "proxychains4" in captured.out

    @pytest.mark.unit
    def test_proxychains4_row_shows_active_when_enabled_and_found(self, monkeypatch, capsys):
        """When proxy enabled and binary found, show 'active' details."""
        from cerno_pkg.render import render_tool_availability_table
        from cerno_pkg.config import CernoConfig

        import shutil as _shutil

        config = CernoConfig(proxychains_enabled=True, proxychains_host="127.0.0.1", proxychains_port=9000)
        monkeypatch.setattr("cerno_pkg.render.load_config", lambda: config)
        monkeypatch.setattr(_shutil, "which", lambda name: "/usr/bin/proxychains4" if name == "proxychains4" else None)

        render_tool_availability_table(include_unavailable=True)
        captured = capsys.readouterr()
        assert "SOCKS5 127.0.0.1:9000 (active)" in captured.out

    @pytest.mark.unit
    def test_proxychains4_row_warns_when_enabled_but_missing(self, monkeypatch, capsys):
        """When proxy enabled but binary missing, show warning in details."""
        from cerno_pkg.render import render_tool_availability_table
        from cerno_pkg.config import CernoConfig

        import shutil as _shutil

        config = CernoConfig(proxychains_enabled=True)
        monkeypatch.setattr("cerno_pkg.render.load_config", lambda: config)
        monkeypatch.setattr(_shutil, "which", lambda name: None)

        render_tool_availability_table(include_unavailable=True)
        captured = capsys.readouterr()
        assert "proxychains4" in captured.out
        assert "proxy mode will not work" in captured.out

    @pytest.mark.unit
    def test_proxychains4_row_shows_version_when_available_and_disabled(self, monkeypatch, capsys):
        """When proxy disabled and binary found, show version (no SOCKS5/active marker)."""
        from cerno_pkg.render import render_tool_availability_table
        from cerno_pkg.config import CernoConfig
        import shutil as _shutil

        config = CernoConfig(proxychains_enabled=False)
        monkeypatch.setattr("cerno_pkg.render.load_config", lambda: config)
        monkeypatch.setattr(_shutil, "which", lambda name: "/usr/bin/proxychains4" if name == "proxychains4" else None)

        render_tool_availability_table(include_unavailable=True)
        captured = capsys.readouterr()
        assert "proxychains4" in captured.out
        assert "active" not in captured.out
        assert "SOCKS5" not in captured.out