"""Tests for NetExec database integration module.

Tests the NxcDatabaseManager and related dataclasses for querying
NetExec protocol databases to enrich Cerno finding displays.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Generator

import pytest

from cerno_pkg.nxc_db import (
    NxcCredential,
    NxcDatabaseManager,
    NxcEnrichmentSummary,
    NxcHostData,
    NxcSecurityFlags,
    NxcShare,
    get_nxc_manager,
    reset_nxc_manager,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def nxc_fixtures_path() -> Path:
    """Path to the NetExec test fixtures directory."""
    return Path(__file__).parent / "fixtures" / "nxc"


@pytest.fixture
def temp_nxc_workspace(tmp_path: Path) -> Path:
    """Create a temporary NXC workspace directory."""
    workspace = tmp_path / "nxc_workspace"
    workspace.mkdir()
    return workspace


@pytest.fixture
def populated_smb_db(temp_nxc_workspace: Path) -> Path:
    """Create an SMB database with test data."""
    db_path = temp_nxc_workspace / "smb.db"
    conn = sqlite3.connect(db_path)

    # Create tables matching NetExec SMB schema
    conn.executescript("""
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY,
            ip TEXT,
            hostname TEXT,
            domain TEXT,
            os TEXT,
            smbv1 INTEGER,
            signing INTEGER,
            zerologon INTEGER,
            petitpotam INTEGER
        );

        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            domain TEXT,
            username TEXT,
            password TEXT,
            credtype TEXT,
            pillaged_from_hostid INTEGER
        );

        CREATE TABLE admin_relations (
            id INTEGER PRIMARY KEY,
            userid INTEGER,
            hostid INTEGER,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        );

        CREATE TABLE loggedin_relations (
            id INTEGER PRIMARY KEY,
            userid INTEGER,
            hostid INTEGER,
            FOREIGN KEY(userid) REFERENCES users(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        );

        CREATE TABLE shares (
            id INTEGER PRIMARY KEY,
            hostid INTEGER,
            userid INTEGER,
            name TEXT,
            remark TEXT,
            read INTEGER,
            write INTEGER,
            FOREIGN KEY(hostid) REFERENCES hosts(id),
            FOREIGN KEY(userid) REFERENCES users(id)
        );
    """)

    # Insert test data
    # Host 1: DC01 - has vulnerabilities
    conn.execute("""
        INSERT INTO hosts (id, ip, hostname, domain, os, smbv1, signing, zerologon, petitpotam)
        VALUES (1, '192.168.1.10', 'DC01', 'CORP.LOCAL', 'Windows Server 2019', 0, 0, 1, 1)
    """)

    # Host 2: WEB01 - no vulnerabilities
    conn.execute("""
        INSERT INTO hosts (id, ip, hostname, domain, os, smbv1, signing, zerologon, petitpotam)
        VALUES (2, '192.168.1.20', 'WEB01', 'CORP.LOCAL', 'Windows Server 2016', 0, 1, 0, 0)
    """)

    # Users
    conn.execute("""
        INSERT INTO users (id, domain, username, password, credtype)
        VALUES (1, 'CORP', 'admin', 'e3b0c44298fc1c149afbf4c8996fb924', 'hash')
    """)
    conn.execute("""
        INSERT INTO users (id, domain, username, password, credtype)
        VALUES (2, 'CORP', 'svc_backup', 'password123', 'plaintext')
    """)

    # Admin relations - admin has admin on DC01
    conn.execute("INSERT INTO admin_relations (id, userid, hostid) VALUES (1, 1, 1)")

    # Loggedin relations - svc_backup logged into WEB01
    conn.execute("INSERT INTO loggedin_relations (id, userid, hostid) VALUES (1, 2, 2)")

    # Shares
    conn.execute("""
        INSERT INTO shares (id, hostid, name, read, write)
        VALUES (1, 1, 'C$', 1, 1)
    """)
    conn.execute("""
        INSERT INTO shares (id, hostid, name, read, write)
        VALUES (2, 1, 'ADMIN$', 1, 0)
    """)
    conn.execute("""
        INSERT INTO shares (id, hostid, name, read, write)
        VALUES (3, 1, 'SYSVOL', 1, 0)
    """)

    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def populated_ssh_db(temp_nxc_workspace: Path) -> Path:
    """Create an SSH database with test data."""
    db_path = temp_nxc_workspace / "ssh.db"
    conn = sqlite3.connect(db_path)

    # Create tables matching NetExec SSH schema
    conn.executescript("""
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY,
            host TEXT,
            hostname TEXT,
            port INTEGER,
            banner TEXT,
            os TEXT
        );

        CREATE TABLE credentials (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            credtype TEXT
        );

        CREATE TABLE admin_relations (
            id INTEGER PRIMARY KEY,
            credid INTEGER,
            hostid INTEGER,
            FOREIGN KEY(credid) REFERENCES credentials(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        );

        CREATE TABLE loggedin_relations (
            id INTEGER PRIMARY KEY,
            credid INTEGER,
            hostid INTEGER,
            shell INTEGER,
            FOREIGN KEY(credid) REFERENCES credentials(id),
            FOREIGN KEY(hostid) REFERENCES hosts(id)
        );
    """)

    # Insert test data
    conn.execute("""
        INSERT INTO hosts (id, host, hostname, port, banner, os)
        VALUES (1, '192.168.1.20', 'WEB01', 22, 'SSH-2.0-OpenSSH_8.2p1', 'Linux')
    """)

    conn.execute("""
        INSERT INTO credentials (id, username, password, credtype)
        VALUES (1, 'root', '', 'key')
    """)

    conn.execute("INSERT INTO admin_relations (id, credid, hostid) VALUES (1, 1, 1)")

    conn.commit()
    conn.close()
    return db_path


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    """Reset the NXC manager singleton before and after each test."""
    reset_nxc_manager()
    yield
    reset_nxc_manager()


# =============================================================================
# Unit Tests: Dataclasses
# =============================================================================


class TestNxcDataclasses:
    """Test NXC dataclass construction and defaults."""

    def test_nxc_credential_defaults(self) -> None:
        """Test NxcCredential with minimal arguments."""
        cred = NxcCredential(protocol="smb", username="admin")
        assert cred.protocol == "smb"
        assert cred.username == "admin"
        assert cred.domain is None
        assert cred.credential_type == "plaintext"
        assert cred.has_admin is False

    def test_nxc_credential_full(self) -> None:
        """Test NxcCredential with all arguments."""
        cred = NxcCredential(
            protocol="smb",
            username="admin",
            domain="CORP",
            credential_type="hash",
            has_admin=True,
        )
        assert cred.domain == "CORP"
        assert cred.credential_type == "hash"
        assert cred.has_admin is True

    def test_nxc_share_defaults(self) -> None:
        """Test NxcShare with minimal arguments."""
        share = NxcShare(name="C$")
        assert share.name == "C$"
        assert share.read_access is False
        assert share.write_access is False

    def test_nxc_share_with_access(self) -> None:
        """Test NxcShare with access flags."""
        share = NxcShare(name="ADMIN$", read_access=True, write_access=True)
        assert share.read_access is True
        assert share.write_access is True

    def test_nxc_security_flags_defaults(self) -> None:
        """Test NxcSecurityFlags with defaults."""
        flags = NxcSecurityFlags()
        assert flags.signing_required is True
        assert flags.smbv1_enabled is False
        assert flags.zerologon_vulnerable is False
        assert flags.petitpotam_vulnerable is False

    def test_nxc_security_flags_vulnerable(self) -> None:
        """Test NxcSecurityFlags with vulnerabilities."""
        flags = NxcSecurityFlags(
            signing_required=False,
            smbv1_enabled=True,
            zerologon_vulnerable=True,
            petitpotam_vulnerable=True,
        )
        assert flags.signing_required is False
        assert flags.smbv1_enabled is True
        assert flags.zerologon_vulnerable is True
        assert flags.petitpotam_vulnerable is True

    def test_nxc_host_data_empty(self) -> None:
        """Test NxcHostData with minimal arguments."""
        data = NxcHostData(host_address="192.168.1.1")
        assert data.host_address == "192.168.1.1"
        assert data.hostname is None
        assert data.protocols_seen == []
        assert data.credentials == []
        assert data.shares == []
        assert data.security_flags is None

    def test_nxc_enrichment_summary_empty(self) -> None:
        """Test NxcEnrichmentSummary with minimal arguments."""
        summary = NxcEnrichmentSummary(total_hosts_queried=5, hosts_with_data=0)
        assert summary.total_hosts_queried == 5
        assert summary.hosts_with_data == 0
        assert summary.protocols_seen == []
        assert summary.unique_credentials == []
        assert summary.shares_summary == {}
        assert summary.security_flag_counts == {}
        assert summary.per_host_data == {}


# =============================================================================
# Unit Tests: NxcDatabaseManager
# =============================================================================


class TestNxcDatabaseManager:
    """Test NxcDatabaseManager with mocked databases."""

    def test_is_available_no_path(self, tmp_path: Path) -> None:
        """Test is_available returns False when path doesn't exist."""
        mgr = NxcDatabaseManager(tmp_path / "nonexistent")
        assert mgr.is_available() is False

    def test_is_available_empty_dir(self, temp_nxc_workspace: Path) -> None:
        """Test is_available returns False when directory is empty."""
        mgr = NxcDatabaseManager(temp_nxc_workspace)
        assert mgr.is_available() is False

    def test_is_available_with_smb_db(self, populated_smb_db: Path) -> None:
        """Test is_available returns True when SMB database exists."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)
        assert mgr.is_available() is True

    def test_get_available_protocols_empty(self, temp_nxc_workspace: Path) -> None:
        """Test get_available_protocols returns empty list when no DBs exist."""
        mgr = NxcDatabaseManager(temp_nxc_workspace)
        assert mgr.get_available_protocols() == []

    def test_get_available_protocols_smb(self, populated_smb_db: Path) -> None:
        """Test get_available_protocols returns SMB when SMB DB exists."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)
        assert "smb" in mgr.get_available_protocols()

    def test_get_available_protocols_multiple(
        self, populated_smb_db: Path, populated_ssh_db: Path
    ) -> None:
        """Test get_available_protocols returns multiple protocols."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)
        protocols = mgr.get_available_protocols()
        assert "smb" in protocols
        assert "ssh" in protocols


# =============================================================================
# Integration Tests: SMB Database Queries
# =============================================================================


class TestSmbDatabaseQueries:
    """Test SMB database query functionality."""

    def test_query_existing_host(self, populated_smb_db: Path) -> None:
        """Test querying an existing host returns data."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        result = mgr.get_host_enrichment("192.168.1.10")

        assert result is not None
        assert result.host_address == "192.168.1.10"
        assert result.hostname == "DC01"
        assert "smb" in result.protocols_seen

    def test_query_nonexistent_host(self, populated_smb_db: Path) -> None:
        """Test querying a nonexistent host returns None."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        result = mgr.get_host_enrichment("10.0.0.99")

        assert result is None

    def test_query_host_credentials(self, populated_smb_db: Path) -> None:
        """Test that credentials are retrieved for a host."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        result = mgr.get_host_enrichment("192.168.1.10")

        assert result is not None
        assert len(result.credentials) == 1
        cred = result.credentials[0]
        assert cred.username == "admin"
        assert cred.domain == "CORP"
        assert cred.credential_type == "hash"
        assert cred.has_admin is True

    def test_query_host_shares(self, populated_smb_db: Path) -> None:
        """Test that shares are retrieved for a host."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        result = mgr.get_host_enrichment("192.168.1.10")

        assert result is not None
        assert len(result.shares) == 3

        # Find C$ share
        c_share = next((s for s in result.shares if s.name == "C$"), None)
        assert c_share is not None
        assert c_share.read_access is True
        assert c_share.write_access is True

        # Find ADMIN$ share
        admin_share = next((s for s in result.shares if s.name == "ADMIN$"), None)
        assert admin_share is not None
        assert admin_share.read_access is True
        assert admin_share.write_access is False

    def test_query_host_security_flags(self, populated_smb_db: Path) -> None:
        """Test that security flags are retrieved for a host."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        result = mgr.get_host_enrichment("192.168.1.10")

        assert result is not None
        assert result.security_flags is not None
        flags = result.security_flags
        assert flags.signing_required is False  # signing=0 in test data
        assert flags.smbv1_enabled is False
        assert flags.zerologon_vulnerable is True
        assert flags.petitpotam_vulnerable is True


# =============================================================================
# Integration Tests: SSH Database Queries
# =============================================================================


class TestSshDatabaseQueries:
    """Test SSH database query functionality."""

    def test_query_ssh_host(self, populated_ssh_db: Path) -> None:
        """Test querying a host from SSH database."""
        workspace = populated_ssh_db.parent
        mgr = NxcDatabaseManager(workspace)

        result = mgr.get_host_enrichment("192.168.1.20")

        assert result is not None
        assert result.host_address == "192.168.1.20"
        assert "ssh" in result.protocols_seen

    def test_query_ssh_credentials(self, populated_ssh_db: Path) -> None:
        """Test that SSH credentials are retrieved."""
        workspace = populated_ssh_db.parent
        mgr = NxcDatabaseManager(workspace)

        result = mgr.get_host_enrichment("192.168.1.20")

        assert result is not None
        assert len(result.credentials) == 1
        cred = result.credentials[0]
        assert cred.protocol == "ssh"
        assert cred.username == "root"
        assert cred.credential_type == "key"
        assert cred.has_admin is True


# =============================================================================
# Integration Tests: Multi-Protocol Queries
# =============================================================================


class TestMultiProtocolQueries:
    """Test queries across multiple protocol databases."""

    def test_merged_data_from_smb_and_ssh(
        self, populated_smb_db: Path, populated_ssh_db: Path
    ) -> None:
        """Test that data is merged when host exists in multiple DBs."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        # WEB01 (192.168.1.20) exists in both SMB and SSH
        result = mgr.get_host_enrichment("192.168.1.20")

        assert result is not None
        # Should have protocols from both
        assert "smb" in result.protocols_seen
        assert "ssh" in result.protocols_seen

        # Should have credentials from SSH (root with key)
        ssh_creds = [c for c in result.credentials if c.protocol == "ssh"]
        assert len(ssh_creds) == 1


# =============================================================================
# Integration Tests: Batch Enrichment
# =============================================================================


class TestBatchEnrichment:
    """Test batch enrichment for multiple hosts."""

    def test_get_hosts_enrichment_all_found(self, populated_smb_db: Path) -> None:
        """Test batch enrichment when all hosts exist."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        summary = mgr.get_hosts_enrichment(["192.168.1.10", "192.168.1.20"])

        assert summary.total_hosts_queried == 2
        assert summary.hosts_with_data == 2
        assert "smb" in summary.protocols_seen

    def test_get_hosts_enrichment_partial(self, populated_smb_db: Path) -> None:
        """Test batch enrichment when some hosts don't exist."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        summary = mgr.get_hosts_enrichment(["192.168.1.10", "10.0.0.99", "10.0.0.100"])

        assert summary.total_hosts_queried == 3
        assert summary.hosts_with_data == 1

    def test_get_hosts_enrichment_none_found(self, populated_smb_db: Path) -> None:
        """Test batch enrichment when no hosts exist."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        summary = mgr.get_hosts_enrichment(["10.0.0.99", "10.0.0.100"])

        assert summary.total_hosts_queried == 2
        assert summary.hosts_with_data == 0

    def test_get_hosts_enrichment_security_flag_counts(
        self, populated_smb_db: Path
    ) -> None:
        """Test that security flags are counted correctly."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        summary = mgr.get_hosts_enrichment(["192.168.1.10", "192.168.1.20"])

        # DC01 has signing disabled, zerologon, petitpotam
        # WEB01 has signing enabled, no vulnerabilities
        assert "signing_disabled" in summary.security_flag_counts
        assert summary.security_flag_counts["signing_disabled"] == 1
        assert summary.security_flag_counts.get("zerologon", 0) == 1
        assert summary.security_flag_counts.get("petitpotam", 0) == 1

    def test_get_hosts_enrichment_unique_credentials(
        self, populated_smb_db: Path
    ) -> None:
        """Test that credentials are deduplicated with counts."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        summary = mgr.get_hosts_enrichment(["192.168.1.10", "192.168.1.20"])

        # Should have 2 unique credentials: admin (on 1 host), svc_backup (on 1 host)
        assert len(summary.unique_credentials) == 2

    def test_get_hosts_enrichment_shares_summary(self, populated_smb_db: Path) -> None:
        """Test that shares are summarized correctly."""
        workspace = populated_smb_db.parent
        mgr = NxcDatabaseManager(workspace)

        summary = mgr.get_hosts_enrichment(["192.168.1.10"])

        # DC01 has C$ (RW), ADMIN$ (R), SYSVOL (R)
        assert "C$" in summary.shares_summary
        assert summary.shares_summary["C$"] == (1, 1)  # (read_count, write_count)
        assert "ADMIN$" in summary.shares_summary
        assert summary.shares_summary["ADMIN$"] == (1, 0)


# =============================================================================
# Integration Tests: Using Fixture DBs
# =============================================================================


class TestWithFixtureDBs:
    """Test with the actual fixture databases in tests/fixtures/nxc/."""

    def test_fixture_dbs_exist(self, nxc_fixtures_path: Path) -> None:
        """Test that fixture databases exist."""
        assert nxc_fixtures_path.exists()
        assert (nxc_fixtures_path / "smb.db").exists()

    def test_manager_with_fixtures(self, nxc_fixtures_path: Path) -> None:
        """Test that manager recognizes fixture databases."""
        mgr = NxcDatabaseManager(nxc_fixtures_path)
        assert mgr.is_available() is True

        # Check that all expected protocols are available
        protocols = mgr.get_available_protocols()
        assert "smb" in protocols
        # The fixture DBs are empty (schema only) but should still be recognized

    def test_query_empty_fixture_db(self, nxc_fixtures_path: Path) -> None:
        """Test querying empty fixture DB returns None."""
        mgr = NxcDatabaseManager(nxc_fixtures_path)

        # Fixture DBs have schema but no data
        result = mgr.get_host_enrichment("192.168.1.1")

        # Should return None since no data
        assert result is None


# =============================================================================
# Unit Tests: Module-level Functions
# =============================================================================


class TestModuleFunctions:
    """Test module-level singleton functions."""

    def test_get_nxc_manager_no_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test get_nxc_manager returns None when path doesn't exist."""
        # Mock config to return non-existent path
        from cerno_pkg import config

        fake_config = config.CernoConfig(
            nxc_workspace_path="/nonexistent/path",
            nxc_enrichment_enabled=True,
        )
        monkeypatch.setattr(config, "load_config", lambda: fake_config)

        result = get_nxc_manager()
        assert result is None

    def test_get_nxc_manager_disabled(
        self, monkeypatch: pytest.MonkeyPatch, populated_smb_db: Path
    ) -> None:
        """Test get_nxc_manager returns None when disabled in config."""
        from cerno_pkg import config

        fake_config = config.CernoConfig(
            nxc_workspace_path=str(populated_smb_db.parent),
            nxc_enrichment_enabled=False,
        )
        monkeypatch.setattr(config, "load_config", lambda: fake_config)

        result = get_nxc_manager()
        assert result is None

    def test_get_nxc_manager_with_valid_path(
        self, monkeypatch: pytest.MonkeyPatch, populated_smb_db: Path
    ) -> None:
        """Test get_nxc_manager returns manager when path is valid."""
        from cerno_pkg import config

        fake_config = config.CernoConfig(
            nxc_workspace_path=str(populated_smb_db.parent),
            nxc_enrichment_enabled=True,
        )
        monkeypatch.setattr(config, "load_config", lambda: fake_config)

        result = get_nxc_manager()
        assert result is not None
        assert result.is_available() is True
