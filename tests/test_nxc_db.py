"""Tests for NetExec database integration module.

Tests the NxcDatabaseManager and related dataclasses for querying
NetExec protocol databases to enrich Cerno finding displays.
"""

from __future__ import annotations

import shutil
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
    return FIXTURES_DIR


@pytest.fixture
def temp_nxc_workspace(tmp_path: Path) -> Path:
    """Create a temporary NXC workspace directory."""
    workspace = tmp_path / "nxc_workspace"
    workspace.mkdir()
    return workspace


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "nxc"


def _copy_fixture_db(protocol: str, workspace: Path) -> Path:
    """Copy the real (empty) NetExec 1.5.1 schema for ``protocol`` into ``workspace``."""
    db_path = workspace / f"{protocol}.db"
    shutil.copyfile(FIXTURES_DIR / f"{protocol}.db", db_path)
    return db_path


def _seed(db_path: Path, sql: str) -> None:
    """Run seed SQL against a copied fixture database."""
    conn = sqlite3.connect(db_path)
    conn.executescript(sql)
    conn.commit()
    conn.close()


@pytest.fixture
def populated_smb_db(temp_nxc_workspace: Path) -> Path:
    """SMB database (real NetExec schema) with test data."""
    db_path = _copy_fixture_db("smb", temp_nxc_workspace)
    _seed(
        db_path,
        """
        -- DC01 has vulnerabilities; WEB01 has none
        INSERT INTO hosts (id, ip, hostname, domain, os, smbv1, signing, zerologon, petitpotam)
        VALUES (1, '192.168.1.10', 'DC01', 'CORP.LOCAL', 'Windows Server 2019', 0, 0, 1, 1),
               (2, '192.168.1.20', 'WEB01', 'CORP.LOCAL', 'Windows Server 2016', 0, 1, 0, 0);

        INSERT INTO users (id, domain, username, password, credtype)
        VALUES (1, 'CORP', 'admin', NULL, 'hash'),
               (2, 'CORP', 'svc_backup', NULL, 'plaintext');

        -- admin has admin on DC01; svc_backup logged into WEB01
        INSERT INTO admin_relations (id, userid, hostid) VALUES (1, 1, 1);
        INSERT INTO loggedin_relations (id, userid, hostid) VALUES (1, 2, 2);

        INSERT INTO shares (id, hostid, name, read, write)
        VALUES (1, 1, 'C$', 1, 1), (2, 1, 'ADMIN$', 1, 0), (3, 1, 'SYSVOL', 1, 0);
    """,
    )
    return db_path


@pytest.fixture
def populated_ssh_db(temp_nxc_workspace: Path) -> Path:
    """SSH database (real NetExec schema: `host` column, no hostname) with test data."""
    db_path = _copy_fixture_db("ssh", temp_nxc_workspace)
    _seed(
        db_path,
        """
        INSERT INTO hosts (id, host, port, banner, os)
        VALUES (1, '192.168.1.20', 22, 'SSH-2.0-OpenSSH_8.2p1', 'Linux');
        INSERT INTO credentials (id, username, password, credtype) VALUES (1, 'root', NULL, 'key');
        INSERT INTO admin_relations (id, credid, hostid) VALUES (1, 1, 1);
    """,
    )
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
# Integration Tests: Real NetExec 1.5.1 Schemas (regression guard)
# =============================================================================

REAL_IP = "10.0.0.5"

# One seed per protocol, written against the real schemas in tests/fixtures/nxc/.
# Passwords are NULL: only identities matter for enrichment.
REAL_SEEDS = {
    "smb": """
        INSERT INTO hosts (id, ip, hostname, domain, os, dc, smbv1, signing, spooler, zerologon, petitpotam)
        VALUES (1, '10.0.0.5', 'DC01', 'corp.local', 'Windows Server 2019', 1, 0, 0, 1, 0, 1);
        INSERT INTO users (id, domain, username, credtype, pillaged_from_hostid)
        VALUES (1, 'CORP', 'alice', 'plaintext', NULL),
               (2, 'CORP', 'bob', 'hash', NULL),
               (3, '.', 'localadmin', 'hash', 1);
        -- duplicate relation rows must not duplicate the credential
        INSERT INTO admin_relations (userid, hostid) VALUES (1, 1), (1, 1);
        INSERT INTO loggedin_relations (userid, hostid) VALUES (1, 1), (1, 1), (2, 1);
        -- one share row per user: must collapse to one share per name
        INSERT INTO shares (hostid, userid, name, read, write)
        VALUES (1, 1, 'C$', 1, 1), (1, 2, 'C$', 0, 0), (1, 1, 'SYSVOL', 1, 0), (1, 2, 'SYSVOL', 1, 0);
        INSERT INTO conf_checks (id, name, description) VALUES (1, 'SMBv1', 'd'), (2, 'LDAP signing', 'd');
        INSERT INTO conf_checks_results (host_id, check_id, secure, reasons)
        VALUES (1, 1, 1, ''), (1, 2, 0, 'Not enforced');
    """,
    "ssh": """
        -- one hosts row per port
        INSERT INTO hosts (id, host, port, banner) VALUES
            (1, '10.0.0.5', 22, 'SSH-2.0-OpenSSH_9.6'), (2, '10.0.0.5', 2222, 'SSH-2.0-dropbear');
        INSERT INTO credentials (id, username, credtype) VALUES (1, 'root', 'key'), (2, 'deploy', 'plaintext');
        INSERT INTO admin_relations (credid, hostid) VALUES (1, 1);
        INSERT INTO loggedin_relations (credid, hostid, shell) VALUES (2, 2, 1);
    """,
    "ftp": """
        INSERT INTO hosts (id, host, port, banner) VALUES (1, '10.0.0.5', 21, 'vsFTPd 3.0.3');
        INSERT INTO credentials (id, username) VALUES (1, 'anonymous');
        INSERT INTO loggedin_relations (credid, hostid) VALUES (1, 1);
    """,
    "nfs": """
        INSERT INTO hosts (id, ip, port) VALUES (1, '10.0.0.5', 2049);
        INSERT INTO credentials (id, username) VALUES (1, 'nobody');
        INSERT INTO loggedin_relations (cred_id, host_id) VALUES (1, 1);
    """,
    "ldap": """
        INSERT INTO hosts (id, ip, hostname, domain, os, signing_required, channel_binding)
        VALUES (1, '10.0.0.5', 'DC01', 'corp.local', 'Windows Server 2019', 0, 'Never');
    """,
    "mssql": """
        INSERT INTO hosts (id, ip, hostname, domain, os, instances)
        VALUES (1, '10.0.0.5', 'DC01', 'CORP', 'Windows Server 2019', 2);
        INSERT INTO users (id, credtype, domain, username) VALUES (1, 'plaintext', 'CORP', 'sqladmin');
        INSERT INTO admin_relations (userid, hostid) VALUES (1, 1);
    """,
    "winrm": """
        INSERT INTO hosts (id, ip, port, hostname, domain, os)
        VALUES (1, '10.0.0.5', 5985, 'DC01', 'CORP', 'Windows Server 2019');
        INSERT INTO users (id, domain, username, credtype) VALUES (1, 'CORP', 'helpdesk', 'plaintext');
        INSERT INTO loggedin_relations (userid, hostid) VALUES (1, 1);
    """,
    "rdp": """
        INSERT INTO hosts (id, ip, port, hostname, domain, os, nla)
        VALUES (1, '10.0.0.5', 3389, 'DC01', 'CORP', 'Windows Server 2019', 0);
    """,
    "vnc": """
        INSERT INTO hosts (id, ip, hostname, port, server_banner) VALUES (1, '10.0.0.5', NULL, 5900, 'RFB 003.008');
        -- no relations table in the real schema: cannot be tied to the host
        INSERT INTO credentials (id, username) VALUES (1, 'viewer');
    """,
    "wmi": """
        INSERT INTO hosts (id, ip, hostname, port) VALUES (1, '10.0.0.5', NULL, 135);
        INSERT INTO credentials (id, username) VALUES (1, 'wmiuser');
    """,
}

# protocol -> (expected credential usernames, expected protocol_details subset)
REAL_EXPECTED: dict[str, tuple[set[str], dict]] = {
    "smb": (
        {"alice", "bob", "localadmin"},
        {"dc": True, "spooler": True, "signing": False},
    ),
    "ssh": ({"root", "deploy"}, {"ports": [22, 2222], "banner": "SSH-2.0-OpenSSH_9.6"}),
    "ftp": ({"anonymous"}, {"ports": [21], "banner": "vsFTPd 3.0.3"}),
    "nfs": ({"nobody"}, {"ports": [2049]}),
    "ldap": (set(), {"signing_required": False, "channel_binding": "Never"}),
    "mssql": ({"sqladmin"}, {"instances": 2}),
    "winrm": ({"helpdesk"}, {"ports": [5985]}),
    "rdp": (set(), {"ports": [3389], "nla": False}),
    "vnc": (set(), {"ports": [5900], "server_banner": "RFB 003.008"}),
    "wmi": (set(), {"ports": [135]}),
}


@pytest.fixture
def query_errors(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Capture nxc_db debug logs; a non-empty list means a query hit a schema error."""
    import cerno_pkg.nxc_db as nxc_db_module

    messages: list[str] = []
    monkeypatch.setattr(nxc_db_module, "log_debug", messages.append)
    return messages


def _real_workspace(workspace: Path, protocols: list[str]) -> NxcDatabaseManager:
    for protocol in protocols:
        _seed(_copy_fixture_db(protocol, workspace), REAL_SEEDS[protocol])
    return NxcDatabaseManager(workspace)


class TestRealSchemas:
    """Every protocol must enrich against the schemas NetExec actually creates."""

    @pytest.mark.parametrize("protocol", sorted(REAL_SEEDS))
    def test_protocol_enriches_host(
        self, protocol: str, temp_nxc_workspace: Path, query_errors: list[str]
    ) -> None:
        mgr = _real_workspace(temp_nxc_workspace, [protocol])

        result = mgr.get_host_enrichment(REAL_IP)

        assert query_errors == []
        assert result is not None, f"{protocol}: host not found"
        assert result.protocols_seen == [protocol]
        expected_users, expected_details = REAL_EXPECTED[protocol]
        usernames = [c.username for c in result.credentials]
        assert set(usernames) == expected_users
        assert len(usernames) == len(set(usernames)), "credential duplicated"
        details = result.protocol_details[protocol]
        for key, value in expected_details.items():
            assert details[key] == value, f"{protocol}.{key}"

    def test_all_protocols_merge(
        self, temp_nxc_workspace: Path, query_errors: list[str]
    ) -> None:
        mgr = _real_workspace(temp_nxc_workspace, list(REAL_SEEDS))

        result = mgr.get_host_enrichment(REAL_IP)

        assert query_errors == []
        assert result is not None
        assert sorted(result.protocols_seen) == sorted(REAL_SEEDS)
        assert result.hostname == "DC01"
        assert set(result.protocol_details) == set(REAL_SEEDS)

    def test_smb_admin_loggedin_and_pillaged(self, temp_nxc_workspace: Path) -> None:
        mgr = _real_workspace(temp_nxc_workspace, ["smb"])

        result = mgr.get_host_enrichment(REAL_IP)

        assert result is not None
        creds = {c.username: c for c in result.credentials}
        assert creds["alice"].has_admin is True and creds["alice"].pillaged is False
        assert creds["bob"].has_admin is False and creds["bob"].pillaged is False
        assert (
            creds["localadmin"].pillaged is True
            and creds["localadmin"].has_admin is False
        )

    def test_smb_shares_collapse_per_name(self, temp_nxc_workspace: Path) -> None:
        mgr = _real_workspace(temp_nxc_workspace, ["smb"])

        result = mgr.get_host_enrichment(REAL_IP)
        summary = mgr.get_hosts_enrichment([REAL_IP])

        assert result is not None
        assert [(s.name, s.read_access, s.write_access) for s in result.shares] == [
            ("C$", True, True),
            ("SYSVOL", True, False),
        ]
        assert summary.shares_summary == {"C$": (1, 1), "SYSVOL": (1, 0)}

    def test_smb_failed_conf_checks(self, temp_nxc_workspace: Path) -> None:
        mgr = _real_workspace(temp_nxc_workspace, ["smb"])

        result = mgr.get_host_enrichment(REAL_IP)

        assert result is not None
        assert [(c.name, c.reasons) for c in result.failed_checks] == [
            ("LDAP signing", "Not enforced")
        ]

    def test_ssh_admin_flag(self, temp_nxc_workspace: Path) -> None:
        mgr = _real_workspace(temp_nxc_workspace, ["ssh"])

        result = mgr.get_host_enrichment(REAL_IP)

        assert result is not None
        creds = {c.username: c for c in result.credentials}
        assert (
            creds["root"].has_admin is True and creds["root"].credential_type == "key"
        )
        assert creds["deploy"].has_admin is False

    def test_summary_flag_counts(self, temp_nxc_workspace: Path) -> None:
        mgr = _real_workspace(temp_nxc_workspace, list(REAL_SEEDS))

        summary = mgr.get_hosts_enrichment([REAL_IP, "10.0.0.99"])

        assert summary.hosts_with_data == 1
        assert summary.security_flag_counts == {
            "signing_disabled": 1,
            "petitpotam": 1,
            "ldap_signing_disabled": 1,
            "rdp_nla_disabled": 1,
        }
        pillaged = [c for c, _ in summary.unique_credentials if c.pillaged]
        assert [c.username for c in pillaged] == ["localadmin"]

    def test_null_flags_not_counted(self, temp_nxc_workspace: Path) -> None:
        """NULL (unchecked) LDAP signing / RDP NLA must not be reported as disabled."""
        _seed(
            _copy_fixture_db("ldap", temp_nxc_workspace),
            "INSERT INTO hosts (id, ip) VALUES (1, '10.0.0.5');",
        )
        _seed(
            _copy_fixture_db("rdp", temp_nxc_workspace),
            "INSERT INTO hosts (id, ip, port) VALUES (1, '10.0.0.5', 3389);",
        )
        mgr = NxcDatabaseManager(temp_nxc_workspace)

        summary = mgr.get_hosts_enrichment([REAL_IP])

        assert summary.hosts_with_data == 1
        assert summary.security_flag_counts == {}


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

    def test_query_empty_fixture_db(
        self, nxc_fixtures_path: Path, query_errors: list[str]
    ) -> None:
        """Querying empty real-schema DBs returns None — because no row matched, not an error."""
        mgr = NxcDatabaseManager(nxc_fixtures_path)

        # Fixture DBs have schema but no data
        result = mgr.get_host_enrichment("192.168.1.1")

        # Should return None since no data
        assert result is None
        assert query_errors == []


class TestDemoNxcWorkspace:
    """Test the synthetic NetExec workspace used by Cerno demos."""

    @pytest.fixture
    def demo_nxc_workspace(self) -> Path:
        """Path to the demo NetExec workspace."""
        workspace = Path(__file__).parents[1] / "docs" / "demo" / "nxc-workspace"
        if not workspace.exists():
            pytest.skip("demo NetExec workspace not found")
        return workspace

    def test_demo_workspace_available(self, demo_nxc_workspace: Path) -> None:
        """Demo workspace exposes the expected protocol databases."""
        mgr = NxcDatabaseManager(demo_nxc_workspace)

        assert mgr.is_available() is True
        assert mgr.get_available_protocols() == [
            "smb",
            "ssh",
            "ldap",
            "rdp",
            "ftp",
            "vnc",
        ]

    def test_demo_workspace_enriches_smb_signing_hosts(
        self, demo_nxc_workspace: Path
    ) -> None:
        """SMB signing demo hosts have credentials, shares, and security flags."""
        mgr = NxcDatabaseManager(demo_nxc_workspace)

        summary = mgr.get_hosts_enrichment(
            [
                "198.51.100.20",
                "198.51.100.21",
                "198.51.100.30",
                "198.51.100.32",
                "198.51.100.60",
                "198.51.100.61",
                "198.51.100.62",
                "198.51.100.63",
                "198.51.100.64",
                "198.51.100.65",
            ]
        )

        assert summary.hosts_with_data == 10
        # DC01 and WIN01-03 also appear in the demo ldap/rdp databases
        assert summary.protocols_seen == ["ldap", "rdp", "smb"]
        assert summary.security_flag_counts["signing_disabled"] == 9
        assert summary.security_flag_counts["smbv1_enabled"] == 2
        assert summary.security_flag_counts["zerologon"] == 1
        assert summary.security_flag_counts["petitpotam"] == 2
        assert "C$" in summary.shares_summary
        assert "SYSVOL" in summary.shares_summary
        assert any(
            cred.username == "svc_deploy" for cred, _ in summary.unique_credentials
        )

    def test_demo_workspace_enriches_multi_protocol_hosts(
        self, demo_nxc_workspace: Path
    ) -> None:
        """Legacy and backup hosts show non-SMB and merged protocol context."""
        mgr = NxcDatabaseManager(demo_nxc_workspace)

        legacy = mgr.get_host_enrichment("198.51.100.33")
        assert legacy is not None
        assert legacy.protocols_seen == ["ftp", "vnc"]
        # vnc has no relations table in the real schema: presence + banner only
        assert {cred.username for cred in legacy.credentials} == {"anonymous"}
        assert legacy.protocol_details["vnc"]["ports"] == [5900]

        backup = mgr.get_host_enrichment("203.0.113.63")
        assert backup is not None
        assert "smb" in backup.protocols_seen
        assert "ssh" in backup.protocols_seen
        assert any(
            cred.protocol == "ssh" and cred.has_admin for cred in backup.credentials
        )

    def test_demo_workspace_ldap_and_rdp_flags(self, demo_nxc_workspace: Path) -> None:
        """DC01 shows LDAP signing not required; WIN01/WIN02 have RDP NLA disabled."""
        mgr = NxcDatabaseManager(demo_nxc_workspace)

        summary = mgr.get_hosts_enrichment(
            ["198.51.100.30", "198.51.100.60", "198.51.100.61"]
        )

        assert summary.security_flag_counts["ldap_signing_disabled"] == 1
        assert summary.security_flag_counts["rdp_nla_disabled"] == 2
        assert {"smb", "ldap", "rdp"} <= set(summary.protocols_seen)


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


# =============================================================================
# Thread safety: the MCP server runs tool bodies on asyncio.to_thread workers,
# so workspace reads must not reuse a connection bound to another thread.
# =============================================================================


def _smb_workspace_with_secret(tmp_path: Path) -> Path:
    """A workspace whose smb.db has one host and one password credential."""
    workspace = tmp_path / "nxc_ws"
    workspace.mkdir()
    db_path = _copy_fixture_db("smb", workspace)
    _seed(
        db_path,
        """
        INSERT INTO hosts (id, ip, hostname, domain, os, smbv1, signing, zerologon, petitpotam)
        VALUES (1, '10.0.0.1', 'DC01', 'CORP', 'Windows', 0, 0, 0, 0);
        INSERT INTO users (id, domain, username, password, credtype)
        VALUES (1, 'CORP', 'alice', 'Sup3rSecret!', 'plaintext');
    """,
    )
    return workspace


@pytest.mark.integration
class TestThreadSafety:
    def _in_worker(self, fn):
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(fn).result()

    def test_resolve_credential_secret_from_worker_thread(self, tmp_path: Path) -> None:
        mgr = NxcDatabaseManager(_smb_workspace_with_secret(tmp_path))
        # Prime any caching on the MAIN thread (this is what used to bind a
        # connection to this thread and break the worker below).
        assert mgr.list_credential_refs()[0].secret_kind == "password"
        secret = self._in_worker(lambda: mgr.resolve_credential_secret("smb:1"))
        assert secret is not None
        assert secret.secret_value == "Sup3rSecret!"

    def test_list_credential_refs_from_worker_thread(self, tmp_path: Path) -> None:
        mgr = NxcDatabaseManager(_smb_workspace_with_secret(tmp_path))
        mgr.list_credential_refs()  # prime on main thread
        refs = self._in_worker(mgr.list_credential_refs)
        assert [r.ref for r in refs] == ["smb:1"]

    def test_get_host_enrichment_from_worker_thread(self, tmp_path: Path) -> None:
        mgr = NxcDatabaseManager(_smb_workspace_with_secret(tmp_path))
        mgr.get_host_enrichment("10.0.0.1")  # prime on main thread
        data = self._in_worker(lambda: mgr.get_host_enrichment("10.0.0.1"))
        assert data is not None
        assert data.host_address == "10.0.0.1"


@pytest.mark.integration
class TestErrorHandlingNoMasquerade:
    def test_genuinely_secretless_credential_returns_none(self, tmp_path: Path) -> None:
        workspace = tmp_path / "nxc_ws"
        workspace.mkdir()
        db_path = _copy_fixture_db("smb", workspace)
        _seed(
            db_path,
            """
            INSERT INTO users (id, domain, username, password, credtype)
            VALUES (1, 'CORP', 'nopw', NULL, 'plaintext');
        """,
        )
        mgr = NxcDatabaseManager(workspace)
        assert mgr.list_credential_refs()[0].secret_kind is None
        assert mgr.resolve_credential_secret("smb:1") is None

    def test_db_error_surfaces_not_masquerades_as_no_secret(
        self, tmp_path: Path
    ) -> None:
        workspace = tmp_path / "nxc_ws"
        workspace.mkdir()
        _copy_fixture_db("smb", workspace)
        mgr = NxcDatabaseManager(workspace)

        # A connection where PRAGMA table_info succeeds (so column detection
        # passes) but the credential SELECT raises — the error must propagate,
        # not be swallowed into a misleading "no secret" (None).
        class _Cur:
            def __init__(self, rows):
                self._rows = rows

            def fetchall(self):
                return self._rows

            def fetchone(self):
                return self._rows[0] if self._rows else None

        class _BoomConn:
            def execute(self, sql, params=()):
                if sql.strip().upper().startswith("PRAGMA"):
                    return _Cur([(0, "username"), (1, "password"), (2, "credtype")])
                raise sqlite3.OperationalError("disk I/O error")

            def close(self) -> None:
                pass

        import types

        mgr._get_connection = types.MethodType(  # type: ignore[method-assign]
            lambda self, protocol: _BoomConn(), mgr
        )
        with pytest.raises(sqlite3.Error):
            mgr.resolve_credential_secret("smb:1")
