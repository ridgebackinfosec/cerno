"""Tests for the audited credential reveal path (CLI + gated MCP tool)."""

import asyncio
import shutil
import sqlite3
from pathlib import Path

import pytest

from cerno_pkg import creds, nxc_db
from cerno_pkg.config import CernoConfig
from cerno_pkg.mcp_server import build_server, server as mcp

FIXTURES = Path(__file__).parent / "fixtures" / "nxc"


@pytest.fixture
def nxc_workspace(tmp_path: Path, monkeypatch):
    """Workspace with one plaintext + one hash smb credential, wired to the singleton."""
    shutil.copyfile(FIXTURES / "smb.db", tmp_path / "smb.db")
    conn = sqlite3.connect(str(tmp_path / "smb.db"))
    conn.executemany(
        "INSERT INTO users (id, domain, username, password, credtype) VALUES (?,?,?,?,?)",
        [
            (1, "CORP", "alice", "Sup3rSecret!", "plaintext"),
            (2, "CORP", "admin", "aad3b435b51404eeaad3b435b51404ee", "hash"),
            (3, "CORP", "nopw", None, "plaintext"),
        ],
    )
    conn.commit()
    conn.close()

    from cerno_pkg import config as config_mod

    monkeypatch.setattr(
        config_mod,
        "load_config",
        lambda: CernoConfig(
            nxc_workspace_path=str(tmp_path), nxc_enrichment_enabled=True
        ),
    )
    nxc_db.reset_nxc_manager()
    yield tmp_path
    nxc_db.reset_nxc_manager()


def _tool_names(config) -> list[str]:
    srv = build_server(config)
    tools = asyncio.new_event_loop().run_until_complete(srv.list_tools())
    return sorted(t.name for t in tools)


@pytest.mark.integration
class TestRevealHelper:
    def test_reveal_returns_secret(
        self, nxc_workspace, temp_db: sqlite3.Connection
    ) -> None:
        secret = creds.reveal_credential("smb:1", conn=temp_db)
        assert secret is not None
        assert secret.secret_value == "Sup3rSecret!"
        assert secret.secret_kind == "password"

    def test_reveal_writes_audit_without_secret(
        self, nxc_workspace, temp_db: sqlite3.Connection
    ) -> None:
        creds.reveal_credential("smb:2", conn=temp_db)
        rows = temp_db.execute(
            "SELECT tool_name, command_text FROM tool_executions WHERE tool_name = 'cred_reveal'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["command_text"] == "reveal_credential smb:2"
        # the secret value must never appear in the audit record
        assert "aad3b435b51404ee" not in rows[0]["command_text"]

    def test_secretless_credential_returns_none_and_no_audit(
        self, nxc_workspace, temp_db: sqlite3.Connection
    ) -> None:
        assert creds.reveal_credential("smb:3", conn=temp_db) is None
        n = temp_db.execute(
            "SELECT COUNT(*) AS n FROM tool_executions WHERE tool_name = 'cred_reveal'"
        ).fetchone()["n"]
        assert n == 0  # only successful reveals are audited


@pytest.mark.integration
class TestMcpRevealGating:
    def test_reveal_tool_absent_when_gate_off(self, nxc_workspace) -> None:
        names = _tool_names(CernoConfig(mcp_allow_cred_reveal=False))
        assert "reveal_credential" not in names

    def test_reveal_tool_present_when_gate_on(self, nxc_workspace) -> None:
        names = _tool_names(CernoConfig(mcp_allow_cred_reveal=True))
        assert "reveal_credential" in names

    def test_reveal_independent_of_injection(self, nxc_workspace) -> None:
        # injection on but reveal off -> reveal tool must NOT appear
        names = _tool_names(
            CernoConfig(mcp_allow_execution=True, mcp_allow_cred_injection=True)
        )
        assert "reveal_credential" not in names

    def test_tool_reveal_returns_secret(
        self, nxc_workspace, temp_db: sqlite3.Connection
    ) -> None:
        out = mcp.tool_reveal_credential("smb:1", conn=temp_db)
        assert out["secret_value"] == "Sup3rSecret!"
        assert "SENSITIVE" in out["warning"]

    def test_tool_reveal_raises_for_secretless(
        self, nxc_workspace, temp_db: sqlite3.Connection
    ) -> None:
        with pytest.raises(ValueError):
            mcp.tool_reveal_credential("smb:3", conn=temp_db)

    def test_capabilities_report_cred_reveal(self, nxc_workspace) -> None:
        caps_on = mcp.tool_get_capabilities(CernoConfig(mcp_allow_cred_reveal=True))
        caps_off = mcp.tool_get_capabilities(CernoConfig(mcp_allow_cred_reveal=False))
        assert caps_on["cred_reveal_enabled"] is True
        assert caps_off["cred_reveal_enabled"] is False
