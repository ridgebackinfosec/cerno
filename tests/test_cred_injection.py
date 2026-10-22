"""Tests for credential-aware generation + server-side secret handling (Phase 3)."""

import shutil
import sqlite3
from pathlib import Path

import pytest

from cerno_pkg import nxc_db
from cerno_pkg.config import CernoConfig
from cerno_pkg.mcp_server import server as mcp
from cerno_pkg.ops import mask_auth_flags
from cerno_pkg.tools import build_netexec_cmd, credential_placeholder

FIXTURES = Path(__file__).parent / "fixtures" / "nxc"


@pytest.fixture
def nxc_workspace(tmp_path: Path):
    """A NetExec workspace with one plaintext + one hash smb credential."""
    shutil.copyfile(FIXTURES / "smb.db", tmp_path / "smb.db")
    conn = sqlite3.connect(str(tmp_path / "smb.db"))
    conn.executemany(
        "INSERT INTO users (id, domain, username, password, credtype) VALUES (?,?,?,?,?)",
        [
            (1, "CORP", "alice", "Sup3rSecret!", "plaintext"),
            (2, "CORP", "admin", "aad3b435b51404eeaad3b435b51404ee", "hash"),
        ],
    )
    conn.commit()
    conn.close()
    mgr = nxc_db.NxcDatabaseManager(tmp_path)
    yield mgr
    mgr.close()


@pytest.mark.unit
class TestBuildNetexecCredential:
    def test_placeholder_not_secret_in_command(self) -> None:
        cmd, _log, _relay = build_netexec_cmd(
            "nxc",
            "smb",
            Path("/t/ips"),
            Path("/t/out"),
            credential={
                "username": "alice",
                "domain": "CORP",
                "secret_kind": "password",
                "ref": "smb:1",
            },
        )
        assert "-u" in cmd and "alice" in cmd
        assert "-d" in cmd and "CORP" in cmd
        assert credential_placeholder("smb:1") in cmd
        assert "Sup3rSecret!" not in " ".join(cmd)

    def test_hash_uses_H_flag(self) -> None:
        cmd, _log, _relay = build_netexec_cmd(
            "nxc",
            "smb",
            Path("/t/ips"),
            Path("/t/out"),
            credential={"username": "admin", "secret_kind": "hash", "ref": "smb:2"},
        )
        assert "-H" in cmd and credential_placeholder("smb:2") in cmd

    def test_missing_secret_kind_raises(self) -> None:
        with pytest.raises(ValueError):
            build_netexec_cmd(
                "nxc",
                "smb",
                Path("/t/ips"),
                Path("/t/out"),
                credential={"username": "alice", "secret_kind": None, "ref": "smb:1"},
            )


@pytest.mark.integration
class TestCredentialRefs:
    def test_list_refs_no_secret_value(self, nxc_workspace) -> None:
        refs = nxc_workspace.list_credential_refs()
        by_ref = {r.ref: r for r in refs}
        assert by_ref["smb:1"].secret_kind == "password"
        assert by_ref["smb:2"].secret_kind == "hash"
        assert by_ref["smb:1"].username == "alice"
        # NxcCredentialRef has no secret field at all
        assert not hasattr(by_ref["smb:1"], "secret_value")

    def test_resolve_returns_secret(self, nxc_workspace) -> None:
        secret = nxc_workspace.resolve_credential_secret("smb:1")
        assert secret is not None
        assert secret.secret_kind == "password"
        assert secret.secret_value == "Sup3rSecret!"

    def test_resolve_unknown_ref(self, nxc_workspace) -> None:
        assert nxc_workspace.resolve_credential_secret("smb:999") is None
        assert nxc_workspace.resolve_credential_secret("garbage") is None


@pytest.mark.unit
class TestMasking:
    def test_mask_command_text_masks_password_and_placeholder(self) -> None:
        masked = mcp._mask_command_text(
            ["nxc", "smb", "t", "-u", "alice", "-p", "@cred:smb:1@"]
        )
        assert "@cred" not in masked
        assert "alice" in masked  # username is not secret
        assert "********" in masked

    def test_mask_command_text_preserves_nmap_ports(self) -> None:
        # Bug B: -p is nmap's ports flag here, NOT a secret. Must stay intact.
        masked = mcp._mask_command_text(["nmap", "-A", "-p", "445", "-oA", "out"])
        assert masked == "nmap -A -p 445 -oA out"

    def test_mask_command_text_only_masks_placeholder(self) -> None:
        # A literal secret is left to the nxc-scoped ops layer; _mask_command_text
        # masks only the @cred placeholder (the sole secret-bearing token pre-run).
        masked = mcp._mask_command_text(["nxc", "smb", "t", "-H", "DEADBEEF"])
        assert masked == "nxc smb t -H DEADBEEF"
        masked2 = mcp._mask_command_text(["nxc", "smb", "t", "-H", "@cred:smb:2@"])
        assert "@cred" not in masked2 and "********" in masked2

    def test_scrub_secrets(self) -> None:
        out = mcp._scrub_secrets("login Sup3rSecret! ok", ["Sup3rSecret!"])
        assert "Sup3rSecret!" not in out and "********" in out

    def test_ops_mask_auth_flags(self) -> None:
        assert (
            mask_auth_flags("nxc smb t -u a -p hunter2") == "nxc smb t -u a -p ********"
        )
        assert mask_auth_flags("nxc smb t -H abc123") == "nxc smb t -H ********"


@pytest.mark.integration
class TestLoggedCommandTextMasking:
    """The persisted tool_executions.command_text must keep nmap -p <ports> intact
    while masking a literal secret only for nxc/netexec runs."""

    def _log(self, conn: sqlite3.Connection, tool_name: str, command_text: str) -> str:
        from cerno_pkg.ops import ExecutionMetadata, log_tool_execution

        meta = ExecutionMetadata(exit_code=0, duration_seconds=0.1, used_sudo=False)
        eid = log_tool_execution(tool_name, command_text, meta, conn=conn)
        row = conn.execute(
            "SELECT command_text FROM tool_executions WHERE execution_id = ?", (eid,)
        ).fetchone()
        return row["command_text"]

    def test_nmap_ports_preserved(self, temp_db: sqlite3.Connection) -> None:
        stored = self._log(temp_db, "mcp", "nmap -A -p 445 -oA out -iL ips.txt")
        assert "-p 445" in stored
        assert "********" not in stored

    def test_nxc_literal_secret_masked(self, temp_db: sqlite3.Connection) -> None:
        stored = self._log(temp_db, "mcp", "nxc smb targets -u alice -p hunter2")
        assert "hunter2" not in stored
        assert "-p ********" in stored


@pytest.mark.integration
class TestExecuteGating:
    def test_placeholder_refused_when_injection_disabled(
        self, temp_db: sqlite3.Connection
    ) -> None:
        cfg = CernoConfig(
            mcp_allow_execution=True,
            mcp_allow_cred_injection=False,
            mcp_exec_allowlist=["nxc"],
        )
        with pytest.raises(ValueError, match="injection is disabled"):
            mcp.tool_execute_command(
                ["nxc", "smb", "t", "-u", "a", "-p", "@cred:smb:1@"],
                config=cfg,
                conn=temp_db,
            )


@pytest.mark.integration
class TestLogArtifactScrub:
    """Part D: a resolved secret must never survive in a registered artifact file."""

    def _point_singleton_at(self, workspace_path, monkeypatch):
        from cerno_pkg import config as config_mod

        monkeypatch.setattr(
            config_mod,
            "load_config",
            lambda: CernoConfig(
                nxc_workspace_path=str(workspace_path), nxc_enrichment_enabled=True
            ),
        )
        nxc_db.reset_nxc_manager()

    def test_nxc_log_artifact_is_scrubbed(
        self, temp_db, nxc_workspace, monkeypatch, tmp_path
    ):
        self._point_singleton_at(nxc_workspace.workspace_path, monkeypatch)
        from cerno_pkg import ops
        from cerno_pkg.ops import ExecutionMetadata

        secret = "aad3b435b51404eeaad3b435b51404ee"  # smb:2 (hash) value
        log_path = tmp_path / "scan.nxc.smb.log"

        def fake_run(cmd, timeout=300, proxy_config=None):
            # nxc writes its full (resolved) argv to the --log file.
            resolved = cmd[cmd.index("-H") + 1]
            log_path.write_text(f"SMB 10.0.0.1 nxc -u admin -H {resolved} --shares\n")
            return (
                ExecutionMetadata(0, 0.1, False),
                f"authenticated with {resolved}",
                "",
            )

        monkeypatch.setattr(ops, "run_command_captured", fake_run)

        cfg = CernoConfig(
            mcp_allow_execution=True,
            mcp_allow_cred_injection=True,
            mcp_exec_allowlist=["nxc"],
        )
        cmd = [
            "nxc",
            "smb",
            "targets",
            "-u",
            "admin",
            "-H",
            "@cred:smb:2@",
            "--shares",
            "--log",
            str(log_path),
        ]
        result = mcp.tool_execute_command(cmd, config=cfg, conn=temp_db)

        # stdout/command_text already scrubbed/masked...
        assert secret not in result["stdout"]
        assert "********" in result["stdout"]
        # ...and the ON-DISK log file no longer contains the cleartext secret.
        on_disk = log_path.read_text()
        assert secret not in on_disk
        assert "********" in on_disk

        # ...and reading it back through the registered artifact shows the mask.
        row = temp_db.execute(
            "SELECT artifact_id FROM artifacts WHERE execution_id = ?",
            (result["execution_id"],),
        ).fetchone()
        assert row is not None
        art = mcp.tool_read_artifact(row["artifact_id"], conn=temp_db)
        assert secret not in (art["content"] or "")
        assert "********" in (art["content"] or "")

        # command_text persisted with the placeholder masked, no secret.
        ct = temp_db.execute(
            "SELECT command_text FROM tool_executions WHERE execution_id = ?",
            (result["execution_id"],),
        ).fetchone()["command_text"]
        assert secret not in ct and "@cred" not in ct
