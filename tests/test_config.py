"""Tests for CernoConfig fields, focused on the MCP exec allowlist."""

import pytest

import cerno_pkg.config as config_mod
from cerno_pkg.config import CernoConfig, load_config, save_config

_DEFAULT_ALLOWLIST = ["nmap", "nxc", "netexec", "msfconsole", "proxychains4"]


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    """Point the config loader/saver at a throwaway file."""
    path = tmp_path / "config.yaml"
    monkeypatch.setattr(config_mod, "get_config_path", lambda: path)
    return path


@pytest.mark.unit
def test_mcp_exec_allowlist_default():
    assert CernoConfig().mcp_exec_allowlist == _DEFAULT_ALLOWLIST


@pytest.mark.unit
def test_mcp_exec_allowlist_default_is_not_shared():
    """default_factory must give each instance its own list (no shared mutable)."""
    a = CernoConfig()
    b = CernoConfig()
    a.mcp_exec_allowlist.append("sqlmap")
    assert "sqlmap" not in b.mcp_exec_allowlist


@pytest.mark.integration
def test_mcp_exec_allowlist_save_load_roundtrip(config_path):
    assert save_config(CernoConfig(mcp_exec_allowlist=["nmap", "ffuf"]))
    assert load_config().mcp_exec_allowlist == ["nmap", "ffuf"]


@pytest.mark.integration
def test_mcp_exec_allowlist_missing_uses_default(config_path):
    # A config file without the key loads the built-in default.
    config_path.write_text("debug_logging: true\n", encoding="utf-8")
    assert load_config().mcp_exec_allowlist == _DEFAULT_ALLOWLIST


@pytest.mark.unit
def test_mcp_exec_allowlist_csv_coercion_matches_config_set():
    """Mirror the CSV→list coercion used by `cerno config set`."""
    value = " nmap , nxc ,, msfconsole "
    coerced = [s.strip() for s in value.split(",") if s.strip()]
    assert coerced == ["nmap", "nxc", "msfconsole"]
