"""Tests for CernoConfig fields, focused on the MCP exec allow/deny lists."""

import pytest

import cerno_pkg.config as config_mod
from cerno_pkg.config import (
    DEFAULT_MCP_EXEC_ALLOWLIST,
    DEFAULT_MCP_EXEC_DENYLIST,
    CernoConfig,
    coerce_str_list,
    load_config,
    save_config,
)

_DEFAULT_ALLOWLIST = list(DEFAULT_MCP_EXEC_ALLOWLIST)
_DEFAULT_DENYLIST = list(DEFAULT_MCP_EXEC_DENYLIST)


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
def test_claude_assistant_disabled_by_default():
    assert CernoConfig().claude_assistant_enabled is False


@pytest.mark.integration
def test_claude_assistant_default_persists_false(config_path):
    # A config file without the key loads the opt-in default (off).
    config_path.write_text("debug_logging: true\n", encoding="utf-8")
    assert load_config().claude_assistant_enabled is False


@pytest.mark.unit
def test_default_allowlist_drops_proxychains():
    # proxychains4 is unwrapped (and covered by use_proxy), so it needs no entry.
    assert "proxychains4" not in _DEFAULT_ALLOWLIST


@pytest.mark.unit
def test_mcp_exec_denylist_default():
    cfg = CernoConfig()
    assert cfg.mcp_exec_denylist == _DEFAULT_DENYLIST
    assert "rm" in cfg.mcp_exec_denylist


@pytest.mark.unit
def test_mcp_exec_denylist_default_is_not_shared():
    a = CernoConfig()
    b = CernoConfig()
    a.mcp_exec_denylist.append("curl")
    assert "curl" not in b.mcp_exec_denylist


@pytest.mark.integration
def test_mcp_exec_denylist_save_load_roundtrip(config_path):
    assert save_config(CernoConfig(mcp_exec_denylist=["rm", "sh"]))
    assert load_config().mcp_exec_denylist == ["rm", "sh"]


@pytest.mark.integration
def test_mcp_exec_denylist_missing_uses_default(config_path):
    config_path.write_text("debug_logging: true\n", encoding="utf-8")
    assert load_config().mcp_exec_denylist == _DEFAULT_DENYLIST


@pytest.mark.integration
def test_empty_allowlist_persists_as_empty(config_path):
    # Empty means deny-all now, so it must not be replaced by the default on load.
    assert save_config(CernoConfig(mcp_exec_allowlist=[]))
    assert load_config().mcp_exec_allowlist == []


@pytest.mark.integration
def test_scalar_yaml_allowlist_is_coerced_to_list(config_path):
    # A hand-edited scalar must become a list, not stay a str (substring matching).
    config_path.write_text(
        "mcp_exec_allowlist: nmap,nxc\nmcp_exec_denylist: '*'\n", encoding="utf-8"
    )
    cfg = load_config()
    assert cfg.mcp_exec_allowlist == ["nmap", "nxc"]
    assert cfg.mcp_exec_denylist == ["*"]


@pytest.mark.unit
@pytest.mark.parametrize(
    "value, expected",
    [
        (" nmap , nxc ,, msfconsole ", ["nmap", "nxc", "msfconsole"]),
        ("*", ["*"]),
        ("", []),
        ([" nmap ", "", "nxc"], ["nmap", "nxc"]),
        (("a", "b"), ["a", "b"]),
        (None, ["dflt"]),
        (42, ["dflt"]),
    ],
)
def test_coerce_str_list(value, expected):
    assert coerce_str_list(value, ("dflt",)) == expected
