"""MCP server adherence to user config (``CernoConfig``).

Each wired setting follows one precedence rule: explicit MCP tool argument >
config value > hardcoded default. Adapters are exercised directly against the
in-memory ``temp_db`` fixture with an explicit ``CernoConfig``.
"""

import dataclasses
from pathlib import Path

import pytest
import yaml

from cerno_pkg.config import MCP_NOT_APPLICABLE_KEYS, CernoConfig
from cerno_pkg.mcp_server import server as mcp
from cerno_pkg.models import Finding, Host, Plugin, Port, Scan

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


def _seed_finding(conn, scan_id, plugin_id, hosts, ports, *, severity=2):
    Plugin(
        plugin_id=plugin_id, plugin_name=f"Plugin {plugin_id}", severity_int=severity
    ).save(conn)
    finding_id = Finding(scan_id=scan_id, plugin_id=plugin_id).save(conn)
    for ip in hosts:
        host_id = Host.get_or_create(
            ip_address=ip, scan_target=ip, scan_target_type="ipv4", conn=conn
        )
        for port in ports:
            Port.get_or_create(port, conn=conn)
            conn.execute(
                "INSERT OR IGNORE INTO finding_affected_hosts "
                "(finding_id, host_id, port_number, plugin_output) VALUES (?, ?, ?, 'out')",
                (finding_id, host_id, port),
            )
    conn.commit()
    return finding_id


@pytest.fixture
def seeded(temp_db):
    """One scan with two synthetic (never bundled-mapped) plugins: 100 and 200."""
    scan_id = Scan(scan_name="engagement", export_root="/tmp").save(temp_db)
    f1 = _seed_finding(temp_db, scan_id, 100, ["10.0.0.1"], [445], severity=4)
    f2 = _seed_finding(temp_db, scan_id, 200, ["10.0.0.2"], [22], severity=1)
    return {"conn": temp_db, "scan_id": scan_id, "f1": f1, "f2": f2}


@pytest.fixture
def many(temp_db):
    """One scan with 12 findings (for default-limit tests)."""
    scan_id = Scan(scan_name="big", export_root="/tmp").save(temp_db)
    for pid in range(1000, 1012):
        _seed_finding(temp_db, scan_id, pid, ["10.0.1.1"], [80])
    return {"conn": temp_db, "scan_id": scan_id}


@pytest.fixture
def custom_wf(tmp_path) -> Path:
    """Custom workflow YAML mapping synthetic plugin 100."""
    data = {
        "version": "1.0",
        "workflows": [
            {
                "plugin_id": "100",
                "workflow_name": "Custom 100",
                "description": "custom",
                "steps": [
                    {
                        "title": "Check",
                        "commands": ["nmap -p <PORT> <TARGET>"],
                        "notes": "",
                    }
                ],
                "references": [],
            }
        ],
    }
    path = tmp_path / "custom_workflows.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# custom_workflows_path
# ---------------------------------------------------------------------------


def test_workflow_gaps_drop_custom_mapped_plugin(seeded, custom_wf):
    cfg = CernoConfig(custom_workflows_path=str(custom_wf))
    rows = mcp.tool_list_workflow_gaps(
        scan_ids=[seeded["scan_id"]], config=cfg, conn=seeded["conn"]
    )
    assert [r["plugin_id"] for r in rows] == [200]


def test_workflow_gaps_unset_uses_bundled_only(seeded):
    rows = mcp.tool_list_workflow_gaps(
        scan_ids=[seeded["scan_id"]], config=CernoConfig(), conn=seeded["conn"]
    )
    assert [r["plugin_id"] for r in rows] == [100, 200]


def test_workflow_missing_custom_path_falls_back_to_bundled(seeded, tmp_path):
    cfg = CernoConfig(custom_workflows_path=str(tmp_path / "nope.yaml"))
    rows = mcp.tool_list_workflow_gaps(
        scan_ids=[seeded["scan_id"]], config=cfg, conn=seeded["conn"]
    )
    assert [r["plugin_id"] for r in rows] == [100, 200]


def test_malformed_custom_workflows_never_write_stdout(tmp_path, capsys):
    # stdout is the MCP JSON-RPC channel: mapper warnings must go to stderr.
    from cerno_pkg.workflow_mapper import WorkflowMapper, build_workflow_mapper

    bad = tmp_path / "bad.yaml"
    bad.write_text("workflows:\n  - plugin_id: [unclosed\n", encoding="utf-8")
    mapper = build_workflow_mapper(CernoConfig(custom_workflows_path=str(bad)))
    assert mapper.count() == WorkflowMapper().count()  # bundled set intact
    assert capsys.readouterr().out == ""


def test_query_findings_has_workflow_uses_custom(seeded, custom_wf):
    cfg = CernoConfig(custom_workflows_path=str(custom_wf))
    rows = mcp.tool_query_findings(
        scan_ids=[seeded["scan_id"]], has_workflow=True, config=cfg, conn=seeded["conn"]
    )
    assert [r["plugin_id"] for r in rows] == [100]
    assert rows[0]["has_workflow"] is True


def test_get_workflow_uses_custom(custom_wf):
    cfg = CernoConfig(custom_workflows_path=str(custom_wf))
    wf = mcp.tool_get_workflow(100, config=cfg)
    assert wf is not None and wf["workflow_name"] == "Custom 100"
    assert mcp.tool_get_workflow(100, config=CernoConfig()) is None


def test_resource_and_prompt_use_custom_workflow(seeded, custom_wf):
    cfg = CernoConfig(custom_workflows_path=str(custom_wf))
    text = mcp.resource_finding_workflow(seeded["f1"], conn=seeded["conn"], config=cfg)
    assert text.startswith("# Custom 100")
    prompt = mcp.prompt_triage_finding(seeded["f1"], conn=seeded["conn"], config=cfg)
    assert "Custom 100" in prompt


def test_prepare_workflow_uses_custom(seeded, custom_wf):
    cfg = CernoConfig(custom_workflows_path=str(custom_wf))
    prep = mcp.tool_prepare_workflow(seeded["f1"], config=cfg, conn=seeded["conn"])
    assert prep is not None
    assert prep["steps"][0]["commands"][0]["filled"] == "nmap -p 445 10.0.0.1"
    assert (
        mcp.tool_prepare_workflow(
            seeded["f1"], config=CernoConfig(), conn=seeded["conn"]
        )
        is None
    )


def test_plan_batch_has_workflow_uses_custom(seeded, custom_wf):
    cfg = CernoConfig(custom_workflows_path=str(custom_wf))
    plan = mcp.tool_plan_batch(
        "msf",
        scan_ids=[seeded["scan_id"]],
        has_workflow=True,
        skip_done=False,
        config=cfg,
        conn=seeded["conn"],
    )
    assert [i["plugin_id"] for i in plan["items"]] == [100]


# ---------------------------------------------------------------------------
# default_netexec_protocol
# ---------------------------------------------------------------------------


def _nxc_proto(out: dict) -> str:
    return out["command"][1]


def test_netexec_protocol_defaults_to_smb(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path))
    out = mcp.tool_generate_netexec_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])
    assert _nxc_proto(out) == "smb"


def test_netexec_protocol_from_config(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), default_netexec_protocol="SSH")
    out = mcp.tool_generate_netexec_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])
    assert _nxc_proto(out) == "ssh"


def test_netexec_explicit_protocol_beats_config(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), default_netexec_protocol="ssh")
    out = mcp.tool_generate_netexec_cmd(
        seeded["f1"], "winrm", config=cfg, conn=seeded["conn"]
    )
    assert _nxc_proto(out) == "winrm"


def test_netexec_invalid_config_protocol_names_key(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), default_netexec_protocol="bogus")
    with pytest.raises(ValueError, match="default_netexec_protocol"):
        mcp.tool_generate_netexec_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])


def test_batch_bare_netexec_strategy_uses_config_default(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), default_netexec_protocol="ldap")
    plan = mcp.tool_plan_batch(
        "netexec",
        scan_ids=[seeded["scan_id"]],
        skip_done=False,
        config=cfg,
        conn=seeded["conn"],
    )
    assert plan["items"]
    assert all(i["generated_command"][1] == "ldap" for i in plan["items"])


# ---------------------------------------------------------------------------
# nmap_default_profile
# ---------------------------------------------------------------------------


def _script_arg(cmd: list[str]):
    return next((t for t in cmd if t.startswith("--script=")), None)


def test_nmap_profile_from_config(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), nmap_default_profile="smb")
    out = mcp.tool_generate_nmap_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])
    assert (
        _script_arg(out["command"]) == "--script=smb-security-mode,smb2-security-mode"
    )
    assert "-sU" not in out["command"]


def test_nmap_explicit_nse_option_beats_profile(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), nmap_default_profile="smb")
    out = mcp.tool_generate_nmap_cmd(
        seeded["f1"], nse_option="vuln", config=cfg, conn=seeded["conn"]
    )
    assert _script_arg(out["command"]) == "--script=vuln"


def test_nmap_empty_nse_option_means_no_scripts(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), nmap_default_profile="smb")
    out = mcp.tool_generate_nmap_cmd(
        seeded["f1"], nse_option="", config=cfg, conn=seeded["conn"]
    )
    assert _script_arg(out["command"]) is None


def test_nmap_udp_profile_implies_udp_unless_overridden(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), nmap_default_profile="SNMP")
    out = mcp.tool_generate_nmap_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])
    assert _script_arg(out["command"]) == "--script=snmp*"
    assert "-sU" in out["command"]
    out = mcp.tool_generate_nmap_cmd(
        seeded["f1"], udp=False, config=cfg, conn=seeded["conn"]
    )
    assert "-sU" not in out["command"]


def test_nmap_unknown_profile_means_no_scripts(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path), nmap_default_profile="nonexistent")
    out = mcp.tool_generate_nmap_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])
    assert _script_arg(out["command"]) is None


def test_nmap_no_profile_no_scripts(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path))
    out = mcp.tool_generate_nmap_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])
    assert _script_arg(out["command"]) is None
    assert "-sU" not in out["command"]


# ---------------------------------------------------------------------------
# default_page_size
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["list", "query", "search"])
def test_default_limit_follows_page_size(many, tool):
    conn, sid = many["conn"], many["scan_id"]

    def call(cfg, **kw):
        if tool == "list":
            return mcp.tool_list_findings([sid], config=cfg, conn=conn, **kw)
        if tool == "query":
            return mcp.tool_query_findings(scan_ids=[sid], config=cfg, conn=conn, **kw)
        return mcp.tool_search_findings(config=cfg, conn=conn, **kw)

    assert len(call(CernoConfig())) == 12  # no config -> 500 default
    assert len(call(CernoConfig(default_page_size=9))) == 9
    assert len(call(CernoConfig(default_page_size=3))) == 8  # TUI floor of 8
    assert len(call(CernoConfig(default_page_size=9), limit=2)) == 2  # arg wins


# ---------------------------------------------------------------------------
# Already-honored settings (regression guards)
# ---------------------------------------------------------------------------


def test_results_root_places_mcp_run_dirs_and_artifacts(seeded, tmp_path):
    from cerno_pkg.ops import ExecutionMetadata

    root = tmp_path / "rr"
    cfg = CernoConfig(results_root=str(root), mcp_exec_allowlist=["nmap"])
    out = mcp.tool_generate_nmap_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])
    run_parent = root / "_mcp" / str(seeded["f1"])
    assert Path(out["ips_file"]).parent.parent == run_parent
    assert Path(out["output_base"]).parent.parent == run_parent

    def fake_runner(argv, timeout, proxy):
        base = argv[argv.index("-oA") + 1]
        for ext in (".xml", ".nmap", ".gnmap"):
            Path(base + ext).write_text("<nmaprun/>" if ext == ".xml" else "x")
        return ExecutionMetadata(0, 0.1, False), "", ""

    res = mcp._run_and_record(
        out["command"],
        tool_name="nmap",
        use_proxy=False,
        timeout=10,
        finding_id=seeded["f1"],
        config=cfg,
        conn=seeded["conn"],
        runner=fake_runner,
    )
    paths = [
        r[0]
        for r in seeded["conn"].execute(
            "SELECT artifact_path FROM artifacts WHERE execution_id = ?",
            (res["execution_id"],),
        )
    ]
    assert paths
    assert all(Path(p).is_relative_to(run_parent) for p in paths)


def test_proxychains_config_reaches_runner(seeded):
    cfg = CernoConfig(
        mcp_exec_allowlist=["nmap"],
        proxychains_enabled=True,
        proxychains_host="10.9.9.9",
        proxychains_port=1081,
    )
    seen = {}

    def fake_runner(argv, timeout, proxy):
        from cerno_pkg.ops import ExecutionMetadata

        seen["proxy"] = proxy
        return ExecutionMetadata(0, 0.0, False), "", ""

    mcp._run_and_record(
        ["nmap", "-sT", "10.0.0.1"],
        tool_name="nmap",
        use_proxy=True,
        timeout=10,
        finding_id=None,
        config=cfg,
        conn=seeded["conn"],
        runner=fake_runner,
    )
    assert (seen["proxy"].host, seen["proxy"].port) == ("10.9.9.9", 1081)


def test_nxc_enrichment_disabled_reported_unavailable(monkeypatch):
    from cerno_pkg import config as config_mod
    from cerno_pkg.nxc_db import reset_nxc_manager

    monkeypatch.setattr(
        config_mod, "load_config", lambda: CernoConfig(nxc_enrichment_enabled=False)
    )
    reset_nxc_manager()
    try:
        caps = mcp.tool_get_capabilities(CernoConfig(nxc_enrichment_enabled=False))
        assert caps["nxc_available"] is False
    finally:
        reset_nxc_manager()


# ---------------------------------------------------------------------------
# Workflow contributions: contribution_export_dir + custom_workflows_path
# ---------------------------------------------------------------------------


def _verified_with_run(
    seeded, cfg, command="nmap -p 445 --script smb2-security-mode 10.0.0.1"
):
    from cerno_pkg.models import ToolExecution

    conn, fid = seeded["conn"], seeded["f1"]
    ToolExecution(
        finding_id=fid, tool_name="mcp", command_text=command, exit_code=0
    ).save(conn)
    conn.commit()
    return mcp.tool_set_finding_verdict(fid, "confirmed", conn=conn, config=cfg)


def test_contribution_export_dir_from_config(seeded, tmp_path):
    cfg = CernoConfig(contribution_export_dir=str(tmp_path / "contribs"))
    _verified_with_run(seeded, cfg)
    res = mcp.tool_export_workflow_contribution(
        seeded["f1"], config=cfg, conn=seeded["conn"]
    )
    assert Path(res["path"]).parent == tmp_path / "contribs"


def test_contribution_export_dir_defaults_under_results_root(seeded, tmp_path):
    from cerno_pkg.constants import reset_results_root_cache

    reset_results_root_cache()
    cfg = CernoConfig(results_root=str(tmp_path / "rr"))
    _verified_with_run(seeded, cfg)
    res = mcp.tool_export_workflow_contribution(
        seeded["f1"], config=cfg, conn=seeded["conn"]
    )
    assert Path(res["path"]).parent == tmp_path / "rr" / "contributions"


def test_contribution_hint_uses_custom_workflows(seeded, custom_wf, tmp_path):
    # Unmapped plugin 100 -> "new"; once custom_workflows_path maps it -> "enhanced".
    plain = _verified_with_run(seeded, CernoConfig())
    assert plain["workflow_candidate"] == {"available": True, "reason": "new"}
    custom = mcp.tool_get_finding_verdict(
        seeded["f1"],
        conn=seeded["conn"],
        config=CernoConfig(custom_workflows_path=str(custom_wf)),
    )
    assert custom["workflow_candidate"] == {"available": True, "reason": "enhanced"}


# ---------------------------------------------------------------------------
# Contract: every config key is either applied by the MCP or explicitly N/A
# ---------------------------------------------------------------------------

#: Keys the MCP server honors (directly or via shared code it calls).
MCP_APPLIED = {
    "results_root",
    "log_path",
    "debug_logging",
    "default_page_size",
    "default_netexec_protocol",
    "nmap_default_profile",
    "custom_workflows_path",
    "nxc_workspace_path",
    "nxc_enrichment_enabled",
    "mcp_allow_execution",
    "mcp_allow_mutations",
    "mcp_allow_cred_injection",
    "mcp_allow_cred_reveal",
    "mcp_exec_allowlist",
    "mcp_exec_denylist",
    "mcp_allow_batch",
    "mcp_batch_concurrency",
    "mcp_batch_timeout",
    "mcp_enforce_scope",
    "mcp_scope_extra",
    "contribution_export_dir",
    "proxychains_enabled",
    "proxychains_host",
    "proxychains_port",
}


def test_every_config_key_is_classified_for_mcp():
    fields = {f.name for f in dataclasses.fields(CernoConfig)}
    assert MCP_APPLIED.isdisjoint(MCP_NOT_APPLICABLE_KEYS)
    unclassified = fields - MCP_APPLIED - MCP_NOT_APPLICABLE_KEYS
    assert not unclassified, (
        f"New config key(s) {sorted(unclassified)}: decide whether the MCP server "
        "applies them (wire + add to MCP_APPLIED) or add to "
        "config.MCP_NOT_APPLICABLE_KEYS"
    )
    assert (MCP_APPLIED | MCP_NOT_APPLICABLE_KEYS) == fields
