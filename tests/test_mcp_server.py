"""Tests for the Cerno MCP server (cerno_pkg.mcp_server).

Adapter functions are exercised directly with the in-memory ``temp_db`` fixture
(no stdio round-trip). ``build_server`` is checked for correct tool gating.
"""

import asyncio

import pytest

from cerno_pkg.config import CernoConfig
from cerno_pkg.models import Finding, Host, Plugin, Port, Scan
from cerno_pkg.mcp_server import build_server, server as mcp

# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


def _seed_finding(conn, scan_id, plugin_id, hosts, ports, *, has_msf=False, severity=2):
    Plugin(
        plugin_id=plugin_id,
        plugin_name=f"Plugin {plugin_id}",
        severity_int=severity,
        has_metasploit=has_msf,
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
    """One scan, two findings with hosts/ports."""
    scan_id = Scan(scan_name="engagement", export_root="/tmp").save(temp_db)
    f1 = _seed_finding(
        temp_db, scan_id, 100, ["10.0.0.1", "10.0.0.2"], [445], has_msf=True, severity=4
    )
    f2 = _seed_finding(temp_db, scan_id, 200, ["10.0.0.1"], [22], severity=1)
    return {"conn": temp_db, "scan_id": scan_id, "f1": f1, "f2": f2}


# ---------------------------------------------------------------------------
# Gating
# ---------------------------------------------------------------------------


def _tool_names(config):
    srv = build_server(config)
    tools = asyncio.new_event_loop().run_until_complete(srv.list_tools())
    return sorted(t.name for t in tools)


@pytest.mark.integration
def test_readonly_omits_execution_and_mutation_tools():
    names = _tool_names(CernoConfig())
    assert "execute_command" not in names
    assert "set_review_state" not in names
    assert "import_nessus" not in names
    assert "list_scans" in names
    assert "generate_nmap_cmd" in names


@pytest.mark.integration
def test_flags_enable_gated_tools():
    names = _tool_names(CernoConfig(mcp_allow_execution=True, mcp_allow_mutations=True))
    assert "execute_command" in names
    assert "set_review_state" in names
    assert "import_nessus" in names


@pytest.mark.integration
def test_execution_flag_is_independent_of_mutation_flag():
    exec_only = _tool_names(CernoConfig(mcp_allow_execution=True))
    assert "execute_command" in exec_only
    assert "set_review_state" not in exec_only


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_list_scans(seeded):
    scans = mcp.tool_list_scans(conn=seeded["conn"])
    assert len(scans) == 1
    assert scans[0]["scan_name"] == "engagement"
    assert scans[0]["total_findings"] == 2


@pytest.mark.integration
def test_list_findings_all(seeded):
    findings = mcp.tool_list_findings([seeded["scan_id"]], conn=seeded["conn"])
    assert {f["plugin_id"] for f in findings} == {100, 200}


@pytest.mark.integration
def test_list_findings_severity_filter(seeded):
    crit = mcp.tool_list_findings(
        [seeded["scan_id"]], severity_int=4, conn=seeded["conn"]
    )
    assert [f["plugin_id"] for f in crit] == [100]
    assert crit[0]["has_metasploit"] is True


@pytest.mark.integration
def test_list_findings_metasploit_filter(seeded):
    msf = mcp.tool_list_findings(
        [seeded["scan_id"]], has_metasploit=True, conn=seeded["conn"]
    )
    assert [f["plugin_id"] for f in msf] == [100]


@pytest.mark.integration
def test_get_finding_hosts(seeded):
    data = mcp.tool_get_finding_hosts(seeded["f1"], conn=seeded["conn"])
    assert set(data["hosts"]) == {"10.0.0.1", "10.0.0.2"}
    assert data["ports"] == "445"
    assert data["target_lines"]


@pytest.mark.integration
def test_get_finding_hosts_unknown_raises(seeded):
    with pytest.raises(ValueError):
        mcp.tool_get_finding_hosts(999999, conn=seeded["conn"])


@pytest.mark.integration
def test_get_workflow_unknown_returns_none():
    assert mcp.tool_get_workflow(999999999) is None


# ---------------------------------------------------------------------------
# Command generation
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_generate_nmap_cmd_writes_targets(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path))
    out = mcp.tool_generate_nmap_cmd(seeded["f1"], config=cfg, conn=seeded["conn"])
    assert out["command"][0] == "nmap" or out["command"][:2] == ["sudo", "nmap"]
    assert "-p" in out["command"]
    assert "445" in out["command"]
    # IPs file written with the finding's hosts
    with open(out["ips_file"]) as fh:
        written = fh.read().split()
    assert set(written) == {"10.0.0.1", "10.0.0.2"}


@pytest.mark.integration
def test_generate_netexec_cmd(seeded, tmp_path):
    cfg = CernoConfig(results_root=str(tmp_path))
    out = mcp.tool_generate_netexec_cmd(
        seeded["f1"], "smb", config=cfg, conn=seeded["conn"]
    )
    assert "smb" in out["command"]
    assert out["relay_path"]  # smb produces a relay list path


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_set_review_state(seeded):
    res = mcp.tool_set_review_state(seeded["f1"], "completed", conn=seeded["conn"])
    assert res["review_state"] == "completed"
    reloaded = Finding.get_by_id(seeded["f1"], seeded["conn"])
    assert reloaded.review_state == "completed"


@pytest.mark.integration
def test_set_review_state_invalid_raises(seeded):
    with pytest.raises(ValueError):
        mcp.tool_set_review_state(seeded["f1"], "bogus", conn=seeded["conn"])


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_execute_command_captures_and_logs(seeded):
    out = mcp.tool_execute_command(
        ["python3", "-c", "print('hello-mcp')"],
        tool_name="test",
        conn=seeded["conn"],
    )
    assert out["exit_code"] == 0
    assert "hello-mcp" in out["stdout"]
    assert out["execution_id"] is not None
    # Logged to tool_executions
    row = (
        seeded["conn"]
        .execute(
            "SELECT tool_name FROM tool_executions WHERE execution_id = ?",
            (out["execution_id"],),
        )
        .fetchone()
    )
    assert row["tool_name"] == "test"


@pytest.mark.integration
def test_execute_command_empty_raises(seeded):
    with pytest.raises(ValueError):
        mcp.tool_execute_command([], conn=seeded["conn"])


# ---------------------------------------------------------------------------
# Detail / inventory / history tools
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_get_finding_detail(seeded):
    detail = mcp.tool_get_finding_detail(seeded["f1"], conn=seeded["conn"])
    assert detail["plugin_id"] == 100
    assert detail["severity_label"] == "Critical"
    assert detail["has_metasploit"] is True
    # per-host plugin output present
    assert detail["affected"]
    assert all("plugin_output" in a for a in detail["affected"])
    hosts = {a["host"] for a in detail["affected"]}
    assert hosts == {"10.0.0.1", "10.0.0.2"}


@pytest.mark.integration
def test_get_finding_detail_unknown_raises(seeded):
    with pytest.raises(ValueError):
        mcp.tool_get_finding_detail(999999, conn=seeded["conn"])


@pytest.mark.integration
def test_list_hosts_cross_scan(seeded):
    hosts = mcp.tool_list_hosts(conn=seeded["conn"])
    ips = {h["ip_address"] for h in hosts}
    assert {"10.0.0.1", "10.0.0.2"} <= ips
    # 10.0.0.1 is affected by both findings
    h1 = next(h for h in hosts if h["ip_address"] == "10.0.0.1")
    assert h1["finding_count"] == 2
    assert h1["max_severity"] == 4


@pytest.mark.integration
def test_list_hosts_scoped_to_scan(seeded):
    hosts = mcp.tool_list_hosts(scan_id=seeded["scan_id"], conn=seeded["conn"])
    assert {h["ip_address"] for h in hosts} == {"10.0.0.1", "10.0.0.2"}


@pytest.mark.integration
def test_check_tools_shape():
    result = mcp.tool_check_tools()
    assert set(result) == {"nmap", "netexec", "msfconsole", "proxychains4"}
    for entry in result.values():
        assert "installed" in entry and "version" in entry
        assert isinstance(entry["installed"], bool)


@pytest.mark.integration
def test_list_executions_and_artifacts(seeded):
    # Produce one execution to list
    out = mcp.tool_execute_command(
        ["python3", "-c", "print('x')"], tool_name="probe", conn=seeded["conn"]
    )
    execs = mcp.tool_list_executions(conn=seeded["conn"])
    assert any(e["execution_id"] == out["execution_id"] for e in execs)
    assert execs[0]["tool_name"] == "probe"  # newest first
    # No artifacts logged for this execution -> empty list (not an error)
    assert (
        mcp.tool_list_artifacts(execution_id=out["execution_id"], conn=seeded["conn"])
        == []
    )
