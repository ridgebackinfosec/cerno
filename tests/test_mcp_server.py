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


@pytest.mark.unit
def test_gating_summary_reflects_flags():
    off = mcp.gating_summary(CernoConfig())
    assert "execution=off" in off and "mutations=off" in off
    assert "reconnect" in off.lower()
    on = mcp.gating_summary(
        CernoConfig(mcp_allow_execution=True, mcp_allow_mutations=True)
    )
    assert "execution=on" in on and "mutations=on" in on


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
    res = mcp.tool_set_review_state(seeded["f1"], "in_progress", conn=seeded["conn"])
    assert res["review_state"] == "in_progress"
    reloaded = Finding.get_by_id(seeded["f1"], seeded["conn"])
    assert reloaded.review_state == "in_progress"


@pytest.mark.integration
def test_set_review_state_full_workflow(seeded):
    for state in ("in_progress", "done", "unreviewed"):
        mcp.tool_set_review_state(seeded["f1"], state, conn=seeded["conn"])
    reloaded = Finding.get_by_id(seeded["f1"], seeded["conn"])
    assert reloaded.review_state == "unreviewed"


@pytest.mark.integration
def test_set_review_state_rejects_skipping_in_progress(seeded):
    with pytest.raises(ValueError, match="in_progress"):
        mcp.tool_set_review_state(seeded["f1"], "done", conn=seeded["conn"])


@pytest.mark.integration
@pytest.mark.parametrize(
    "state", ["bogus", "pending", "reviewed", "completed", "skipped"]
)
def test_set_review_state_invalid_raises(seeded, state):
    with pytest.raises(ValueError):
        mcp.tool_set_review_state(seeded["f1"], state, conn=seeded["conn"])


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_execute_command_captures_and_logs(seeded):
    out = mcp.tool_execute_command(
        ["python3", "-c", "print('hello-mcp')"],
        tool_name="test",
        config=CernoConfig(mcp_exec_allowlist=["python3"]),
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
        ["python3", "-c", "print('x')"],
        tool_name="probe",
        config=CernoConfig(mcp_exec_allowlist=["python3"]),
        conn=seeded["conn"],
    )
    execs = mcp.tool_list_executions(conn=seeded["conn"])
    assert any(e["execution_id"] == out["execution_id"] for e in execs)
    assert execs[0]["tool_name"] == "probe"  # newest first
    # No artifacts logged for this execution -> empty list (not an error)
    assert (
        mcp.tool_list_artifacts(execution_id=out["execution_id"], conn=seeded["conn"])
        == []
    )


# ---------------------------------------------------------------------------
# CVEs / services / msf
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_list_cves(temp_db):
    scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
    Plugin(
        plugin_id=1, plugin_name="A", severity_int=4, cves=["CVE-2021-1", "CVE-2021-2"]
    ).save(temp_db)
    Plugin(plugin_id=2, plugin_name="B", severity_int=2, cves=["CVE-2021-2"]).save(
        temp_db
    )
    Finding(scan_id=scan_id, plugin_id=1).save(temp_db)
    Finding(scan_id=scan_id, plugin_id=2).save(temp_db)
    temp_db.commit()

    cves = mcp.tool_list_cves([scan_id], conn=temp_db)
    by_cve = {c["cve"]: c for c in cves}
    assert set(by_cve) == {"CVE-2021-1", "CVE-2021-2"}
    # CVE-2021-2 shared by both plugins
    assert {p["plugin_id"] for p in by_cve["CVE-2021-2"]["plugins"]} == {1, 2}
    # severity filter keeps only critical plugin's CVEs
    crit = mcp.tool_list_cves([scan_id], severity_int=4, conn=temp_db)
    assert {c["cve"] for c in crit} == {"CVE-2021-1", "CVE-2021-2"}
    assert all(all(p["severity_int"] == 4 for p in c["plugins"]) for c in crit)


@pytest.mark.integration
def test_list_services(temp_db):
    scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
    host_id = Host.get_or_create("10.0.0.1", "10.0.0.1", "ipv4", conn=temp_db)
    Port.get_or_create(445, conn=temp_db)
    temp_db.execute(
        "INSERT INTO host_services (scan_id, host_id, port_number, protocol, svc_name) "
        "VALUES (?, ?, ?, 'tcp', 'cifs')",
        (scan_id, host_id, 445),
    )
    temp_db.commit()

    services = mcp.tool_list_services(scan_id, conn=temp_db)
    assert services == [
        {"host": "10.0.0.1", "port": 445, "protocol": "tcp", "svc_name": "cifs"}
    ]


@pytest.mark.integration
def test_generate_msf_search_uses_module_name(temp_db):
    scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
    Plugin(
        plugin_id=5,
        plugin_name="EternalBlue",
        severity_int=4,
        has_metasploit=True,
        metasploit_names=["ms17_010_eternalblue"],
    ).save(temp_db)
    fid = Finding(scan_id=scan_id, plugin_id=5).save(temp_db)
    temp_db.commit()

    out = mcp.tool_generate_msf_search(fid, conn=temp_db)
    assert out["search_term"] == "ms17_010_eternalblue"
    assert "ms17_010_eternalblue" in out["command"]
    assert out["has_metasploit"] is True


@pytest.mark.integration
def test_generate_msf_search_falls_back_to_plugin_name(temp_db):
    scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
    Plugin(plugin_id=6, plugin_name="SomePlugin", severity_int=2).save(temp_db)
    fid = Finding(scan_id=scan_id, plugin_id=6).save(temp_db)
    temp_db.commit()

    out = mcp.tool_generate_msf_search(fid, conn=temp_db)
    assert out["search_term"] == "SomePlugin"


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_resource_scans_is_json(seeded):
    import json

    data = json.loads(mcp.resource_scans(conn=seeded["conn"]))
    assert data[0]["scan_name"] == "engagement"


@pytest.mark.integration
def test_resource_finding_output(seeded):
    text = mcp.resource_finding_output(seeded["f1"], conn=seeded["conn"])
    assert "Plugin 100" in text
    assert "10.0.0.1:445" in text
    assert "out" in text  # the seeded plugin_output value


@pytest.mark.integration
def test_resource_finding_workflow_none(seeded):
    # No workflow mapped for plugin 100 in the bundled YAML -> notice string.
    text = mcp.resource_finding_workflow(seeded["f1"], conn=seeded["conn"])
    assert "No verification workflow" in text


@pytest.mark.integration
def test_resource_finding_output_unknown_raises(seeded):
    with pytest.raises(ValueError):
        mcp.resource_finding_output(999999, conn=seeded["conn"])


@pytest.mark.integration
def test_resource_scan_cves(temp_db):
    import json

    scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
    Plugin(plugin_id=1, plugin_name="A", severity_int=4, cves=["CVE-2021-1"]).save(
        temp_db
    )
    Finding(scan_id=scan_id, plugin_id=1).save(temp_db)
    temp_db.commit()
    data = json.loads(mcp.resource_scan_cves(scan_id, conn=temp_db))
    assert data[0]["cve"] == "CVE-2021-1"


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_prompt_triage_finding(seeded):
    text = mcp.prompt_triage_finding(seeded["f1"], conn=seeded["conn"])
    assert "Plugin 100" in text  # finding context
    assert "10.0.0.1" in text  # affected host
    assert "past tense" in text  # REPORT_BRIEF_QUERY snippet


@pytest.mark.integration
def test_prompt_exploit_plan(seeded):
    text = mcp.prompt_exploit_plan(seeded["f1"], conn=seeded["conn"])
    assert "Plugin 100" in text
    assert "fastest viable path" in text


@pytest.mark.integration
def test_prompt_triage_scope(seeded):
    text = mcp.prompt_triage_scope(seeded["scan_id"], conn=seeded["conn"])
    assert "engagement" in text  # scope description names the scan
    assert "past tense" in text


@pytest.mark.integration
def test_prompt_unknown_finding_raises(seeded):
    with pytest.raises(ValueError):
        mcp.prompt_triage_finding(999999, conn=seeded["conn"])


# ---------------------------------------------------------------------------
# Resource / prompt registration
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_resources_and_prompts_registered():
    import asyncio

    s = build_server(CernoConfig())
    loop = asyncio.new_event_loop()
    static = {str(r.uri) for r in loop.run_until_complete(s.list_resources())}
    templates = {
        t.uriTemplate for t in loop.run_until_complete(s.list_resource_templates())
    }
    prompts = {p.name for p in loop.run_until_complete(s.list_prompts())}

    assert "cerno://scans" in static
    assert "cerno://finding/{finding_id}/output" in templates
    assert {"triage_finding", "exploit_plan", "triage_scope"} <= prompts


# ---------------------------------------------------------------------------
# CVE reverse lookup
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_find_affected_by_cve_exact_match(temp_db):
    scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
    Plugin(plugin_id=1, plugin_name="A", severity_int=4, cves=["CVE-2021-1"]).save(
        temp_db
    )
    Plugin(plugin_id=2, plugin_name="B", severity_int=2, cves=["CVE-2021-10"]).save(
        temp_db
    )
    f1 = Finding(scan_id=scan_id, plugin_id=1).save(temp_db)
    Finding(scan_id=scan_id, plugin_id=2).save(temp_db)
    host_id = Host.get_or_create("10.0.0.9", "10.0.0.9", "ipv4", conn=temp_db)
    Port.get_or_create(443, conn=temp_db)
    temp_db.execute(
        "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) "
        "VALUES (?, ?, 443, 'x')",
        (f1, host_id),
    )
    temp_db.commit()

    # Case-insensitive, and must NOT match CVE-2021-10
    res = mcp.tool_find_affected_by_cve("cve-2021-1", conn=temp_db)
    assert [r["plugin_id"] for r in res] == [1]
    assert "10.0.0.9:443" in res[0]["hosts"]


@pytest.mark.integration
def test_find_affected_by_cve_scan_filter(temp_db):
    s1 = Scan(scan_name="s1", export_root="/tmp").save(temp_db)
    s2 = Scan(scan_name="s2", export_root="/tmp").save(temp_db)
    Plugin(plugin_id=1, plugin_name="A", severity_int=4, cves=["CVE-2021-1"]).save(
        temp_db
    )
    Finding(scan_id=s1, plugin_id=1).save(temp_db)
    Finding(scan_id=s2, plugin_id=1).save(temp_db)
    temp_db.commit()
    res = mcp.tool_find_affected_by_cve("CVE-2021-1", scan_ids=[s2], conn=temp_db)
    assert [r["scan_id"] for r in res] == [s2]


# ---------------------------------------------------------------------------
# read_artifact
# ---------------------------------------------------------------------------


def _seed_artifact(conn, path, artifact_type_id=1):
    cur = conn.execute(
        "INSERT INTO tool_executions (tool_name, command_text, executed_at, exit_code) "
        "VALUES ('nmap', 'nmap -A', 't', 0)"
    )
    exec_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO artifacts (execution_id, artifact_path, artifact_type_id, created_at) "
        "VALUES (?, ?, ?, 't')",
        (exec_id, str(path), artifact_type_id),
    )
    conn.commit()
    return cur.lastrowid


@pytest.mark.integration
def test_read_artifact_returns_content(temp_db, tmp_path):
    f = tmp_path / "scan.nmap"
    f.write_text("Nmap scan report for 10.0.0.1\n80/tcp open http\n")
    aid = _seed_artifact(temp_db, f)
    out = mcp.tool_read_artifact(aid, conn=temp_db)
    assert out["exists"] is True
    assert "80/tcp open http" in out["content"]
    assert out["truncated"] is False


@pytest.mark.integration
def test_read_artifact_truncates(temp_db, tmp_path):
    f = tmp_path / "big.txt"
    f.write_text("A" * 5000)
    aid = _seed_artifact(temp_db, f)
    out = mcp.tool_read_artifact(aid, max_bytes=1000, conn=temp_db)
    assert out["truncated"] is True
    assert len(out["content"]) == 1000


@pytest.mark.integration
def test_read_artifact_missing_file(temp_db, tmp_path):
    aid = _seed_artifact(temp_db, tmp_path / "gone.txt")
    out = mcp.tool_read_artifact(aid, conn=temp_db)
    assert out["exists"] is False


@pytest.mark.integration
def test_read_artifact_unknown_raises(temp_db):
    with pytest.raises(ValueError):
        mcp.tool_read_artifact(999999, conn=temp_db)


# ---------------------------------------------------------------------------
# get_config
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_get_config_exposes_settings():
    cfg = mcp.tool_get_config()
    assert "mcp_allow_execution" in cfg
    assert "mcp_allow_mutations" in cfg
    assert "results_root_resolved" in cfg


# ---------------------------------------------------------------------------
# NetExec enrichment
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_get_host_nxc_unavailable(monkeypatch):
    import cerno_pkg.nxc_db as nxc_db

    monkeypatch.setattr(nxc_db, "get_nxc_manager", lambda: None)
    out = mcp.tool_get_host_nxc("10.0.0.1")
    assert out["available"] is False


@pytest.mark.integration
def test_get_host_nxc_with_data(monkeypatch):
    import cerno_pkg.nxc_db as nxc_db
    from cerno_pkg.nxc_db import NxcCredential, NxcHostData, NxcSecurityFlags, NxcShare

    data = NxcHostData(
        host_address="10.0.0.5",
        hostname="DC01",
        protocols_seen=["smb"],
        credentials=[NxcCredential(protocol="smb", username="admin", has_admin=True)],
        shares=[NxcShare(name="C$", read_access=True, write_access=True)],
        security_flags=NxcSecurityFlags(signing_required=False),
    )

    class FakeMgr:
        def get_host_enrichment(self, ip):
            return data if ip == "10.0.0.5" else None

    monkeypatch.setattr(nxc_db, "get_nxc_manager", lambda: FakeMgr())
    out = mcp.tool_get_host_nxc("10.0.0.5")
    assert out["available"] is True and out["found"] is True
    assert out["credentials"][0]["username"] == "admin"
    assert out["shares"][0]["name"] == "C$"
    assert out["security_flags"]["signing_required"] is False


# ---------------------------------------------------------------------------
# New resources / output schema registration
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_new_resources_registered():
    s = build_server(CernoConfig())
    loop = asyncio.new_event_loop()
    static = {str(r.uri) for r in loop.run_until_complete(s.list_resources())}
    templates = {
        t.uriTemplate for t in loop.run_until_complete(s.list_resource_templates())
    }
    assert "cerno://config" in static
    assert "cerno://host/{host_ip}/nxc" in templates


@pytest.mark.integration
def test_core_read_tools_have_output_schema():
    s = build_server(CernoConfig())
    loop = asyncio.new_event_loop()
    tools = {t.name: t for t in loop.run_until_complete(s.list_tools())}
    for name in [
        "list_scans",
        "list_findings",
        "get_finding_detail",
        "list_services",
        "list_cves",
    ]:
        assert tools[name].outputSchema is not None


# ---------------------------------------------------------------------------
# New: paging / truncation / merged / search / prioritization / capabilities
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_list_findings_limit_and_offset(seeded):
    first = mcp.tool_list_findings([seeded["scan_id"]], limit=1, conn=seeded["conn"])
    assert len(first) == 1
    second = mcp.tool_list_findings(
        [seeded["scan_id"]], limit=1, offset=1, conn=seeded["conn"]
    )
    assert len(second) == 1
    assert first[0]["plugin_id"] != second[0]["plugin_id"]


@pytest.mark.integration
def test_list_findings_merged_dedups_by_plugin(temp_db):
    # Same plugin present in two scans → merged yields one representative row.
    s1 = Scan(scan_name="s1", export_root="/tmp").save(temp_db)
    s2 = Scan(scan_name="s2", export_root="/tmp").save(temp_db)
    _seed_finding(temp_db, s1, 500, ["10.0.0.1"], [445], severity=4)
    _seed_finding(temp_db, s2, 500, ["10.0.0.2"], [445], severity=4)
    concat = mcp.tool_list_findings([s1, s2], conn=temp_db)
    assert len(concat) == 2  # two distinct finding_ids
    merged = mcp.tool_list_findings([s1, s2], merged=True, conn=temp_db)
    assert len(merged) == 1
    assert merged[0]["plugin_id"] == 500


@pytest.mark.integration
def test_get_finding_detail_truncates(seeded):
    full = mcp.tool_get_finding_detail(seeded["f1"], conn=seeded["conn"])
    assert full["affected_total"] == 2
    assert full["affected_truncated"] is False
    capped = mcp.tool_get_finding_detail(seeded["f1"], max_hosts=1, conn=seeded["conn"])
    assert len(capped["affected"]) == 1
    assert capped["affected_total"] == 2
    assert capped["affected_truncated"] is True


@pytest.mark.integration
def test_search_findings_cross_scan(seeded):
    hits = mcp.tool_search_findings(severity_int=4, conn=seeded["conn"])
    assert [h["plugin_id"] for h in hits] == [100]
    assert hits[0]["scan_name"] == "engagement"
    none = mcp.tool_search_findings(plugin_name="no-such-plugin", conn=seeded["conn"])
    assert none == []


@pytest.mark.integration
def test_search_findings_limit(seeded):
    assert len(mcp.tool_search_findings(limit=1, conn=seeded["conn"])) == 1


@pytest.mark.integration
def test_top_hosts_orders_by_severity(seeded):
    hosts = mcp.tool_top_hosts(limit=10, conn=seeded["conn"])
    assert hosts  # at least the seeded hosts
    sevs = [h.get("max_severity") or -1 for h in hosts]
    assert sevs == sorted(sevs, reverse=True)


@pytest.mark.integration
def test_execute_command_allowlist_rejects_unlisted(seeded):
    with pytest.raises(ValueError, match="allowlist"):
        mcp.tool_execute_command(
            ["python3", "-c", "print(1)"],
            config=CernoConfig(mcp_exec_allowlist=["nmap"]),
            conn=seeded["conn"],
        )


@pytest.mark.integration
def test_execute_command_empty_allowlist_falls_back_to_default(seeded):
    # Empty list ⇒ built-in default set, which does NOT include python3.
    with pytest.raises(ValueError, match="allowlist"):
        mcp.tool_execute_command(
            ["python3", "-c", "print(1)"],
            config=CernoConfig(mcp_exec_allowlist=[]),
            conn=seeded["conn"],
        )


@pytest.mark.integration
def test_execute_command_timeout_clamped(seeded):
    # Huge timeout is accepted (clamped internally) and the run still succeeds.
    out = mcp.tool_execute_command(
        ["python3", "-c", "print('ok')"],
        timeout=10_000_000,
        config=CernoConfig(mcp_exec_allowlist=["python3"]),
        conn=seeded["conn"],
    )
    assert out["exit_code"] == 0


@pytest.mark.integration
def test_execute_command_attributes_finding_and_get_finding_artifacts(seeded):
    out = mcp.tool_execute_command(
        ["python3", "-c", "print('hi')"],
        tool_name="probe",
        finding_id=seeded["f1"],
        config=CernoConfig(mcp_exec_allowlist=["python3"]),
        conn=seeded["conn"],
    )
    row = (
        seeded["conn"]
        .execute(
            "SELECT finding_id FROM tool_executions WHERE execution_id = ?",
            (out["execution_id"],),
        )
        .fetchone()
    )
    assert row["finding_id"] == seeded["f1"]
    # No artifacts logged for this run → empty list (not an error).
    assert mcp.tool_get_finding_artifacts(seeded["f1"], conn=seeded["conn"]) == []


@pytest.mark.unit
def test_get_capabilities_reports_flags_and_allowlist():
    caps = mcp.tool_get_capabilities(
        CernoConfig(mcp_allow_execution=True, mcp_exec_allowlist=["nmap", "nxc"])
    )
    assert caps["execution_enabled"] is True
    assert caps["mutations_enabled"] is False
    assert caps["exec_allowlist"] == ["nmap", "nxc"]
    assert "nxc_available" in caps


@pytest.mark.integration
def test_triage_scope_multi_scan(temp_db):
    s1 = Scan(scan_name="alpha", export_root="/tmp").save(temp_db)
    s2 = Scan(scan_name="beta", export_root="/tmp").save(temp_db)
    _seed_finding(temp_db, s1, 700, ["10.0.0.1"], [445], severity=4)
    _seed_finding(temp_db, s2, 800, ["10.0.0.2"], [22], severity=3)
    text = mcp.prompt_triage_scope([s1, s2], conn=temp_db)
    assert "alpha" in text and "beta" in text
