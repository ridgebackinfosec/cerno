"""Cross-interface contract tests for the Cerno MCP server.

These guard the TUI <-> MCP boundary: the MCP tools/resources/prompts are thin
adapters over the same functions the TUI uses, so a change to a shared function
can break MCP (or vice versa). Unlike ``test_mcp_server.py`` (which calls the
adapter functions directly), this module drives the **real MCP path**
(``call_tool`` / ``read_resource`` / ``get_prompt``) against a seeded on-disk
database, with ``DATABASE_PATH`` monkeypatched so nothing touches the user's
``~/.cerno``.

If you intentionally change the MCP surface, update ``EXPECTED_TOOLS`` /
``EXPECTED_*`` below in the same PR — that failure is the tripwire working.
"""

import asyncio
import sqlite3

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import cerno_pkg.database as database
from cerno_pkg.config import CernoConfig
from cerno_pkg.constants import reset_results_root_cache
from cerno_pkg.mcp_server import build_server, server as mcp
from cerno_pkg.models import Finding, Host, Plugin, Port, Scan

# ---------------------------------------------------------------------------
# Frozen MCP surface (tripwire). Update deliberately when changing the server.
# ---------------------------------------------------------------------------

EXPECTED_TOOLS = {
    # read (always on)
    "list_scans",
    "list_findings",
    "get_finding_detail",
    "get_finding_hosts",
    "list_hosts",
    "list_services",
    "get_web_targets",
    "list_cves",
    "find_affected_by_cve",
    "host_history",
    "compare_scans",
    "get_workflow",
    "check_tools",
    "list_executions",
    "list_artifacts",
    "read_artifact",
    "get_config",
    "search_findings",
    "query_findings",
    "top_hosts",
    "get_capabilities",
    "get_finding_artifacts",
    "get_finding_verdict",
    "list_workflow_gaps",
    "get_notes",
    "get_workflow_candidate",
    "export_workflow_contribution",  # writes a local sanitized file only
    # netexec (always on)
    "get_host_nxc",
    "list_nxc_credentials",
    # generate (always on)
    "generate_nmap_cmd",
    "generate_netexec_cmd",
    "generate_msf_search",
    "prepare_workflow",
    "plan_batch",
    # gated
    "execute_command",  # mcp_allow_execution
    "start_execution",  # mcp_allow_execution
    "get_execution_status",  # mcp_allow_execution
    "cancel_execution",  # mcp_allow_execution
    "list_jobs",  # mcp_allow_execution
    "execute_batch",  # mcp_allow_execution AND mcp_allow_batch
    "set_review_state",
    "add_note",  # mcp_allow_mutations
    "import_nessus",  # mcp_allow_mutations
    "ingest_results",  # mcp_allow_mutations
    "set_finding_verdict",  # mcp_allow_mutations
    "reveal_credential",  # mcp_allow_cred_reveal
}
EXPECTED_STATIC_RESOURCES = {"cerno://scans", "cerno://config"}
EXPECTED_RESOURCE_TEMPLATES = {
    "cerno://scan/{scan_id}/hosts",
    "cerno://scan/{scan_id}/cves",
    "cerno://finding/{finding_id}/output",
    "cerno://finding/{finding_id}/workflow",
    "cerno://finding/{finding_id}/verdict",
    "cerno://finding/{finding_id}/results",
    "cerno://host/{host_ip}/nxc",
}
EXPECTED_PROMPTS = {"triage_finding", "exploit_plan", "triage_scope"}


# ---------------------------------------------------------------------------
# Seeded on-disk DB + server, with DATABASE_PATH pointed at it
# ---------------------------------------------------------------------------


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(database.SCHEMA_SQL_TABLES)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executemany(
        "INSERT INTO severity_levels VALUES (?, ?, ?, ?)",
        [
            (4, "Critical", 4, "#8B0000"),
            (3, "High", 3, "#FF4500"),
            (2, "Medium", 2, "#FFA500"),
            (1, "Low", 1, "#FFD700"),
            (0, "Info", 0, "#4682B4"),
        ],
    )
    conn.executemany(
        "INSERT INTO artifact_types (type_name, file_extension, description) VALUES (?, ?, ?)",
        [("nmap_xml", ".xml", "Nmap XML output"), ("log", ".log", "Tool log")],
    )
    conn.executemany(
        "INSERT INTO verdict_types (label, description) VALUES (?, ?)",
        [
            ("confirmed", "true positive"),
            ("false_positive", "false positive"),
            ("unable", "unable to verify"),
        ],
    )
    conn.executemany(
        "INSERT INTO nse_verdicts (label) VALUES (?)",
        [("VULNERABLE",), ("NOT_VULNERABLE",), ("LIKELY_VULNERABLE",), ("UNKNOWN",)],
    )
    conn.executemany(
        "INSERT INTO port_states (label) VALUES (?)",
        [
            ("open",),
            ("closed",),
            ("filtered",),
            ("open|filtered",),
            ("closed|filtered",),
            ("unfiltered",),
        ],
    )
    conn.executescript(database.SCHEMA_SQL_VIEWS)
    conn.commit()


@pytest.fixture
def contract(tmp_path, monkeypatch):
    """Seed an on-disk DB, point DATABASE_PATH at it, build a fully-gated server."""
    dbfile = tmp_path / "cerno.db"
    conn = sqlite3.connect(str(dbfile))
    _init_schema(conn)

    scan_id = Scan(scan_name="engagement", export_root=str(tmp_path)).save(conn)
    Scan(scan_name="baseline", export_root=str(tmp_path)).save(conn)
    Plugin(
        plugin_id=100,
        plugin_name="SMB Signing",
        severity_int=4,
        has_metasploit=True,
        cves=["CVE-2021-1"],
        metasploit_names=["ms17_010"],
    ).save(conn)
    finding_id = Finding(scan_id=scan_id, plugin_id=100).save(conn)
    host_id = Host.get_or_create("10.0.0.1", "10.0.0.1", "ipv4", conn=conn)
    Port.get_or_create(445, conn=conn)
    conn.execute(
        "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) "
        "VALUES (?, ?, 445, 'Signing: disabled')",
        (finding_id, host_id),
    )
    conn.execute(
        "INSERT INTO host_services (scan_id, host_id, port_number, protocol, svc_name) "
        "VALUES (?, ?, 445, 'tcp', 'cifs')",
        (scan_id, host_id),
    )
    cur = conn.execute(
        "INSERT INTO tool_executions (tool_name, command_text, executed_at, exit_code) "
        "VALUES ('nmap', 'nmap -A', 't', 0)"
    )
    exec_id = cur.lastrowid
    # An attributed, successful run so the workflow-contribution loop has a trail.
    conn.execute(
        "INSERT INTO tool_executions (finding_id, tool_name, command_text, executed_at, exit_code) "
        "VALUES (?, 'mcp', 'nmap -p 445 --script smb2-security-mode 10.0.0.1', 't', 0)",
        (finding_id,),
    )
    artifact_file = tmp_path / "scan.nmap"
    artifact_file.write_text(
        "Nmap scan report for 10.0.0.1\n445/tcp open microsoft-ds\n"
    )
    cur = conn.execute(
        "INSERT INTO artifacts (execution_id, artifact_path, artifact_type_id, created_at) "
        "VALUES (?, ?, 1, 't')",
        (exec_id, str(artifact_file)),
    )
    artifact_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Point the production connection path at the seeded DB.
    monkeypatch.setattr(database, "DATABASE_PATH", dbfile)
    reset_results_root_cache()

    cfg = CernoConfig(
        results_root=str(tmp_path / "artifacts"),
        mcp_allow_execution=True,
        mcp_allow_mutations=True,
        mcp_allow_cred_reveal=True,
        mcp_allow_batch=True,
    )
    srv = build_server(cfg)
    return {
        "server": srv,
        "scan_id": scan_id,
        "finding_id": finding_id,
        "plugin_id": 100,
        "artifact_id": artifact_id,
        "execution_id": exec_id,
        "host_ip": "10.0.0.1",
    }


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _client_call_tools(server, calls: dict[str, dict]) -> dict:
    """Call tools through a real in-memory client session.

    Unlike ``FastMCP.call_tool()``, this goes through the low-level server's
    request handler, which validates ``structuredContent`` against each tool's
    output schema — the path real MCP clients (e.g. Claude CLI) hit.
    """

    async def go():
        async with create_connected_server_and_client_session(
            server._mcp_server
        ) as session:
            return {
                name: await session.call_tool(name, kw) for name, kw in calls.items()
            }

    return _run(go())


# ---------------------------------------------------------------------------
# Inventory tripwire
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_mcp_inventory_frozen(contract):
    s = contract["server"]
    tools = {t.name for t in _run(s.list_tools())}
    statics = {str(r.uri) for r in _run(s.list_resources())}
    templates = {t.uriTemplate for t in _run(s.list_resource_templates())}
    prompts = {p.name for p in _run(s.list_prompts())}

    assert (
        tools == EXPECTED_TOOLS
    ), f"MCP tool surface changed: {tools ^ EXPECTED_TOOLS}"
    assert statics == EXPECTED_STATIC_RESOURCES
    assert templates == EXPECTED_RESOURCE_TEMPLATES
    assert prompts == EXPECTED_PROMPTS


# ---------------------------------------------------------------------------
# Call-through: every non-side-effecting tool via the real MCP path
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_tools_callable_through_server(contract):
    s = contract["server"]
    fid, sid, aid, ip = (
        contract["finding_id"],
        contract["scan_id"],
        contract["artifact_id"],
        contract["host_ip"],
    )
    args = {
        "list_scans": {},
        "list_findings": {"scan_ids": [sid]},
        "query_findings": {"scan_ids": [sid], "severity_int": 4, "has_metasploit": True},
        "plan_batch": {"strategy": "nmap", "scan_ids": [sid], "skip_done": False},
        "get_finding_detail": {"finding_id": fid},
        "get_finding_hosts": {"finding_id": fid},
        "list_hosts": {},
        "list_services": {"scan_id": sid},
        "get_web_targets": {"scan_id": sid},
        "list_cves": {"scan_ids": [sid]},
        "find_affected_by_cve": {"cve": "CVE-2021-1"},
        "host_history": {"host_ip": ip},
        "compare_scans": {"scan1_name": "baseline", "scan2_name": "engagement"},
        "get_workflow": {"plugin_id": contract["plugin_id"]},
        "check_tools": {},
        "list_executions": {},
        "list_artifacts": {},
        "read_artifact": {"artifact_id": aid},
        "get_config": {},
        "get_host_nxc": {"host_ip": ip},
        "list_nxc_credentials": {},
        "generate_nmap_cmd": {"finding_id": fid},
        "generate_netexec_cmd": {"finding_id": fid, "protocol": "smb"},
        "generate_msf_search": {"finding_id": fid},
        "prepare_workflow": {"finding_id": fid},
        "get_finding_verdict": {"finding_id": fid},
        "list_workflow_gaps": {"scan_ids": [sid]},
        "get_notes": {"finding_id": fid},
        # mutations (safe against the seeded temp DB)
        "set_review_state": {"finding_id": fid, "new_state": "in_progress"},
        "add_note": {"finding_id": fid, "note": "t"},
        "set_finding_verdict": {"finding_id": fid, "verdict": "confirmed"},
        "ingest_results": {"execution_id": contract["execution_id"]},
        # after set_finding_verdict (export requires a verified finding)
        "get_workflow_candidate": {"finding_id": fid},
        "export_workflow_contribution": {"finding_id": fid},
    }
    # execute_command + the async job tools (start/get/cancel/list_jobs are
    # subprocess/async) and import_nessus (needs a file) are covered by the
    # inventory test + test_mcp_server.py/test_jobs.py; exercising them here would
    # add platform/side-effect flakiness.
    for name, result in _client_call_tools(s, args).items():
        detail = result.content[0].text if result.content else ""
        assert not result.isError, f"{name} failed via MCP client: {detail}"


@pytest.mark.integration
def test_generate_tools_structured_output(contract):
    """Each generate_* tool returns exactly its own keys, with no nulls for
    required fields (regression: a shared total=False TypedDict made FastMCP
    emit absent keys as null, failing output validation)."""
    s, fid = contract["server"], contract["finding_id"]
    results = _client_call_tools(
        s,
        {
            "generate_nmap_cmd": {"finding_id": fid, "nse_option": "smb-security-mode"},
            "generate_netexec_cmd": {"finding_id": fid, "protocol": "smb"},
            "generate_msf_search": {"finding_id": fid},
        },
    )
    nmap = results["generate_nmap_cmd"].structuredContent
    assert set(nmap) == {"command", "ips_file", "output_base"}
    assert isinstance(nmap["command"], list) and "nmap" in nmap["command"]
    # Bare NSE script name must arrive with its --script flag (runnable argv).
    assert "--script=smb-security-mode" in nmap["command"]
    assert "smb-security-mode" not in nmap["command"]
    assert nmap["ips_file"].endswith("targets.txt")

    nxc = results["generate_netexec_cmd"].structuredContent
    assert set(nxc) == {"command", "ips_file", "log_path", "relay_path"}
    assert isinstance(nxc["command"], list) and isinstance(nxc["log_path"], str)

    msf = results["generate_msf_search"].structuredContent
    assert set(msf) == {"command", "search_term", "has_metasploit", "metasploit_names"}
    assert msf["search_term"] == "ms17_010" and msf["has_metasploit"] is True


@pytest.mark.integration
def test_workflow_contribution_structured_output(contract):
    """Verdict hint + candidate + export round-trip through the real MCP path
    (output-schema validated), and the exported file carries no host data."""
    s, fid = contract["server"], contract["finding_id"]
    results = _client_call_tools(
        s,
        {
            "set_finding_verdict": {"finding_id": fid, "verdict": "confirmed"},
            "get_finding_verdict": {"finding_id": fid},
            "get_workflow_candidate": {"finding_id": fid},
            "export_workflow_contribution": {"finding_id": fid},
        },
    )
    for name, result in results.items():
        detail = result.content[0].text if result.content else ""
        assert not result.isError, f"{name} failed: {detail}"

    hint = {"available": True, "reason": "new"}
    assert results["set_finding_verdict"].structuredContent["workflow_candidate"] == hint
    assert results["get_finding_verdict"].structuredContent["workflow_candidate"] == hint

    cand = results["get_workflow_candidate"].structuredContent
    assert cand["exportable"] is True and cand["leak_warnings"] == []
    assert cand["workflow"]["steps"][0]["commands"] == [
        "nmap -p <PORT> --script smb2-security-mode <TARGET>"
    ]

    export = results["export_workflow_contribution"].structuredContent
    assert set(export) == {"path", "reason", "plugin_id", "submission_instructions"}
    text = open(export["path"], encoding="utf-8").read()
    assert "10.0.0.1" not in text and "develop" in export["submission_instructions"]


# ---------------------------------------------------------------------------
# Call-through: resources and prompts
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_resources_readable_through_server(contract):
    s = contract["server"]
    sid, fid, ip = contract["scan_id"], contract["finding_id"], contract["host_ip"]
    uris = [
        "cerno://scans",
        "cerno://config",
        f"cerno://scan/{sid}/hosts",
        f"cerno://scan/{sid}/cves",
        f"cerno://finding/{fid}/output",
        f"cerno://finding/{fid}/workflow",
        f"cerno://host/{ip}/nxc",
    ]
    for uri in uris:
        result = list(_run(s.read_resource(uri)))
        assert result, f"{uri} returned no contents"


@pytest.mark.integration
def test_prompts_renderable_through_server(contract):
    s = contract["server"]
    fid, sid = contract["finding_id"], contract["scan_id"]
    assert _run(s.get_prompt("triage_finding", {"finding_id": str(fid)}))
    assert _run(s.get_prompt("exploit_plan", {"finding_id": str(fid)}))
    assert _run(s.get_prompt("triage_scope", {"scan_ids": str(sid)}))


# ---------------------------------------------------------------------------
# Hermeticity: prompts/adapters must use the injected conn, not the default DB
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_prompts_do_not_touch_default_db(tmp_path, monkeypatch, temp_db):
    """With DATABASE_PATH pointed at a schema-less DB, prompts built with an
    injected connection must still succeed (regression guard for the class of
    bug where an adapter reaches the default ~/.cerno DB)."""
    empty = tmp_path / "empty.db"
    sqlite3.connect(str(empty)).close()  # exists but has no schema
    monkeypatch.setattr(database, "DATABASE_PATH", empty)

    scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
    Plugin(plugin_id=1, plugin_name="P", severity_int=4).save(temp_db)
    fid = Finding(scan_id=scan_id, plugin_id=1).save(temp_db)
    host_id = Host.get_or_create("10.0.0.1", "10.0.0.1", "ipv4", conn=temp_db)
    Port.get_or_create(445, conn=temp_db)
    temp_db.execute(
        "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) "
        "VALUES (?, ?, 445, 'x')",
        (fid, host_id),
    )
    temp_db.commit()

    # Would raise "no such table" if it fell back to the schema-less default DB.
    assert "P" in mcp.prompt_triage_finding(fid, conn=temp_db)
    assert "P" in mcp.prompt_exploit_plan(fid, conn=temp_db)
    assert "s" in mcp.prompt_triage_scope(scan_id, conn=temp_db)
