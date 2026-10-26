"""Tests for the composite finding-query layer (cerno_pkg/query.py).

These cover each AND-combined predicate of ``FindingQuery`` against a seeded
database, the two non-SQL predicates (``cve`` JSON match and ``has_workflow``
via the workflow mapper), merged multi-scan dedup, and paging. The query layer
is the shared foundation the MCP ``query_findings`` tool is a thin adapter over.
"""

import pytest

from cerno_pkg.models import Finding, FindingVerdict, Host, Plugin, Port, Scan
from cerno_pkg.query import FindingQuery, run_finding_query
from cerno_pkg.workflow_mapper import WorkflowMapper


def _add_affected(conn, finding_id, host_id, port, *, output="out"):
    conn.execute(
        "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) "
        "VALUES (?, ?, ?, ?)",
        (finding_id, host_id, port, output),
    )


@pytest.fixture
def seeded(temp_db):
    """Seed two scans with several findings exercising every predicate.

    F1: scan A, plugin 57608 (High, no MSF), host .1:445 svc cifs  -> has_workflow
    F2: scan A, plugin 100   (Critical, MSF, CVE-2021-1), host .2:23 svc telnet, verdict=confirmed
    F3: scan B, plugin 57608 (High)          , host .3:445         -> merged sibling of F1
    F4: scan A, plugin 200   (Low)           , host .1:8080 svc http, review_state=in_progress
    """
    c = temp_db
    scan_a = Scan(scan_name="engagement", export_root="/tmp").save(c)
    scan_b = Scan(scan_name="baseline", export_root="/tmp").save(c)

    Plugin(
        plugin_id=57608, plugin_name="SMB Signing Not Required", severity_int=3
    ).save(c)
    Plugin(
        plugin_id=100,
        plugin_name="Unencrypted Telnet Server",
        severity_int=4,
        has_metasploit=True,
        cves=["CVE-2021-1"],
        metasploit_names=["telnet_login"],
    ).save(c)
    Plugin(
        plugin_id=200, plugin_name="SSL Self-Signed Certificate", severity_int=1
    ).save(c)

    f1 = Finding(scan_id=scan_a, plugin_id=57608).save(c)
    f2 = Finding(scan_id=scan_a, plugin_id=100).save(c)
    f3 = Finding(scan_id=scan_b, plugin_id=57608).save(c)
    f4 = Finding(scan_id=scan_a, plugin_id=200, review_state="in_progress").save(c)

    h1 = Host.get_or_create("10.0.0.1", "10.0.0.1", "ipv4", conn=c)
    h2 = Host.get_or_create("10.0.0.2", "10.0.0.2", "ipv4", conn=c)
    h3 = Host.get_or_create("10.0.0.3", "10.0.0.3", "ipv4", conn=c)
    for p in (445, 23, 8080):
        Port.get_or_create(p, conn=c)

    _add_affected(c, f1, h1, 445)
    _add_affected(c, f2, h2, 23)
    _add_affected(c, f3, h3, 445)
    _add_affected(c, f4, h1, 8080)

    c.executemany(
        "INSERT INTO host_services (scan_id, host_id, port_number, protocol, svc_name) "
        "VALUES (?, ?, ?, 'tcp', ?)",
        [
            (scan_a, h1, 445, "cifs"),
            (scan_a, h2, 23, "telnet"),
            (scan_a, h1, 8080, "http"),
        ],
    )
    FindingVerdict.set(f2, "confirmed", conn=c)
    c.commit()

    return {
        "conn": c,
        "scan_a": scan_a,
        "scan_b": scan_b,
        "f1": f1,
        "f2": f2,
        "f3": f3,
        "f4": f4,
    }


def _plugin_ids(results):
    return sorted(plugin.plugin_id for _, plugin in results)


def test_scan_ids_scopes_to_one_scan(seeded):
    res = run_finding_query(FindingQuery(scan_ids=[seeded["scan_a"]]), seeded["conn"])
    assert _plugin_ids(res) == [100, 200, 57608]


def test_no_scan_ids_spans_all_scans(seeded):
    res = run_finding_query(FindingQuery(), seeded["conn"])
    # F1+F3 share plugin 57608 but are distinct findings across scans (unmerged).
    assert len(res) == 4


def test_severity_int_exact(seeded):
    res = run_finding_query(FindingQuery(severity_int=4), seeded["conn"])
    assert _plugin_ids(res) == [100]


def test_severity_min_inclusive(seeded):
    res = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"]], severity_min=3), seeded["conn"]
    )
    assert _plugin_ids(res) == [100, 57608]


def test_review_state(seeded):
    res = run_finding_query(FindingQuery(review_state="in_progress"), seeded["conn"])
    assert _plugin_ids(res) == [200]


def test_has_metasploit(seeded):
    res = run_finding_query(FindingQuery(has_metasploit=True), seeded["conn"])
    assert _plugin_ids(res) == [100]


def test_plugin_name_substring_case_insensitive(seeded):
    res = run_finding_query(FindingQuery(plugin_name="telnet"), seeded["conn"])
    assert _plugin_ids(res) == [100]


def test_cve_exact_element_match(seeded):
    res = run_finding_query(FindingQuery(cve="CVE-2021-1"), seeded["conn"])
    assert _plugin_ids(res) == [100]


def test_cve_match_is_case_insensitive(seeded):
    res = run_finding_query(FindingQuery(cve="cve-2021-1"), seeded["conn"])
    assert _plugin_ids(res) == [100]


def test_cve_no_substring_false_positive(seeded):
    # "CVE-2021-10" must NOT match the finding whose only CVE is "CVE-2021-1".
    res = run_finding_query(FindingQuery(cve="CVE-2021-10"), seeded["conn"])
    assert res == []


def test_port_predicate(seeded):
    res = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"]], port=23), seeded["conn"]
    )
    assert _plugin_ids(res) == [100]


def test_service_predicate(seeded):
    res = run_finding_query(FindingQuery(service="cifs"), seeded["conn"])
    assert _plugin_ids(res) == [57608]


def test_host_predicate(seeded):
    res = run_finding_query(FindingQuery(host="10.0.0.2"), seeded["conn"])
    assert _plugin_ids(res) == [100]


def test_verdict_confirmed(seeded):
    res = run_finding_query(FindingQuery(verdict="confirmed"), seeded["conn"])
    assert _plugin_ids(res) == [100]


def test_verdict_none_excludes_findings_with_a_verdict(seeded):
    res = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"]], verdict="none"), seeded["conn"]
    )
    # F2 has a verdict; the rest do not.
    assert _plugin_ids(res) == [200, 57608]


def test_has_workflow_true(seeded, tmp_path):
    mapper = _mapper_with(tmp_path, ["57608"])
    res = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"]], has_workflow=True),
        seeded["conn"],
        workflow_mapper=mapper,
    )
    assert _plugin_ids(res) == [57608]


def test_has_workflow_false(seeded, tmp_path):
    mapper = _mapper_with(tmp_path, ["57608"])
    res = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"]], has_workflow=False),
        seeded["conn"],
        workflow_mapper=mapper,
    )
    assert _plugin_ids(res) == [100, 200]


def test_has_workflow_handles_grouped_plugin_keys(seeded, tmp_path):
    # A comma-separated workflow key must mark each listed plugin as having a workflow.
    mapper = _mapper_with(tmp_path, ["90317,57608,70658"])
    res = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"]], has_workflow=True),
        seeded["conn"],
        workflow_mapper=mapper,
    )
    assert _plugin_ids(res) == [57608]


def test_combined_predicates_are_anded(seeded):
    # "unreviewed critical with an MSF module on port 23, not yet verdicted"
    q = FindingQuery(
        scan_ids=[seeded["scan_a"]],
        severity_int=4,
        has_metasploit=True,
        port=23,
    )
    res = run_finding_query(q, seeded["conn"])
    assert _plugin_ids(res) == [100]


def test_merged_dedups_by_plugin_across_scans(seeded):
    res = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"], seeded["scan_b"]], merged=True),
        seeded["conn"],
    )
    # 57608 appears in both scans -> one representative row when merged.
    assert _plugin_ids(res) == [100, 200, 57608]


def test_empty_scan_ids_matches_nothing(seeded):
    # An explicit empty scope is distinct from None (all scans).
    res = run_finding_query(FindingQuery(scan_ids=[]), seeded["conn"])
    assert res == []


def test_limit_and_offset(seeded):
    all_rows = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"]]), seeded["conn"]
    )
    assert len(all_rows) == 3
    page = run_finding_query(
        FindingQuery(scan_ids=[seeded["scan_a"]], limit=1, offset=1), seeded["conn"]
    )
    assert len(page) == 1


def _mapper_with(tmp_path, plugin_id_keys):
    """Build a real WorkflowMapper from a temp YAML listing the given keys."""
    import yaml

    data = {
        "version": "1.0",
        "workflows": [
            {
                "plugin_id": key,
                "workflow_name": f"wf-{key}",
                "description": "d",
                "steps": [],
                "references": [],
            }
            for key in plugin_id_keys
        ],
    }
    path = tmp_path / "wf.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return WorkflowMapper(yaml_path=path)
