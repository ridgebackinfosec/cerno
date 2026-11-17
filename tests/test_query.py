"""Tests for the composite finding-query layer (cerno_pkg/query.py).

These cover each AND-combined predicate of ``FindingQuery`` against a seeded
database, the two non-SQL predicates (``cve`` JSON match and ``has_workflow``
via the workflow mapper), merged multi-dataset dedup, and paging. The query layer
is the shared foundation the MCP ``query_findings`` tool is a thin adapter over.
"""

from cerno_pkg.constants import SOURCE_OPERATOR

import pytest

from cerno_pkg.models import Finding, FindingVerdict, Host, FindingType, Port, Dataset
from cerno_pkg.query import FindingQuery, run_finding_query
from cerno_pkg.workflow_mapper import WorkflowMapper


def _add_affected(conn, finding_id, host_id, port, *, output="out"):
    conn.execute(
        "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, evidence) "
        "VALUES (?, ?, ?, ?)",
        (finding_id, host_id, port, output),
    )


@pytest.fixture
def seeded(temp_db):
    """Seed two datasets with several findings exercising every predicate.

    F1: scan A, finding_type 57608 (High, no MSF), host .1:445 svc cifs  -> has_workflow
    F2: scan A, finding_type 100   (Critical, MSF, CVE-2021-1), host .2:23 svc telnet, verdict=confirmed
    F3: scan B, finding_type 57608 (High)          , host .3:445         -> merged sibling of F1
    F4: scan A, finding_type 200   (Low)           , host .1:8080 svc http, review_state=in_progress
    """
    c = temp_db
    dataset_a = Dataset(dataset_name="engagement", export_root="/tmp").save(c)
    dataset_b = Dataset(dataset_name="baseline", export_root="/tmp").save(c)

    FindingType(
        finding_type_id="nessus:57608",
        finding_type_name="SMB Signing Not Required",
        severity_int=3,
    ).save(c)
    FindingType(
        finding_type_id="nessus:100",
        finding_type_name="Unencrypted Telnet Server",
        severity_int=4,
        has_metasploit=True,
        cves=["CVE-2021-1"],
        metasploit_names=["telnet_login"],
    ).save(c)
    FindingType(
        finding_type_id="nessus:200",
        finding_type_name="SSL Self-Signed Certificate",
        severity_int=1,
    ).save(c)

    f1 = Finding(dataset_id=dataset_a, finding_type_id="nessus:57608").save(c)
    f2 = Finding(dataset_id=dataset_a, finding_type_id="nessus:100").save(c)
    f3 = Finding(dataset_id=dataset_b, finding_type_id="nessus:57608").save(c)
    f4 = Finding(
        dataset_id=dataset_a, finding_type_id="nessus:200", review_state="in_progress"
    ).save(c)

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
        "INSERT INTO host_services (dataset_id, host_id, port_number, protocol, svc_name) "
        "VALUES (?, ?, ?, 'tcp', ?)",
        [
            (dataset_a, h1, 445, "cifs"),
            (dataset_a, h2, 23, "telnet"),
            (dataset_a, h1, 8080, "http"),
        ],
    )
    FindingVerdict.set(f2, "confirmed", SOURCE_OPERATOR, conn=c)
    c.commit()

    return {
        "conn": c,
        "dataset_a": dataset_a,
        "dataset_b": dataset_b,
        "f1": f1,
        "f2": f2,
        "f3": f3,
        "f4": f4,
    }


def _finding_type_ids(results):
    return sorted(finding_type.finding_type_id for _, finding_type in results)


def test_dataset_ids_scopes_to_one_dataset(seeded):
    res = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]]), seeded["conn"]
    )
    assert _finding_type_ids(res) == ["nessus:100", "nessus:200", "nessus:57608"]


def test_no_dataset_ids_spans_all_datasets(seeded):
    res = run_finding_query(FindingQuery(), seeded["conn"])
    # F1+F3 share finding_type 57608 but are distinct findings across datasets (unmerged).
    assert len(res) == 4


def test_severity_int_exact(seeded):
    res = run_finding_query(FindingQuery(severity_int=4), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:100"]


def test_severity_min_inclusive(seeded):
    res = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]], severity_min=3), seeded["conn"]
    )
    assert _finding_type_ids(res) == ["nessus:100", "nessus:57608"]


def test_review_state(seeded):
    res = run_finding_query(FindingQuery(review_state="in_progress"), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:200"]


def test_has_metasploit(seeded):
    res = run_finding_query(FindingQuery(has_metasploit=True), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:100"]


def test_finding_type_name_substring_case_insensitive(seeded):
    res = run_finding_query(FindingQuery(finding_type_name="telnet"), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:100"]


def test_cve_exact_element_match(seeded):
    res = run_finding_query(FindingQuery(cve="CVE-2021-1"), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:100"]


def test_cve_match_is_case_insensitive(seeded):
    res = run_finding_query(FindingQuery(cve="cve-2021-1"), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:100"]


def test_cve_no_substring_false_positive(seeded):
    # "CVE-2021-10" must NOT match the finding whose only CVE is "CVE-2021-1".
    res = run_finding_query(FindingQuery(cve="CVE-2021-10"), seeded["conn"])
    assert res == []


def test_port_predicate(seeded):
    res = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]], port=23), seeded["conn"]
    )
    assert _finding_type_ids(res) == ["nessus:100"]


def test_service_predicate(seeded):
    res = run_finding_query(FindingQuery(service="cifs"), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:57608"]


def test_host_predicate(seeded):
    res = run_finding_query(FindingQuery(host="10.0.0.2"), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:100"]


def test_verdict_confirmed(seeded):
    res = run_finding_query(FindingQuery(verdict="confirmed"), seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:100"]


def test_verdict_none_excludes_findings_with_a_verdict(seeded):
    res = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]], verdict="none"), seeded["conn"]
    )
    # F2 has a verdict; the rest do not.
    assert _finding_type_ids(res) == ["nessus:200", "nessus:57608"]


def test_has_workflow_true(seeded, tmp_path):
    mapper = _mapper_with(tmp_path, ["nessus:57608"])
    res = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]], has_workflow=True),
        seeded["conn"],
        workflow_mapper=mapper,
    )
    assert _finding_type_ids(res) == ["nessus:57608"]


def test_has_workflow_false(seeded, tmp_path):
    mapper = _mapper_with(tmp_path, ["nessus:57608"])
    res = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]], has_workflow=False),
        seeded["conn"],
        workflow_mapper=mapper,
    )
    assert _finding_type_ids(res) == ["nessus:100", "nessus:200"]


def test_has_workflow_handles_grouped_finding_type_keys(seeded, tmp_path):
    # A comma-separated workflow key must mark each listed finding_type as having a workflow.
    mapper = _mapper_with(tmp_path, ["nessus:90317,nessus:57608,nessus:70658"])
    res = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]], has_workflow=True),
        seeded["conn"],
        workflow_mapper=mapper,
    )
    assert _finding_type_ids(res) == ["nessus:57608"]


def test_combined_predicates_are_anded(seeded):
    # "unreviewed critical with an MSF module on port 23, not yet verdicted"
    q = FindingQuery(
        dataset_ids=[seeded["dataset_a"]],
        severity_int=4,
        has_metasploit=True,
        port=23,
    )
    res = run_finding_query(q, seeded["conn"])
    assert _finding_type_ids(res) == ["nessus:100"]


def test_merged_dedups_by_finding_type_across_datasets(seeded):
    res = run_finding_query(
        FindingQuery(
            dataset_ids=[seeded["dataset_a"], seeded["dataset_b"]], merged=True
        ),
        seeded["conn"],
    )
    # 57608 appears in both datasets -> one representative row when merged.
    assert _finding_type_ids(res) == ["nessus:100", "nessus:200", "nessus:57608"]


def test_merged_dedups_without_an_explicit_dataset_scope(seeded):
    """``dataset_ids=None`` means every dataset, so merged must still dedup.

    None is also falsy, so the merge was skipped in exactly the widest scope --
    the one with the most to merge. An agent calling ``query_findings`` with no
    scope, or ``list_workflow_gaps()``, which hardcodes ``merged=True`` and
    defaults to None, got one row per (finding type, dataset) from a tool
    promising one row per finding type; under a ``limit`` the surplus rows
    pushed whole sources off the end of the page.
    """
    unscoped = run_finding_query(FindingQuery(merged=True), seeded["conn"])
    explicit = run_finding_query(
        FindingQuery(
            dataset_ids=[seeded["dataset_a"], seeded["dataset_b"]], merged=True
        ),
        seeded["conn"],
    )
    assert _finding_type_ids(unscoped) == _finding_type_ids(explicit)
    assert _finding_type_ids(unscoped) == ["nessus:100", "nessus:200", "nessus:57608"]

    # The representative keeps its sibling from the other dataset, so host and
    # port lookups still span both.
    rep = next(f for f, p in unscoped if p.finding_type_id == "nessus:57608")
    assert rep.finding_id == seeded["f1"]
    assert rep.extra_finding_ids == [seeded["f3"]]


def test_empty_dataset_ids_matches_nothing(seeded):
    # An explicit empty scope is distinct from None (all datasets).
    res = run_finding_query(FindingQuery(dataset_ids=[]), seeded["conn"])
    assert res == []


def test_limit_and_offset(seeded):
    all_rows = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]]), seeded["conn"]
    )
    assert len(all_rows) == 3
    page = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]], limit=1, offset=1),
        seeded["conn"],
    )
    assert len(page) == 1


def test_worst_severity_comes_back_first(seeded):
    """A page cut short by ``limit`` must keep the worst findings.

    Rows were ordered by finding type id alone, so a truncated page kept the
    lowest-numbered Nessus ids and dropped whatever sorted later. On the demo
    data a limit of 6 over the criticals returned six Nessus rows and discarded
    the one Critical Log4j RCE, which sorts last under the ``nuclei:`` prefix.
    """
    rows = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]]), seeded["conn"]
    )
    assert [p.severity_int for _f, p in rows] == [4, 3, 1]
    top = run_finding_query(
        FindingQuery(dataset_ids=[seeded["dataset_a"]], limit=1), seeded["conn"]
    )
    assert [p.finding_type_id for _f, p in top] == ["nessus:100"]


def _mapper_with(tmp_path, finding_type_id_keys):
    """Build a real WorkflowMapper from a temp YAML listing the given keys."""
    import yaml

    data = {
        "version": "1.0",
        "workflows": [
            {
                "finding_type_id": key,
                "workflow_name": f"wf-{key}",
                "description": "d",
                "steps": [],
                "references": [],
            }
            for key in finding_type_id_keys
        ],
    }
    path = tmp_path / "wf.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return WorkflowMapper(yaml_path=path)


# ---------------------------------------------------------------------------
# source predicate (multi-source findings)
# ---------------------------------------------------------------------------


@pytest.fixture
def mixed_source_db(temp_db):
    """One Nessus finding and one nuclei finding in the same scan."""
    from cerno_pkg.models import Finding, FindingType, Dataset

    dataset = Dataset(dataset_name="mixed", export_root="/tmp").save(temp_db)
    FindingType(
        finding_type_id="nessus:57608", finding_type_name="SMB Signing", severity_int=3
    ).save(temp_db)
    FindingType(
        finding_type_id="nuclei:tech-detect",
        finding_type_name="Tech Detect",
        severity_int=3,
    ).save(temp_db)
    Finding(dataset_id=dataset, finding_type_id="nessus:57608").save(temp_db)
    Finding(dataset_id=dataset, finding_type_id="nuclei:tech-detect").save(temp_db)
    return temp_db


@pytest.mark.integration
def test_source_predicate_selects_nessus_only(mixed_source_db):
    res = run_finding_query(FindingQuery(source="nessus"), mixed_source_db)
    assert _finding_type_ids(res) == ["nessus:57608"]


@pytest.mark.integration
def test_source_predicate_selects_nuclei_only(mixed_source_db):
    res = run_finding_query(FindingQuery(source="nuclei"), mixed_source_db)
    assert _finding_type_ids(res) == ["nuclei:tech-detect"]


@pytest.mark.integration
def test_source_predicate_is_case_insensitive(mixed_source_db):
    res = run_finding_query(FindingQuery(source="  NUCLEI "), mixed_source_db)
    assert _finding_type_ids(res) == ["nuclei:tech-detect"]


@pytest.mark.integration
def test_unset_source_spans_every_source(mixed_source_db):
    res = run_finding_query(FindingQuery(), mixed_source_db)
    assert set(_finding_type_ids(res)) == {"nessus:57608", "nuclei:tech-detect"}


@pytest.mark.integration
def test_unknown_source_is_rejected(mixed_source_db):
    """An unrecognised source is an error, not an empty result.

    This asserted the opposite until 4.0.0. Returning ``[]`` made a typo
    indistinguishable from "no findings match": an external MCP audit read the
    empty result as proof that burp, operator and agent were not valid sources,
    which a stale tool description had also claimed. The message names every
    valid value so the caller can correct itself.
    """
    with pytest.raises(ValueError, match="unknown source 'openvas'"):
        run_finding_query(FindingQuery(source="openvas"), mixed_source_db)

    for name in ("nessus", "nuclei", "burp", "operator", "agent"):
        run_finding_query(FindingQuery(source=name), mixed_source_db)


@pytest.mark.integration
def test_unknown_review_state_and_verdict_are_rejected(mixed_source_db):
    with pytest.raises(ValueError, match="unknown review_state"):
        run_finding_query(FindingQuery(review_state="reviewed"), mixed_source_db)
    with pytest.raises(ValueError, match="unknown verdict"):
        run_finding_query(FindingQuery(verdict="true_positive"), mixed_source_db)
    # "none" is a valid verdict filter: findings with no verdict yet.
    run_finding_query(FindingQuery(verdict="none"), mixed_source_db)


@pytest.mark.integration
def test_empty_dataset_scope_still_matches_nothing(mixed_source_db):
    """An explicitly empty scope is a legitimate filter, not a bad value."""
    assert run_finding_query(FindingQuery(dataset_ids=[]), mixed_source_db) == []


@pytest.mark.integration
def test_source_combines_with_other_predicates(mixed_source_db):
    res = run_finding_query(
        FindingQuery(source="nuclei", severity_min=4), mixed_source_db
    )
    assert res == []


@pytest.mark.integration
def test_numeric_nessus_ids_still_sort_numerically(temp_db):
    """finding_type_id is TEXT now; a plain sort would put '9' after '10114'."""
    from cerno_pkg.models import Finding, FindingType, Dataset

    dataset = Dataset(dataset_name="ordering", export_root="/tmp").save(temp_db)
    for pid in ("nessus:9", "nessus:10114", "nessus:100"):
        FindingType(
            finding_type_id=pid, finding_type_name=f"P{pid}", severity_int=1
        ).save(temp_db)
        Finding(dataset_id=dataset, finding_type_id=pid).save(temp_db)
    res = run_finding_query(FindingQuery(), temp_db)
    assert [p.finding_type_id for _f, p in res] == [
        "nessus:9",
        "nessus:100",
        "nessus:10114",
    ]
