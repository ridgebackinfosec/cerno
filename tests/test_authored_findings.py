"""Tests for hand-authored findings (cerno_pkg.authored_findings).

These are the sources created rather than imported, so the things worth
pinning are the ones no parser fixture can cover: how each shared scan comes
into being, how the sequential ref is allocated per source, what validation
refuses, and that an edit never moves a finding's identity.

The source-dependent behaviour is parametrized over both channels, because the
whole point of the ``operator:``/``agent:`` split is that the two stay
distinguishable while behaving identically -- a test that only exercised one
would let the other rot.
"""

import pytest

from cerno_pkg.constants import (
    AUTHORED_DATASET_NAMES,
    SOURCE_AGENT,
    SOURCE_IDS,
    SOURCE_OPERATOR,
)
from cerno_pkg.authored_findings import (
    AuthoredFindingInput,
    AuthoredFindingError,
    create_authored_finding,
    get_or_create_authored_dataset,
    next_authored_ref,
    parse_target_tokens,
    update_authored_finding,
    validate_authored_input,
)


def _input(**kw) -> AuthoredFindingInput:
    base = dict(
        title="Weak JWT validation",
        severity_int=3,
        targets=[("10.0.0.21", 443)],
        description="The API accepts a token signed with alg=none.",
    )
    base.update(kw)
    return AuthoredFindingInput(**base)  # type: ignore[arg-type]


def _create(data, source: str = SOURCE_OPERATOR, conn=None):
    """Create through the real writer, defaulting attribution to the operator.

    Most tests here are about validation, refs and edits, where the channel is
    incidental; the ones that are about attribution pass ``source`` explicitly
    or call :func:`create_authored_finding` directly. That the real function has
    *no* default is pinned by ``TestAttribution``.
    """
    return create_authored_finding(data, source, conn=conn)


@pytest.mark.unit
class TestParseTargetTokens:
    def test_host_and_port(self) -> None:
        assert parse_target_tokens(["10.0.0.21:443"]) == [("10.0.0.21", 443)]

    def test_host_without_port(self) -> None:
        assert parse_target_tokens(["10.0.0.21"]) == [("10.0.0.21", None)]

    def test_hostname(self) -> None:
        assert parse_target_tokens(["web01.corp.local:8443"]) == [
            ("web01.corp.local", 8443)
        ]

    def test_bracketed_ipv6(self) -> None:
        # hosts.ip_address stores bare addresses; brackets would key a second row.
        assert parse_target_tokens(["[2001:db8::1]:443"]) == [("2001:db8::1", 443)]

    def test_bare_ipv6(self) -> None:
        assert parse_target_tokens(["2001:db8::1"]) == [("2001:db8::1", None)]

    def test_comma_and_whitespace_separated_in_one_string(self) -> None:
        assert parse_target_tokens(["10.0.0.21:443, 10.0.0.22:80  10.0.0.23"]) == [
            ("10.0.0.21", 443),
            ("10.0.0.22", 80),
            ("10.0.0.23", None),
        ]

    def test_duplicates_collapse(self) -> None:
        # finding_affected_hosts is UNIQUE per (finding_id, host_id, port).
        assert parse_target_tokens(["10.0.0.21:443", "10.0.0.21:443"]) == [
            ("10.0.0.21", 443)
        ]

    def test_order_is_preserved(self) -> None:
        assert parse_target_tokens(["b.example:80", "a.example:80"]) == [
            ("b.example", 80),
            ("a.example", 80),
        ]

    def test_empty_input(self) -> None:
        assert parse_target_tokens([]) == []
        assert parse_target_tokens(["", "   "]) == []


@pytest.mark.unit
class TestValidation:
    def test_a_good_finding_has_no_problems(self) -> None:
        assert validate_authored_input(_input()) == []

    def test_title_is_required(self) -> None:
        assert validate_authored_input(_input(title="   "))

    def test_title_length_is_capped(self) -> None:
        assert validate_authored_input(_input(title="x" * 5000))

    def test_severity_must_be_in_range(self) -> None:
        assert validate_authored_input(_input(severity_int=5))
        assert validate_authored_input(_input(severity_int=-1))

    def test_every_severity_including_critical_is_allowed(self) -> None:
        # Unlike Burp, an operator may call something Critical.
        for severity in range(5):
            assert validate_authored_input(_input(severity_int=severity)) == []

    def test_description_length_is_capped(self) -> None:
        assert validate_authored_input(_input(description="x" * 100_000))

    def test_port_out_of_range_is_refused(self) -> None:
        # ports.port_number CHECKs BETWEEN 1 AND 65535.
        assert validate_authored_input(_input(targets=[("10.0.0.21", 0)]))
        assert validate_authored_input(_input(targets=[("10.0.0.21", 70000)]))

    def test_empty_host_is_refused(self) -> None:
        assert validate_authored_input(_input(targets=[("", 443)]))

    def test_no_targets_is_allowed(self) -> None:
        # An engagement-level observation has no host to name.
        assert validate_authored_input(_input(targets=[])) == []

    def test_malformed_cve_is_refused(self) -> None:
        assert validate_authored_input(_input(cves=["CVE-21-4"]))

    def test_valid_cves_pass(self) -> None:
        assert validate_authored_input(_input(cves=["CVE-2021-44228"])) == []

    def test_non_http_reference_url_is_refused(self) -> None:
        # details_url is interpolated into a Rich style to build the OSC-8 link.
        assert validate_authored_input(_input(reference_url="javascript:alert(1)"))

    def test_reference_url_with_whitespace_is_refused(self) -> None:
        assert validate_authored_input(_input(reference_url="https://example.com/a b"))

    def test_https_reference_url_passes(self) -> None:
        assert (
            validate_authored_input(_input(reference_url="https://example.com/x")) == []
        )

    def test_problems_are_reported_together(self) -> None:
        problems = validate_authored_input(_input(title="", severity_int=9))
        assert len(problems) >= 2


@pytest.mark.integration
@pytest.mark.parametrize("source", [SOURCE_OPERATOR, SOURCE_AGENT])
class TestAuthoredScan:
    def test_dataset_is_created_on_first_use(self, temp_db, source) -> None:
        dataset = get_or_create_authored_dataset(source, temp_db)
        assert dataset.dataset_name == AUTHORED_DATASET_NAMES[source]
        assert dataset.dataset_id is not None
        # No scanner file produced it.
        assert dataset.source_file_path is None
        assert dataset.source_file_hash is None

    def test_dataset_is_reused_not_duplicated(self, temp_db, source) -> None:
        first = get_or_create_authored_dataset(source, temp_db)
        second = get_or_create_authored_dataset(source, temp_db)
        assert first.dataset_id == second.dataset_id
        assert temp_db.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 1

    def test_scanner_source_is_refused(self, temp_db, source) -> None:
        """A scanner source must not get an auto-created scan of its own."""
        with pytest.raises(AuthoredFindingError):
            get_or_create_authored_dataset("nessus", temp_db)
        assert temp_db.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 0


@pytest.mark.integration
class TestAuthoredScanSeparation:
    def test_each_source_gets_its_own_dataset(self, temp_db) -> None:
        operator = get_or_create_authored_dataset(SOURCE_OPERATOR, temp_db)
        agent = get_or_create_authored_dataset(SOURCE_AGENT, temp_db)
        assert operator.dataset_id != agent.dataset_id
        assert {operator.dataset_name, agent.dataset_name} == {"Operator", "Agent"}


@pytest.mark.integration
@pytest.mark.parametrize("source", [SOURCE_OPERATOR, SOURCE_AGENT])
class TestRefAllocation:
    def test_first_finding_is_one(self, temp_db, source) -> None:
        assert next_authored_ref(source, temp_db) == 1

    def test_refs_increment(self, temp_db, source) -> None:
        _create(_input(title="First"), source, conn=temp_db)
        assert next_authored_ref(source, temp_db) == 2

    def test_numeric_not_lexicographic(self, temp_db, source) -> None:
        """operator:10 must follow operator:9, not sort between 1 and 2."""
        for i in range(9):
            _create(_input(title=f"Finding {i}"), source, conn=temp_db)
        finding_type_id, _ = _create(_input(title="Tenth"), source, conn=temp_db)
        assert finding_type_id == f"{source}:10"
        assert next_authored_ref(source, temp_db) == 11

    def test_other_sources_do_not_shift_the_sequence(self, temp_db, source) -> None:
        from cerno_pkg.models import FindingType

        FindingType(
            finding_type_id="nessus:99999", finding_type_name="N", severity_int=1
        ).save(temp_db)
        FindingType(
            finding_type_id="burp:00200300", finding_type_name="B", severity_int=3
        ).save(temp_db)
        assert next_authored_ref(source, temp_db) == 1


@pytest.mark.integration
class TestRefCountersAreIndependent:
    """The two channels number their findings separately.

    ``operator:1`` and ``agent:1`` must be able to coexist: the counter is
    filtered on ``source_id``, so one channel's activity cannot advance the
    other's sequence or make its ids look non-sequential.
    """

    def test_both_start_at_one(self, temp_db) -> None:
        operator_id, _ = _create(_input(title="Mine"), SOURCE_OPERATOR, conn=temp_db)
        agent_id, _ = _create(_input(title="Yours"), SOURCE_AGENT, conn=temp_db)
        assert operator_id == "operator:1"
        assert agent_id == "agent:1"

    def test_each_increments_alone(self, temp_db) -> None:
        for _ in range(3):
            _create(_input(), SOURCE_AGENT, conn=temp_db)
        assert next_authored_ref(SOURCE_AGENT, temp_db) == 4
        assert next_authored_ref(SOURCE_OPERATOR, temp_db) == 1

        _create(_input(), SOURCE_OPERATOR, conn=temp_db)
        assert next_authored_ref(SOURCE_OPERATOR, temp_db) == 2
        assert next_authored_ref(SOURCE_AGENT, temp_db) == 4


@pytest.mark.integration
class TestCreate:
    def test_returns_namespaced_id_and_finding_id(self, temp_db) -> None:
        finding_type_id, finding_id = _create(_input(), conn=temp_db)
        assert finding_type_id == "operator:1"
        assert isinstance(finding_id, int)

    def test_finding_type_row_records_the_source(self, temp_db) -> None:
        _create(_input(), conn=temp_db)
        row = temp_db.execute(
            "SELECT source_id, finding_type_name, severity_int, has_metasploit, details_url "
            "FROM finding_types WHERE finding_type_id = 'operator:1'"
        ).fetchone()
        assert row["source_id"] == SOURCE_IDS[SOURCE_OPERATOR]
        assert row["finding_type_name"] == "Weak JWT validation"
        assert row["severity_int"] == 3
        assert not row["has_metasploit"]
        assert row["details_url"] is None

    def test_finding_lands_in_the_operator_dataset(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(_input(), conn=temp_db)
        row = temp_db.execute(
            "SELECT s.dataset_name, f.review_state FROM findings f "
            "JOIN datasets s ON s.dataset_id = f.dataset_id WHERE f.finding_id = ?",
            (finding_id,),
        ).fetchone()
        assert row["dataset_name"] == AUTHORED_DATASET_NAMES[SOURCE_OPERATOR]
        assert row["review_state"] == "unreviewed"

    def test_description_is_stored_as_the_host_evidence(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(
            _input(targets=[("10.0.0.21", 443), ("10.0.0.22", 80)]), conn=temp_db
        )
        rows = temp_db.execute(
            "SELECT evidence FROM finding_affected_hosts WHERE finding_id = ?",
            (finding_id,),
        ).fetchall()
        assert len(rows) == 2
        assert all("alg=none" in r["evidence"] for r in rows)

    def test_hosts_and_ports_are_normalized(self, temp_db) -> None:
        _create(
            _input(targets=[("web01.corp.local", 8443), ("2001:db8::1", None)]),
            conn=temp_db,
        )
        hosts = {
            (r["scan_target"], r["scan_target_type"])
            for r in temp_db.execute("SELECT scan_target, scan_target_type FROM hosts")
        }
        assert ("web01.corp.local", "fqdn") in hosts
        assert ("2001:db8::1", "ipv6") in hosts
        ports = {r[0] for r in temp_db.execute("SELECT port_number FROM ports")}
        assert ports == {8443}

    def test_a_finding_with_no_targets_still_exists(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(_input(targets=[]), conn=temp_db)
        assert (
            temp_db.execute(
                "SELECT COUNT(*) FROM finding_affected_hosts WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()[0]
            == 0
        )

    def test_cves_and_reference_url_are_stored(self, temp_db) -> None:
        _create(
            _input(cves=["CVE-2021-44228"], reference_url="https://example.com/x"),
            conn=temp_db,
        )
        row = temp_db.execute(
            "SELECT cves, details_url FROM finding_types WHERE finding_type_id = 'operator:1'"
        ).fetchone()
        assert "CVE-2021-44228" in row["cves"]
        assert row["details_url"] == "https://example.com/x"

    def test_no_service_is_invented(self, temp_db) -> None:
        """The operator describes a finding, not a service discovery."""
        _create(_input(), conn=temp_db)
        assert temp_db.execute("SELECT COUNT(*) FROM host_services").fetchone()[0] == 0

    def test_invalid_input_is_refused_and_writes_nothing(self, temp_db) -> None:
        with pytest.raises(AuthoredFindingError):
            _create(_input(severity_int=9), conn=temp_db)
        assert temp_db.execute("SELECT COUNT(*) FROM finding_types").fetchone()[0] == 0
        assert temp_db.execute("SELECT COUNT(*) FROM datasets").fetchone()[0] == 0

    def test_two_findings_with_the_same_title_do_not_collide(self, temp_db) -> None:
        """FindingType.save() is INSERT OR REPLACE, so a shared id would overwrite."""
        first, _ = _create(_input(severity_int=3), conn=temp_db)
        second, _ = _create(_input(severity_int=1), conn=temp_db)
        assert first != second
        severities = {
            r[0]
            for r in temp_db.execute(
                "SELECT severity_int FROM finding_types WHERE finding_type_id LIKE 'operator:%'"
            )
        }
        assert severities == {1, 3}

    def test_findings_reach_the_normal_review_path(self, temp_db) -> None:
        from cerno_pkg.models import Finding

        _finding_type_id, finding_id = _create(_input(), conn=temp_db)
        dataset_id = temp_db.execute(
            "SELECT dataset_id FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()[0]
        pairs = Finding.get_by_dataset_with_finding_type(dataset_id, conn=temp_db)
        assert len(pairs) == 1
        _finding, finding_type = pairs[0]
        assert finding_type.source == SOURCE_OPERATOR

    def test_query_findings_by_source(self, temp_db) -> None:
        from cerno_pkg.query import FindingQuery, run_finding_query

        _create(_input(), conn=temp_db)
        assert len(run_finding_query(FindingQuery(source="operator"), temp_db)) == 1


@pytest.mark.integration
class TestUpdate:
    def test_title_change_keeps_the_identity(self, temp_db) -> None:
        """The payoff of a sequential ref over a title slug."""
        finding_type_id, finding_id = _create(_input(), conn=temp_db)
        update_authored_finding(finding_id, title="Renamed entirely", conn=temp_db)
        row = temp_db.execute(
            "SELECT finding_type_id, finding_type_name FROM finding_types WHERE finding_type_id = ?",
            (finding_type_id,),
        ).fetchone()
        assert row["finding_type_id"] == "operator:1"
        assert row["finding_type_name"] == "Renamed entirely"

    def test_severity_change(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(_input(), conn=temp_db)
        update_authored_finding(finding_id, severity_int=1, conn=temp_db)
        assert (
            temp_db.execute(
                "SELECT severity_int FROM finding_types WHERE finding_type_id = 'operator:1'"
            ).fetchone()[0]
            == 1
        )

    def test_omitted_fields_are_left_alone(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(
            _input(cves=["CVE-2021-44228"]), conn=temp_db
        )
        update_authored_finding(finding_id, severity_int=0, conn=temp_db)
        row = temp_db.execute(
            "SELECT finding_type_name, cves FROM finding_types WHERE finding_type_id = 'operator:1'"
        ).fetchone()
        assert row["finding_type_name"] == "Weak JWT validation"
        assert "CVE-2021-44228" in row["cves"]

    def test_targets_are_replaced_not_appended(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(
            _input(targets=[("10.0.0.21", 443), ("10.0.0.22", 80)]), conn=temp_db
        )
        update_authored_finding(finding_id, targets=[("10.0.0.99", 22)], conn=temp_db)
        rows = temp_db.execute(
            "SELECT h.scan_target, fah.port_number FROM finding_affected_hosts fah "
            "JOIN hosts h ON h.host_id = fah.host_id WHERE fah.finding_id = ?",
            (finding_id,),
        ).fetchall()
        assert [(r[0], r[1]) for r in rows] == [("10.0.0.99", 22)]

    def test_description_change_rewrites_every_host_row(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(
            _input(targets=[("10.0.0.21", 443), ("10.0.0.22", 80)]), conn=temp_db
        )
        update_authored_finding(finding_id, description="Rewritten.", conn=temp_db)
        outputs = {
            r[0]
            for r in temp_db.execute(
                "SELECT evidence FROM finding_affected_hosts WHERE finding_id = ?",
                (finding_id,),
            )
        }
        assert outputs == {"Rewritten."}

    def test_review_state_survives_an_edit(self, temp_db) -> None:
        from cerno_pkg.models import Finding

        _finding_type_id, finding_id = _create(_input(), conn=temp_db)
        finding = Finding.get_by_id(finding_id, temp_db)
        assert finding is not None
        finding.update_review_state("in_progress", SOURCE_OPERATOR, conn=temp_db)
        update_authored_finding(finding_id, title="Edited", conn=temp_db)
        assert (
            temp_db.execute(
                "SELECT review_state FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()[0]
            == "in_progress"
        )

    def test_a_scanner_finding_cannot_be_edited(self, temp_db) -> None:
        """Scanner findings are a record of what the scanner reported."""
        from cerno_pkg.models import Finding, FindingType, Dataset

        dataset_id = Dataset(dataset_name="s", export_root="/tmp/s").save(temp_db)
        FindingType(
            finding_type_id="nessus:57608", finding_type_name="SMB", severity_int=3
        ).save(temp_db)
        finding_id = Finding(
            dataset_id=dataset_id, finding_type_id="nessus:57608"
        ).save(temp_db)

        with pytest.raises(AuthoredFindingError):
            update_authored_finding(finding_id, title="Hijacked", conn=temp_db)
        assert (
            temp_db.execute(
                "SELECT finding_type_name FROM finding_types WHERE finding_type_id = 'nessus:57608'"
            ).fetchone()[0]
            == "SMB"
        )

    def test_unknown_finding_is_refused(self, temp_db) -> None:
        with pytest.raises(AuthoredFindingError):
            update_authored_finding(9999, title="Nope", conn=temp_db)

    def test_invalid_edit_is_refused_and_changes_nothing(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(_input(), conn=temp_db)
        with pytest.raises(AuthoredFindingError):
            update_authored_finding(finding_id, severity_int=9, conn=temp_db)
        assert (
            temp_db.execute(
                "SELECT severity_int FROM finding_types WHERE finding_type_id = 'operator:1'"
            ).fetchone()[0]
            == 3
        )

    def test_nothing_to_change_is_not_an_error(self, temp_db) -> None:
        _finding_type_id, finding_id = _create(_input(), conn=temp_db)
        update_authored_finding(finding_id, conn=temp_db)
        assert (
            temp_db.execute(
                "SELECT finding_type_name FROM finding_types WHERE finding_type_id = 'operator:1'"
            ).fetchone()[0]
            == "Weak JWT validation"
        )


@pytest.mark.integration
class TestLoad:
    def test_round_trips_everything_an_edit_needs(self, temp_db) -> None:
        from cerno_pkg.authored_findings import load_authored_finding

        original = _input(
            targets=[("10.0.0.21", 443), ("web01.corp.local", None)],
            cves=["CVE-2021-44228"],
            reference_url="https://example.com/x",
        )
        _finding_type_id, finding_id = _create(original, conn=temp_db)

        loaded = load_authored_finding(finding_id, conn=temp_db)
        assert loaded.title == original.title
        assert loaded.severity_int == original.severity_int
        assert loaded.targets == original.targets
        assert loaded.description == original.description
        assert loaded.cves == original.cves
        assert loaded.reference_url == original.reference_url

    def test_a_scanner_finding_cannot_be_loaded(self, temp_db) -> None:
        from cerno_pkg.models import Finding, FindingType, Dataset
        from cerno_pkg.authored_findings import load_authored_finding

        dataset_id = Dataset(dataset_name="s", export_root="/tmp/s").save(temp_db)
        FindingType(
            finding_type_id="nessus:57608", finding_type_name="SMB", severity_int=3
        ).save(temp_db)
        finding_id = Finding(
            dataset_id=dataset_id, finding_type_id="nessus:57608"
        ).save(temp_db)
        with pytest.raises(AuthoredFindingError):
            load_authored_finding(finding_id, conn=temp_db)


@pytest.mark.integration
class TestAttribution:
    """The split's whole purpose: a stored finding says which channel wrote it.

    These are the regression tests for the incident that prompted the split --
    findings whose provenance was indistinguishable from a scanner's once
    written.
    """

    def test_source_has_no_default(self) -> None:
        """Attribution must be stated, never inherited.

        A default would let a new caller silently file its own findings under
        whichever channel happened to be the default, which is exactly the
        confusion the namespaces exist to prevent.
        """
        with pytest.raises(TypeError):
            create_authored_finding(_input())  # type: ignore[call-arg]

    @pytest.mark.parametrize("source", [SOURCE_OPERATOR, SOURCE_AGENT])
    def test_namespace_and_dataset_follow_the_source(self, temp_db, source) -> None:
        finding_type_id, finding_id = _create(_input(), source, conn=temp_db)
        assert finding_type_id.startswith(f"{source}:")

        row = temp_db.execute(
            "SELECT p.source_id, s.dataset_name FROM findings f "
            "JOIN finding_types p ON p.finding_type_id = f.finding_type_id "
            "JOIN datasets s ON s.dataset_id = f.dataset_id WHERE f.finding_id = ?",
            (finding_id,),
        ).fetchone()
        assert row["source_id"] == SOURCE_IDS[source]
        assert row["dataset_name"] == AUTHORED_DATASET_NAMES[source]

    def test_a_scanner_source_cannot_be_written(self, temp_db) -> None:
        """No hand-authored finding may masquerade as scanner output."""
        for scanner in ("nessus", "nuclei", "burp"):
            with pytest.raises(AuthoredFindingError):
                create_authored_finding(_input(), scanner, conn=temp_db)
        assert temp_db.execute("SELECT COUNT(*) FROM finding_types").fetchone()[0] == 0

    def test_unknown_source_is_refused(self, temp_db) -> None:
        with pytest.raises(AuthoredFindingError):
            create_authored_finding(_input(), "operater", conn=temp_db)

    def test_each_source_is_queryable_on_its_own(self, temp_db) -> None:
        from cerno_pkg.query import FindingQuery, run_finding_query

        _create(_input(title="Mine"), SOURCE_OPERATOR, conn=temp_db)
        _create(_input(title="Yours"), SOURCE_AGENT, conn=temp_db)

        operator_pairs = run_finding_query(FindingQuery(source="operator"), temp_db)
        agent_pairs = run_finding_query(FindingQuery(source="agent"), temp_db)
        assert [p.finding_type_name for _f, p in operator_pairs] == ["Mine"]
        assert [p.finding_type_name for _f, p in agent_pairs] == ["Yours"]
        assert [p.finding_type_id for _f, p in agent_pairs] == ["agent:1"]


@pytest.mark.integration
class TestEditsAreSymmetric:
    """Either channel may edit either namespace, and neither reattributes.

    The operator owns the engagement, so they must be able to correct what an
    agent asserted; an agent refining a finding the operator dictated is
    ordinary collaboration. What must *not* happen is the namespace moving,
    which would erase who first made the claim.
    """

    @pytest.mark.parametrize("source", [SOURCE_OPERATOR, SOURCE_AGENT])
    def test_edit_keeps_the_creating_namespace(self, temp_db, source) -> None:
        finding_type_id, finding_id = _create(_input(), source, conn=temp_db)
        returned = update_authored_finding(
            finding_id, title="Reworded entirely", severity_int=4, conn=temp_db
        )
        assert returned == finding_type_id == f"{source}:1"

        row = temp_db.execute(
            "SELECT finding_type_name, severity_int, source_id FROM finding_types "
            "WHERE finding_type_id = ?",
            (finding_type_id,),
        ).fetchone()
        assert row["finding_type_name"] == "Reworded entirely"
        assert row["severity_int"] == 4
        assert row["source_id"] == SOURCE_IDS[source]
