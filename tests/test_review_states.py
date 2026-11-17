"""Tests for the finding review workflow (unreviewed -> in_progress -> done -> unreviewed)."""

from cerno_pkg.constants import SOURCE_OPERATOR

import itertools
import sqlite3

import pytest

from cerno_pkg import database
from cerno_pkg.constants import REVIEW_STATES, REVIEW_TRANSITIONS
from cerno_pkg.database import SCHEMA_VERSION, SchemaVersionError, initialize_database
from cerno_pkg.fs import move_review_state
from cerno_pkg.models import (
    Finding,
    InvalidReviewTransition,
    FindingType,
    Dataset,
    count_review_states,
)

ALLOWED = {
    ("unreviewed", "in_progress"),
    ("in_progress", "done"),
    ("done", "unreviewed"),
}


def _seed_finding(conn, state="unreviewed") -> Finding:
    """Insert one scan + finding_type + finding in the given review state."""
    dataset_id = Dataset(dataset_name="s1", export_root="/tmp").save(conn)
    assert dataset_id is not None
    FindingType(
        finding_type_id="nessus:1001", finding_type_name="Test", severity_int=3
    ).save(conn)
    finding = Finding(
        dataset_id=dataset_id, finding_type_id="nessus:1001", review_state=state
    )
    finding.save(conn)
    return finding


@pytest.fixture
def file_db(temp_dir, monkeypatch):
    """Initialized on-disk DB with DATABASE_PATH pointed at it, plus one unreviewed finding."""
    db_path = temp_dir / "cerno.db"
    monkeypatch.setattr(database, "DATABASE_PATH", db_path)
    assert initialize_database(db_path)

    with database.db_transaction(database_path=db_path) as conn:
        finding = _seed_finding(conn)
    return db_path, finding


def _state(db_path, finding_id):
    conn = database.get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT review_state FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return row[0]
    finally:
        conn.close()


@pytest.mark.unit
def test_review_states_constant():
    assert REVIEW_STATES == ("unreviewed", "in_progress", "done")


@pytest.mark.unit
def test_transition_table_matches_workflow():
    pairs = {(src, dst) for src, dsts in REVIEW_TRANSITIONS.items() for dst in dsts}
    assert pairs == ALLOWED


@pytest.mark.unit
def test_new_finding_defaults_to_unreviewed():
    assert Finding().review_state == "unreviewed"


@pytest.mark.integration
class TestReviewStateCheckConstraint:
    @pytest.mark.parametrize("state", REVIEW_STATES)
    def test_valid_states_accepted(self, temp_db, state):
        assert _seed_finding(temp_db, state).review_state == state

    @pytest.mark.parametrize("state", ["pending", "reviewed", "completed", "skipped"])
    def test_legacy_states_rejected(self, temp_db, state):
        with pytest.raises(sqlite3.IntegrityError):
            _seed_finding(temp_db, state)

    def test_import_default_is_unreviewed(self, temp_db):
        dataset_id = Dataset(dataset_name="s", export_root="/tmp").save(temp_db)
        FindingType(
            finding_type_id="nessus:7", finding_type_name="p", severity_int=1
        ).save(temp_db)
        temp_db.execute(
            "INSERT INTO findings (dataset_id, finding_type_id) VALUES (?, 'nessus:7')",
            (dataset_id,),
        )
        row = temp_db.execute(
            "SELECT review_state FROM findings WHERE finding_type_id = 'nessus:7'"
        ).fetchone()
        assert row[0] == "unreviewed"


@pytest.mark.integration
class TestTransitionReviewState:
    @pytest.mark.parametrize(
        "src,dst", [p for p in itertools.product(REVIEW_STATES, repeat=2)]
    )
    def test_only_workflow_transitions_allowed(self, temp_db, src, dst):
        finding = _seed_finding(temp_db, src)
        if (src, dst) in ALLOWED:
            finding.transition_review_state(dst, SOURCE_OPERATOR, conn=temp_db)
            assert finding.review_state == dst
        else:
            with pytest.raises(InvalidReviewTransition):
                finding.transition_review_state(dst, SOURCE_OPERATOR, conn=temp_db)
            assert finding.review_state == src

    def test_invalid_transition_is_value_error(self):
        assert issubclass(InvalidReviewTransition, ValueError)

    @pytest.mark.parametrize(
        "src,expected",
        [("unreviewed", "in_progress"), ("in_progress", "done"), ("done", None)],
    )
    def test_next_review_state(self, src, expected):
        assert Finding(review_state=src).next_review_state() == expected


class TestAppendNote:
    """review_notes is append-only (no clobber across add_note / review-state notes)."""

    def _reload_notes(self, temp_db, finding):
        return Finding.get_by_id(finding.finding_id, temp_db).review_notes

    def test_append_note_accumulates(self, temp_db):
        finding = _seed_finding(temp_db)
        finding.append_note("first", temp_db)
        finding.append_note("second", temp_db)
        raw = self._reload_notes(temp_db, finding)
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        assert len(lines) == 2
        assert "first" in lines[0] and "second" in lines[1]
        # Timestamp prefix present on each entry.
        assert lines[0].startswith("[") and "]" in lines[0]

    def test_update_review_state_notes_append_not_overwrite(self, temp_db):
        finding = _seed_finding(temp_db)
        finding.append_note("manual note", temp_db)
        finding.update_review_state(
            "in_progress", SOURCE_OPERATOR, notes="review note", conn=temp_db
        )
        raw = self._reload_notes(temp_db, finding)
        assert "manual note" in raw
        assert "review note" in raw
        assert raw.index("manual note") < raw.index("review note")

    def test_update_review_state_without_notes_leaves_notes_untouched(self, temp_db):
        finding = _seed_finding(temp_db)
        finding.append_note("only note", temp_db)
        finding.update_review_state("in_progress", SOURCE_OPERATOR, conn=temp_db)
        raw = self._reload_notes(temp_db, finding)
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        assert lines == [raw.splitlines()[0]]
        assert "only note" in raw


@pytest.mark.integration
class TestMoveReviewState:
    def test_move_cycles_through_every_status(self, file_db):
        db_path, finding = file_db
        for expected in ("in_progress", "done", "unreviewed"):
            assert move_review_state(finding) == expected
            assert _state(db_path, finding.finding_id) == expected

    def test_move_back_to_unreviewed_from_done(self, file_db):
        db_path, finding = file_db
        move_review_state(finding)
        move_review_state(finding)
        assert move_review_state(finding, target="unreviewed") == "unreviewed"
        assert _state(db_path, finding.finding_id) == "unreviewed"

    @pytest.mark.parametrize(
        "steps,target", [(0, "done"), (0, "unreviewed"), (1, "unreviewed")]
    )
    def test_disallowed_target_leaves_status(self, file_db, steps, target):
        db_path, finding = file_db
        for _ in range(steps):
            move_review_state(finding)
        before = _state(db_path, finding.finding_id)
        assert move_review_state(finding, target=target) is None
        assert _state(db_path, finding.finding_id) == before


@pytest.mark.unit
def test_count_review_states():
    findings = [
        Finding(review_state=s)
        for s in ("unreviewed", "unreviewed", "in_progress", "done")
    ]
    assert count_review_states(findings) == (2, 1, 1, 4)


@pytest.mark.integration
class TestCountByScanSeverity:
    def test_counts_each_status(self, temp_db):
        dataset_id = Dataset(dataset_name="s", export_root="/tmp").save(temp_db)
        assert dataset_id is not None
        for pid, state in (
            ("nessus:1", "unreviewed"),
            ("nessus:2", "in_progress"),
            ("nessus:3", "done"),
            ("nessus:4", "done"),
        ):
            FindingType(
                finding_type_id=pid, finding_type_name=f"p{pid}", severity_int=3
            ).save(temp_db)
            Finding(
                dataset_id=dataset_id, finding_type_id=pid, review_state=state
            ).save(temp_db)
        assert Finding.count_by_dataset_severity(
            dataset_id, "3_High", conn=temp_db
        ) == (
            1,
            1,
            2,
            4,
        )
        assert Finding.count_by_dataset_severity(
            dataset_id, "2_Medium", conn=temp_db
        ) == (
            0,
            0,
            0,
            0,
        )

    def test_multi_dataset_uses_most_advanced_instance(self, temp_db):
        a = Dataset(dataset_name="a", export_root="/tmp").save(temp_db)
        b = Dataset(dataset_name="b", export_root="/tmp").save(temp_db)
        assert a is not None and b is not None
        FindingType(
            finding_type_id="nessus:1", finding_type_name="p1", severity_int=3
        ).save(temp_db)
        Finding(
            dataset_id=a, finding_type_id="nessus:1", review_state="unreviewed"
        ).save(temp_db)
        Finding(
            dataset_id=b, finding_type_id="nessus:1", review_state="in_progress"
        ).save(temp_db)
        counts = Finding.count_by_dataset_severity(
            a, "3_High", conn=temp_db, dataset_ids=[a, b]
        )
        assert counts == (0, 1, 0, 1)


@pytest.mark.integration
class TestSchemaVersionGuard:
    def test_fresh_database_gets_current_version(self, temp_dir):
        db_path = temp_dir / "fresh.db"
        assert initialize_database(db_path)
        conn = database.get_connection(db_path)
        try:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        finally:
            conn.close()

    def test_reinitialize_current_database_ok(self, temp_dir):
        db_path = temp_dir / "current.db"
        assert initialize_database(db_path)
        assert initialize_database(db_path)

    @pytest.mark.parametrize("old_version", [0, 2])
    def test_outdated_database_rejected(self, temp_dir, old_version):
        db_path = temp_dir / "old.db"
        assert initialize_database(db_path)
        conn = sqlite3.connect(str(db_path))
        conn.execute(f"PRAGMA user_version = {old_version}")
        conn.commit()
        conn.close()

        with pytest.raises(SchemaVersionError, match="re-import"):
            initialize_database(db_path)


@pytest.mark.unit
def test_status_legend_and_icons():
    """The legend explains every icon the Status column can show.

    Done used to be unreachable in this list, so the legend left ✓ out. Under
    the [D] Done-only filter every visible row carries ✓, so an incomplete
    legend is an unexplained glyph.
    """
    from cerno_pkg.render import (
        _review_state_cell,
        _status_legend,
    )  # pyright: ignore[reportPrivateUsage]

    assert _status_legend().plain == "Status: ○ Unreviewed  ◐ In Progress  ✓ Done"
    assert _review_state_cell("unreviewed").plain == "○"
    assert _review_state_cell("in_progress").plain == "◐"
    assert _review_state_cell("done").plain == "✓"


@pytest.mark.unit
class TestFilterFindingCandidates:
    """findings-list [I] status filter combined with the name and group filters."""

    @staticmethod
    def _records():
        return [
            (
                Finding(finding_type_id="nessus:1", review_state="unreviewed"),
                FindingType(
                    finding_type_id="nessus:1", finding_type_name="SSL Weak Cipher"
                ),
            ),
            (
                Finding(finding_type_id="nessus:2", review_state="in_progress"),
                FindingType(
                    finding_type_id="nessus:2", finding_type_name="SSL Self-Signed"
                ),
            ),
            (
                Finding(finding_type_id="nessus:3", review_state="in_progress"),
                FindingType(
                    finding_type_id="nessus:3", finding_type_name="SMB Signing"
                ),
            ),
            (
                Finding(finding_type_id="nessus:4", review_state="done"),
                FindingType(
                    finding_type_id="nessus:4", finding_type_name="SSL Expired Cert"
                ),
            ),
            (
                Finding(finding_type_id="nessus:5", review_state="done"),
                FindingType(
                    finding_type_id="nessus:5", finding_type_name="SMB Null Session"
                ),
            ),
        ]

    @staticmethod
    def _ids(records):
        return [p.finding_type_id for (_f, p) in records]

    def test_no_filters_returns_the_whole_pool(self):
        """With no status filter, every record in the pool survives.

        Hiding Done findings is the *caller's* job: ``browse_file_list`` picks
        the open or Done pool before calling this. Filtering Done out here too
        would make the Done-only view impossible.
        """
        from cerno_pkg.tui import filter_finding_candidates

        assert self._ids(
            filter_finding_candidates(self._records(), "", None, None)
        ) == ["nessus:1", "nessus:2", "nessus:3", "nessus:4", "nessus:5"]

    def test_in_progress_only(self):
        from cerno_pkg.tui import filter_finding_candidates

        result = filter_finding_candidates(self._records(), "", None, "in_progress")
        assert self._ids(result) == ["nessus:2", "nessus:3"]

    def test_done_only(self):
        """[D] filters to Done exactly as [I] filters to In Progress."""
        from cerno_pkg.tui import filter_finding_candidates

        result = filter_finding_candidates(self._records(), "", None, "done")
        assert self._ids(result) == ["nessus:4", "nessus:5"]

    def test_combines_with_name_filter(self):
        from cerno_pkg.tui import filter_finding_candidates

        result = filter_finding_candidates(self._records(), "ssl", None, "in_progress")
        assert self._ids(result) == ["nessus:2"]

    def test_done_combines_with_name_filter(self):
        """[F] narrows a Done-only list -- the workflow that replaced the
        old Done list's "move 1,3,5 back" subset prompt."""
        from cerno_pkg.tui import filter_finding_candidates

        result = filter_finding_candidates(self._records(), "smb", None, "done")
        assert self._ids(result) == ["nessus:5"]

    def test_combines_with_group_filter(self):
        from cerno_pkg.tui import filter_finding_candidates

        group = (
            1,
            {"Finding nessus:3: SMB Signing", "Finding nessus:1: SSL Weak Cipher"},
            "desc",
        )
        assert self._ids(
            filter_finding_candidates(self._records(), "", group, None)
        ) == ["nessus:1", "nessus:3"]
        assert self._ids(
            filter_finding_candidates(self._records(), "", group, "in_progress")
        ) == ["nessus:3"]

    def test_done_combines_with_group_filter(self):
        from cerno_pkg.tui import filter_finding_candidates

        group = (
            1,
            {
                "Finding nessus:4: SSL Expired Cert",
                "Finding nessus:1: SSL Weak Cipher",
            },
            "desc",
        )
        assert self._ids(
            filter_finding_candidates(self._records(), "", group, "done")
        ) == ["nessus:4"]


@pytest.mark.unit
class TestDoneListRemoved:
    """The separate [D] Done list is gone; [D] is a status filter now.

    The old list was a parallel reimplementation of the findings list that
    refused selection outright ("Read-only view; no finding selection here."),
    so a Done finding could not be opened, sorted, paged, or analysed. These
    tests pin the removal so it cannot grow back.
    """

    def test_action_result_has_no_reviewed_filter(self):
        """The Done list's private name filter left the action-result tuple."""
        import typing

        from cerno_pkg.tui import ActionResult

        assert len(typing.get_args(ActionResult)) == 5

    def test_handler_takes_neither_reviewed_nor_sev_map(self):
        """Its ``reviewed`` pool and dead ``sev_map`` parameter went with it."""
        import inspect

        from cerno_pkg.tui import handle_finding_list_actions

        params = inspect.signature(handle_finding_list_actions).parameters
        assert "reviewed" not in params
        assert "reviewed_filter" not in params
        assert "sev_map" not in params

    def test_handler_returns_five_tuple(self):
        """A real call returns the 5-tuple, not just an annotation that says so."""
        from cerno_pkg.tui import handle_finding_list_actions

        result = handle_finding_list_actions(
            "b",
            candidates=[],
            page_items=[],
            display=[],
            file_filter="",
            group_filter=None,
            sort_mode="severity",
            page_idx=0,
            total_pages=1,
        )
        assert len(result) == 5
        assert result[0] == "back"

    def test_d_is_no_longer_swallowed_by_the_handler(self):
        """``browse_file_list`` intercepts 'd' before the handler, like 'i'.

        If the handler still claimed 'd' it would shadow the filter toggle.
        """
        from cerno_pkg.tui import handle_finding_list_actions

        action_type, *_ = handle_finding_list_actions(
            "d",
            candidates=[],
            page_items=[],
            display=[],
            file_filter="",
            group_filter=None,
            sort_mode="severity",
            page_idx=0,
            total_pages=1,
        )
        assert action_type is None


@pytest.mark.integration
class TestRecordVerdict:
    """TUI manual verdict entry (fs.record_verdict)."""

    def _current(self, db_path, fid):
        from cerno_pkg.models import FindingVerdict

        conn = database.get_connection(db_path)
        try:
            v = FindingVerdict.get_current(fid, conn)
            return None if v is None else v.verdict_label
        finally:
            conn.close()

    def test_confirmed_records_and_offers_done(self, file_db, monkeypatch):
        from cerno_pkg import fs

        db_path, finding = file_db
        monkeypatch.setattr(fs.Prompt, "ask", staticmethod(lambda *a, **k: "1"))
        monkeypatch.setattr(fs.Confirm, "ask", staticmethod(lambda *a, **k: True))

        moved = fs.record_verdict(finding)
        assert moved is True
        assert self._current(db_path, finding.finding_id) == "confirmed"
        assert _state(db_path, finding.finding_id) == "done"

    def test_confirmed_decline_move_keeps_state(self, file_db, monkeypatch):
        from cerno_pkg import fs

        db_path, finding = file_db
        monkeypatch.setattr(fs.Prompt, "ask", staticmethod(lambda *a, **k: "1"))
        monkeypatch.setattr(fs.Confirm, "ask", staticmethod(lambda *a, **k: False))

        moved = fs.record_verdict(finding)
        assert moved is False
        assert self._current(db_path, finding.finding_id) == "confirmed"
        assert _state(db_path, finding.finding_id) == "unreviewed"

    def test_unable_records_without_move_offer(self, file_db, monkeypatch):
        from cerno_pkg import fs

        db_path, finding = file_db
        monkeypatch.setattr(fs.Prompt, "ask", staticmethod(lambda *a, **k: "3"))

        def _no_confirm(*a, **k):  # must not be called for 'unable'
            raise AssertionError("Confirm.ask should not be called for 'unable'")

        monkeypatch.setattr(fs.Confirm, "ask", staticmethod(_no_confirm))

        moved = fs.record_verdict(finding)
        assert moved is False
        assert self._current(db_path, finding.finding_id) == "unable"
        assert _state(db_path, finding.finding_id) == "unreviewed"

    def test_cancel_records_nothing(self, file_db, monkeypatch):
        from cerno_pkg import fs

        db_path, finding = file_db
        monkeypatch.setattr(fs.Prompt, "ask", staticmethod(lambda *a, **k: ""))

        moved = fs.record_verdict(finding)
        assert moved is False
        assert self._current(db_path, finding.finding_id) is None


@pytest.mark.integration
class TestCompletionAttribution:
    """`findings.completed_by` records which channel moved a finding to Done.

    The point of the column is that it is trustworthy, so these tests pin the
    two things that make it so: the actor is required (never defaulted), and it
    does not linger once the finding leaves Done.
    """

    def test_operator_move_to_done_records_the_operator_channel(self, temp_db):
        from cerno_pkg.constants import SOURCE_IDS

        finding = _seed_finding(temp_db, state="in_progress")
        finding.transition_review_state("done", SOURCE_OPERATOR, conn=temp_db)
        row = temp_db.execute(
            "SELECT completed_by FROM findings WHERE finding_id = ?",
            (finding.finding_id,),
        ).fetchone()
        assert row["completed_by"] == SOURCE_IDS[SOURCE_OPERATOR]

    def test_agent_move_to_done_records_the_agent_channel(self, temp_db):
        from cerno_pkg.constants import SOURCE_AGENT, SOURCE_IDS

        finding = _seed_finding(temp_db, state="in_progress")
        finding.transition_review_state("done", SOURCE_AGENT, conn=temp_db)
        row = temp_db.execute(
            "SELECT completed_by FROM findings WHERE finding_id = ?",
            (finding.finding_id,),
        ).fetchone()
        assert row["completed_by"] == SOURCE_IDS[SOURCE_AGENT]

    def test_moving_back_out_of_done_clears_the_attribution(self, temp_db):
        """Otherwise the column claims someone completed a finding in review."""
        finding = _seed_finding(temp_db, state="in_progress")
        finding.transition_review_state("done", SOURCE_OPERATOR, conn=temp_db)
        finding.transition_review_state("unreviewed", SOURCE_OPERATOR, conn=temp_db)
        row = temp_db.execute(
            "SELECT completed_by, reviewed_at FROM findings WHERE finding_id = ?",
            (finding.finding_id,),
        ).fetchone()
        assert row["completed_by"] is None
        assert row["reviewed_at"] is None

    def test_in_progress_carries_no_completion(self, temp_db):
        finding = _seed_finding(temp_db)
        finding.transition_review_state("in_progress", SOURCE_OPERATOR, conn=temp_db)
        row = temp_db.execute(
            "SELECT completed_by FROM findings WHERE finding_id = ?",
            (finding.finding_id,),
        ).fetchone()
        assert row["completed_by"] is None

    def test_a_scanner_source_is_not_an_acting_channel(self, temp_db):
        """nessus did not move anything to Done."""
        from cerno_pkg.constants import SOURCE_NESSUS

        finding = _seed_finding(temp_db, state="in_progress")
        with pytest.raises(ValueError, match="not an acting channel"):
            finding.transition_review_state("done", SOURCE_NESSUS, conn=temp_db)

    def test_the_actor_is_required(self, temp_db):
        """A default would let a caller silently file an agent move as the operator."""
        finding = _seed_finding(temp_db, state="in_progress")
        with pytest.raises(TypeError):
            finding.transition_review_state("done", conn=temp_db)  # type: ignore[call-arg]
