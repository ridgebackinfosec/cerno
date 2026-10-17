"""Tests for the finding review workflow (unreviewed -> in_progress -> done -> unreviewed)."""

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
    Plugin,
    Scan,
    count_review_states,
)

ALLOWED = {
    ("unreviewed", "in_progress"),
    ("in_progress", "done"),
    ("done", "unreviewed"),
}


def _seed_finding(conn, state="unreviewed") -> Finding:
    """Insert one scan + plugin + finding in the given review state."""
    scan_id = Scan(scan_name="s1", export_root="/tmp").save(conn)
    assert scan_id is not None
    Plugin(plugin_id=1001, plugin_name="Test", severity_int=3).save(conn)
    finding = Finding(scan_id=scan_id, plugin_id=1001, review_state=state)
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
        scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
        Plugin(plugin_id=7, plugin_name="p", severity_int=1).save(temp_db)
        temp_db.execute("INSERT INTO findings (scan_id, plugin_id) VALUES (?, 7)", (scan_id,))
        row = temp_db.execute("SELECT review_state FROM findings WHERE plugin_id = 7").fetchone()
        assert row[0] == "unreviewed"


@pytest.mark.integration
class TestTransitionReviewState:
    @pytest.mark.parametrize(
        "src,dst", [p for p in itertools.product(REVIEW_STATES, repeat=2)]
    )
    def test_only_workflow_transitions_allowed(self, temp_db, src, dst):
        finding = _seed_finding(temp_db, src)
        if (src, dst) in ALLOWED:
            finding.transition_review_state(dst, conn=temp_db)
            assert finding.review_state == dst
        else:
            with pytest.raises(InvalidReviewTransition):
                finding.transition_review_state(dst, conn=temp_db)
            assert finding.review_state == src

    def test_invalid_transition_is_value_error(self):
        assert issubclass(InvalidReviewTransition, ValueError)

    @pytest.mark.parametrize(
        "src,expected",
        [("unreviewed", "in_progress"), ("in_progress", "done"), ("done", None)],
    )
    def test_next_review_state(self, src, expected):
        assert Finding(review_state=src).next_review_state() == expected


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

    @pytest.mark.parametrize("steps,target", [(0, "done"), (0, "unreviewed"), (1, "unreviewed")])
    def test_disallowed_target_leaves_status(self, file_db, steps, target):
        db_path, finding = file_db
        for _ in range(steps):
            move_review_state(finding)
        before = _state(db_path, finding.finding_id)
        assert move_review_state(finding, target=target) is None
        assert _state(db_path, finding.finding_id) == before


@pytest.mark.unit
def test_count_review_states():
    findings = [Finding(review_state=s) for s in ("unreviewed", "unreviewed", "in_progress", "done")]
    assert count_review_states(findings) == (2, 1, 1, 4)


@pytest.mark.integration
class TestCountByScanSeverity:
    def test_counts_each_status(self, temp_db):
        scan_id = Scan(scan_name="s", export_root="/tmp").save(temp_db)
        assert scan_id is not None
        for pid, state in ((1, "unreviewed"), (2, "in_progress"), (3, "done"), (4, "done")):
            Plugin(plugin_id=pid, plugin_name=f"p{pid}", severity_int=3).save(temp_db)
            Finding(scan_id=scan_id, plugin_id=pid, review_state=state).save(temp_db)
        assert Finding.count_by_scan_severity(scan_id, "3_High", conn=temp_db) == (1, 1, 2, 4)
        assert Finding.count_by_scan_severity(scan_id, "2_Medium", conn=temp_db) == (0, 0, 0, 0)

    def test_multi_scan_uses_most_advanced_instance(self, temp_db):
        a = Scan(scan_name="a", export_root="/tmp").save(temp_db)
        b = Scan(scan_name="b", export_root="/tmp").save(temp_db)
        assert a is not None and b is not None
        Plugin(plugin_id=1, plugin_name="p1", severity_int=3).save(temp_db)
        Finding(scan_id=a, plugin_id=1, review_state="unreviewed").save(temp_db)
        Finding(scan_id=b, plugin_id=1, review_state="in_progress").save(temp_db)
        counts = Finding.count_by_scan_severity(a, "3_High", conn=temp_db, scan_ids=[a, b])
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
    from cerno_pkg.render import _review_state_cell, _status_legend  # pyright: ignore[reportPrivateUsage]

    assert _status_legend().plain == "Status: ○ Unreviewed  ◐ In Progress"
    assert _review_state_cell("unreviewed").plain == "○"
    assert _review_state_cell("in_progress").plain == "◐"
