"""Tests for cerno_pkg.session module (database-only mode)."""

from datetime import datetime

import pytest

from cerno_pkg.session import (
    SessionState,
    save_session,
    load_session,
    delete_session,
)


# Ensure database is enabled for tests and use temp_db
@pytest.fixture(autouse=True)
def ensure_db_enabled(monkeypatch, temp_db):
    """Ensure database is enabled and use temp_db for all tests."""
    import cerno_pkg.database

    # Monkeypatch get_connection to return our temp_db
    # Create a wrapper that prevents the connection from being closed
    class UnclosableConnection:
        """Wrapper that delegates to real connection but prevents close()."""

        def __init__(self, conn):
            self._conn = conn

        def __getattr__(self, name):
            if name == "close":
                # Don't actually close the connection
                return lambda: None
            return getattr(self._conn, name)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    def mock_get_connection(database_path=None):
        return UnclosableConnection(temp_db)

    monkeypatch.setattr(cerno_pkg.database, "get_connection", mock_get_connection)


class TestSessionState:
    """Tests for SessionState dataclass."""

    def test_session_state_creation(self):
        """Test creating SessionState with all fields."""
        state = SessionState(
            scan_name="test_scan",
            session_start="2024-01-15T10:30:00",
            in_progress_count=2,
            done_count=1,
            tool_executions=5,
            cve_extractions=2,
        )

        assert state.scan_name == "test_scan"
        assert state.in_progress_count == 2
        assert state.done_count == 1
        assert state.tool_executions == 5
        assert state.cve_extractions == 2

    def test_session_state_empty_counts(self):
        """Test SessionState with zero counts."""
        state = SessionState(
            scan_name="empty_scan",
            session_start="2024-01-15T10:00:00",
            in_progress_count=0,
            done_count=0,
            tool_executions=0,
            cve_extractions=0,
        )

        assert state.in_progress_count == 0
        assert state.done_count == 0


class TestSaveSession:
    """Tests for save_session function."""

    def test_save_session_basic(self, temp_db):
        """Test basic session save to database."""
        from cerno_pkg.models import Scan, Plugin, Finding

        # Create scan in database
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        session_start = datetime(2024, 1, 15, 10, 30, 0)

        # Create plugin files with reviewed_at timestamps after session start
        # so they'll be counted by v_session_stats view
        review_time = (
            session_start + __import__("datetime").timedelta(minutes=5)
        ).isoformat()

        # Create 2 in-progress files
        for i in range(2):
            plugin = Plugin(
                plugin_id=f"nessus:{1000 + i}", plugin_name=f"Test{i}", severity_int=3
            )
            plugin.save(temp_db)
            pf = Finding(
                scan_id=scan_id,
                plugin_id=f"nessus:{1000 + i}",
                review_state="in_progress",
                reviewed_at=review_time,
            )
            pf.save(temp_db)

        # Create 1 done file
        plugin = Plugin(plugin_id="nessus:1002", plugin_name="Test2", severity_int=3)
        plugin.save(temp_db)
        pf = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1002",
            review_state="done",
            reviewed_at=review_time,
        )
        pf.save(temp_db)

        # Create 1 pending file (not counted by v_session_stats)
        plugin = Plugin(plugin_id="nessus:1003", plugin_name="Test3", severity_int=3)
        plugin.save(temp_db)
        pf = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1003",
            review_state="unreviewed",
            reviewed_at=review_time,
        )
        pf.save(temp_db)

        # Save session (counts are now computed from findings, not stored)
        session_id = save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=2,
            done_count=1,
            tool_executions=5,
            cve_extractions=2,
        )

        assert session_id is not None

        # Verify session in database (use v_session_stats view for computed stats)
        cursor = temp_db.execute(
            """
            SELECT vs.files_in_progress, vs.files_done, 
                   vs.tools_executed, vs.cves_extracted, vs.session_end
            FROM v_session_stats vs
            WHERE vs.scan_id = ? AND vs.session_id = ?
            """,
            (scan_id, session_id),
        )
        row = cursor.fetchone()

        assert row is not None
        assert row["files_in_progress"] == 2
        assert row["files_done"] == 1
        # tools_executed and cves_extracted will be 0 since we didn't create those records
        assert row["session_end"] is None  # Active session

    def test_save_session_updates_scan_last_reviewed(self, temp_db):
        """Test that save_session updates scan's last_reviewed_at."""
        from cerno_pkg.models import Scan

        # Create scan
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Verify last_reviewed_at is initially None
        cursor = temp_db.execute(
            "SELECT last_reviewed_at FROM scans WHERE scan_id = ?", (scan_id,)
        )
        assert cursor.fetchone()["last_reviewed_at"] is None

        # Save session
        session_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(scan_id=scan_id, session_start=session_start, in_progress_count=1)

        # Verify last_reviewed_at is now set
        cursor = temp_db.execute(
            "SELECT last_reviewed_at FROM scans WHERE scan_id = ?", (scan_id,)
        )
        last_reviewed = cursor.fetchone()["last_reviewed_at"]
        assert last_reviewed is not None

    def test_save_session_updates_last_reviewed_for_all_scans(self, temp_db):
        """Test that multi-scan sessions stamp last_reviewed_at on every selected scan."""
        from cerno_pkg.models import Scan

        scan_a = Scan(scan_name="scan_a", export_root="/tmp").save(temp_db)
        scan_b = Scan(scan_name="scan_b", export_root="/tmp").save(temp_db)
        scan_c = Scan(scan_name="scan_c", export_root="/tmp").save(temp_db)
        assert scan_a is not None and scan_b is not None and scan_c is not None

        save_session(
            scan_id=scan_a,
            session_start=datetime(2024, 1, 15, 10, 0, 0),
            additional_scan_ids=[scan_b],
        )

        rows = {
            r["scan_id"]: r["last_reviewed_at"]
            for r in temp_db.execute("SELECT scan_id, last_reviewed_at FROM scans")
        }
        assert rows[scan_a] is not None
        assert rows[scan_b] == rows[scan_a]
        assert rows[scan_c] is None

    def test_save_session_updates_existing_session(self, temp_db):
        """Test that save_session updates existing active session."""
        from cerno_pkg.models import Scan, Plugin, Finding

        # Create scan
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        review_time = (
            session_start + __import__("datetime").timedelta(minutes=5)
        ).isoformat()

        # First save - create session
        session_id_1 = save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=1,
            done_count=0,
            tool_executions=1,
            cve_extractions=0,
        )

        # Add plugin files for second save scenario
        # Create 3 in-progress files
        for i in range(3):
            plugin = Plugin(
                plugin_id=f"nessus:{2000 + i}", plugin_name=f"Test{i}", severity_int=3
            )
            plugin.save(temp_db)
            pf = Finding(
                scan_id=scan_id,
                plugin_id=f"nessus:{2000 + i}",
                review_state="in_progress",
                reviewed_at=review_time,
            )
            pf.save(temp_db)

        # Create 2 done files
        for i in range(2):
            plugin = Plugin(
                plugin_id=f"nessus:{2010 + i}",
                plugin_name=f"Complete{i}",
                severity_int=3,
            )
            plugin.save(temp_db)
            pf = Finding(
                scan_id=scan_id,
                plugin_id=f"nessus:{2010 + i}",
                review_state="done",
                reviewed_at=review_time,
            )
            pf.save(temp_db)

        # Second save (should update, not create new)
        session_id_2 = save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=3,
            done_count=2,
            tool_executions=5,
            cve_extractions=2,
        )

        # Should return same session_id
        assert session_id_1 == session_id_2

        # Verify only one active session exists with updated counts
        cursor = temp_db.execute(
            """
            SELECT COUNT(*) as count, vs.files_in_progress, vs.files_done, vs.tools_executed
            FROM v_session_stats vs
            WHERE vs.scan_id = ? AND vs.session_end IS NULL
            """,
            (scan_id,),
        )
        row = cursor.fetchone()

        assert row["count"] == 1
        assert row["files_in_progress"] == 3
        assert row["files_done"] == 2
        # tools_executed will be 0 since we didn't create tool_executions records

    def test_save_session_with_zero_counts(self, temp_db):
        """Test saving session with all zero counts."""
        from cerno_pkg.models import Scan

        # Create scan
        scan = Scan(scan_name="empty_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        # Save session with zeros
        session_id = save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=0,
            done_count=0,
            tool_executions=0,
            cve_extractions=0,
        )

        assert session_id is not None

        # Verify database
        cursor = temp_db.execute(
            "SELECT files_in_progress, files_done FROM v_session_stats WHERE session_id = ?",
            (session_id,),
        )
        row = cursor.fetchone()

        assert row["files_in_progress"] == 0
        assert row["files_done"] == 0

    def test_empty_session_updates_last_reviewed_at(self, temp_db):
        """Test that saving an empty session (zero counts) still updates last_reviewed_at."""
        from cerno_pkg.models import Scan

        # Create scan
        scan = Scan(scan_name="empty_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Verify last_reviewed_at is initially None
        cursor = temp_db.execute(
            "SELECT last_reviewed_at FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cursor.fetchone()
        assert row["last_reviewed_at"] is None

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        # Save empty session (zero counts)
        session_id = save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=0,
            done_count=0,
        )

        assert session_id is not None

        # Verify last_reviewed_at is now set
        cursor = temp_db.execute(
            "SELECT last_reviewed_at FROM scans WHERE scan_id = ?", (scan_id,)
        )
        row = cursor.fetchone()
        assert row["last_reviewed_at"] is not None

    def test_empty_session_can_be_ended(self, temp_db):
        """Test that an empty session (zero counts) can be properly ended."""
        from cerno_pkg.models import Scan

        # Create scan
        scan = Scan(scan_name="empty_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        session_start = datetime(2024, 1, 15, 10, 0, 0)

        # Save empty session
        session_id = save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=0,
            done_count=0,
        )

        assert session_id is not None

        # Verify session exists with NULL session_end
        cursor = temp_db.execute(
            "SELECT session_id, session_end FROM sessions WHERE session_id = ?",
            (session_id,),
        )
        row = cursor.fetchone()
        assert row["session_id"] == session_id
        assert row["session_end"] is None

        # End the session
        delete_session(scan_id)

        # Verify session_end is now set
        cursor = temp_db.execute(
            "SELECT session_end FROM sessions WHERE session_id = ?", (session_id,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is not None


class TestLoadSession:
    """Tests for load_session function."""

    def test_load_session_success(self, temp_db):
        """Test loading active session from database."""
        from cerno_pkg.models import Scan, Plugin, Finding

        # Create scan
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Create session first to get session_start
        session_start = datetime(2024, 1, 15, 10, 30, 0)
        review_time = (
            session_start + __import__("datetime").timedelta(minutes=5)
        ).isoformat()

        # Create plugins and files to match expected counts
        # Need unique plugin_id for each Finding due to UNIQUE(scan_id, plugin_id)

        # Create 2 in-progress files
        for i in range(2):
            plugin = Plugin(
                plugin_id=f"nessus:{1001 + i}", plugin_name=f"Test{i}", severity_int=3
            )
            plugin.save(temp_db)
            pf = Finding(
                scan_id=scan_id,
                plugin_id=f"nessus:{1001 + i}",
                review_state="in_progress",
                reviewed_at=review_time,
            )
            pf.save(temp_db)

        # Create 1 done file
        plugin = Plugin(plugin_id="nessus:1003", plugin_name="Test3", severity_int=3)
        plugin.save(temp_db)
        pf = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1003",
            review_state="done",
            reviewed_at=review_time,
        )
        pf.save(temp_db)

        # Create 1 pending file (not counted by v_session_stats)
        plugin = Plugin(plugin_id="nessus:1004", plugin_name="Test4", severity_int=3)
        plugin.save(temp_db)
        pf = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1004",
            review_state="unreviewed",
            reviewed_at=review_time,
        )
        pf.save(temp_db)

        # Create session
        save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=2,
            done_count=1,
            tool_executions=5,
            cve_extractions=2,
        )

        # Load session - counts should come from actual findings review_state
        state = load_session(scan_id)

        assert state is not None
        assert state.scan_name == "test_scan"
        assert state.in_progress_count == 2
        assert state.done_count == 1
        # tool_executions and cve_extractions will be 0 since we didn't create those records

    def test_load_session_nonexistent(self, temp_db):
        """Test loading when no session exists."""
        from cerno_pkg.models import Scan

        # Create scan without session
        scan = Scan(scan_name="no_session_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        state = load_session(scan_id)

        assert state is None

    def test_load_session_ended_session_returns_none(self, temp_db):
        """Test that ended sessions are not loaded."""
        from cerno_pkg.models import Scan

        # Create scan and session
        scan = Scan(scan_name="ended_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(scan_id=scan_id, session_start=session_start, in_progress_count=1)

        # End the session
        delete_session(scan_id)

        # load_session should return None for ended session
        state = load_session(scan_id)
        assert state is None

    def test_load_session_with_findings(self, temp_db):
        """Test that load_session aggregates review states from findings."""
        from cerno_pkg.models import Scan, Plugin, Finding

        # Create scan
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Create session first to get session_start
        session_start = datetime(2024, 1, 15, 10, 0, 0)
        review_time = (
            session_start + __import__("datetime").timedelta(minutes=5)
        ).isoformat()

        # Create plugins and plugin files with different review states
        # Need unique plugin_id for each Finding due to UNIQUE(scan_id, plugin_id)

        plugin1 = Plugin(
            plugin_id="nessus:1001", plugin_name="Test Plugin 1", severity_int=3
        )
        plugin1.save(temp_db)
        pf1 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1001",
            review_state="in_progress",
            reviewed_at=review_time,
        )
        pf1.save(temp_db)

        plugin2 = Plugin(
            plugin_id="nessus:1002", plugin_name="Test Plugin 2", severity_int=3
        )
        plugin2.save(temp_db)
        pf2 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1002",
            review_state="done",
            reviewed_at=review_time,
        )
        pf2.save(temp_db)

        plugin3 = Plugin(
            plugin_id="nessus:1003", plugin_name="Test Plugin 3", severity_int=3
        )
        plugin3.save(temp_db)
        pf3 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1003",
            review_state="unreviewed",
            reviewed_at=review_time,
        )
        pf3.save(temp_db)

        # Create session
        save_session(scan_id=scan_id, session_start=session_start, tool_executions=3)

        # Load session - should aggregate from findings
        state = load_session(scan_id)

        assert state is not None
        assert state.in_progress_count == 1  # One with review_state='in_progress'
        assert state.done_count == 1  # One with review_state='done'


class TestDeleteSession:
    """Tests for delete_session function."""

    def test_delete_session_ends_active_session(self, temp_db):
        """Test that delete_session marks database session as ended."""
        from cerno_pkg.models import Scan

        # Create scan and session
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(scan_id=scan_id, session_start=session_start, in_progress_count=1)

        # Verify session is active
        cursor = temp_db.execute(
            "SELECT session_end FROM sessions WHERE scan_id = ?", (scan_id,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is None

        # Delete session
        delete_session(scan_id)

        # Verify session is ended (use v_session_stats view for duration_seconds)
        cursor = temp_db.execute(
            "SELECT session_end, duration_seconds FROM v_session_stats WHERE scan_id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()
        assert row["session_end"] is not None
        assert row["duration_seconds"] is not None
        assert row["duration_seconds"] >= 0

    def test_delete_session_no_active_session(self, temp_db):
        """Test delete_session when no active session exists."""
        from cerno_pkg.models import Scan

        # Create scan without session
        scan = Scan(scan_name="no_session_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Should not raise exception
        delete_session(scan_id)

    def test_delete_session_with_already_ended_session(self, temp_db):
        """Test delete_session when session is already ended."""
        from cerno_pkg.models import Scan

        # Create scan and session
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(scan_id=scan_id, session_start=session_start, in_progress_count=1)

        # End session once
        delete_session(scan_id)

        # End again - should be no-op
        delete_session(scan_id)

        # Verify only one session exists
        cursor = temp_db.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE scan_id = ?", (scan_id,)
        )
        assert cursor.fetchone()["count"] == 1


class TestSessionLifecycle:
    """Integration tests for complete session lifecycle."""

    def test_complete_session_lifecycle(self, temp_db):
        """Test complete session lifecycle: save → load → update → delete."""
        from cerno_pkg.models import Scan, Plugin, Finding

        # Create scan
        scan = Scan(scan_name="lifecycle_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Create plugins - need unique plugin_id for each Finding due to UNIQUE(scan_id, plugin_id)
        for i in range(1, 7):
            plugin = Plugin(
                plugin_id=f"nessus:{1000 + i}", plugin_name=f"Test{i}", severity_int=3
            )
            plugin.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        review_time = (
            session_start + __import__("datetime").timedelta(minutes=5)
        ).isoformat()

        # 1. Create initial session with 1 reviewed file
        pf1 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1001",
            review_state="in_progress",
            reviewed_at=review_time,
        )
        pf1.save(temp_db)

        save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=1,
            done_count=0,
            tool_executions=1,
            cve_extractions=0,
        )

        # 2. Load session
        state = load_session(scan_id)
        assert state is not None
        assert state.in_progress_count == 1
        # tool_executions will be 0 since we didn't create tool_executions records

        # 3. Update: add more files with different review states
        pf2 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1002",
            review_state="in_progress",
            reviewed_at=review_time,
        )
        pf2.save(temp_db)

        pf3 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1003",
            review_state="in_progress",
            reviewed_at=review_time,
        )
        pf3.save(temp_db)

        pf4 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1004",
            review_state="done",
            reviewed_at=review_time,
        )
        pf4.save(temp_db)

        pf5 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1005",
            review_state="done",
            reviewed_at=review_time,
        )
        pf5.save(temp_db)

        pf6 = Finding(
            scan_id=scan_id,
            plugin_id="nessus:1006",
            review_state="unreviewed",
            reviewed_at=review_time,
        )
        pf6.save(temp_db)

        # Update session
        save_session(
            scan_id=scan_id,
            session_start=session_start,
            in_progress_count=3,
            done_count=2,
            tool_executions=8,
            cve_extractions=3,
        )

        # 4. Load updated session - counts from findings
        state = load_session(scan_id)
        assert state is not None
        assert state.in_progress_count == 3
        assert state.done_count == 2
        # tool_executions and cve_extractions will be 0 since we didn't create those records

        # 5. Verify database has updated counts
        cursor = temp_db.execute(
            """
            SELECT files_in_progress, files_done, tools_executed, cves_extracted
            FROM v_session_stats WHERE scan_id = ?
            """,
            (scan_id,),
        )
        row = cursor.fetchone()
        assert row["files_in_progress"] == 3
        assert row["files_done"] == 2
        # tools_executed and cves_extracted will be 0 since we didn't create those records

        # 6. Delete session
        delete_session(scan_id)

        # 7. Verify cleanup
        state = load_session(scan_id)
        assert state is None

        # Verify database session is marked ended
        cursor = temp_db.execute(
            "SELECT session_end FROM sessions WHERE scan_id = ?", (scan_id,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is not None

    def test_multiple_sessions_for_same_scan(self, temp_db):
        """Test multiple sequential sessions for the same scan."""
        from cerno_pkg.models import Scan

        # Create scan
        scan = Scan(scan_name="multi_session_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        # Session 1
        session1_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(
            scan_id=scan_id,
            session_start=session1_start,
            in_progress_count=1,
            done_count=0,
        )
        delete_session(scan_id)

        # Session 2
        session2_start = datetime(2024, 1, 15, 14, 0, 0)
        save_session(
            scan_id=scan_id,
            session_start=session2_start,
            in_progress_count=2,
            done_count=1,
        )
        delete_session(scan_id)

        # Verify both sessions in database
        cursor = temp_db.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE scan_id = ?", (scan_id,)
        )
        row = cursor.fetchone()
        assert row["count"] == 2

        # Verify both sessions have end times
        cursor = temp_db.execute(
            "SELECT COUNT(*) as ended_count FROM sessions WHERE scan_id = ? AND session_end IS NOT NULL",
            (scan_id,),
        )
        row = cursor.fetchone()
        assert row["ended_count"] == 2


@pytest.mark.unit
def test_show_session_statistics_prints_severity_breakdown(monkeypatch, tmp_path):
    """The per-severity Done table is printed, not just built."""
    from contextlib import contextmanager
    from io import StringIO

    from rich.console import Console

    import cerno
    import cerno_pkg.database as database

    buf = StringIO()
    console = Console(file=buf, width=120, force_terminal=False)
    monkeypatch.setattr(cerno, "get_console", lambda: console)
    monkeypatch.setattr(cerno, "_console_global", console)

    @contextmanager
    def fake_tx(conn=None):
        yield None

    monkeypatch.setattr(database, "db_transaction", fake_tx)
    monkeypatch.setattr(
        database, "query_all", lambda *a, **k: [("High", 2), ("Critical", 1)]
    )

    cerno.show_session_statistics(
        datetime.now(), [], ["f1", "f2", "f3"], tmp_path, scan_id=1
    )

    out = buf.getvalue()
    assert "Done by severity" in out
    # Ordered by severity (Critical before High), not alphabetically.
    assert out.index("Critical") < out.index("High")


# ---------------------------------------------------------------------------
# Scan overview "Host & Port Analysis" breakdown
#
# Regression: the IPv4/IPv6 rows used to be bucketed by hosts.scan_target_type
# (the type of the *scan target string*) while the value being bucketed was
# hosts.ip_address. A host scanned by hostname is type 'fqdn', so its perfectly
# valid resolved IP landed in neither bucket and the children did not sum to
# the parent -- the "unique hosts count is off by one" report.
# ---------------------------------------------------------------------------


def _overview_rows(temp_db, monkeypatch, scan_id):
    """Render show_scan_summary and return {row label: int} for the analysis table."""
    import re
    from io import StringIO
    from pathlib import Path

    from rich.console import Console

    import cerno_pkg.ansi as ansi

    buf = StringIO()
    console = Console(file=buf, width=120, force_terminal=False)
    monkeypatch.setattr(ansi, "get_console", lambda: console)

    from cerno_pkg.session import show_scan_summary

    show_scan_summary(Path("engagement"), top_ports_n=1, scan_id=scan_id)

    rows = {}
    for line in buf.getvalue().splitlines():
        m = re.match(r"\s*(?:└─\s*)?([A-Za-z][A-Za-z0-9 ]*?)\s{2,}(\d+)\s*$", line)
        if m:
            rows[m.group(1).strip()] = int(m.group(2))
    return rows


@pytest.fixture
def overview_scan(temp_db):
    """One scan whose hosts cover every ip_address/scan_target_type combination."""
    from cerno_pkg.models import Finding, Host, Plugin, Port, Scan

    scan_id = Scan(scan_name="engagement", export_root="/tmp").save(temp_db)
    Plugin(plugin_id="nessus:100", plugin_name="SMB Signing", severity_int=3).save(
        temp_db
    )
    finding_id = Finding(scan_id=scan_id, plugin_id="nessus:100").save(temp_db)
    Port.get_or_create(445, conn=temp_db)

    host_ids = [
        # Scanned by IP -> type 'ipv4', ip is IPv4.
        Host.get_or_create("10.0.0.1", "10.0.0.1", "ipv4", conn=temp_db),
        # Scanned by hostname -> type 'fqdn', but the resolved ip IS IPv4.
        Host.get_or_create("10.0.0.2", "portal.example", "fqdn", conn=temp_db),
        # Scanned by hostname -> type 'fqdn', and the resolved ip is IPv6.
        Host.get_or_create("2001:db8::1", "v6.example", "fqdn", conn=temp_db),
        # No resolved IP at all: nuclei/ingest key such hosts as (host, host).
        Host.get_or_create("orphan.example", "orphan.example", "fqdn", conn=temp_db),
    ]
    for host_id in host_ids:
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number) "
            "VALUES (?, ?, ?)",
            (finding_id, host_id, 445),
        )
    temp_db.commit()
    return scan_id


@pytest.mark.integration
def test_overview_breakdown_sums_to_unique_hosts(overview_scan, temp_db, monkeypatch):
    """IPv4 + IPv6 + No resolved IP must equal Unique Hosts."""
    rows = _overview_rows(temp_db, monkeypatch, overview_scan)

    assert rows["Unique Hosts"] == 4
    children = rows["IPv4"] + rows["IPv6"] + rows["No resolved IP"]
    assert children == rows["Unique Hosts"], rows


@pytest.mark.integration
def test_overview_classifies_by_ip_not_scan_target_type(
    overview_scan, temp_db, monkeypatch
):
    """A hostname-targeted host is classified by its resolved IP, not its target type."""
    rows = _overview_rows(temp_db, monkeypatch, overview_scan)

    # 10.0.0.1 (ipv4 target) and 10.0.0.2 (fqdn target, IPv4 ip).
    assert rows["IPv4"] == 2
    # 2001:db8::1 reached via an fqdn target still counts as IPv6.
    assert rows["IPv6"] == 1
    # orphan.example has no resolvable address in ip_address.
    assert rows["No resolved IP"] == 1


@pytest.mark.integration
def test_overview_reports_scan_targets_under_vhosting(temp_db, monkeypatch):
    """One IP with several vhosts: 1 machine, 3 scan targets."""
    from cerno_pkg.models import Finding, Host, Plugin, Port, Scan

    scan_id = Scan(scan_name="vhosts", export_root="/tmp").save(temp_db)
    Plugin(plugin_id="nuclei:tls-version", plugin_name="TLS", severity_int=1).save(
        temp_db
    )
    finding_id = Finding(scan_id=scan_id, plugin_id="nuclei:tls-version").save(temp_db)
    Port.get_or_create(443, conn=temp_db)
    for name in ("shop.example", "blog.example", "api.example"):
        host_id = Host.get_or_create("10.0.0.9", name, "fqdn", conn=temp_db)
        temp_db.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number) "
            "VALUES (?, ?, ?)",
            (finding_id, host_id, 443),
        )
    temp_db.commit()

    rows = _overview_rows(temp_db, monkeypatch, scan_id)

    assert rows["Unique Hosts"] == 1
    assert rows["IPv4"] == 1
    assert rows["Scan Targets"] == 3
