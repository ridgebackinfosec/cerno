"""Tests for cerno_pkg.session module (database-only mode)."""

from datetime import datetime
from pathlib import Path

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
            if name == 'close':
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
            reviewed_count=2,
            completed_count=1,
            skipped_count=1,
            tool_executions=5,
            cve_extractions=2
        )

        assert state.scan_name == "test_scan"
        assert state.reviewed_count == 2
        assert state.completed_count == 1
        assert state.skipped_count == 1
        assert state.tool_executions == 5
        assert state.cve_extractions == 2

    def test_session_state_empty_counts(self):
        """Test SessionState with zero counts."""
        state = SessionState(
            scan_name="empty_scan",
            session_start="2024-01-15T10:00:00",
            reviewed_count=0,
            completed_count=0,
            skipped_count=0,
            tool_executions=0,
            cve_extractions=0
        )

        assert state.reviewed_count == 0
        assert state.completed_count == 0
        assert state.skipped_count == 0


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
        review_time = (session_start + __import__('datetime').timedelta(minutes=5)).isoformat()

        # Create 2 reviewed files
        for i in range(2):
            plugin = Plugin(plugin_id=1000+i, plugin_name=f"Test{i}", severity_int=3)
            plugin.save(temp_db)
            pf = Finding(
                scan_id=scan_id,
                plugin_id=1000+i,
                review_state="reviewed",
                reviewed_at=review_time
            )
            pf.save(temp_db)

        # Create 1 completed file
        plugin = Plugin(plugin_id=1002, plugin_name="Test2", severity_int=3)
        plugin.save(temp_db)
        pf = Finding(
            scan_id=scan_id,
            plugin_id=1002,
            review_state="completed",
            reviewed_at=review_time
        )
        pf.save(temp_db)

        # Create 1 skipped file
        plugin = Plugin(plugin_id=1003, plugin_name="Test3", severity_int=3)
        plugin.save(temp_db)
        pf = Finding(
            scan_id=scan_id,
            plugin_id=1003,
            review_state="skipped",
            reviewed_at=review_time
        )
        pf.save(temp_db)

        # Save session (counts are now computed from findings, not stored)
        session_id = save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=2,
            completed_count=1,
            skipped_count=1,
            tool_executions=5,
            cve_extractions=2
        )

        assert session_id is not None

        # Verify session in database (schema v5: use v_session_stats view)
        cursor = temp_db.execute(
            """
            SELECT vs.files_reviewed, vs.files_completed, vs.files_skipped,
                   vs.tools_executed, vs.cves_extracted, vs.session_end
            FROM v_session_stats vs
            WHERE vs.scan_id = ? AND vs.session_id = ?
            """,
            (scan_id, session_id)
        )
        row = cursor.fetchone()

        assert row is not None
        assert row["files_reviewed"] == 2
        assert row["files_completed"] == 1
        assert row["files_skipped"] == 1
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
        cursor = temp_db.execute("SELECT last_reviewed_at FROM scans WHERE scan_id = ?", (scan_id,))
        assert cursor.fetchone()["last_reviewed_at"] is None

        # Save session
        session_start = datetime(2024, 1, 15, 10, 0, 0)
        save_session(scan_id=scan_id, session_start=session_start, reviewed_count=1)

        # Verify last_reviewed_at is now set
        cursor = temp_db.execute("SELECT last_reviewed_at FROM scans WHERE scan_id = ?", (scan_id,))
        last_reviewed = cursor.fetchone()["last_reviewed_at"]
        assert last_reviewed is not None

    def test_save_session_updates_existing_session(self, temp_db):
        """Test that save_session updates existing active session."""
        from cerno_pkg.models import Scan, Plugin, Finding

        # Create scan
        scan = Scan(scan_name="test_scan", export_root="/tmp")
        scan_id = scan.save(temp_db)
        assert scan_id is not None

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        review_time = (session_start + __import__('datetime').timedelta(minutes=5)).isoformat()

        # First save - create session
        session_id_1 = save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=1,
            completed_count=0,
            skipped_count=0,
            tool_executions=1,
            cve_extractions=0
        )

        # Add plugin files for second save scenario
        # Create 3 reviewed files
        for i in range(3):
            plugin = Plugin(plugin_id=2000+i, plugin_name=f"Test{i}", severity_int=3)
            plugin.save(temp_db)
            pf = Finding(
                scan_id=scan_id,
                plugin_id=2000+i,
                review_state="reviewed",
                reviewed_at=review_time
            )
            pf.save(temp_db)

        # Create 2 completed files
        for i in range(2):
            plugin = Plugin(plugin_id=2010+i, plugin_name=f"Complete{i}", severity_int=3)
            plugin.save(temp_db)
            pf = Finding(
                scan_id=scan_id,
                plugin_id=2010+i,
                review_state="completed",
                reviewed_at=review_time
            )
            pf.save(temp_db)

        # Second save (should update, not create new)
        session_id_2 = save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=3,
            completed_count=2,
            skipped_count=1,
            tool_executions=5,
            cve_extractions=2
        )

        # Should return same session_id
        assert session_id_1 == session_id_2

        # Verify only one active session exists with updated counts
        cursor = temp_db.execute(
            """
            SELECT COUNT(*) as count, vs.files_reviewed, vs.files_completed, vs.tools_executed
            FROM v_session_stats vs
            WHERE vs.scan_id = ? AND vs.session_end IS NULL
            """,
            (scan_id,)
        )
        row = cursor.fetchone()

        assert row["count"] == 1
        assert row["files_reviewed"] == 3
        assert row["files_completed"] == 2
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
            reviewed_count=0,
            completed_count=0,
            skipped_count=0,
            tool_executions=0,
            cve_extractions=0
        )

        assert session_id is not None

        # Verify database
        cursor = temp_db.execute(
            "SELECT files_reviewed, files_completed, files_skipped FROM v_session_stats WHERE session_id = ?",
            (session_id,)
        )
        row = cursor.fetchone()

        assert row["files_reviewed"] == 0
        assert row["files_completed"] == 0
        assert row["files_skipped"] == 0


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
        review_time = (session_start + __import__('datetime').timedelta(minutes=5)).isoformat()

        # Create plugins and files to match expected counts
        # Need unique plugin_id for each Finding due to UNIQUE(scan_id, plugin_id)

        # Create 2 reviewed files
        for i in range(2):
            plugin = Plugin(plugin_id=1001+i, plugin_name=f"Test{i}", severity_int=3)
            plugin.save(temp_db)
            pf = Finding(
                scan_id=scan_id,
                plugin_id=1001+i,
                review_state="reviewed",
                reviewed_at=review_time
            )
            pf.save(temp_db)

        # Create 1 completed file
        plugin = Plugin(plugin_id=1003, plugin_name="Test3", severity_int=3)
        plugin.save(temp_db)
        pf = Finding(
            scan_id=scan_id,
            plugin_id=1003,
            review_state="completed",
            reviewed_at=review_time
        )
        pf.save(temp_db)

        # Create 1 skipped file
        plugin = Plugin(plugin_id=1004, plugin_name="Test4", severity_int=3)
        plugin.save(temp_db)
        pf = Finding(
            scan_id=scan_id,
            plugin_id=1004,
            review_state="skipped",
            reviewed_at=review_time
        )
        pf.save(temp_db)

        # Create session
        save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=2,
            completed_count=1,
            skipped_count=1,
            tool_executions=5,
            cve_extractions=2
        )

        # Load session - counts should come from actual findings review_state
        state = load_session(scan_id)

        assert state is not None
        assert state.scan_name == "test_scan"
        assert state.reviewed_count == 2
        assert state.completed_count == 1
        assert state.skipped_count == 1
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
        save_session(scan_id=scan_id, session_start=session_start, reviewed_count=1)

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
        review_time = (session_start + __import__('datetime').timedelta(minutes=5)).isoformat()

        # Create plugins and plugin files with different review states
        # Need unique plugin_id for each Finding due to UNIQUE(scan_id, plugin_id)

        plugin1 = Plugin(plugin_id=1001, plugin_name="Test Plugin 1", severity_int=3)
        plugin1.save(temp_db)
        pf1 = Finding(
            scan_id=scan_id,
            plugin_id=1001,
            review_state="reviewed",
            reviewed_at=review_time
        )
        pf1.save(temp_db)

        plugin2 = Plugin(plugin_id=1002, plugin_name="Test Plugin 2", severity_int=3)
        plugin2.save(temp_db)
        pf2 = Finding(
            scan_id=scan_id,
            plugin_id=1002,
            review_state="completed",
            reviewed_at=review_time
        )
        pf2.save(temp_db)

        plugin3 = Plugin(plugin_id=1003, plugin_name="Test Plugin 3", severity_int=3)
        plugin3.save(temp_db)
        pf3 = Finding(
            scan_id=scan_id,
            plugin_id=1003,
            review_state="skipped",
            reviewed_at=review_time
        )
        pf3.save(temp_db)

        # Create session
        save_session(scan_id=scan_id, session_start=session_start, tool_executions=3)

        # Load session - should aggregate from findings
        state = load_session(scan_id)

        assert state is not None
        assert state.reviewed_count == 1  # One with review_state='reviewed'
        assert state.completed_count == 1  # One with review_state='completed'
        assert state.skipped_count == 1    # One with review_state='skipped'


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
        save_session(scan_id=scan_id, session_start=session_start, reviewed_count=1)

        # Verify session is active
        cursor = temp_db.execute(
            "SELECT session_end FROM sessions WHERE scan_id = ?",
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["session_end"] is None

        # Delete session
        delete_session(scan_id)

        # Verify session is ended (use v_session_stats view for duration_seconds in schema v5)
        cursor = temp_db.execute(
            "SELECT session_end, duration_seconds FROM v_session_stats WHERE scan_id = ?",
            (scan_id,)
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
        save_session(scan_id=scan_id, session_start=session_start, reviewed_count=1)

        # End session once
        delete_session(scan_id)

        # End again - should be no-op
        delete_session(scan_id)

        # Verify only one session exists
        cursor = temp_db.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE scan_id = ?",
            (scan_id,)
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
            plugin = Plugin(plugin_id=1000+i, plugin_name=f"Test{i}", severity_int=3)
            plugin.save(temp_db)

        session_start = datetime(2024, 1, 15, 10, 0, 0)
        review_time = (session_start + __import__('datetime').timedelta(minutes=5)).isoformat()

        # 1. Create initial session with 1 reviewed file
        pf1 = Finding(
            scan_id=scan_id,
            plugin_id=1001,
            review_state="reviewed",
            reviewed_at=review_time
        )
        pf1.save(temp_db)

        save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=1,
            completed_count=0,
            skipped_count=0,
            tool_executions=1,
            cve_extractions=0
        )

        # 2. Load session
        state = load_session(scan_id)
        assert state is not None
        assert state.reviewed_count == 1
        # tool_executions will be 0 since we didn't create tool_executions records

        # 3. Update: add more files with different review states
        pf2 = Finding(
            scan_id=scan_id,
            plugin_id=1002,
            review_state="reviewed",
            reviewed_at=review_time
        )
        pf2.save(temp_db)

        pf3 = Finding(
            scan_id=scan_id,
            plugin_id=1003,
            review_state="reviewed",
            reviewed_at=review_time
        )
        pf3.save(temp_db)

        pf4 = Finding(
            scan_id=scan_id,
            plugin_id=1004,
            review_state="completed",
            reviewed_at=review_time
        )
        pf4.save(temp_db)

        pf5 = Finding(
            scan_id=scan_id,
            plugin_id=1005,
            review_state="completed",
            reviewed_at=review_time
        )
        pf5.save(temp_db)

        pf6 = Finding(
            scan_id=scan_id,
            plugin_id=1006,
            review_state="skipped",
            reviewed_at=review_time
        )
        pf6.save(temp_db)

        # Update session
        save_session(
            scan_id=scan_id,
            session_start=session_start,
            reviewed_count=3,
            completed_count=2,
            skipped_count=1,
            tool_executions=8,
            cve_extractions=3
        )

        # 4. Load updated session - counts from findings
        state = load_session(scan_id)
        assert state is not None
        assert state.reviewed_count == 3
        assert state.completed_count == 2
        assert state.skipped_count == 1
        # tool_executions and cve_extractions will be 0 since we didn't create those records

        # 5. Verify database has updated counts
        cursor = temp_db.execute(
            """
            SELECT files_reviewed, files_completed, tools_executed, cves_extracted
            FROM v_session_stats WHERE scan_id = ?
            """,
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["files_reviewed"] == 3
        assert row["files_completed"] == 2
        # tools_executed and cves_extracted will be 0 since we didn't create those records

        # 6. Delete session
        delete_session(scan_id)

        # 7. Verify cleanup
        state = load_session(scan_id)
        assert state is None

        # Verify database session is marked ended
        cursor = temp_db.execute(
            "SELECT session_end FROM sessions WHERE scan_id = ?",
            (scan_id,)
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
            reviewed_count=1,
            completed_count=0,
            skipped_count=0
        )
        delete_session(scan_id)

        # Session 2
        session2_start = datetime(2024, 1, 15, 14, 0, 0)
        save_session(
            scan_id=scan_id,
            session_start=session2_start,
            reviewed_count=2,
            completed_count=1,
            skipped_count=0
        )
        delete_session(scan_id)

        # Verify both sessions in database
        cursor = temp_db.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE scan_id = ?",
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["count"] == 2

        # Verify both sessions have end times
        cursor = temp_db.execute(
            "SELECT COUNT(*) as ended_count FROM sessions WHERE scan_id = ? AND session_end IS NOT NULL",
            (scan_id,)
        )
        row = cursor.fetchone()
        assert row["ended_count"] == 2