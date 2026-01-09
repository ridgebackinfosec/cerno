"""Tests for cerno_pkg.database module."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from cerno_pkg.database import (
    get_connection,
    db_transaction,
    initialize_database,
    compute_file_hash,
    query_one,
    query_all,
)


class TestDatabaseConnection:
    """Tests for database connection management."""

    def test_get_connection_creates_db(self, temp_dir):
        """Test that get_connection creates database file."""
        db_path = temp_dir / "test.db"
        conn = get_connection(db_path)

        assert db_path.exists()
        assert isinstance(conn, sqlite3.Connection)

        conn.close()

    def test_connection_has_row_factory(self, temp_dir):
        """Test that connection has Row factory set."""
        db_path = temp_dir / "test.db"
        conn = get_connection(db_path)

        assert conn.row_factory == sqlite3.Row

        conn.close()

    def test_foreign_keys_enabled(self, temp_dir):
        """Test that foreign keys are enabled."""
        db_path = temp_dir / "test.db"
        conn = get_connection(db_path)

        cursor = conn.execute("PRAGMA foreign_keys")
        result = cursor.fetchone()
        assert result[0] == 1  # Foreign keys ON

        conn.close()

    def test_wal_mode_enabled(self, temp_dir):
        """Test that WAL mode is enabled."""
        db_path = temp_dir / "test.db"
        conn = get_connection(db_path)

        cursor = conn.execute("PRAGMA journal_mode")
        result = cursor.fetchone()
        assert result[0].upper() == "WAL"

        conn.close()


class TestDatabaseTransaction:
    """Tests for database transaction management."""

    def test_transaction_commits_on_success(self, temp_db):
        """Test that transaction commits when no exception."""
        with db_transaction(temp_db) as conn:
            conn.execute(
                "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
                ("test_scan", "/tmp/test")
            )

        # Verify data was committed
        cursor = temp_db.execute("SELECT scan_name FROM scans")
        result = cursor.fetchone()
        assert result["scan_name"] == "test_scan"

    def test_transaction_rolls_back_on_error(self, temp_db):
        """Test that transaction rolls back on exception."""
        try:
            with db_transaction(temp_db) as conn:
                conn.execute(
                    "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
                    ("test_scan", "/tmp/test")
                )
                # Force an error
                raise ValueError("Test error")
        except ValueError:
            pass

        # Verify data was NOT committed
        cursor = temp_db.execute("SELECT COUNT(*) as count FROM scans")
        result = cursor.fetchone()
        assert result["count"] == 0

    def test_nested_transactions(self, temp_db):
        """Test nested transaction behavior."""
        with db_transaction(temp_db) as conn:
            conn.execute(
                "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
                ("scan1", "/tmp/test1")
            )

            # Inner transaction should share same connection
            with db_transaction(conn) as inner_conn:
                inner_conn.execute(
                    "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
                    ("scan2", "/tmp/test2")
                )

        # Both should be committed
        cursor = temp_db.execute("SELECT COUNT(*) as count FROM scans")
        result = cursor.fetchone()
        assert result["count"] == 2


class TestSchemaInitialization:
    """Tests for database schema initialization."""

    def test_initialize_creates_tables(self, temp_dir):
        """Test that initialize_database creates all tables."""
        db_path = temp_dir / "test.db"
        initialize_database(db_path)

        conn = get_connection(db_path)

        # Check that key tables exist
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]

        expected_tables = [
            "scans",
            "plugins",
            "findings",
            "finding_affected_hosts",
            "sessions",
            "tool_executions",
            "artifacts",
        ]

        for table in expected_tables:
            assert table in tables

        conn.close()

    def test_initialize_idempotent(self, temp_dir):
        """Test that initialize_database can be called multiple times."""
        db_path = temp_dir / "test.db"

        # Initialize twice
        initialize_database(db_path)
        initialize_database(db_path)

        # Should not raise error and database should be valid
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        count = cursor.fetchone()[0]
        assert count > 0

        conn.close()


class TestForeignKeyConstraints:
    """Tests for foreign key constraint enforcement."""

    def test_cascade_delete_findings(self, temp_db):
        """Test that deleting scan cascades to findings."""
        # Insert scan
        cursor = temp_db.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
            ("test_scan", "/tmp/test")
        )
        scan_id = cursor.lastrowid

        # Insert plugin (severity_label fetched from view, not stored)
        temp_db.execute(
            "INSERT INTO plugins (plugin_id, plugin_name, severity_int) VALUES (?, ?, ?)",
            (12345, "Test Plugin", 2)
        )

        # Insert plugin file
        temp_db.execute(
            """INSERT INTO findings (scan_id, plugin_id)
               VALUES (?, ?)""",
            (scan_id, 12345)
        )

        temp_db.commit()

        # Delete scan
        temp_db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        temp_db.commit()

        # Plugin files should be deleted
        cursor = temp_db.execute("SELECT COUNT(*) as count FROM findings")
        result = cursor.fetchone()
        assert result["count"] == 0

    def test_cannot_insert_invalid_foreign_key(self, temp_db):
        """Test that invalid foreign keys are rejected."""
        with pytest.raises(sqlite3.IntegrityError):
            temp_db.execute(
                """INSERT INTO findings (scan_id, plugin_id)
                   VALUES (?, ?)""",
                (9999, 12345)  # scan_id 9999 doesn't exist
            )
            temp_db.commit()


class TestComputeFileHash:
    """Tests for compute_file_hash function."""

    def test_hash_consistency(self, temp_dir):
        """Test that hash is consistent for same content."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test content")

        hash1 = compute_file_hash(test_file)
        hash2 = compute_file_hash(test_file)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 produces 64 hex chars

    def test_different_content_different_hash(self, temp_dir):
        """Test that different content produces different hash."""
        file1 = temp_dir / "file1.txt"
        file2 = temp_dir / "file2.txt"

        file1.write_text("content 1")
        file2.write_text("content 2")

        hash1 = compute_file_hash(file1)
        hash2 = compute_file_hash(file2)

        assert hash1 != hash2

    def test_known_hash_value(self, temp_dir):
        """Test hash against known value."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("hello")

        hash_value = compute_file_hash(test_file)

        # SHA256 of "hello"
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assert hash_value == expected

    def test_nonexistent_file(self, temp_dir):
        """Test handling of nonexistent file."""
        nonexistent = temp_dir / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            compute_file_hash(nonexistent)


class TestQueryHelpers:
    """Tests for query helper functions."""

    def test_query_one_returns_single_row(self, temp_db):
        """Test query_one returns single row."""
        temp_db.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
            ("test_scan", "/tmp/test")
        )
        temp_db.commit()

        result = query_one(temp_db, "SELECT scan_name FROM scans WHERE scan_name = ?", ("test_scan",))

        assert result is not None
        assert result["scan_name"] == "test_scan"

    def test_query_one_returns_none_when_empty(self, temp_db):
        """Test query_one returns None when no results."""
        result = query_one(temp_db, "SELECT scan_name FROM scans WHERE scan_name = ?", ("nonexistent",))

        assert result is None

    def test_query_all_returns_multiple_rows(self, temp_db):
        """Test query_all returns multiple rows."""
        temp_db.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
            ("scan1", "/tmp/test1")
        )
        temp_db.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
            ("scan2", "/tmp/test2")
        )
        temp_db.commit()

        results = query_all(temp_db, "SELECT scan_name FROM scans ORDER BY scan_name")

        assert len(results) == 2
        assert results[0]["scan_name"] == "scan1"
        assert results[1]["scan_name"] == "scan2"

    def test_query_all_returns_empty_list(self, temp_db):
        """Test query_all returns empty list when no results."""
        results = query_all(temp_db, "SELECT scan_name FROM scans")

        assert results == []


class TestConcurrency:
    """Tests for concurrent database access."""

    @pytest.mark.integration
    def test_concurrent_reads(self, temp_dir):
        """Test multiple concurrent read connections."""
        db_path = temp_dir / "test.db"
        initialize_database(db_path)

        # Insert test data
        conn = get_connection(db_path)
        conn.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
            ("test_scan", "/tmp/test")
        )
        conn.commit()
        conn.close()

        # Multiple read connections should work
        conn1 = get_connection(db_path)
        conn2 = get_connection(db_path)

        cursor1 = conn1.execute("SELECT scan_name FROM scans")
        cursor2 = conn2.execute("SELECT scan_name FROM scans")

        assert cursor1.fetchone()["scan_name"] == "test_scan"
        assert cursor2.fetchone()["scan_name"] == "test_scan"

        conn1.close()
        conn2.close()

    @pytest.mark.integration
    def test_wal_mode_allows_concurrent_read_write(self, temp_dir):
        """Test that WAL mode allows concurrent reads during writes."""
        db_path = temp_dir / "test.db"
        initialize_database(db_path)

        write_conn = get_connection(db_path)
        read_conn = get_connection(db_path)

        # Start a write transaction (don't commit yet)
        write_conn.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
            ("scan1", "/tmp/test1")
        )

        # Read connection should still work (sees old data)
        cursor = read_conn.execute("SELECT COUNT(*) as count FROM scans")
        # Should see 0 (uncommitted write not visible)
        assert cursor.fetchone()["count"] == 0

        # Commit write
        write_conn.commit()

        # Now read should see new data
        cursor = read_conn.execute("SELECT COUNT(*) as count FROM scans")
        assert cursor.fetchone()["count"] == 1

        write_conn.close()
        read_conn.close()
