"""Tests for cerno_pkg.database module."""

import sqlite3

import pytest

from cerno_pkg.database import (
    get_connection,
    db_transaction,
    initialize_database,
    compute_file_hash,
    plugin_id_order_sql,
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
                ("test_scan", "/tmp/test"),
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
                    ("test_scan", "/tmp/test"),
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
                ("scan1", "/tmp/test1"),
            )

            # Inner transaction should share same connection
            with db_transaction(conn) as inner_conn:
                inner_conn.execute(
                    "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
                    ("scan2", "/tmp/test2"),
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
            ("test_scan", "/tmp/test"),
        )
        scan_id = cursor.lastrowid

        # Insert plugin (severity_label fetched from view, not stored)
        temp_db.execute(
            "INSERT INTO plugins (plugin_id, plugin_name, severity_int) VALUES (?, ?, ?)",
            ("nessus:12345", "Test Plugin", 2),
        )

        # Insert plugin file
        temp_db.execute(
            """INSERT INTO findings (scan_id, plugin_id)
               VALUES (?, ?)""",
            (scan_id, "nessus:12345"),
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
                (9999, "nessus:12345"),  # scan_id 9999 doesn't exist
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
            ("test_scan", "/tmp/test"),
        )
        temp_db.commit()

        result = query_one(
            temp_db, "SELECT scan_name FROM scans WHERE scan_name = ?", ("test_scan",)
        )

        assert result is not None
        assert result["scan_name"] == "test_scan"

    def test_query_one_returns_none_when_empty(self, temp_db):
        """Test query_one returns None when no results."""
        result = query_one(
            temp_db, "SELECT scan_name FROM scans WHERE scan_name = ?", ("nonexistent",)
        )

        assert result is None

    def test_query_all_returns_multiple_rows(self, temp_db):
        """Test query_all returns multiple rows."""
        temp_db.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
            ("scan1", "/tmp/test1"),
        )
        temp_db.execute(
            "INSERT INTO scans (scan_name, export_root) VALUES (?, ?)",
            ("scan2", "/tmp/test2"),
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
            ("test_scan", "/tmp/test"),
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
            ("scan1", "/tmp/test1"),
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


@pytest.mark.unit
def test_schema_sql_reference_matches_database_py():
    """schema.sql (reference copy) defines the same tables, views and indexes."""
    import sqlite3
    from pathlib import Path

    from cerno_pkg.database import SCHEMA_SQL_TABLES, SCHEMA_SQL_VIEWS

    def objects(sql: str) -> set[tuple[str, str]]:
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(sql)
            return set(
                conn.execute(
                    "SELECT type, name FROM sqlite_master "
                    "WHERE name NOT LIKE 'sqlite_%'"
                ).fetchall()
            )
        finally:
            conn.close()

    reference = (Path(__file__).parent.parent / "schema.sql").read_text()
    assert objects(reference) == objects(SCHEMA_SQL_TABLES + SCHEMA_SQL_VIEWS)


@pytest.mark.unit
class TestPluginIdOrdering:
    """plugin_id is TEXT, so ordering it needs the numeric part cast."""

    IDS = [
        "nessus:9",
        "nessus:10114",
        "nessus:57608",
        "nuclei:apache-detect",
        "nuclei:CVE-2021-44228",
    ]

    def _ordered(self, conn):
        conn.execute("CREATE TABLE t (pid TEXT)")
        conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in self.IDS])
        sql = f"SELECT pid FROM t ORDER BY {plugin_id_order_sql('pid')}"
        return [r[0] for r in conn.execute(sql)]

    def test_numeric_refs_sort_numerically_not_lexicographically(self):
        """'nessus:9' must precede 'nessus:10114'.

        Guards the regression that namespacing every id introduces: casting the
        whole column yields 0 for every prefixed id, collapsing the numeric
        term and silently degrading to a lexicographic sort that puts 10114
        first.
        """
        conn = sqlite3.connect(":memory:")
        try:
            ordered = self._ordered(conn)
        finally:
            conn.close()
        assert ordered.index("nessus:9") < ordered.index("nessus:10114")
        assert ordered.index("nessus:10114") < ordered.index("nessus:57608")

    def test_sources_stay_grouped(self):
        conn = sqlite3.connect(":memory:")
        try:
            ordered = self._ordered(conn)
        finally:
            conn.close()
        sources = [pid.split(":")[0] for pid in ordered]
        assert sources == sorted(sources), "a source's ids must be contiguous"

    def test_non_numeric_refs_fall_back_to_text_order(self):
        conn = sqlite3.connect(":memory:")
        try:
            ordered = self._ordered(conn)
        finally:
            conn.close()
        nuclei = [p for p in ordered if p.startswith("nuclei:")]
        assert nuclei == sorted(nuclei)


@pytest.mark.integration
class TestViewsAreRecreatedOnInit:
    """A changed view definition must reach an existing database.

    `CREATE VIEW IF NOT EXISTS` does not replace an existing view, so before
    this every view change silently applied to fresh databases only. The
    symptom was a missing column rather than an error, which is why it went
    unnoticed across several releases. Views hold no data, so init drops and
    recreates them.
    """

    def test_changed_view_definition_reaches_an_existing_db(self, tmp_path):
        from cerno_pkg import database as db

        path = tmp_path / "upgrade.db"
        db.initialize_database(path)

        original = db.SCHEMA_SQL_VIEWS
        try:
            db.SCHEMA_SQL_VIEWS = original.replace(
                "COUNT(DISTINCT vp.verified_port_id) AS verified_port_count",
                "COUNT(DISTINCT vp.verified_port_id) AS verified_port_count,"
                " 99 AS probe_column",
            )
            db.initialize_database(path)
        finally:
            db.SCHEMA_SQL_VIEWS = original

        conn = sqlite3.connect(path)
        try:
            cols = [
                d[0]
                for d in conn.execute(
                    "SELECT * FROM v_finding_verified_stats LIMIT 0"
                ).description
            ]
        finally:
            conn.close()
        assert (
            "probe_column" in cols
        ), "a changed view definition did not reach the existing database"

    def test_every_declared_view_exists_after_init(self, tmp_path):
        from cerno_pkg import database as db

        path = tmp_path / "views.db"
        db.initialize_database(path)
        conn = sqlite3.connect(path)
        try:
            present = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='view'"
                )
            }
        finally:
            conn.close()
        declared = set(db._view_names(db.SCHEMA_SQL_VIEWS))
        assert (
            declared and declared <= present
        ), f"missing: {sorted(declared - present)}"
