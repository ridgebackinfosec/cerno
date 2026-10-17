"""Tests for `cerno scan list` output modes (compact / --wide / --json)."""

import json
import sqlite3

import pytest

from cerno_pkg import database
from cerno_pkg.models import Finding, Plugin, Scan


def _column_separators(table_output: str) -> int:
    """Count column separators (┳) in a Rich table's top border = columns - 1."""
    for line in table_output.splitlines():
        if "┳" in line:
            return line.count("┳")
    return 0


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
    conn.executescript(database.SCHEMA_SQL_VIEWS)
    conn.commit()


@pytest.fixture
def seeded_db(tmp_path, monkeypatch):
    dbfile = tmp_path / "cerno.db"
    conn = sqlite3.connect(str(dbfile))
    _init_schema(conn)
    scan_id = Scan(scan_name="engagement", export_root=str(tmp_path)).save(conn)
    Plugin(plugin_id=100, plugin_name="SMB Signing", severity_int=4).save(conn)
    Finding(scan_id=scan_id, plugin_id=100).save(conn)
    conn.commit()
    conn.close()
    monkeypatch.setattr(database, "DATABASE_PATH", dbfile)
    return dbfile


@pytest.mark.integration
def test_scan_list_json_is_parseable(seeded_db, capsys):
    from cerno import list_scans

    list_scans(wide=False, json_output=True)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list) and data
    assert data[0]["scan_name"] == "engagement"
    assert "done_count" in data[0]
    assert "total_findings" in data[0]


@pytest.mark.integration
def test_scan_list_compact_has_seven_columns(seeded_db, capsys):
    from cerno import list_scans

    list_scans(wide=False, json_output=False)
    out = capsys.readouterr().out
    assert "engagement" in out
    assert "Done %" in out
    # Compact table has 7 columns (header border has 6 column separators).
    assert _column_separators(out) == 6


@pytest.mark.integration
def test_scan_list_wide_has_more_columns_than_compact(seeded_db, capsys):
    from cerno import list_scans

    list_scans(wide=True, json_output=False)
    wide_out = capsys.readouterr().out
    assert "engagement" in wide_out
    # Wide table has 10 columns (9 separators) — the full per-severity breakdown.
    assert _column_separators(wide_out) == 9
