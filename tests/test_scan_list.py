"""Tests for `cerno scan list` output modes (compact / wide / --json).

The wide view is driven by the ``scan_list_wide`` config key; the ``--wide`` /
``--details`` flags were removed in favour of it. ``--json`` stays a flag: it
is an output channel, not a preference, and it short-circuits before any table
is built.
"""

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


def _set_wide(enabled: bool) -> None:
    """Write scan_list_wide into the test-isolated config file."""
    import yaml

    from cerno_pkg import config as config_mod

    config_mod.get_config_path().write_text(
        yaml.safe_dump({"scan_list_wide": enabled}), encoding="utf-8"
    )


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(database.SCHEMA_SQL_TABLES)
    conn.execute("PRAGMA foreign_keys=ON")
    database.seed_lookup_tables(conn)
    conn.executescript(database.SCHEMA_SQL_VIEWS)
    conn.commit()


@pytest.fixture
def seeded_db(tmp_path, monkeypatch):
    dbfile = tmp_path / "cerno.db"
    conn = sqlite3.connect(str(dbfile))
    _init_schema(conn)
    scan_id = Scan(scan_name="engagement", export_root=str(tmp_path)).save(conn)
    Plugin(plugin_id="nessus:100", plugin_name="SMB Signing", severity_int=4).save(conn)
    Finding(scan_id=scan_id, plugin_id="nessus:100").save(conn)
    conn.commit()
    conn.close()
    monkeypatch.setattr(database, "DATABASE_PATH", dbfile)
    return dbfile


@pytest.mark.integration
def test_scan_list_json_is_parseable(seeded_db, capsys):
    from cerno import list_scans

    list_scans(json_output=True)
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list) and data
    assert data[0]["scan_name"] == "engagement"
    assert "done_count" in data[0]
    assert "total_findings" in data[0]


@pytest.mark.integration
def test_scan_list_compact_has_eight_columns(seeded_db, capsys):
    from cerno import list_scans

    list_scans(json_output=False)
    out = capsys.readouterr().out
    assert "engagement" in out
    assert "Done %" in out
    # Compact table has 8 columns (header border has 7 column separators).
    assert _column_separators(out) == 7


@pytest.mark.integration
def test_scan_list_wide_has_more_columns_than_compact(seeded_db, capsys):
    from cerno import list_scans

    _set_wide(True)
    list_scans(json_output=False)
    wide_out = capsys.readouterr().out
    assert "engagement" in wide_out
    # Wide table has 11 columns (10 separators) — the full per-severity breakdown.
    assert _column_separators(wide_out) == 10


@pytest.mark.integration
def test_scan_list_shows_the_scanner_for_each_scan(seeded_db, capsys):
    """Two scans from different tools are not comparable, so say which is which.

    Without this the only hint is the MixedSourceComparisonError raised after
    the operator has already picked two scans to compare.
    """
    from cerno import list_scans

    list_scans(json_output=False)
    out = capsys.readouterr().out
    assert "Source" in out
    assert "nessus" in out


@pytest.mark.integration
def test_scan_list_json_includes_source(seeded_db, capsys):
    import json

    from cerno import list_scans

    list_scans(json_output=True)
    rows = json.loads(capsys.readouterr().out)
    assert rows and all("source" in r for r in rows)
    assert rows[0]["source"] == "nessus"


@pytest.fixture
def vhost_db(tmp_path, monkeypatch):
    """A scan where one machine serves three virtual hosts."""
    dbfile = tmp_path / "cerno.db"
    conn = sqlite3.connect(str(dbfile))
    _init_schema(conn)

    from cerno_pkg.models import Host, Port

    scan_id = Scan(scan_name="vhosts", export_root=str(tmp_path)).save(conn)
    Plugin(plugin_id="nuclei:tls-version", plugin_name="TLS", severity_int=1).save(conn)
    finding_id = Finding(scan_id=scan_id, plugin_id="nuclei:tls-version").save(conn)
    Port.get_or_create(443, conn=conn)
    for name in ("shop.example", "blog.example", "api.example"):
        host_id = Host.get_or_create("10.0.0.9", name, "fqdn", conn=conn)
        conn.execute(
            "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number) "
            "VALUES (?, ?, ?)",
            (finding_id, host_id, 443),
        )
    conn.commit()
    conn.close()
    monkeypatch.setattr(database, "DATABASE_PATH", dbfile)
    return dbfile


@pytest.mark.integration
def test_scan_list_host_column_counts_machines(vhost_db, capsys):
    """Three vhosts on one IP are one machine, not three."""
    from cerno import list_scans

    list_scans(json_output=True)
    data = json.loads(capsys.readouterr().out)

    assert data[0]["unique_hosts"] == 1


@pytest.fixture
def same_second_db(tmp_path, monkeypatch):
    """Four unreviewed scans sharing one `created_at`, as `cerno demo` produces.

    `created_at` is CURRENT_TIMESTAMP at second resolution and an import takes
    milliseconds, so this is the ordinary case for a scripted import, not a
    contrived one.
    """
    dbfile = tmp_path / "cerno.db"
    conn = sqlite3.connect(str(dbfile))
    _init_schema(conn)
    for name in ("alpha", "bravo", "charlie", "delta"):
        Scan(scan_name=name, export_root=str(tmp_path)).save(conn)
    conn.execute("UPDATE scans SET created_at = '2026-01-01 00:00:00'")
    conn.commit()
    conn.close()
    monkeypatch.setattr(database, "DATABASE_PATH", dbfile)
    return dbfile


@pytest.mark.integration
def test_scan_list_order_is_deterministic_when_created_at_ties(same_second_db):
    """Scans tied on both sort keys must still come back in a fixed order.

    `ORDER BY last_reviewed_at DESC NULLS LAST, created_at DESC` leaves scans
    imported in the same second tied on *both* keys, and SQLite's row order for
    a full tie is unspecified -- it follows the query plan. `cerno scan list`
    therefore reordered itself between invocations, and the generated
    `scan-list.svg` doc example drifted intermittently on CI (ubuntu 3.12 failed
    on a commit whose other eleven jobs passed). `scan_id DESC` breaks the tie.
    """
    from cerno_pkg.database import get_connection

    conn = get_connection()
    expected = [s["scan_name"] for s in Scan.get_all_with_stats(conn)]

    # A full table scan and an index-driven plan can emit tied rows in
    # different orders; re-running under both must not change the answer.
    for pragma in ("ANALYZE", "REINDEX"):
        conn.execute(pragma)
        assert [
            s["scan_name"] for s in Scan.get_all_with_stats(conn)
        ] == expected, f"order changed after {pragma}"
        assert [s.scan_name for s in Scan.get_all(conn)] == expected

    # Newest first, which for a tie on created_at means highest scan_id.
    assert expected == ["delta", "charlie", "bravo", "alpha"]
