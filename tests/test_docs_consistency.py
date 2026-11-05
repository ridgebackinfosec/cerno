"""Guard: numbers stated in the documentation must match the code.

A v3.x audit found eight documented figures that had gone wrong -- 26 tables and
11 views (really 27 and 12), 5 seeded artifact types (6), 9 bundled workflows
(15), 36 test modules (43), 46 MCP tools (47), and schema v4 in a file whose
contents were v5. Each was wrong in a way no test could see, because prose is
not executable.

Every one of those is mechanically checkable, so this module checks them. It is
the same idea as ``test_mcp_contract.py``'s frozen inventory and
``test_database.py``'s ``schema.sql`` parity, applied to prose: not a guarantee
the docs are *right*, but a guarantee they cannot be silently wrong about a
number.

Each check parses the figure out of the doc with a narrow anchored pattern and
reports the file, the stale figure and the real one, so a failure says exactly
what to edit.
"""

import re
import sqlite3
import tempfile
from pathlib import Path

import pytest

from cerno_pkg import database as db

REPO_ROOT = Path(__file__).parent.parent


def _read(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def _documented(relative: str, pattern: str) -> list[str]:
    """Every capture of ``pattern`` in a doc, so a figure repeated twice is
    checked twice rather than only at its first mention."""
    return re.findall(pattern, _read(relative))


# ---------------------------------------------------------------------------
# Live values
# ---------------------------------------------------------------------------


def _live_counts() -> dict[str, int]:
    ddl = db.SCHEMA_SQL_TABLES + db.SCHEMA_SQL_VIEWS
    return {
        "tables": len(re.findall(r"CREATE TABLE IF NOT EXISTS", ddl)),
        "views": len(re.findall(r"CREATE VIEW IF NOT EXISTS", ddl)),
    }


@pytest.fixture(scope="module")
def seeded_counts() -> dict[str, int]:
    """Row counts of the lookup tables, from a freshly initialised database."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "counts.db"
        db.initialize_database(path)
        conn = sqlite3.connect(path)
        try:
            return {
                name: conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                for name in (
                    "artifact_types",
                    "severity_levels",
                    "verdict_types",
                    "nse_verdicts",
                    "port_states",
                    "finding_sources",
                )
            }
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "doc, pattern",
    [
        (
            "docs/DATABASE.md",
            r"\*\*(\d+) tables\*\* and \*\*(\d+) views\*\*",
        ),
        ("docs/ARCHITECTURE.md", r"(\d+) tables, (\d+) views"),
        ("docs/diagrams/02-architecture.mmd", r"(\d+) tables · (\d+) views"),
    ],
)
def test_documented_table_and_view_counts(doc, pattern):
    live = _live_counts()
    found = _documented(doc, pattern)
    assert found, f"{doc}: no table/view count found with {pattern!r}"
    for tables, views in found:
        assert (
            int(tables) == live["tables"]
        ), f"{doc} says {tables} tables; SCHEMA_SQL_* defines {live['tables']}"
        assert (
            int(views) == live["views"]
        ), f"{doc} says {views} views; SCHEMA_SQL_* defines {live['views']}"


@pytest.mark.integration
def test_documented_artifact_type_count(seeded_counts):
    """CLAUDE.md's schema-check snippet asserts the seeded row counts."""
    expected = {
        "severity_levels": seeded_counts["severity_levels"],
        "artifact_types": seeded_counts["artifact_types"],
        "verdict_types": seeded_counts["verdict_types"],
        "nse_verdicts": seeded_counts["nse_verdicts"],
        "port_states": seeded_counts["port_states"],
        "finding_sources": seeded_counts["finding_sources"],
    }
    claude = _read("CLAUDE.md")
    for table, count in expected.items():
        match = re.search(
            rf"SELECT COUNT\(\*\) FROM {table};\"\s*#\s*Expected:\s*(\d+)", claude
        )
        assert match, f"CLAUDE.md has no documented row count for {table}"
        assert (
            int(match.group(1)) == count
        ), f"CLAUDE.md says {table} seeds {match.group(1)} rows; it seeds {count}"


@pytest.mark.integration
def test_documented_seeded_rows_in_diagram(seeded_counts):
    found = _documented(
        "docs/diagrams/05-er-reference.mmd", r'artifact_type_id PK "(\d+) seeded rows"'
    )
    assert found, "05-er-reference.mmd no longer annotates artifact_types"
    assert int(found[0]) == seeded_counts["artifact_types"]


@pytest.mark.unit
def test_documented_schema_version():
    """Every doc that states a schema version must state the current one."""
    sources = {
        "schema.sql": r"schema version (\d+)",
        "docs/diagrams/02-architecture.mmd": r"schema v(\d+)",
    }
    for doc, pattern in sources.items():
        found = _documented(doc, pattern)
        assert found, f"{doc}: no schema version found"
        for value in found:
            assert (
                int(value) == db.SCHEMA_VERSION
            ), f"{doc} says schema v{value}; SCHEMA_VERSION is {db.SCHEMA_VERSION}"


@pytest.mark.unit
def test_documented_workflow_count():
    from cerno_pkg.workflow_mapper import WorkflowMapper

    live = WorkflowMapper().count()
    found = _documented(
        "docs/CUSTOM_WORKFLOWS.md", r"workflow_mappings\.yaml`? for (\d+) complete"
    )
    assert found, "CUSTOM_WORKFLOWS.md no longer states the bundled workflow count"
    assert (
        int(found[0]) == live
    ), f"CUSTOM_WORKFLOWS.md says {found[0]} bundled workflows; there are {live}"


@pytest.mark.unit
def test_documented_test_module_count():
    live = len(list((REPO_ROOT / "tests").glob("test_*.py")))
    found = _documented("TESTING.md", r"(\d+) test modules")
    assert found, "TESTING.md no longer states a test-module count"
    assert (
        int(found[0]) == live
    ), f"TESTING.md says {found[0]} test modules; there are {live}"


@pytest.mark.integration
def test_documented_mcp_surface_counts():
    """The architecture diagram states the MCP tool/resource/prompt counts."""
    from cerno_pkg.config import CernoConfig
    from cerno_pkg.mcp_server import build_server

    server = build_server(
        CernoConfig(
            mcp_allow_execution=True,
            mcp_allow_mutations=True,
            mcp_allow_batch=True,
            mcp_allow_cred_reveal=True,
        )
    )
    live_tools = len(server._tool_manager._tools)

    found = _documented(
        "docs/diagrams/02-architecture.mmd", r"(\d+) tools · (\d+) resources"
    )
    assert found, "02-architecture.mmd no longer states the MCP surface size"
    assert int(found[0][0]) == live_tools, (
        f"02-architecture.mmd says {found[0][0]} MCP tools; build_server "
        f"registers {live_tools} with every gate enabled"
    )


@pytest.mark.unit
def test_configuration_reference_lists_every_setting():
    """docs/CONFIGURATION.md's table must cover every setting.

    The table is generated from ``config.build_config_rows()``, so it cannot
    omit a key while the generator runs. This guards the step before that: a
    deleted marker pair, or a generator that produced nothing, would leave the
    reference silently empty -- which ``--check`` alone would not catch, because
    an empty region still matches an empty region.

    The hand-maintained predecessor in README drifted twice, losing the four
    ``nuclei_*`` keys and both ``mcp_*scope*`` keys while still claiming to list
    every setting.
    """
    from dataclasses import fields

    from cerno_pkg.config import CernoConfig

    live = {f.name for f in fields(CernoConfig)}
    documented = set(
        re.findall(r"^\| `([a-z_0-9]+)`", _read("docs/CONFIGURATION.md"), re.M)
    )

    missing = live - documented
    assert not missing, (
        f"docs/CONFIGURATION.md is missing {sorted(missing)} - regenerate with "
        "python scripts/generate_doc_examples.py"
    )

    unknown = documented - live
    assert (
        not unknown
    ), f"docs/CONFIGURATION.md documents settings that do not exist: {sorted(unknown)}"
