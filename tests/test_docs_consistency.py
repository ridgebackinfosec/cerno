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
    """Every doc that states a schema version must state the current one.

    CLAUDE.md is in here because it states the version **twice** -- in the
    Schema Management bullet and in the ``PRAGMA user_version`` verification
    block -- and the 4.0.0 rename updated only the first. Both said 5 while
    ``SCHEMA_VERSION`` was 6, and nothing caught it: this test covered only
    ``schema.sql`` and the architecture diagram.
    """
    sources = {
        "schema.sql": r"schema version (\d+)",
        "docs/diagrams/02-architecture.mmd": r"schema v(\d+)",
        "CLAUDE.md": (
            r"(?:SCHEMA_VERSION` \(current: "
            r"|PRAGMA user_version;\"\s*#\s*Expected: )(\d+)"
        ),
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


# ---------------------------------------------------------------------------
# Documented labels, not just documented numbers
# ---------------------------------------------------------------------------
#
# Everything above checks a *figure*. The 4.0.0 rename made the gap obvious:
# every number in ``02-architecture.mmd`` was correct (25 tables, 12 views,
# schema v6, 50 tools) while two of its **labels** named things the release had
# deleted -- a ``cross_scan.py`` module and a ``scan`` CLI command. Nothing read
# the labels, and CLAUDE.md already notes the rendered PNGs are caught by no
# test at all, so the error would have shipped in the README's front-page image
# for the very release that did the renaming.
#
# Fixing the diagram was not enough, because the same two facts are written
# elsewhere: ``CLAUDE.md``'s module-structure block listed the identical stale
# ``scan`` command, and ``TESTING.md``'s table named three test modules this
# branch renamed -- right beside a module *count* that this file already
# guarded and that was correct. So all three rules below read every hand-owned
# doc, not just the diagrams.
#
# The third rule covers a different shape of the same rot: ``TESTING.md``'s
# example test did ``from cerno_pkg.models import Scan`` and built a
# ``Scan(scan_name=...)``, so the snippet a contributor is told to copy raised
# ImportError. A name in a doc is checkable whether it sits in a table or in a
# code fence.
#
# They are existence checks against the code rather than word lists, so they
# cannot go stale and they leave the docs free to say "remote scan" or
# "untrusted scan text", which remain correct.
#
# ``CHANGELOG.md`` is excluded on purpose: its history correctly names
# ``cross_scan.py`` and ``cerno scan history`` as they existed in past
# releases, and rewriting history to satisfy a test would be the actual bug.

# Impacket ships this; it is named in workflow commands, not owned by us.
_EXTERNAL_TOOLS = {"ntlmrelayx.py"}

# The "add a tool" tutorials import the tool the *reader* is about to write, so
# these never resolve and must not.
_TUTORIAL_PLACEHOLDERS = {"build_mytool_cmd"}


def _doc_sources() -> list[Path]:
    """Every hand-owned doc, Mermaid sources included."""
    paths = [
        REPO_ROOT / name
        for name in ("CLAUDE.md", "CONTRIBUTING.md", "README.md", "TESTING.md")
    ]
    paths += sorted((REPO_ROOT / "docs").rglob("*.md"))
    paths += sorted((REPO_ROOT / "docs" / "diagrams").glob("*.mmd"))
    paths += sorted((REPO_ROOT / "cerno_pkg" / "skills").glob("*.md"))
    return [p for p in paths if p.is_file()]


@pytest.mark.unit
def test_documented_module_names_exist():
    """Every ``*.py`` named in a doc or diagram must be a real file.

    ``02-architecture.mmd`` kept listing ``cross_scan.py`` after the module was
    renamed to ``cross_dataset.py``, and ``TESTING.md`` kept listing
    ``test_cross_scan.py``, ``test_scan_list.py`` and
    ``test_multi_scan_review.py`` after all three were renamed.
    """
    search_dirs = [
        REPO_ROOT,
        REPO_ROOT / "cerno_pkg",
        REPO_ROOT / "cerno_pkg" / "mcp_server",
        REPO_ROOT / "tests",
        REPO_ROOT / "scripts",
    ]

    docs = _doc_sources()
    assert docs, "no docs found to check"

    offenders = []
    for path in docs:
        # Markdown escapes dunders as ``\_\_init\_\_.py``; unescape so the name
        # resolves instead of reading as a bogus "_.py".
        text = path.read_text(encoding="utf-8").replace("\\_", "_")
        for name in sorted(set(re.findall(r"\b[a-z_][a-z0-9_]*\.py\b", text))):
            if name in _EXTERNAL_TOOLS:
                continue
            if not any((d / name).is_file() for d in search_dirs):
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {name}")

    assert not offenders, "doc names a module that does not exist:\n" + "\n".join(
        offenders
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "doc, pattern",
    [
        # "<b>cerno.py</b> — Typer CLI<br/>review · import · dataset · check..."
        (
            "docs/diagrams/02-architecture.mmd",
            r'<b>cerno\.py</b>[^<]*<br/>([^"]*)',
        ),
        # "cerno.py  # Typer CLI entry point: review/import/dataset/check/..."
        ("CLAUDE.md", r"# Typer CLI entry point:([^\n]*)"),
    ],
)
def test_documented_cli_commands_exist(doc, pattern):
    """Every command in a doc's enumerated command list must be registered.

    The diagram node read ``review · import · scan · config`` long after
    ``cerno scan`` was replaced by ``cerno dataset``, so the picture advertised
    a command that exits with "No such command 'scan'" -- and CLAUDE.md's
    entry-point line carried the identical stale list.
    """
    import typer.main

    from cerno import app

    # get_command() is typed as Command but returns a Group for a multi-command
    # app; getattr keeps the type checkers quiet without a cast.
    live = set(getattr(typer.main.get_command(app), "commands", {}))
    assert live, "no commands registered on the Typer app"

    match = re.search(pattern, _read(doc))
    assert match, f"{doc} no longer has a command list matching {pattern!r}"

    # Split on every separator the two formats use. Tokens are *validated*
    # rather than filtered: a filter silently dropped the final ``reset"`` of
    # the Mermaid node, so the last command in the list was never checked.
    listed = [token for token in re.split(r"<br/>|·|/|\s+", match.group(1)) if token]
    assert listed, f"{doc}: no commands parsed out of {match.group(1)!r}"

    unknown = sorted(set(listed) - live)
    assert not unknown, (
        f"{doc} lists commands that do not exist: {unknown}; "
        f"registered commands are {sorted(live)}"
    )


@pytest.mark.unit
def test_documented_imports_resolve():
    """Every ``from cerno_pkg... import X`` in a doc must actually import.

    ``TESTING.md``'s example test imported ``Scan`` from ``cerno_pkg.models``
    and passed ``scan_name=`` to it, so the snippet contributors are told to
    copy raised ImportError once the class became ``Dataset``. The example was
    never executed by anything, and the module-name and command guards cannot
    see inside a code fence.
    """
    import importlib

    pattern = re.compile(r"^\s*from\s+(cerno_pkg[\w.]*)\s+import\s+([^\n#]+)", re.M)

    offenders = []
    checked = 0
    for path in _doc_sources():
        for module_name, names in pattern.findall(path.read_text(encoding="utf-8")):
            try:
                module = importlib.import_module(module_name)
            except Exception as exc:  # pragma: no cover - a real failure
                offenders.append(
                    f"{path.relative_to(REPO_ROOT)}: {module_name} ({exc})"
                )
                continue
            for raw in names.split(","):
                symbol = raw.strip().split(" as ")[0].strip()
                if not symbol or symbol in _TUTORIAL_PLACEHOLDERS:
                    continue
                checked += 1
                if not hasattr(module, symbol):
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}: "
                        f"{module_name} has no {symbol!r}"
                    )

    assert checked, "no documented cerno_pkg imports found to check"
    assert not offenders, "doc imports a name that does not exist:\n" + "\n".join(
        offenders
    )


def _dataclass_fields_by_name() -> dict[str, set[str]]:
    """``{class name: field names}`` for every dataclass in ``cerno_pkg``.

    Keyed by bare class name so a doc snippet is checkable without importing
    anything -- which matters, because the snippets that construct these
    objects are fragments with no import line.
    """
    import dataclasses
    import importlib
    import pkgutil

    import cerno_pkg

    found: dict[str, set[str]] = {}
    for info in pkgutil.walk_packages(cerno_pkg.__path__, "cerno_pkg."):
        try:
            module = importlib.import_module(info.name)
        except Exception:  # pragma: no cover - an unimportable module
            continue
        for name, obj in vars(module).items():
            if isinstance(obj, type) and dataclasses.is_dataclass(obj):
                found.setdefault(name, set()).update(
                    f.name for f in dataclasses.fields(obj)
                )
    return found


@pytest.mark.unit
def test_documented_constructor_kwargs_exist():
    """Every keyword a doc passes to a cerno_pkg dataclass must be a real field.

    ``docs/TOOL_SYSTEM_GUIDE.md`` built a ``ToolContext(scan_dir=...)`` after
    the field became ``dataset_dir``, so a contributor following the
    add-a-tool guide writes code that raises ``TypeError``. The snippet has no
    import line, so :func:`test_documented_imports_resolve` cannot see it --
    this matches on the class *name* instead, which needs no word list because
    the names come from walking the package.
    """
    import ast
    import textwrap

    known = _dataclass_fields_by_name()
    assert known, "no dataclasses discovered in cerno_pkg"

    fence = re.compile(r"```python\n(.*?)```", re.S)
    offenders = []
    checked = 0
    for path in _doc_sources():
        for block in fence.findall(path.read_text(encoding="utf-8")):
            tree = None
            # A fragment may be a bare ``return ...``, illegal at module level;
            # retry wrapped in a function before giving up on it.
            for source in (block, "def _f():\n" + textwrap.indent(block, "    ")):
                try:
                    tree = ast.parse(source)
                    break
                except SyntaxError:
                    continue
            if tree is None:
                continue
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                    continue
                fields = known.get(node.func.id)
                if fields is None:
                    continue
                for keyword in node.keywords:
                    if keyword.arg is None:
                        continue
                    checked += 1
                    if keyword.arg not in fields:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}: "
                            f"{node.func.id} has no field {keyword.arg!r}"
                        )

    assert checked, "no documented dataclass constructions found to check"
    assert not offenders, "doc passes a field that does not exist:\n" + "\n".join(
        sorted(set(offenders))
    )


# ---------------------------------------------------------------------------
# Documented SQL has to run
# ---------------------------------------------------------------------------
#
# The guards above check that a documented *name* exists. This one checks that
# a documented *query* works, by handing every SQL block in the docs to SQLite
# against a freshly initialised schema. ``docs/DATABASE.md`` had three
# statements selecting ``affected_hosts`` and ``host_count`` -- columns the
# views call ``affected_targets`` and ``target_count``, a distinction CLAUDE.md
# spells out at length. The file teaches the schema, so a query in it that
# cannot run teaches the wrong schema.


@pytest.mark.integration
def test_documented_sql_executes():
    """Every documented SQL statement must parse and resolve against the schema.

    ``EXPLAIN`` compiles the statement -- resolving every table, view and
    column -- without running it, so this costs nothing and needs no data.
    """
    import sqlite3 as _sqlite3
    import tempfile as _tempfile

    placeholder = re.compile(r"<[a-z_]+>|\.\.\.|\$\{")
    blocks: list[tuple[Path, str]] = []
    for path in _doc_sources():
        for block in re.findall(
            r"```sql\n(.*?)```", path.read_text(encoding="utf-8"), re.S
        ):
            blocks.append((path, block))
    assert blocks, "no documented SQL blocks found to check"

    with _tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "docs.db"
        db.initialize_database(db_path)
        conn = _sqlite3.connect(db_path)
        try:
            offenders = []
            checked = 0
            for path, block in blocks:
                for statement in block.split(";"):
                    body = "\n".join(
                        line
                        for line in statement.splitlines()
                        if line.strip() and not line.strip().startswith("--")
                    ).strip()
                    if not body or placeholder.search(body):
                        continue
                    checked += 1
                    try:
                        conn.execute("EXPLAIN " + body)
                    except _sqlite3.Error as exc:
                        offenders.append(
                            f"{path.relative_to(REPO_ROOT)}: {exc} "
                            f"-- in {body.splitlines()[0][:70]!r}"
                        )
        finally:
            conn.close()

    assert checked, "no runnable SQL statements found"
    assert not offenders, "documented SQL does not run:\n" + "\n".join(
        sorted(set(offenders))
    )


# ---------------------------------------------------------------------------
# Retired phrasing: "plugin output"
# ---------------------------------------------------------------------------
#
# Evidence captured at import lives in ``finding_affected_hosts.evidence`` and
# comes from four sources, three of which have no plugins. The rename moved
# "plugin output" to "finding_type output", which is wrong a second way -- the
# text is not the finding *type's* output -- and the fix reached the MCP server
# and nowhere else, leaving the phrase in four docs describing nuclei and Burp.
#
# Tenable's own term is the one legitimate use, and in this repo it is always
# written "Nessus plugin output", so requiring that single preceding word needs
# no exception list. ``CHANGELOG.md`` is outside ``_doc_sources()`` and so is
# not checked: it quotes the retired phrasing as history.


@pytest.mark.unit
def test_docs_do_not_call_evidence_plugin_output():
    """ "plugin output" in a doc must be Tenable's own term, i.e. Nessus's."""
    docs = _doc_sources()
    assert docs, "no docs found to check"

    offenders = []
    for path in docs:
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"plugin output", text, re.IGNORECASE):
            if re.search(r"nessus\s+$", text[: match.start()], re.IGNORECASE):
                continue
            line = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{path.relative_to(REPO_ROOT)}:{line}")

    assert not offenders, (
        "doc calls per-host evidence 'plugin output' (say 'evidence', or name "
        "Nessus if it really is a Tenable plugin's output):\n"
        + "\n".join(sorted(set(offenders)))
    )
