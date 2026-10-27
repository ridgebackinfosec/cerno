# Contributing to Cerno

Thanks for contributing! This guide covers dev setup, the test workflow, and the
one rule that keeps Cerno's two interfaces — the interactive **TUI** and the
**MCP server** — from breaking each other.

## Branching: target `develop`

**All pull requests should be opened against the `develop` branch, not `main`.**
`main` is the release branch; changes flow `develop` → `main` via PR, and the
release workflow tags/publishes from `main`. A PR aimed at `main` will be asked
to retarget `develop`.

## Dev setup

```bash
git clone https://github.com/ridgebackinfosec/cerno.git
cd cerno
pip install -e ".[dev]"
```

Run the checks before opening a PR:

```bash
pytest                                   # full test suite
black cerno.py cerno_pkg/ tests/         # format
mypy cerno.py cerno_pkg/ --ignore-missing-imports   # type check (primary)
```

CI runs the full suite on every push and PR across **{ubuntu, windows, macos} ×
{Python 3.11, 3.12, 3.13}** (3.13 is allowed to fail). Because the minimum
supported version is **3.11**, verify anything version-sensitive against 3.11 —
e.g. `typing`/`pydantic` behavior differs from newer Pythons.

## The TUI ↔ MCP shared-core contract

Cerno exposes the same underlying capabilities two ways:

- **TUI** — `cerno review` and friends (`cerno.py`, `cerno_pkg/tui.py`,
  `cerno_pkg/fs.py`, `cerno_pkg/render.py`).
- **MCP server** — `cerno mcp` (`cerno_pkg/mcp_server/server.py`).

**The MCP tools/resources/prompts are thin adapters over the *same* functions the
TUI uses** — `cerno_pkg/models.py`, `analysis.py`, `cross_scan.py`, `tools.py`,
and `claude_assistant.py`. That shared core is the contract between the two
interfaces. A change to a shared function (signature, return shape, or its
database-access behavior) can break the interface you weren't looking at.

**Rule:** run the **full** `pytest` suite before every PR — both the TUI tests
*and* `tests/test_mcp_server.py` / `tests/test_mcp_contract.py` must pass. If you
change a shared function, exercise both paths.

### `tests/test_mcp_contract.py` (the safeguard)

This module is a tripwire + smoke test for the MCP surface:

- **Frozen inventory** — it asserts the exact set of registered tool, resource,
  and prompt names. If you intentionally add/remove/rename an MCP tool, update
  this list **in the same PR** (that failure is by design, so surface changes are
  deliberate).
- **Call-through** — it invokes each category through the real MCP path
  (`call_tool` / `read_resource` / `get_prompt`) against a seeded database, so a
  shared-function change that breaks serialization, output-schema validation, or
  argument handling fails here.
- **Hermeticity** — it points the database path at an empty DB to catch adapters
  that accidentally reach the default `~/.cerno/cerno.db` instead of the injected
  connection.

When you touch the MCP surface, also update `docs/MCP.md` and the README's
MCP section.

### MCP stdio rule

The MCP server speaks JSON-RPC over **stdout**, so MCP code paths must never
`print()` to stdout — use the `log_*` helpers (which write to
`~/.cerno/cerno.log`), and run external commands through
`ops.run_command_captured` (no Rich spinner / interactive prompts).

## Database changes

Cerno's schema is created directly (no migrations yet), so schema changes
require a major version bump and users re-importing scans. See the
[Database Design Principles](CLAUDE.md#database-design-principles) in `CLAUDE.md`
and [docs/DATABASE.md](docs/DATABASE.md). Mirror every DDL change in the
reference `schema.sql` (a test checks it defines the same tables, views and
indexes as `cerno_pkg/database.py`). Always test schema changes against a fresh
database.

## Versioning & changelog

- Bump the version in `pyproject.toml` and add an entry under `[Unreleased]` in
  `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/) format).
- User-visible changes **must** be documented in `CHANGELOG.md`.
- The release workflow tags and publishes automatically when the version change
  reaches `main`.

## Documentation

Keep docs in sync with code in the same PR: docstrings, `README.md`,
`docs/`, `CLAUDE.md`, and the `[Unreleased]` changelog section.
