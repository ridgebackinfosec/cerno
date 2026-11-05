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
TUI uses** — `cerno_pkg/models.py`, `database.py`, `cross_scan.py`, `tools.py`,
`nxc_db.py`, `workflow_mapper.py` and `claude_assistant.py`. That shared core is
the contract between the two interfaces. A change to a shared function
(signature, return shape, or its database-access behavior) can break the
interface you weren't looking at.

Note that `analysis.py`, `render.py`, `tui.py` and `fs.py` are **TUI-only** (they
print), and `query.py`, `batch.py`, `ingest.py`, `workflow_prep.py`,
`workflow_contrib.py` and `exec_chain.py` are currently **MCP-only**. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full layer map.

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

## Contributing a verification workflow

The bundled workflows in `cerno_pkg/workflow_mappings.yaml` are meant to come
from real engagements, not from the demo data. If you verified a finding with a
method the bundled set doesn't cover, Cerno will turn the commands you actually
ran into a PR-ready entry.

1. **Run with attribution** so the commands are tied to the finding — TUI tool
   runs are attributed automatically; pass `finding_id` to the MCP
   `execute_command` / `start_execution`.
2. **Record a verdict** (`[R]` in the TUI, or `set_finding_verdict`). Only
   `confirmed` / `false_positive` findings can be contributed.
3. **Draft and review** with the MCP `get_workflow_candidate(finding_id)`. Hosts,
   ports, credentials, output paths and local directories are templated or
   dropped; read `review_hints` and rewrite the generated titles and notes into
   something that says *how to read the output* — what proves vulnerable versus
   not. That prose is the part only you can write.
4. **Export** with `export_workflow_contribution(finding_id)`, test it locally
   (`cerno review --custom-workflows <file>`, then `[W]` on a matching finding),
   and open a PR against `develop`. The exported file's header carries these
   steps too. Nothing is submitted for you.

**Prefer co-mapping over a duplicate entry.** If the issue you verified is
already covered for another scanner, add your finding's id to that entry rather
than adding a second one — pass `also_covers=["nessus:84502"]` to either tool,
or edit the existing entry's comma-separated `finding_id` in your PR. One entry
per real issue means `[W]` shows one card however the finding was discovered,
and it is what lets Cerno treat a match from one scanner as corroboration of
another's finding. Say in the PR *why* the ids are the same issue; that claim is
a judgement call and reviewers need it.

A **detection-only** finding (a technology fingerprint such as
`nuclei:tech-detect`) has nothing to verify and is deliberately left unmapped —
see [docs/CUSTOM_WORKFLOWS.md](docs/CUSTOM_WORKFLOWS.md). Please don't add
workflows just to clear `list_workflow_gaps`.

Every export passes a fail-closed leak scan, but **read the file before you push
it**: it came from your engagement.

## Versioning & changelog

- Bump the version in `pyproject.toml` and add an entry under `[Unreleased]` in
  `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/) format).
- User-visible changes **must** be documented in `CHANGELOG.md`.
- The release workflow tags and publishes automatically when the version change
  reaches `main`.

## Documentation

Keep docs in sync with code in the same PR: docstrings, `README.md`,
`docs/`, `CLAUDE.md`, and the `[Unreleased]` changelog section.
