# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Shorthand Commands

- **bcp** — bump the version, commit, and push to the current branch

## General Development Principles

Follow Python best practices (PEP 8, type hints, docstrings, SOLID, DRY, parameterized queries, proper error handling). The following are project-specific mandates:

- **Documentation**: Always update relevant documentation alongside code changes to keep everything synchronized and up-to-date automatically. This includes docstrings, CLAUDE.md, README.md, and **MANDATORY** updates to the [Unreleased] section in CHANGELOG.md for all user-visible code changes
- **Smoke Testing**: After completing ANY changes (code, documentation, configuration), ALWAYS provide a concise smoke test summary with manual testing steps the user can perform to verify the changes work correctly. Include specific commands, expected outputs, and edge cases to validate
- **Git Operations**: The user handles all git staging and commits manually. However, ALWAYS provide a concise one-line git commit message suggestion that accurately describes the change following conventional commit format (e.g., "feat: add user authentication", "fix: resolve parsing edge case", "docs: update installation guide", "refactor: extract validation logic"). Keep messages under 72 characters when possible. Do NOT execute git commands like `git add` or `git commit` - only provide the suggested commit message

## Database Design Principles

**CRITICAL**: Cerno uses SQLite as its primary data store. ALL database design and modifications MUST follow these principles:

### Normalization (Required)
1. **Eliminate Redundant Data**: Never store derived/computed values (counts, sums, durations) in tables - use SQL aggregation or views instead
2. **Lookup Tables**: Extract reference data (severity levels, artifact types, etc.) into separate lookup tables with foreign key constraints
3. **Single Source of Truth**: Each piece of data should exist in exactly one place - use JOINs to combine data, not duplication
4. **Functional Dependencies**: If column B is always determined by column A, create a separate table or use a view

### Foreign Key Integrity (Required)
1. **Always Define FKs**: Every relationship between tables MUST use `FOREIGN KEY` constraints
2. **Enable FK Enforcement**: Use `PRAGMA foreign_keys=ON` on all connections (already configured in database.py)
3. **Cascade Behavior**: Explicitly define `ON DELETE CASCADE` or `ON DELETE SET NULL` for each FK based on business logic
4. **Referential Integrity**: Design schema to prevent orphaned records through proper FK constraints

### Computed Values (Required)
1. **Use SQL Views**: For derived statistics (counts, durations, aggregates), create SQL views instead of storing in tables
2. **Aggregate on Query**: Use `COUNT()`, `SUM()`, `GROUP BY` in SELECT queries rather than maintaining cached counts
3. **Generated Columns**: For simple computed values, consider using SQLite's GENERATED ALWAYS columns
4. **Materialized Views**: Only cache computed values if performance profiling proves it necessary (and document why)

### Data Consistency (Required)
1. **CHECK Constraints**: Use CHECK constraints for enum-like fields (e.g., `CHECK(severity_int BETWEEN 0 AND 4)`)
2. **UNIQUE Constraints**: Enforce uniqueness at database level, not just application level
3. **NOT NULL**: Use NOT NULL for required fields to prevent NULL-related bugs
4. **Triggers for Audit**: Use triggers only for audit logging, not for maintaining derived data

### SQLite-Specific Best Practices
1. **Indexes**: Create indexes on foreign keys and frequently-queried columns (but avoid over-indexing)
2. **Transactions**: Always use transactions for multi-statement operations (use `db_transaction()` context manager)
3. **JSON Columns**: Use JSON columns only for truly variable/unstructured metadata - prefer structured columns when schema is known
4. **Type Affinity**: Be explicit with types (TEXT, INTEGER, REAL, BLOB) and use CHECK constraints to enforce
5. **Query Planning**: Use `EXPLAIN QUERY PLAN` to optimize slow queries

### Cross-Scan Data Tracking
1. **Shared Entity Tables**: Create dedicated tables for entities that span multiple scans (hosts, plugins, CVEs)
2. **Junction Tables**: Use proper many-to-many junction tables with composite keys
3. **Temporal Tracking**: Add `first_seen` / `last_seen` timestamps to track entity history across scans
4. **Global Queries**: Design schema to enable "all findings for host X across all scans" type queries

### Schema Management
- Database uses normalized structure created on initialization
- Schema version tracked in `database.py:SCHEMA_VERSION` (current: 4), written to `PRAGMA user_version`; `initialize_database()` raises `SchemaVersionError` for older DBs (CLI prints re-import instructions to stderr)
- Future schema changes will include migration system when needed
- Always test schema changes with fresh database before release

### Anti-Patterns to Avoid
❌ **Never** store counts/sums in tables when you can compute them with SQL
❌ **Never** duplicate reference data (severity labels, service names) across records
❌ **Never** use boolean flags for data that can be computed (e.g., `is_ipv4` from `ip_address`)
❌ **Never** use freeform text fields for categorical data (use lookup tables with FKs)
❌ **Never** skip foreign key constraints "for performance" (they're fast and prevent bugs)
❌ **Never** cache data without a clear performance justification (measure first)

### Design Review Checklist
Before implementing any schema change, verify:
- [ ] All relationships have foreign key constraints
- [ ] No redundant/derived data is stored in tables
- [ ] Reference data is normalized into lookup tables
- [ ] Computed values use views or aggregation queries
- [ ] CHECK constraints enforce valid values
- [ ] Indexes exist for foreign keys and query patterns
- [ ] Schema tested with fresh database
- [ ] Breaking change documented in CHANGELOG.md
- [ ] Major version bumped if needed

## Project Overview

**Cerno** is a Python CLI tool for reviewing Nessus vulnerability scan findings and orchestrating security tools (nmap, NetExec, Metasploit). It features a Rich-based TUI for interactive review, SQLite-backed persistence, and session state tracking.

**Core workflow**: Import `.nessus` files → Review findings in TUI → Run security tools → Track progress in database

**Target Python**: 3.11+ (3.8+ may work but not the target)

## Python Packaging Best Practices

**CRITICAL**: When adding new Python subpackages, you MUST explicitly list them in `pyproject.toml`. Setuptools does NOT auto-discover subpackages — omitting one causes `ModuleNotFoundError` in pipx/pip installations.

**Current `[tool.setuptools]` in pyproject.toml:**
```toml
packages = ["cerno_pkg", "cerno_pkg.mcp_server"]
py-modules = ["cerno"]

[tool.setuptools.package-data]
cerno_pkg = ["*.yaml", "skills/*.md", "demo/*.nessus", "demo/nxc-workspace/*"]
```

When adding a new `cerno_pkg/<subpkg>/` directory with `__init__.py`, add it to the `packages` list. Non-Python files shipped with the package (YAML, the assistant skill prompt, demo data) must match a `package-data` glob.

## Build & Development Commands

### Setup Development Environment

```bash
# Install package in editable mode with dev dependencies
pip install -e ".[dev]"

# Or install from requirements (production dependencies only)
pip install -r requirements.txt
```

### Running the Application

```bash
# Direct execution (development)
python cerno.py --help

# Installed command (after pip install)
cerno --help

# Common commands
cerno import nessus scan.nessus   # Import Nessus scan
cerno review                      # Start interactive review
                                  #   At scan prompt, enter "1-3" or "1,3,5" to review multiple scans merged
cerno scan list                   # List all scans (compact; --wide = all severities, --json = scripting)
cerno scan delete <scan_name>     # Delete scan from database
cerno scan compare <s1> <s2>      # Compare findings between two scans
cerno scan history <host_ip>      # Show vulnerability timeline for a host
cerno creds list                  # List NetExec credential refs (never shows secret values)
cerno creds reveal <ref>          # Reveal a credential's cleartext (SENSITIVE, local, audited)
cerno mcp                         # Run the MCP server over stdio (launched by an MCP client)
```

### Testing

```bash
# Run all tests with coverage
pytest

# Run with verbose coverage report
pytest --cov=cerno_pkg --cov-report=term-missing --cov-report=html

# Run specific test file
pytest tests/test_parsing.py

# Run by marker
pytest -m unit                      # Fast unit tests only
pytest -m integration               # Integration tests (DB, filesystem)
pytest -m "not slow"                # Skip slow tests

# Run specific test
pytest tests/test_parsing.py::TestSplitHostPort::test_ipv4_with_port

# Show test durations (find slow tests)
pytest --durations=10
```

**Coverage goals**: 85% overall, 90%+ for critical modules (database.py, models.py, parsing.py, nessus_import.py)

### Linting & Formatting

```bash
# Format code with black
black cerno.py cerno_pkg/ tests/

# Type checking with mypy (primary checker)
mypy cerno.py cerno_pkg/ --ignore-missing-imports

# Type checking with pyright (secondary checker)
pyright cerno.py cerno_pkg/

# Generate full type checking report (JSON)
pyright . --outputjson > pylance-report.json

# Check specific file
pyright cerno_pkg/tui.py
```

### Type Checking Philosophy

**Dual type checking**: mypy (primary, CI/CD with `continue-on-error: true`) + pyright (secondary, local). Config: `pyproject.toml` `[tool.mypy]` and `pyrightconfig.json` (typeCheckingMode: "basic"). Fix mypy errors first. Known type errors documented in `pylance-report.json` — checking will become stricter in future releases.

## Architecture

### Database Architecture

Cerno uses a **fully normalized database architecture** with SQLite as the source of truth:

- **Location**: `~/.cerno/cerno.db` (global, cross-scan)
- **Schema version**: Tracked in `database.py:SCHEMA_VERSION` (current: 4; v2/v3 renamed review states — shipped in 1.7.0 as a minor bump by explicit user decision; v4 added the execution→data loop tables/views — major bump, forces re-import)
- **Schema approach**: Normalized structure created on initialization
- Import writes **no** per-plugin `.txt` files; all data lives in the database

**Key design principles**:
- Database is source of truth for review state, host:port data, session state
- File browsing queries database directly (no filesystem walks during review)
- Review state tracked only in the `findings.review_state` column
- CVEs are read from the `.nessus` file at import and stored in the `plugins.cves` JSON column
- Normalized host/port tables enable cross-scan tracking
- SQL views compute statistics on-demand (no redundant cached data)

### Module Structure

```
cerno.py                  # Typer CLI entry point: review/import/scan/config/workflow/creds/demo/mcp/reset
                          # Navigation: browse_file_list, browse_workflow_groups, show_session_statistics
                          # Claude chat: browse_claude_chat() (per-finding), browse_claude_chat_aggregate() (scope)
cerno_pkg/
  ├── database.py          # SQLite connection, schema (SCHEMA_SQL_TABLES/VIEWS, SCHEMA_VERSION), db_transaction()
  ├── models.py            # Data models: Scan, Plugin, Finding, Host, Port, ToolExecution, Artifact,
  │                        # lookup models, verdict/ingest models (FindingVerdict, VerifiedPort, …),
  │                        # ClaudeConversationTurn / ClaudeAggregateConversationTurn
  │                        # Single-scan: Finding.get_by_scan_with_plugin(); multi-scan: get_by_scan_ids_merged()
  ├── nessus_import.py     # .nessus XML parsing and database import (DB only; no files written)
  ├── cross_scan.py        # `cerno scan compare` / `scan history` data (v_scan_plugin_summary, v_host_scan_findings)
  ├── parsing.py           # Host:port parsing: parse_hosts_ports(), split_host_port()
  ├── analysis.py          # Identical host:port groups ([H]) and superset/overlap analysis ([O])
  ├── query.py             # FindingQuery + run_finding_query(): AND-combined, parameterized predicates
  │                        # shared by MCP query_findings, list_workflow_gaps and batch
  ├── nmap_parse.py        # Pure nmap XML parser (open ports + NSE vuln verdicts; no DB)
  ├── ingest.py            # ingest_execution(): run output -> verified_ports / nse_script_results /
  │                        # nxc_flag_observations; idempotent per execution_id (rows reconciled in place)
  ├── nxc_db.py            # Read-only NetExec workspace access (creds as refs, shares, flags); get_nxc_manager()
  ├── creds.py             # Audited credential reveal shared by `cerno creds` and MCP reveal_credential
  ├── exec_chain.py        # Wrapper unwrapping (sudo/env/timeout/proxychains4…), allow/deny glob matching,
  │                        # is_runnable(); shared by MCP exec policy, workflow_prep, batch, workflow_contrib
  ├── workflow_mapper.py   # Workflow YAML loading; build_workflow_mapper(config) merges custom_workflows_path
  ├── workflow_mappings.yaml  # Bundled verification workflows
  ├── workflow_prep.py     # prepare_workflow(): fill <TARGET>/<PORT>/<USERNAME>/<PASSWORD>/<DOMAIN>/<INTERFACE>
  │                        # (variants canonicalized) and mark each command executable or manual
  ├── workflow_contrib.py  # Workflow contribution loop: genericize_command(), fail-closed leak scan,
  │                        # assess_candidate() (new | enhanced | None), to_yaml_fragment()
  ├── batch.py             # plan_batch (dry run) + execute_batch over a FindingQuery via the job registry
  ├── mcp_server/          # MCP server (BETA), `cerno mcp`, stdio transport
  │   ├── __init__.py      #   build_server(), main()
  │   ├── jobs.py          #   In-memory async job registry (start/status/cancel/list; killpg cancellation)
  │   └── server.py        #   Pure tool_*/resource_*/prompt_* adapters (testable with a conn) + FastMCP
  │                        #   registration gated by config flags. Tool reference: docs/MCP.md.
  │                        #   stdout is the JSON-RPC channel: adapters never print
  │                        #   (exec uses ops.run_command_captured)
  ├── claude_assistant.py  # Claude Assistant: context builders, run_exchange()/run_aggregate_exchange(),
  │                        # consent (ensure_enabled, claude_enabled); load_skill_prompt() reads
  │                        # cerno_pkg/skills/cerno-assistant.md (inline fallback)
  ├── session.py           # Review session persistence (sessions + session_scans), scan summary
  ├── onboarding.py        # First-run guided tour, post-scan-selection tips
  ├── tool_context.py      # ToolContext / CommandResult (workflow builder I/O); ReviewContext (exported, unused)
  ├── tool_registry.py     # Tool dataclass + TOOL_REGISTRY helpers
  ├── tool_definitions.py  # register_all_tools(): nmap, netexec, metasploit, custom command
  ├── tools.py             # Command builders (build_*_cmd), workflow builders (build_*_workflow),
  │                        # run_tool_workflow() dispatch, NSE profiles, remote scan mode
  ├── ops.py               # Command execution, sudo/proxychains4 handling, logging runs, remote-scan HTTPS server
  ├── render.py            # Rich rendering: tables, menus, pagers, finding display, Claude panel
  ├── tui.py               # Findings-list action handling, severity selection, multi-line Claude input
  ├── fs.py                # Finding view (handle_finding_view), host views, move_review_state(), page size
  ├── enums.py             # DisplayFormat, ViewFormat, SortMode
  ├── config.py            # CernoConfig dataclass, load/save, reset_config_key(), MCP_NOT_APPLICABLE_KEYS
  ├── constants.py         # Paths, review-state constants, NSE profiles, LIGHT_BG_COLOR_MAP
  ├── ansi.py              # CernoConsole (color_scheme remapping), err/warn/info/ok helpers
  ├── banner.py            # Promotional startup banner (`review -q` hides it)
  ├── logging_setup.py     # Loguru setup with rotation; log_info/log_debug/log_error
  ├── skills/cerno-assistant.md  # Claude Assistant system prompt
  ├── demo/                # Packaged copy of the demo scans + NetExec workspace (`cerno demo`)
  └── _version.py          # Version resolution (importlib.metadata → pyproject.toml)
```

**Module organization**:
- Modular design with clear separation of concerns
- `ToolContext`/`CommandResult` give every tool workflow builder the same signature
- Clear separation: `tui.py` handles navigation, `fs.py` handles file operations, `render.py` handles display
- Database objects (`Plugin`, `Finding`) flow through entire call chain

### Core Data Flow

1. **Import**: `.nessus` XML → `nessus_import.py` → SQLite (`scans`, `plugins`, `findings`, `finding_affected_hosts`)
2. **Review**: `Finding.get_by_scan_with_plugin()` → `(Finding, Plugin)` tuples → `render.py` tables → User actions → Update `review_state` column
3. **Tools**: TUI menu → Pass `Plugin`/`Finding` objects → `tools.py` → Execute command → `tool_executions` + `artifacts` tables
4. **Session**: Auto-save to `sessions` table (start time, duration, statistics)
5. **Multi-scan review**: User selects multiple scans at prompt (e.g. `1,3` or `1-3`) → `Finding.get_by_scan_ids_merged(scan_ids)` deduplicates by `plugin_id` (one representative Finding per plugin, with sibling IDs from other scans in `extra_finding_ids` so all host/port queries and analyses span every selected scan) → "Scans" column shows `All N` or `M of N` → review-state changes broadcast to all selected scans → `session_scans` junction table records all scan IDs for the session
6. **Claude Assistant**: `[A]` key → `browse_claude_chat()` (per-finding) or `browse_claude_chat_aggregate()` (scope-level) → `claude_assistant.py` builds context + calls `claude -p` → response persisted in `claude_conversations` (per-finding FK) or `claude_aggregate_conversations` (context_key string)

**Key principle**: Plugin and Finding database objects flow through entire call chain. No filename parsing for plugin_id extraction - synthetic paths used only for display/directory structure.

### Parsing Architecture

**Canonical parser**: `parsing.py:parse_hosts_ports(lines)` returns `(hosts, ports_str)`:
- Hosts de-duplicated in original order
- Ports unique and sorted numerically, comma-joined
- Tokens split by `split_host_port()` (IPv4, bracketed IPv6, hostnames; port returned as a string)

**Usage**: All host:port parsing must use `parse_hosts_ports()` to ensure consistency.

### Tool Registry Pattern

`tool_registry.py` defines the `Tool` dataclass (`id`, `name`, `description`,
`workflow_builder`, `command_builder`, `requires`, `menu_order`, `options`);
`tool_definitions.py:register_all_tools()` registers nmap, netexec, metasploit and
the custom command. `tools.py:run_tool_workflow()` builds one `ToolContext` and calls
`tool.workflow_builder(ctx)`, which returns a `CommandResult`, so adding a tool needs
no dispatch changes. See `docs/TOOL_SYSTEM_GUIDE.md`.

### Database Schema

**Foundation Tables**:
- `severity_levels`: Normalized severity reference data (0-4, labels, colors)
- `artifact_types`: Artifact type definitions
- `hosts`: Normalized host data across ALL scans (enables cross-scan tracking)
- `ports`: Port metadata
- `audit_log`: Change tracking (reserved; nothing writes to it yet)

**Core Tables**:
- `scans`: Top-level scan metadata (scan_name, export_root, .nessus hash)
- `plugins`: Plugin metadata (plugin_id, severity_int, CVSS, CVEs, Metasploit modules)
  - Note: `severity_label` accessed via `severity_levels` table JOIN
- `findings`: Findings per scan (scan_id + plugin_id, review_state)
  - Note: `host_count`, `port_count` computed via `v_finding_stats` view
- `finding_affected_hosts`: Host:port combinations (finding_id, host_id FK, port_number FK, plugin_output)
  - Uses foreign keys to normalized `hosts` and `ports` tables
- `host_services`: Per-scan service discovery (scan_id, host_id, port_number, protocol, svc_name)
  - Populated from Nessus ReportItem `svc_name`/`protocol` attributes during import
  - Uses foreign keys to `scans`, `hosts`, and `ports` tables
- `sessions`: Review session tracking (start time, end time)
  - Note: Statistics computed via `v_session_stats` view
- `session_scans`: Junction table linking sessions to their scans in multi-scan mode (session_id FK, scan_id FK; composite PK)
- `tool_executions`: Command history (tool_name, command_text, exit_code, duration, sudo usage)
- `artifacts`: Generated files (artifact_path, artifact_type_id FK, file_hash, file_size, metadata JSON)
  - Uses `artifact_type_id` foreign key to `artifact_types` table
- `workflow_executions`: Workflow tracking (reserved; nothing writes to it yet)
- `claude_conversations`: Per-finding Claude Assistant chat history (finding_id FK → findings, CASCADE delete)
  - Keyed to `finding_id`; each row is one turn (role: user|assistant, content, created_at)
  - Used by `browse_claude_chat()` / `ClaudeConversationTurn` model
- `claude_aggregate_conversations`: Scope-level Claude Assistant chat history (no FK — free-form context_key)
  - context_key format: `"sev_menu:{scan_ids}[:{host_filter}]"` (sorted, comma-joined IDs) or `"findings_list:{scan_ids}:{scope_hash}"`
  - Used by `browse_claude_chat_aggregate()` / `ClaudeAggregateConversationTurn` model

**Execution→Data Loop Tables** (schema v4):
- `verdict_types` / `nse_verdicts` / `port_states`: lookup tables (seeded in init)
- `verified_ports`: live-verified open ports from a tool run (FK `execution_id`→tool_executions CASCADE; idempotent per execution)
- `nse_script_results`: NSE script results + vuln verdicts (FK `execution_id` CASCADE; `port_number` NULL = host script)
- `nxc_flag_observations`: point-in-time nxc security-flag snapshot (FK `execution_id` CASCADE); creds/shares stay live-read via `nxc_db.py` (not duplicated)
- `finding_verdicts`: append-only verification verdict history (FK `finding_id`→findings CASCADE); current = latest `created_at`, ties broken by highest `verdict_id`
- `verdict_evidence`: evidence backing a verdict (FK `verdict_id` CASCADE; `execution_id`/`artifact_id`/`nse_result_id` SET NULL)

**SQL Views** (Computed Statistics):
- `v_finding_stats`: Host/port counts per finding
- `v_session_stats`: Session duration and statistics
- `v_plugins_with_severity`: Plugins with severity labels
- `v_host_findings`: Cross-scan host analysis
- `v_artifacts_with_types`: Artifacts with type names
- `v_scan_plugin_summary`: Plugin presence + host/port counts per scan (`cerno scan compare`)
- `v_host_scan_findings`: Per-host stats by scan (`cerno scan history`)
- `v_http_services`: HTTP/HTTPS services per scan (identifies web services by svc_name heuristics)
- `v_finding_current_verdict`: latest verification verdict per finding (joined to `verdict_types`)
- `v_nse_results_with_verdict`: `nse_script_results` with resolved verdict label
- `v_finding_verified_stats`: per-finding verified_port/nse_result/vulnerable counts (via `tool_executions.finding_id`)

**Schema changes**: Update `database.py:SCHEMA_SQL_TABLES` and `SCHEMA_SQL_VIEWS`, then mirror the change in `schema.sql` (`tests/test_database.py` fails if its tables/views/indexes differ) and `docs/DATABASE.md`. Test with fresh database before release.

### Version Management

Version is defined in `pyproject.toml:project.version` (single source of truth).

`_version.py` resolves version with fallback chain:
1. `importlib.metadata.version("cerno")` (installed package)
2. Parse `pyproject.toml` (development mode)
3. "unknown" (fallback)

**When bumping version**: Update `pyproject.toml` only. Do NOT hardcode version elsewhere.

#### Incremental Changelog Updates

**MANDATORY**: All code changes that affect functionality, behavior, or user experience MUST be documented in the `[Unreleased]` section of CHANGELOG.md immediately after implementation.

**When to update [Unreleased] (Required):**
- ✅ After implementing any feature (Added section)
- ✅ After fixing any bug (Fixed section)
- ✅ After modifying existing behavior (Changed section)
- ✅ After deprecating functionality (Deprecated section)
- ✅ After removing features (Removed section)
- ✅ After addressing security issues (Security section)

**When to skip [Unreleased] updates (Exceptions):**
- Internal refactoring with no user-visible changes
- Pure documentation updates (README, comments only)
- Test-only changes with no production code impact
- Development tooling changes (CI/CD, scripts)

**Process (Automatic):**
1. After making code changes with Edit/Write tools, IMMEDIATELY update CHANGELOG.md
2. Locate the `[Unreleased]` section (line 8)
3. Add bullet points under appropriate subsections (Added/Changed/Fixed/etc.)
4. Follow existing format and style from recent releases (v1.1.0 as reference)
5. Include file references where helpful (e.g., `render.py:render_actions_footer()`)
6. Preserve any existing [Unreleased] content (append, don't replace)

**Enforcement:**
- This is NOT optional - Claude will proactively update [Unreleased] after code changes
- If you make changes without updating [Unreleased], that is a bug in Claude's behavior
- You should never need to ask "did you update the changelog?" - it happens automatically

#### Version Increment SOP

**CRITICAL**: Whenever the user requests a version increment, you MUST follow this comprehensive process with mandatory user confirmation.

**Phase 1: Gather All Changes**
1. **Read current version** from `pyproject.toml` line 7 (`version = "X.Y.Z"`)
   - This is the last version that was documented
   - Git tags are only created on release (main branch merge), not on every version bump

2. **Read [Unreleased] section** in CHANGELOG.md (line 8)
   - Extract all documented changes
   - Note which subsections have content (Added/Changed/Fixed/etc.)

3. **Review git commit history** since last version in CHANGELOG.md:
   ```bash
   # Find the last version section in CHANGELOG.md (e.g., ## [1.1.1])
   # Then get commits since that version was documented
   git log --oneline --since="<date from last changelog entry>" HEAD
   ```
   - Identify commits that might not be documented in [Unreleased]
   - Look for conventional commit prefixes (feat:, fix:, docs:, refactor:)

4. **Check for uncommitted changes** in git status
   - Review modified files that might not be documented yet
   - Cross-reference with [Unreleased] section

5. **Compile comprehensive change list**
   - Combine [Unreleased] content + undocumented git commits + unstaged changes
   - Organize into Keep a Changelog categories

**Phase 2: Present Changes for Approval (MANDATORY)**
Present the gathered changes to the user in this format:

```
I found the following changes since version [LAST_VERSION]:

### Added
- [List all items from [Unreleased] Added section]
- [Any undocumented features from git history]

### Changed
- [List all items from [Unreleased] Changed section]
- [Any undocumented behavior changes from git history]

### Fixed
- [List all items from [Unreleased] Fixed section]
- [Any undocumented bug fixes from git history]

[Include other sections as applicable: Deprecated, Removed, Security]

### Undocumented Changes
[If any commits found without corresponding [Unreleased] entries, list them here]
- Commit abc123: feat: add new feature (NOT DOCUMENTED)
- Commit def456: fix: resolve edge case (NOT DOCUMENTED)

---

Questions before proceeding:
1. Are all changes listed above accurate and complete?
2. Should any undocumented commits be added to the changelog?
3. Are there any additional changes to document?
4. What version number should this be? (Current: X.Y.Z)
```

**Wait for user confirmation before proceeding to Phase 3.**

**Phase 3: Update Both Files Atomically (After Approval)**
Only after user confirms the changelog content:

1. **Update `pyproject.toml`**: Change `project.version` to the approved version number

2. **Update `CHANGELOG.md`**:
   - Create new version section: `## [X.Y.Z] - YYYY-MM-DD` (use current date)
   - Move all approved content from [Unreleased] to the new version section
   - Add any additional items the user requested
   - Organize sections in standard order: Added, Changed, Deprecated, Removed, Fixed, Security
   - Ensure proper formatting (bullets, sub-bullets, indentation)
   - Reset [Unreleased] section to empty (keep header `## [Unreleased]`, remove all content below it)

3. **Verify final state**:
   - New version section exists with format `## [X.Y.Z] - YYYY-MM-DD`
   - [Unreleased] section is empty and ready for next development cycle
   - Both files updated in same operation

**Phase 4: Validation**
- Confirm both files updated atomically
- Verify changelog entry matches required format for release workflow
- Check that all user-requested changes are included
- Ensure [Unreleased] section reset correctly

**This is mandatory** - never increment the version without:
1. Gathering changes from ALL sources ([Unreleased], git history, user input)
2. Presenting changes to user for confirmation
3. Waiting for explicit approval before updating files
4. Documenting ALL changes in the final changelog entry

**Important Notes:**
- Git tags are created automatically by the release workflow when changes are merged to `main` branch
- Not every version bump in `pyproject.toml` gets a git tag immediately
- Always check `pyproject.toml` for current version, not git tags
- The automated release workflow will fail if CHANGELOG.md is missing the version entry or has incorrect format

#### Automated Release Workflow

**Release workflow** (`.github/workflows/release.yml`): Triggered automatically when `pyproject.toml` version changes on `main`. Requires matching `## [X.Y.Z] - YYYY-MM-DD` entry in CHANGELOG.md. Creates annotated git tag and GitHub Release automatically.

### Constants & Configuration

**Configuration** (`~/.cerno/config.yaml`): All user preferences managed via config file. Auto-created with defaults on first run. All configuration values are set through this file only.

**CLI commands**:
- `cerno config show` - Display all configuration settings with current values
- `cerno config set <key> <value>` - Change a configuration value
- `cerno config get <key>` - Get current value of a setting
- `cerno config reset <key>` - Reset a single setting to its default (`config.reset_config_key()`; nullable keys drop out of the YAML)
- `cerno config reset` - Reset configuration to defaults (creates backup)

**Note**: Environment variables are not used for configuration. Use `config.yaml` for all settings including:
- `results_root` - Artifact storage path (default: `~/.cerno/artifacts`)
- `top_ports_count` - Top ports shown in the scan overview (default `5`, capped at 100)
- `term_override` - Force a terminal type (`dumb` disables colors)
- `nxc_workspace_path` - NetExec workspace (default `~/.nxc/workspaces/default`; `""` disables)
- `nxc_enrichment_enabled` - NetExec enrichment (default `true`); when off, `get_nxc_manager()` returns None, which also disables `cerno creds`, MCP credential tools/injection/reveal and nxc ingest
- `proxychains_enabled` / `proxychains_host` / `proxychains_port` - Route tools through `proxychains4` (SOCKS5; default off, `127.0.0.1:9000`)
- `pivot_interface` / `pivot_http_port` - Remote scan mode: interface and HTTPS port (default `8877`) serving the target list to a pivot host
- `log_path` - Log file location (default: `~/.cerno/cerno.log`)
- `debug_logging` - Enable DEBUG level logging (default: `false`)
- `no_color` - Disable ANSI color output (default: `false`)
- `color_scheme` - Terminal background the colors are tuned for: `light` (default) or `dark`. Light remaps every named color via `constants.LIGHT_BG_COLOR_MAP` in one place: `ansi.CernoConsole.get_style()` (all Rich string styles + Rich's built-in theme; also installed as Rich's global console so `Prompt`/`Progress` match) and `ansi.initialize_colors()` (raw ANSI `C.*` codes). Dark = classic named colors, unchanged. Keep using plain color names in new code; don't hardcode light-only variants. `config set` rejects values outside a field's `choices` metadata
- `default_tool` - Pre-select tool in menu (e.g., `nmap`, `netexec`)
- `default_netexec_protocol` - Default protocol for NetExec (e.g., `smb`, `ssh`); MCP `generate_netexec_cmd` / bare `"netexec"` batch strategy use it when `protocol` is omitted (else `smb`)
- `nmap_default_profile` - Default NSE profile name; MCP `generate_nmap_cmd` uses its scripts when `nse_option` is omitted (`""` = none), and its UDP need when `udp` is omitted (`tools.find_nse_profile()`)
- `custom_workflows_path` - Path to custom workflows YAML file; merged over bundled workflows everywhere in the MCP via `workflow_mapper.build_workflow_mapper(config)` (also the default in `query.run_finding_query` / `workflow_prep.prepare_workflow`)
- `claude_assistant_enabled` - Enable/disable Claude Assistant (default: `false`, opt-in). Pressing `[A]` while installed-but-disabled shows a data-path disclosure (`claude_assistant.CONSENT_DISCLOSURE`) and persists consent via `claude_assistant.ensure_enabled()`; `claude_assistant.claude_enabled(config)` is the single availability gate. `[A]` is hidden only when `claude` is not on PATH
- `mcp_allow_execution` - Allow the `cerno mcp` server to execute tool commands via `execute_command` (default: `false`)
- `mcp_allow_mutations` - Allow the `cerno mcp` server to mutate state (`set_review_state`, `add_note`, `import_nessus`, `ingest_results`, `set_finding_verdict`) (default: `false`)
- `mcp_allow_cred_injection` - Allow `execute_command` to resolve `@cred:<ref>@` placeholders to real NetExec secrets server-side at run time (default: `false`). Independent of `mcp_allow_execution`; the resolved secret is never logged, returned, or written to an artifact (masked in `command_text`, scrubbed from stdout/stderr **and from registered `--log`/`-oA` artifact files**)
- `mcp_allow_cred_reveal` - Allow the MCP `reveal_credential` tool to return a credential's **cleartext** secret to the caller (default: `false`). Strictly more sensitive than injection (reveal hands the secret back), gated independently — injection being on does NOT enable reveal. The local `cerno creds reveal <ref>` CLI works regardless of this flag; every reveal is audited to `tool_executions` (`tool_name='cred_reveal'`, ref only, never the value)
- `mcp_exec_allowlist` - Glob patterns for the binaries the MCP `execute_command` tool may run, matched on the basename of the target binary after unwrapping `sudo`/`proxychains4` (default: `config.DEFAULT_MCP_EXEC_ALLOWLIST` = `nmap, nxc, netexec, msfconsole` plus low-impact recon utilities: `curl, wget, dig, host, nslookup, whois, ping, traceroute, ssh-audit, sslscan, testssl*, whatweb, showmount, rpcinfo, snmpwalk, onesixtyone`; binaries with built-in command escapes such as `find`/`ssh`/`nc`/`smbclient` are deliberately excluded). `*` = any binary not denied; **empty list = deny all**. Only consulted when `mcp_allow_execution` is on. Set via CSV: `cerno config set mcp_exec_allowlist "nmap,nxc"`
- `mcp_exec_denylist` - Glob patterns for binaries `execute_command` may never run, checked against every binary in the chain including wrappers; always wins over the allowlist (default: `config.DEFAULT_MCP_EXEC_DENYLIST`, destructive commands like `rm, dd, mkfs*`). A guardrail, not a security boundary. Both list keys go through `config.coerce_str_list()` on load and `config set`, so YAML scalars and CSV strings become lists
- `mcp_allow_batch` - Allow the MCP `execute_batch` tool to RUN the generated command for every finding matched by a query (default: `false`). `plan_batch` (the reviewable dry run) is always available; `execute_batch` is registered only when BOTH `mcp_allow_execution` and `mcp_allow_batch` are on, and every command still passes `_check_exec_policy`, the cred gate, and the per-command timeout — this flag only authorizes the fan-out across a query
- `mcp_batch_concurrency` - Max commands `execute_batch` runs concurrently (default: `1` = sequential; keep small, 2-3, since nmap/nxc are already internally parallel). Implemented via a shared semaphore gate on the job registry
- `mcp_batch_timeout` - Per-command timeout in seconds for each `execute_batch` command (default: `300`), clamped to the same [1, 3600] ceiling as `execute_command`
- `contribution_export_dir` - Where the MCP `export_workflow_contribution` tool writes sanitized, PR-ready workflow YAML files (default: `None` = `<results_root>/contributions`). Local file only; nothing is submitted

**MCP config contract**: the MCP server honors every config key with precedence explicit tool arg > config > hardcoded default (`default_page_size` → default `limit` for `list_findings`/`query_findings`/`search_findings`, min 8, else 500), except the TUI-only keys in `config.MCP_NOT_APPLICABLE_KEYS` (`no_color`, `color_scheme`, `term_override`, `default_tool`, `claude_assistant_enabled`, `pivot_interface`, `pivot_http_port`, `top_ports_count`). `tests/test_mcp_config.py` fails when a new key is added without classifying it. Tests isolate `config.get_config_path()` to a temp file (autouse `conftest.reset_environment`), so the developer's real config never leaks in.

**NSE profiles** (`constants.py:NSE_PROFILES`): Pre-configured nmap script sets (SMB, SSL, HTTP, etc.)

### Workflow Mappings

`workflow_mappings.yaml`: Maps plugin IDs → verification workflows (YAML format).

**CLI options**:
- `--custom-workflows PATH`: Supplement bundled workflows (custom overrides on conflict)
- `--custom-workflows-only PATH`: Replace bundled workflows entirely

**Workflow features**:
- Multi-plugin workflows (comma-separated plugin IDs)
- Display-only (commands, notes, references)
- Press `[W]` in TUI to view workflow for current plugin

### Logging

**Backend**: Prefers loguru with rotation (1 MB, 7 days retention), falls back to stdlib logging.

**Decorators**: `@log_timing` logs execution duration at DEBUG level.

**Global exception hook**: Logs unhandled exceptions (Rich still shows pretty tracebacks).

**Shims**: `_log_info()`, `_log_debug()`, `_log_error()` keep code backend-agnostic.

## Development Patterns

### Data vs Render Separation

**Pattern**: Compute pure data first, then render with Rich. Example: `analysis.py:build_compare_data()` returns data dict → `render_compare_table()` creates Rich table.

### Severity Handling

**Centralized helpers**:
- `_severity_color_name(severity_int: int) -> str`: Returns Rich color name
- `colorize_severity_label(label: str, severity_int: int) -> str`: ANSI-colored label
- `severity_style(severity_int: int) -> Style`: Rich Style object
- `pretty_severity_label(severity_int: int) -> str`: Formatted Rich text

**Mapping**: `0=Info, 1=Low, 2=Medium, 3=High, 4=Critical`

### Review State Management

**States** (`constants.py:REVIEW_STATES`): `unreviewed` → `in_progress` → `done`, and `done` → `unreviewed`
- Transitions are defined once in `constants.py:REVIEW_TRANSITIONS` and enforced by `Finding.transition_review_state()` (raises `InvalidReviewTransition`) — used by the TUI and MCP `set_review_state`
- `Finding.update_review_state()` is the raw setter with no check; use it only to sync multi-scan siblings to an already-validated state
- All TUI status changes go through `fs.py:move_review_state(finding, target=None)` (default = next status in the cycle)
- UI wording/colours come from `constants.py` (`REVIEW_STATE_LABELS`, `REVIEW_STATE_STYLES`, `REVIEW_STATE_ICONS`, `REVIEW_MOVE_LABELS`): users see "status" and the verb "Move" ("Move to In Progress", "Move to Done", "Move back to Unreviewed", bulk "Move to next status") — reuse these rather than hardcoding strings
- Finding view `[M]` moves one step; findings list `[M]` moves every filtered finding one step; `[D]` Done list → `[M]` moves Done findings back to Unreviewed (multi-select)
- Findings list `[I]` toggles an In Progress-only status filter (`tui.py:filter_finding_candidates()` applies name/group/status filters); `[C]` clears it with the name filter

**Database-only**: `findings.review_state` is the sole record (no filename prefixes).

### Session Persistence

**Auto-save**: Review progress saved to `sessions` table (no `.cerno_session.json` files in DB-only mode).

**Resume prompt**: On startup, shows session details (in-progress/done counts, session start time).

**Cleanup**: Auto-delete session after successful completion.

**Multi-scan sessions**: When reviewing multiple scans, all selected scan IDs are recorded in `session_scans` (junction table). On resume, the same set of scans is restored automatically.

### Terminal Responsiveness

**Terminal width detection**: `ansi.py:get_terminal_width()` detects current terminal width with graceful fallback to 80 chars.

**Responsive layouts**: UI adapts to terminal width for optimal display:
- **Action footer** (`render.py:render_actions_footer()`):
  - Wide terminal (≥100 chars): 2-column grid layout
  - Narrow terminal (<100 chars): Single-column layout to prevent wrapping
- **Status line** (`cerno.py:browse_file_list()`):
  - Wide terminal (≥120 chars): Single line with separators
  - Medium terminal (80-119 chars): Two-line layout
  - Narrow terminal (<80 chars): Multi-line layout (one item per line)

**Group filter descriptions**: Enhanced `group_filter` tuple from `(index, plugin_ids)` to `(index, plugin_ids, description)` to provide context in status line (e.g., "Group #1: Identical host:port combinations").

**Page size configuration**: Users can override auto-detected page size via `config.yaml`:
```yaml
default_page_size: 20  # Fixed page size (overrides auto-detection)
```
Set to `null` or omit for automatic detection from terminal height. Falls back to 12 if detection fails (logs debug hint).

**UI Improvements**:
- **Streamlined file view**: Default to grouped format, offer post-view menu for Copy/Change format/Back (reduces 4 steps to 1-2)
- **Smart CVE format**: Auto-selects combined format for 1-2 findings, separated for 3+ (shows preview before asking)
- **MSF indicator**: Metasploit module indicator moved to panel subtitle for cleaner visual hierarchy
- **Done list**: `[D]` in the findings list opens the Done list; `[M]` there moves selected findings back to Unreviewed
- **Comparison groups pager**: After `[H]` Compare, groups with >8 findings can be paged in full by answering `D` at the prompt

## Testing Practices

### Fixture Usage

**Database**: Use `temp_db` fixture (in-memory SQLite, schema initialized) for integration tests.

**Filesystem**: Use `temp_dir` (auto-cleanup).

**Nessus data**: `goad_nessus_fixture` (74 plugins, 755 hosts; conftest) for slow tests, `sample_nessus_xml` (conftest) or the module-local `minimal_nessus_fixture` (3 plugins, 3 hosts; `tests/test_nessus_import.py`) for fast ones.

**Isolation**: the autouse `reset_environment` fixture points `config.get_config_path()` at a temp file, so tests never touch the real `~/.cerno/config.yaml`. Code that uses `Path.home()` (e.g. `cerno reset`) must still be monkeypatched explicitly.

### Test Markers

- `@pytest.mark.unit`: Fast, isolated (< 0.1s each)
- `@pytest.mark.integration`: DB or filesystem (< 1s each)
- `@pytest.mark.slow`: Large file processing (mark as slow)

### TUI ↔ MCP contract

The MCP server (`cerno_pkg/mcp_server/server.py`) is thin adapters over the same
functions the TUI uses (`models.py`, `analysis.py`, `cross_scan.py`, `tools.py`,
`claude_assistant.py`), so changing a shared function can break the other
interface. `tests/test_mcp_contract.py` guards this: it freezes the MCP
tool/resource/prompt inventory and drives every category through the real MCP
path against a seeded DB. When you intentionally change the MCP surface, update
that test's `EXPECTED_*` sets in the same change. See `CONTRIBUTING.md`.

## Common Tasks

### Adding a New Command

1. Add Typer command in `cerno.py` (use `@app.command()` decorator)
2. Import required functions from `cerno_pkg`
3. Add docstring for `--help` output
4. Test manually: `python cerno.py <command> --help`

### Adding a New Database Column

**Note**: Database schema changes currently require bumping the major version and having users re-import scans. A proper migration system will be implemented in a future release.

1. Update `database.py:SCHEMA_SQL_TABLES` with new column
2. Update `schema.sql` (reference copy; `tests/test_database.py` checks parity) and `docs/DATABASE.md`
3. Update `models.py` dataclass if applicable
4. Test with fresh database: `pytest tests/test_database.py`
5. Document breaking change in CHANGELOG.md
6. Bump major version in `pyproject.toml`

### Database Schema Management

**Current approach**: No migration system — database created directly in final normalized structure. Schema changes require major version bump and users re-importing scans.

**Testing the schema**:
```bash
# Delete existing database
rm ~/.cerno/cerno.db

# Run cerno (creates fresh database)
cerno scan list

# Verify schema
sqlite3 ~/.cerno/cerno.db ".schema"

# Check foundation tables populated
sqlite3 ~/.cerno/cerno.db "SELECT COUNT(*) FROM severity_levels;"  # Expected: 5
sqlite3 ~/.cerno/cerno.db "SELECT COUNT(*) FROM artifact_types;"   # Expected: 5
sqlite3 ~/.cerno/cerno.db "SELECT COUNT(*) FROM verdict_types;"    # Expected: 3
sqlite3 ~/.cerno/cerno.db "SELECT COUNT(*) FROM nse_verdicts;"     # Expected: 4
sqlite3 ~/.cerno/cerno.db "SELECT COUNT(*) FROM port_states;"      # Expected: 6
sqlite3 ~/.cerno/cerno.db "PRAGMA user_version;"                   # Expected: 4
```

### Adding a New Tool

1. Write a pure command builder `build_<tool>_cmd(...)` in `tools.py`
2. Write a workflow builder `build_<tool>_workflow(ctx: ToolContext) -> Optional[CommandResult]` in `tools.py` (prompts, then calls the command builder)
3. Register a `Tool(...)` in `tool_definitions.py:register_all_tools()`
4. Add tool-specific constants to `constants.py` if needed
5. Test in TUI: `cerno review` → Run tool → Verify command generation (see `docs/ADDING_TOOLS_QUICKSTART.md`)

### Updating Workflow Mappings

1. Edit `cerno_pkg/workflow_mappings.yaml` (or create custom YAML)
2. Follow schema: `version`, `workflows` list, each with `plugin_id`, `workflow_name`, `description`, `steps`, `references`; use canonical `<TARGET>`/`<PORT>`/`<USERNAME>`/`<PASSWORD>`/`<DOMAIN>`/`<INTERFACE>` placeholders (see `docs/CUSTOM_WORKFLOWS.md`)
3. Test in TUI: `cerno review --custom-workflows <path>` → Press `[W]` on matching plugin

### Debugging Database Issues

```bash
# Enable DEBUG logging via config
cerno config set debug_logging true
cerno review
tail -f ~/.cerno/cerno.log

# Inspect database directly
sqlite3 ~/.cerno/cerno.db
sqlite> .schema
sqlite> SELECT * FROM scans;
sqlite> SELECT review_state, COUNT(*) FROM findings GROUP BY review_state;
```

## Important Notes

- **Schema changes**: no migration system. Verify an older DB is rejected with `SchemaVersionError` and a fresh DB initializes before release
- **Version bumps**: Update `pyproject.toml` version only; the release workflow tags and publishes when it reaches `main`
- **Breaking changes**: Document in CHANGELOG.md (and README if users must act, e.g. re-import)
- **No per-plugin files**: import writes nothing but the database (and `scans/<name>/http_urls.txt` when web services exist)
- **CI/CD**: GitHub Actions runs tests on Python 3.11/3.12/3.13 (3.13 allowed to fail), Ubuntu/Windows/macOS (see `.github/workflows/test.yml`)
- **Dependencies**: Keep `requirements.txt` and `pyproject.toml:dependencies` in sync
- **Nessus XML parsing**: Based on DefensiveOrigins/NessusPluginHosts (respect attribution)
