# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.2.0] - 2026-11-05

### Added
- **nuclei evidence is readable.** `nuclei_match_observations` was write-only for two releases: the ingester filled it and nothing read it back, so an operator could ingest matches and have no way to see them short of SQL. Now `models.NucleiMatchObservation` (`get_by_execution` / `get_by_finding`, mirroring `NseScriptResult`), `cerno://finding/{id}/results` gains a `nuclei_matches` list through `v_nuclei_observations` (which already resolved the severity label and host IP but was never queried), and `v_finding_verified_stats` gains `nuclei_match_count`, surfaced by `get_finding_detail`.
  - **`suggested_verdict` stays NSE-only, deliberately.** Letting a nuclei match above some severity suggest `confirmed` does not survive contact with real template severities: nuclei's `info` tier holds both pure fingerprinting (`tech-detect`, `nginx-version`) and genuine findings (`deprecated-tls`, `http-missing-security-headers`), and `low` holds `expired-ssl` and `weak-cipher-suites`. A High floor would exclude every corroboration case the integration exists to demonstrate; a floor at Info would let a technology fingerprint suggest `confirmed`. The count is reported instead. The principled signal is relevance — a workflow entry co-mapping a Nessus plugin with a nuclei template — which is recorded in `docs/MCP.md` as the rule to implement once enough `nuclei:` workflow entries exist for it to fire.

### Fixed
- **A view change never reached an existing database.** `initialize_database()` ran `CREATE VIEW IF NOT EXISTS`, which does **not** replace an existing view, so every view change since the schema was written applied to fresh databases only — the symptom a missing column rather than an error, which is why it went unnoticed. Views hold no data, so init now drops and recreates the views it declares (leaving any a user created by hand alone). A view change consequently needs no schema version bump; a table change still does.
- **MCP `ingest_results` reported nothing for a nuclei run.** It returned `nuclei_matches` in the text body but the field was absent from the `IngestResult` TypedDict, so the SDK built an output schema without it and stripped it from `structured_content` — the typed path clients prefer. An agent saw `verified_ports: 0, nse_results: 0, nxc_flags: 0` and concluded the ingest did nothing, while 28 rows had landed. Shipped in 3.0.0. A parity guard now asserts every field `IngestSummary.as_dict()` reports is declared on `IngestResult`, in both directions.
- **The tool-availability doc example documented whatever was installed on the machine that generated it.** `render_tool_availability_table()` probes `PATH` and reads each binary's version, so the committed example changed the moment a tool was installed, and would have differed on CI and on every contributor's machine. The capture now stubs the probe to show the menu an operator with the tools installed sees; verified byte-identical with an empty `PATH`.

## [3.1.1] - 2026-11-04

### Added
- **`docs/CONFIGURATION.md` — the settings reference, moved out of README and generated.** README's Configuration section was 180 of its 800 lines, the second-largest section, and 47 of those were a hand-maintained 36-row settings table. That is reference material, consulted for a specific key rather than read while learning the tool, and it had gone six keys stale while still claiming to list "All settings". The table is now generated from `config.build_config_rows()` — the same source `cerno config show` renders from — so the doc and the command cannot disagree about which settings exist, and adding a config key needs no doc edit. README keeps the five `cerno config` commands and the two settings people change first (`color_scheme`, the `proxychains_*` trio) and links onward; it drops from 800 lines to 653.
  - The `help=` metadata was deliberately **not** enriched to carry the doc prose. Those strings feed a ~36-character column in `cerno config show` that already wraps, so lengthening them would have degraded the CLI to improve the README. The few settings needing more than a line — allowlist/denylist semantics, the batch concurrency clamp, the two credential gates, scope enforcement, and the fact that MCP gating flags are read once at startup — are hand-written notes beneath the table.
  - `scripts/generate_doc_examples.py` gained a `markdown` example kind for this: the callable returns a string instead of printing, and no SVG is produced. Same markers, same `--check`, same guard.

- **The TUI examples in the documentation are generated, not screenshotted.** `scripts/generate_doc_examples.py` captures them from the real renderers against the bundled demo data and emits each one twice — a colour SVG under `docs/images/examples/` for the README, and a plain text block for `docs/`, where copy-paste and review diffs matter more than colour. Content is written between `<!-- BEGIN GENERATED: name -->` markers, so surrounding prose and captions stay hand-owned. The eight PNG screenshots it replaces dated from March and still showed pre-3.0 labels ("Plugin ID", "Plugin Details:") and bare finding IDs; they could only be refreshed by hand, so they weren't. 512 KB of PNGs becomes 112 KB of SVG.
  - `--check` exits non-zero on drift and names the regeneration command; `tests/test_doc_examples.py` runs it, so an example that no longer matches its renderer fails the suite. `bcp` now regenerates first (see CLAUDE.md).
  - Determinism is what makes the check viable: a fixed console width per example, a throwaway `HOME` so the demo database is identical every run, and masking of absolute paths and timestamps. Verified byte-identical across runs.
  - The set is not a 1:1 swap. `scan-list` is new, since the Source column is the headline multi-source feature and had no visual anywhere; `finding-browser` now shows nuclei and Nessus findings in one list; `config-show` moved into a collapsed block beneath the settings table it backs, rather than restating it as a 66 KB image; and `scan-history` across two scanners is shown in `docs/demo/`.
- **`tests/test_docs_consistency.py`** asserts documented figures against live values — table and view counts, seeded lookup rows, bundled workflows, test modules, MCP tools, the schema version, and that README's settings table lists every config key. It found eight wrong numbers on its first run.

### Fixed
- **`cerno_pkg/workflow_mappings.yaml` documented a YAML key that no longer loads.** The header comment and the commented-out template still showed `plugin_id:` with bare numeric IDs (`"57608"`), both rejected by the loader since 3.0.0 — in the one file users copy their own workflows from. The 3.0.0 rename updated the active entries and missed the comments.
- **A v3.x documentation audit, ~60 defects.** The ones that would leave a reader broken: `docs/DATABASE.md` stated "Nessus IDs deliberately stay unprefixed … every existing `plugin_id` key keeps working" 25 lines after correctly saying the opposite; `docs/CUSTOM_WORKFLOWS.md`'s schema reference told you to write a bare number beside an example that was correctly prefixed; `CLAUDE.md`'s workflow instructions still named the `plugin_id` key; a `docs/DATABASE.md` SQL example (`WHERE plugin_id = 57608`) now returns zero rows; and `docs/MCP.md` contradicted itself on whether nuclei is in the default exec allowlist.
- **`cerno_pkg/skills/cerno-assistant.md` is a live system prompt, and it was wrong.** It described Cerno as Nessus-only, documented a context block that no longer matched `claude_assistant.py`, and showed bare finding IDs where the builder emits `nessus:`/`nuclei:` prefixes — so the assistant was being told a format it would never receive.
- **The tool-authoring guides would have reintroduced the 3.1.0 ingest bug.** `docs/ADDING_TOOLS_QUICKSTART.md` and `docs/TOOL_SYSTEM_GUIDE.md` used `menu_order=5` (taken by the custom command since nuclei claimed slot 3) and said "**Done!** No dispatch changes needed" without mentioning `ops.log_artifacts_for_run()` — the omission that left a nuclei run with no artifact to ingest.
- **Wrong counts throughout**: 26 tables/11 views (27/12), 5 seeded artifact types (6), 9 bundled workflows (15), 36 test modules, 46 MCP tools (47), `schema.sql` headed "schema version 4" while its contents were v5, and `MCP_NOT_APPLICABLE_KEYS` listed without the four `nuclei_*` keys in two places. README's settings table was missing six keys while claiming to list every setting.
- **Diagram sources** corrected and re-rendered: the architecture diagram said schema v4 and 25 tables, the core ER diagram showed an unprefixed Nessus ID, the reference ER diagram said 5 seeded artifact types and referenced `nuclei_match_observations` with no entity block, and the workflow diagram's tool and ingest nodes omitted nuclei.

## [3.1.0] - 2026-11-04

### Added
- **Packaging guards** (`tests/test_packaging.py`): every `[tool.setuptools.package-data]` glob must match at least one file, every `cerno_pkg/*/` directory with an `__init__.py` must appear in `packages`, and every file under `cerno_pkg/demo/` must be covered by a glob. A glob matching nothing fails silently and a wheel missing a subpackage raises `ModuleNotFoundError` — neither shows up in an editable install, which is how development and CI run, so nothing else would have noticed. Verified alongside a real wheel build: `cerno demo` runs correctly from a clean `pip install` of the built wheel.

### Changed
- **nuclei is now in the default MCP exec allowlist** (`config.DEFAULT_MCP_EXEC_ALLOWLIST`), reversing the 3.0.0 decision below. `execute_command` can run it and `ingest_results` reads the output back without a config change. Recorded deliberately, because the allowlist matches the binary **basename** and the caller chooses the arguments: nuclei runs `code:`-protocol templates when passed `-code` (the bundled template set ships ~960 of them, signed), reads local files via `-l` and writes them via `-o`/`-je`/`-me`. It is allowlisted on the basis that this is the same risk class as the already-allowlisted `curl`/`wget`, which can likewise read and write local files — not because it is inert. The denylist and scope enforcement still apply, and removing it is one `cerno config set mcp_exec_allowlist ...` away.

### Fixed
- **A nuclei run started from the TUI could not be ingested.** `[T]` → nuclei logged a `tool_executions` row but registered no artifact, because the run loop gated artifact registration on `selected_tool.name == "nmap"`; `ingest_results` on that execution then returned `"no nuclei_json artifact registered for this execution"`, leaving the execution→data loop one step short of closed. New `ops.log_artifacts_for_run()` holds the per-tool knowledge in one place — the nmap `-oA` triple and nuclei's JSON — and the run loop calls it unconditionally, so a future tool needs no branch there and a tool that writes nothing registerable is a no-op rather than an error. The MCP path deliberately keeps its own registration, which parses the real output flag out of the caller's argv and scrubs secrets first, since an MCP command need not use Cerno's `oabase`.
- **MCP `execute_command`, `start_execution` and `execute_batch` returned an un-awaited coroutine instead of running.** Clients received a *successful* text result reading `"<coroutine object build_server.<locals>.execute_command at 0x…>"`; no command ran and no `tool_executions` row was written. `_visible_errors` — the wrapper `build_server` applies to **every** tool so adapters' `ValueError` messages reach the client — was a plain `def`. `functools.wraps` copies `__name__`/`__wrapped__` but does not make a function a coroutine function, and the SDK's `is_async_callable` does not unwrap, so all three `async def` tools registered as sync: the SDK ran the wrapper on a worker thread, which called the coroutine function and returned the coroutine object unawaited. Annotated `-> dict`, they have no output model to reject it, so `pydantic_core.to_json(..., fallback=str)` stringified it rather than erroring. The wrapper is now async-aware and `await`s inside its own `try`, which also fixes a second defect: a `ValueError` raised inside one of those coroutines could never reach the `except`, so its message was masked. Introduced in 2.10.0 with the mcp SDK 2.x migration.
  - Nothing caught it because `test_mcp_server.py` calls the pure adapters directly and `test_mcp_contract.py` excluded exactly these three from its client round-trip as "subprocess/async flakiness". A registry invariant now asserts `is_async` matches the underlying function for **every** tool, catching the whole class rather than these three names, plus a side-effect-free client round-trip of an async tool.

## [3.0.0] - 2026-11-04

> **Upgrading from 2.x requires a re-import.** The schema moved from v4 to v5 and
> there is no migration system, so an older database is rejected at startup with
> `SchemaVersionError`. Back up and delete `~/.cerno/cerno.db`, then re-import:
>
> ```bash
> mv ~/.cerno/cerno.db ~/.cerno/cerno.db.bak
> cerno import nessus <scan.nessus>
> cerno import nuclei <nuclei.json>
> ```
>
> Review state, notes and verdicts live in that database and are not carried over.

### Added
- **`cerno import nuclei` — nuclei results as a second import source.** Both shapes nuclei writes are accepted and detected from the file contents rather than the extension: a single JSON array (`-je`/`-json-export`) or newline-delimited records (`-jle`/`-jsonl-export`, `-j`). Options: `--name` (nuclei output carries no scan name, unlike a `.nessus` `Report@name`, so the file stem is the default) and `--min-severity 0-4` (a real `pentest.yml` run is dominated by Info findings). A directory argument imports every `.json`/`.jsonl` under it after confirmation. Imported findings share the Nessus review loop entirely — review states, verdicts, notes, workflows, multi-scan review and the MCP surface all work unchanged, and a multi-scan review can span both sources.
- **`cerno_pkg/nuclei_parse.py`** — a pure parser (no database dependency) following the `nmap_parse.py` contract: never raises on a missing, malformed, empty or truncated file, so an interrupted scan still imports whatever it flushed.
- **`import_nuclei` MCP tool** (gated by `mcp_allow_mutations`, deliberately unannotated so clients never auto-approve it) and a **`source` predicate** on `FindingQuery`, exposed through `query_findings`, `plan_batch` and `execute_batch` for filtering to one scanner's findings.
- **Four config keys shaping the suggested nuclei command**: `nuclei_templates_path`, `nuclei_profile`, `nuclei_user_agent`, `nuclei_concurrency`. All four are classified MCP-not-applicable, since the MCP server prints no suggestions.
- **`finding_sources` lookup table** (`nessus`, `nuclei`) and `plugins.source_id`.
- **`database.seed_lookup_tables()`** — one definition of every lookup table's reference rows, now shared by `initialize_database()` and the test fixtures, which each carried their own copy. Adding a lookup table could previously be seeded in production and silently forgotten in tests.
- **`database.plugin_id_order_sql()`** — an `ORDER BY` fragment that casts before sorting, so numeric Nessus IDs keep numeric order now that `plugin_id` is TEXT.
- **Demo nuclei data, so `cerno demo` loads both import paths.** Two new bundled fixtures, `cerno-demo-nuclei-initial.json` and `cerno-demo-nuclei-expanded.json`, join the two `.nessus` scans. They target exactly the web services the Nessus scans discovered and reuse the same host rows, so a multi-scan review can span both sources — select a Nessus and a nuclei scan at the prompt (e.g. `2,4`). This matters because the demo's addresses are RFC 5737 documentation ranges: running the suggested nuclei command against them produces an empty file, since nothing resolves.
  - The fixtures are shaped to show why a second scanner earns its place. nuclei **corroborates** eight Nessus findings on the same host:port (self-signed and expired certificates, weak ciphers, deprecated TLS, wrong hostname, server banners, Tomcat default files, directory enumeration), and **finds three things Nessus did not**: Log4Shell (critical), an Apache 2.4.49 path traversal where Nessus only reports "unsupported version", and Tomcat *default credentials* where Nessus only reports default *files*.
  - The centrepiece is the six `203.0.113.8x` shop hosts: Nessus splits missing security headers into three separate plugins (84502, 85601, 98033), while nuclei reports all three as matcher names on one finding that Cerno merges into a single plugin output. Same evidence, two scanner models, visible side by side.
- **`scripts/create_demo_nuclei_results.py`** — generates those fixtures, following the `create_demo_nxc_workspace.py` precedent. It **parses the demo `.nessus` files to derive its target list**, reproducing the `v_http_services` selection logic, so a finding can only land on a host:port that actually exists in the corresponding scan; a spec naming an unknown target is a hard error rather than a silently wrong fixture. Output is deterministic, so regenerating an unchanged fixture is byte-identical. All template metadata is copied verbatim from upstream nuclei-templates.

- **A nuclei-only scan is now a first-class flow.** The nuclei importer populates `host_services`, deriving the service from the scheme in `matched-at` (`http://x/robots.txt` → `http`), which `v_http_services` already accepts as a literal token — so no view change was needed. Previously a scan with no Nessus import behind it reported **zero** web services: `v_http_services`, `get_web_targets`, `list_services`, `FindingQuery.service`, `get_http_urls_for_scan` and the `cerno://scan/{id}/hosts` resource were all empty, which matters because a web-app engagement may import nothing but nuclei. A record with no scheme (an `ssl` template's `matched-at` is a bare `host:port`) falls back to its `type` and is deliberately **not** mapped to http/https — an ssl template firing on 3389 is not a web service — while the view's port arm still classifies 443 correctly. Where one host:port is reported by several templates, an explicit URL scheme beats a bare record type, chosen deliberately rather than by insertion order. This reverses the stance previously documented in `docs/DATABASE.md`.
- **Suggested next steps after a nuclei import.** `show_nuclei_tool_suggestions()` writes the matched URLs to `http_urls.txt` and prints an nmap fingerprint command, a wider nuclei re-run, and the `cerno import nessus` corroboration step. The existing suggestions hung off `_import_single_nessus` only, so an operator who started with nuclei was given no onward step at all.

- **nuclei is a runnable tool in the TUI, and its output ingests back as evidence.** `[T]` → nuclei builds a run scoped to the current finding's host:port list (`tools.build_nuclei_scan_cmd`, registered via `tool_definitions`), prompting for a `-tags` filter or falling back to the configured profile. It emits `-jle` (streaming JSONL) rather than `-je` so a run cancelled from the TUI still leaves an ingestible file; `nuclei_parse` accepts either shape.
  - **New additive table `nuclei_match_observations` and view `v_nuclei_observations`**, plus a `nuclei_json` artifact type. `ingest._ingest_nuclei()` reads the run's JSON artifact and reconciles rows per execution, so re-ingest preserves primary keys and keeps `verdict_evidence` links intact. These are **evidence, not findings** — `cerno import nuclei` remains what creates `findings` rows — so `verdict_evidence` reaches them through its existing `execution_id` rather than gaining a column.
  - **No schema version bump and no re-import:** a new table, a new view and a new seeded lookup row are picked up by existing v5 databases through `CREATE TABLE IF NOT EXISTS` and idempotent `INSERT OR IGNORE` (verified against a database built with the previous schema). `PRAGMA user_version` stays 5; `artifact_types` now seeds 6 rows.
  - Row identity is `(execution_id, host_id, port_number, template_ref, matcher_name, extracted)`. Both `matcher_name` **and** `extracted` are needed: `http-missing-security-headers` reports several matches on one host:port differing only by matcher name, while `tls-version` carries no matcher name and differs only by extracted results — keying on either alone silently dropped a match.
  - **nuclei stays out of `DEFAULT_MCP_EXEC_ALLOWLIST`**, since its `code`-protocol templates run arbitrary code. Running it through the MCP `execute_command` path is therefore an explicit opt-in; the TUI tool needs no allowlist change. Documented in `docs/MCP.md`.

### Changed
- **BREAKING (schema v5, re-import required).** `plugins.plugin_id` and `findings.plugin_id` widened from INTEGER to TEXT, and finding IDs are now namespaced per source — for **every** source, Nessus included: `'nessus:57608'`, `'nuclei:apache-detect'`. nuclei identifies findings by template name, not number, and an `INTEGER PRIMARY KEY` is a SQLite rowid alias that cannot store one at all. Prefixing Nessus too means no source is the default: a bare token is not a valid finding ID anywhere, `parsing.plugin_source()` reports an explicit `unknown` instead of guessing "nessus", and `plugin_source_id()` raises rather than letting an unprefixed ID reach the database. Adding a future source now costs a prefix and a `finding_sources` row and nothing else. Back up and delete `~/.cerno/cerno.db`, then re-import.
  - `database.plugin_id_order_sql()` now sorts by prefix, then by the reference **cast to an integer**, then by text. Casting the whole column (the pre-namespacing form) yields 0 for every namespaced ID, which collapses the numeric term and silently degrades to a lexicographic sort placing `nessus:10114` before `nessus:9`. No existing test covered this; one does now.
  - The Tenable details URL is still built from the bare reference via `parsing.plugin_ref()`, so `nessus:57608` links to `/plugins/nessus/57608`.
- **BREAKING (workflow YAML).** The `plugin_id` key in `workflow_mappings.yaml` and any custom workflows file is renamed to **`finding_id`**, and every ID in its value must carry a source prefix. There is no alias and no implicit normalisation: an entry using the old key, or holding a bare number like `"57608"`, does not load. Because a workflow that fails to load raises nothing and simply never appears in the TUI, the loader now `warn()`s with the file name, the workflow name, the offending IDs and the fix, and an entry with even one unprefixed ID is rejected whole rather than half-registered. **If you keep a file under `custom_workflows_path`, rename the key and prefix every ID.**
  - One entry's `finding_id` may list IDs from **different scanners**, so a single workflow serves the same issue found by two tools. The bundled HSTS workflow now covers `nessus:142960`, `nessus:84502` and `nuclei:http-missing-security-headers`; pressing `[W]` on either source's finding shows the same steps.
  - `WorkflowMapper.get_all_plugin_ids()` is renamed `get_all_finding_ids()`, and `Workflow.plugin_id` is now `Workflow.finding_id`. Both loader paths share one `_parse_workflow_entry()`, so the key and prefix rules are defined once.
- **BREAKING (schema v5).** `scans.nessus_file_path` / `nessus_file_hash` renamed to `source_file_path` / `source_file_hash`, which is what they now hold.
- **The nuclei command suggested after an import is now built from config, and its outputs land in the scan directory.** Previously a hardcoded one-liner writing to `~/nuclei_results.*`; now `tools.build_nuclei_cmd()` emits `-profile`/`-ud`/`-duc`/`-rsr`/`-rss`/`-c`/`-ts`/`-stats` with `-je`, `-o` and `-me` all inside `~/.cerno/scans/<scan>/`, followed by the exact `cerno import nuclei …` command to ingest it. Cerno already told operators to run nuclei; it now has somewhere to put the results.
- **The finding panel's identifier row and details link are source-aware.** The row is labelled "Nessus Plugin ID" or "Nuclei Template ID" (`constants.PLUGIN_ID_LABELS`), and the details URL comes from `constants.PLUGIN_URL_TEMPLATES` via `Plugin.details_url`. The row is omitted when a source has no known details page, rather than fabricating a dead `tenable.com` link. `tools.py` no longer rebuilds a Tenable URL from any plugin ID, ignoring the one captured at import.
- **`cerno scan compare` refuses two scans from different sources.** Comparison classifies findings purely by `plugin_id` set membership, and plugin IDs across sources share no namespace, so every finding would be reported as both new and resolved. Raises `MixedSourceComparisonError` (a `ValueError`, so the MCP tool surfaces it too).
- **`get_workflow`'s MCP `plugin_id` parameter is now a string**, since a nuclei template ID is not a number.
- **`cerno scan history` no longer claims remediation across two scanners.** The Trend column and the "Overall trend" summary were computed over consecutive scans regardless of source, so a 30-finding Nessus scan followed by a 3-finding nuclei scan rendered `Trend -27` and "Overall trend: −27 findings since first scan" — a confident, entirely false remediation claim. `compare_scans` already refused mixed sources; `scan history` had no such guard. The per-row trend is now `n/a` across a source boundary and the overall summary is replaced by a one-line explanation. `ScanSnapshot.source` derives this from the namespaced plugin IDs it already carries, so no schema or view change was needed.
- **The `scan history` overall-trend line printed its own Rich markup.** It was passed to `info()`, which does not parse markup, so the output read literally `Overall trend: [yellow]No change[/yellow] in finding count`. It now goes through the Rich console, matching the coloured table above it.
- **`cerno workflow list` renders its name and description columns again.** Namespacing every id pushed the longest bundled `finding_id` value to ~160 characters, and with the id column set to `no_wrap` that consumed the whole terminal width, leaving Workflow Name and Description at zero width — a table with nothing readable in it. The column now folds at a fixed width.
- **The custom-command example no longer teaches an un-importable nuclei run.** `tools.py` suggested `nuclei -l … -o <file>.nuclei.txt`, but `-o` is nuclei's *plain text* output and `parse_nuclei_file` rejects it; the example now uses `-je` and a `.json` path.
- `MAX_FILE_BYTES` audited: defined and re-exported but with no use sites, so it imposes no import size ceiling.
- **The MCP `export_workflow_contribution` filename no longer contains a colon.** The namespaced finding ID went into the filename verbatim (`nessus:100-<timestamp>.yaml`), which is a reserved character on Windows — the one platform in the CI matrix where it would have failed outright. The ID is flattened to `nessus-100-…` for the filename only; the exported fragment still carries the real ID.
- **A contributed workflow's Tenable reference is built from the bare plugin number**, not the namespaced ID, so it no longer produces `…/plugins/nessus/nessus:96982`.
- **A nuclei finding's details link now points at the template's source**, not the public viewer. The result's `template` path (`http/cves/2021/CVE-2021-44228.yaml`) is appended to `https://github.com/projectdiscovery/nuclei-templates/blob/main/`, so the operator lands on the matcher logic that actually fired. The viewer URL remains the fallback for results that carry no usable path (`template` is `omitempty` in nuclei's output). Contributed workflows cite the template source too, since `workflow_contrib` reuses `plugin_url` as a reference.
- **"Plugin" retired from user-visible TUI labels.** The findings-list and scan-diff columns are now `Finding ID` (and `Finding Name`), the finding panel reads `Finding Details:`, the workflow listing reads `Finding ID(s)`, and the `[S]` sort indicator reads `Sort: Finding ID`. The panel keeps its source-aware identifier row (`Nessus Plugin ID` / `Nuclei Template ID`), where naming the scanner is accurate and useful.
- **The `"Plugin <id>: <name>"` labels are now `"Finding <id>: <name>"`, through one shared helper.** `fs.finding_label()` is the single definition, called by `[H]` Compare, `[O]` Overlapping, the Done list, the bulk-move status lines, the three view pagers and `tui.filter_finding_candidates`. These were **not** merely labels: `compare_filtered`/`analyze_inclusions` return groups as lists of these strings and the filter re-derives the label from the `Plugin` row to test set membership, so two independent producers of the same literal format had to agree exactly — change one and the group filter matches zero findings with the `[ACTIVE FILTER] Group #N` footer still showing and no error raised. A round-trip test now drives a real group through the filter and fails with a message naming the divergence; previously nothing covered that contract. Remaining chrome followed: "filter by plugin name" → "by finding name", the onboarding counter's "N plugins" → "N findings", and the CVE/missing-metadata warnings.
- **`cerno demo` now imports four scans** (two Nessus, two nuclei) and its "Next commands" block gains the nuclei comparison plus a pointer to reviewing both sources together. `demo/*.json` was added to the `package-data` globs — `demo/*.nessus` does not match `.json`, so without it the fixtures would ship in the sdist but be missing from the wheel, breaking `cerno demo` for pipx users only.

- **`cerno scan list` and `scan history` show which scanner produced each scan.** `Scan.get_all_with_stats()` reports a `source`, surfaced as a Source column in both the compact and `--wide` tables, in `--json`, and in the scan-history timeline. Two scans from different tools are not comparable, and the only previous hint was the `MixedSourceComparisonError` raised *after* the operator had already chosen two scans.

### Fixed
- **The findings-list ID column truncated every nuclei template ID.** It was hard-capped at `max_width=10` with `no_wrap=True`, so Rich's default ellipsis overflow cropped `nuclei:http-missing-security-headers` to `nuclei:ht…` at *any* terminal width. The column is now sized from the widest ID on the page, capped at 38 and budgeted against the console width so the Name column keeps a readable minimum; it also left-justifies when any non-numeric ID is present. A Nessus-only scan renders exactly as before.
- **A nuclei template ID could inject Rich markup into the findings list.** The ID was passed to `Table.add_row()` as a bare `str` while the plugin name beside it was wrapped in `Text(...)` precisely because Rich markup-parses any bare string it is handed. An ID containing `[...]` was therefore parsed. Both cells are now `Text`, with a regression case in `tests/test_markup_injection.py`.
- **The TUI's "Workflow Mapped" group silently dropped every non-numeric workflow ID.** `cerno.py` filtered the mapper's keys with `int(pid) for pid in … if pid.isdigit()`, so a workflow mapped to anything but a bare Nessus number was invisible in that group. Now string-keyed throughout, matching `workflow_mapper`, which was already `plugin_id: str` end to end.
- **The finding panel no longer crashes when the port-distribution lookup fails.** `finding.get_port_distribution()` was unguarded while the verdict lookup beside it was explicitly best-effort; an unavailable or incomplete database now degrades the panel to the counts already in hand.
- **Tests no longer touch the developer's real `~/.cerno/cerno.db`.** The autouse `reset_environment` fixture already isolated `config.get_config_path()`; it now redirects `database.DATABASE_PATH` the same way. Two `cerno config` tests were invoking the real CLI against the real database.
- **`cerno import nuclei` no longer names every import "nuclei".** The command Cerno suggests writes `~/.cerno/scans/<scan>/nuclei.json`, so the file stem is always `nuclei` — meaning the second import through the recommended flow collided with the first and triggered the overwrite/rename prompt. A results file sitting directly inside a scan directory is now named after that directory (`GOAD/nuclei.json` → `GOAD-nuclei`), keeping it tied to the Nessus scan whose target list produced it. Only a scan directory lends its name, never an arbitrary parent, and a still-generic name prints a hint to pass `--name`.
- **An empty nuclei results file now says why, and stops before prompting.** Importing one previously asked the operator to resolve a scan-name collision first and then reported only "No nuclei results found." It now short-circuits with the actual cause — nuclei writes an empty file when no template matched, *including when no target was reachable* — and points at `cerno demo` for data to explore. This is exactly what happens when the suggested command is run against the demo's documentation addresses.
- **Corrected a stale security rationale in `ansi.py`.** `strip_unsafe_escapes()` justified preserving SGR escapes on the grounds that ".nessus data cannot carry an ESC byte at all (it is invalid XML)". JSON escapes ESC legally as `\u001b`, and nuclei's `extracted-results` is copied verbatim out of response bodies, so scan data is now itself an ESC-bearing channel. The Rich path was already safe (`safe_text()` strips every escape); the residual is cosmetic recolouring through the raw-print helpers. Regression cases added to `tests/test_markup_injection.py`.

### Security
- **A nuclei `template-url` is validated before it is stored.** The value is attacker-influenced and is later interpolated into a Rich *style* string to build the finding panel's OSC-8 hyperlink, where embedded whitespace would be parsed as extra style tokens and could abort rendering. Anything that is not `https?://` with no whitespace falls back to the deterministic public-viewer URL.
- **`template-path` is never stored.** nuclei reports the operator's local template path (e.g. `/home/you/nuclei-templates/...`), which leaks a home directory; only the clean `template-url` is kept.

## [2.13.1] - 2026-10-30

### Added
- **Architecture and schema diagrams.** Five Mermaid diagrams, each committed as source in `docs/diagrams/` and rendered to a light/dark PNG pair in `docs/images/diagrams/` so they look native in both GitHub themes: the engagement loop (README "How It Works"), the layered module map (new `docs/ARCHITECTURE.md`), and three entity-relationship diagrams placed in their matching `docs/DATABASE.md` sections (core, verification, lookup tables). `scripts/render_diagrams.sh` regenerates them all; it uses the system Chromium so Puppeteer's bundled browser download is never needed.
- **`docs/ARCHITECTURE.md`** — the layer map plus a walkthrough of what each layer owns, the TUI ↔ MCP shared-core contract, and the design rules (database as source of truth, no derived data, untrusted scan text) that a contributor should know before changing things.

### Fixed
- **Corrected the documented membership of the TUI ↔ MCP shared core.** `CONTRIBUTING.md` and `CLAUDE.md` both listed `analysis.py` as a shared function the MCP adapters call; it is imported only by `__init__.py`, `session.py` and `tui.py`, and `server.py` references it solely in a docstring noting that it *avoids* its console-printing helpers. The shared-core list is corrected, and `analysis.py` (TUI-only) and `query.py` / `batch.py` / `ingest.py` / `workflow_prep.py` / `workflow_contrib.py` / `exec_chain.py` (MCP-only) are now called out explicitly, since assuming the latter are shared is the likely wrong turn when adding a feature both interfaces need.

## [2.13.0] - 2026-10-30

### Changed
- **`cerno review --no-tools` now actually disables tool prompts.** The flag advertised "Disable tool prompts (review-only)" but was only ever read to skip the tool-availability table and print a note — nothing in the finding view consulted it, so `[T]` Run tool stayed fully functional. `[T]` is now hidden from the finding-view footer and refused with an explanatory message if typed anyway, so review-only mode is real. That matters for a tool which can launch nmap, NetExec and Metasploit. The MCP `execute_command` path is deliberately out of scope here and still governed by `mcp_allow_execution`.

### Fixed
- **`cerno review --check --no-tools` now exits instead of dropping into the review.** The `--check` early exit was nested inside the `if not args.no_tools:` block, so combining the two flags silently fell through into the interactive TUI. `--check` is honored independently and always reports tool availability before exiting 0.
- **`tests/test_version.py::test_version_in_installed_package` can now fail.** Its assertion sat inside `try/except Exception → pytest.skip()`, which swallowed the `AssertionError` too, so genuine version drift was reported as a skip and the test could never fail — it misfired exactly that way after a version bump during development. The except clause is narrowed to `PackageNotFoundError`, so a genuinely uninstalled package still skips while a real mismatch fails and names both versions.
- **Corrected the documented behavior of `session.delete_session()`.** It stamps `session_end` and leaves the row in place; `CLAUDE.md` claimed "Auto-delete session after successful completion". The behavior is deliberate — the surviving row is what makes `onboarding.show_workflow_guidance()` treat a scan as already reviewed, keeping first-run guidance suppressed on re-entry — so the docs and docstring are corrected rather than the code. The name is kept because it is part of `cerno_pkg.__all__`.

## [2.12.2] - 2026-10-30

### Added
- **`ansi.print_verbatim()`** (exported from `cerno_pkg`) — emits text byte-for-byte with no Rich markup parsing and no width wrapping, for dumps the operator is meant to copy by hand. Its docstring records why it must stay a builtin `print`, so it is not later "upgraded" to a Rich console call.

### Fixed
- **The manual-copy fallback no longer crashes on bracketed scan text.** When no clipboard tool is available (`xclip` / `wl-copy` / `xsel` absent and no `DISPLAY` — the normal case on headless or SSH-only hosts), `[C]` Copy falls back to printing the payload for manual copying. That print went through Rich, which markup-parses any bare string, so a payload containing `[/]` raised an uncaught `MarkupError`. This is genuinely reachable: a `.nessus` host identifier is stored verbatim, so a bracketed FQDN such as `web [/] server.example` lands straight in the payload — reproduced end-to-end by driving `[V]` → `[C]` with the clipboard disabled. Both fallback sites (the finding host view in `fs.py` and the aggregate host view in `cerno.py`) now use `print_verbatim()`. **Escaping was deliberately not used here:** `safe_text()` would turn `[` into `\[`, and Rich `Text` would wrap to the console width — either would corrupt the text the operator is about to copy.
- **`choose_from_list()` no longer interpolates list items into markup.** It has no callers today but is exported in `cerno_pkg.__all__`, so a future caller passing scan-derived items would have hit the same crash; items now render through `rich.text.Text`. Latent rather than live, and fixed because this bug class has already recurred twice.

These were the two reachable sinks deliberately deferred from 2.12.1 plus one latent site; an independent audit of the `add_row` / `Panel` / `console.print` / `Text.append` sinks found no further reachable raw-string site.

## [2.12.1] - 2026-10-29

### Fixed
- **The findings list no longer crashes on a plugin name containing brackets, and bracketed text is no longer silently dropped.** The 2.12.0 sanitization sweep was **incomplete**: it searched for f-strings *containing* markup tags, so it fixed the panel titles but missed every **table**, where a bare `str` cell is markup-parsed just the same while looking nothing like markup in the source. A plugin named `SMB [/] Signing` raised an uncaught `rich.errors.MarkupError` in `render_finding_list_table` and aborted the main review screen — the most-used view in `cerno review` — and `TLS 1.0 [deprecated] Detection` rendered as `TLS 1.0  Detection` because `[deprecated]` parses as a Rich style name. Scan-, NetExec- and user-derived values now reach Rich as `rich.text.Text`, which never parses markup, across six renderers: `render_finding_list_table`, `render_scan_table` (scan menu), `render_compare_tables` (`[H]` groups), `analysis.analyze_inclusions` (`[O]` groups), `render_nxc_host_panel` (share names plus credential protocol/type) and `render_host_history` (`cerno scan history`). Benign bracketed names such as `Apache Log4j [CVE-2021-44228] RCE` render exactly as before. `tests/test_markup_injection.py` gained 23 cases driving every one of those renderers with `[/]`, `[deprecated]`, `[link=…]` and a benign control, asserting both that nothing raises **and** that the bracketed text survives to the screen — the previous tests covered no table renderer at all, which is why 2.12.0 shipped broken. Verified end-to-end by importing a crafted `.nessus` and driving `cerno review`.

## [2.12.0] - 2026-10-29

### Added
- **`ansi.safe_text()` and `ansi.strip_unsafe_escapes()`**, both exported from `cerno_pkg`, for neutralizing untrusted text. Use `safe_text()` on any scan-derived value interpolated into a Rich markup string; where a single style applies, prefer `rich.text.Text(value, style=...)`, which never parses markup and so is immune by construction rather than by being remembered. `safe_text()` is deliberately **not** idempotent — apply it exactly once. New `tests/test_markup_injection.py` (21 tests) covers both helpers plus the real render paths.

### Fixed
- **Scan-derived text can no longer crash the TUI, lose characters, or hijack the terminal.** Plugin names, hostnames, scan names and workflow step titles come from third-party `.nessus` files and were interpolated straight into Rich markup strings. Confirmed end-to-end by importing crafted scans: a plugin named `SMB [/] Signing` raised an unhandled `MarkupError` that aborted rendering; `TLS Version 1.0 [deprecated] Detection` displayed as `TLS Version 1.0  Detection` because `[deprecated]` parses as a Rich style tag and was silently swallowed; and `SMB [link=file:///etc/passwd]click[/link]` injected a clickable OSC-8 hyperlink into the operator's terminal. Panel titles carrying one style now use `rich.text.Text` (`render.py:display_finding_preview()`, `render_nxc_host_panel()`), and the mixed-style sites escape via `safe_text()` (`render.py:render_scan_comparison()`, `render_host_history()`, `fs.py` workflow step panels, `cerno.py` Claude scope line and import rule). Benign bracketed names such as `Apache Log4j [CVE-2021-44228] RCE` render exactly as before.
- **Terminal escape sequences in status messages no longer reach the terminal.** `err()` / `warn()` / `ok()` / `header()` / `info()` write raw ANSI through `print()`, so an attacker-influenced value could emit an OSC window-title sequence or cursor-movement escape — reproducible with `cerno config get $'\x1b]0;title\x07'`. All five now filter through `strip_unsafe_escapes()`, which removes OSC, cursor-movement and other escape sequences while deliberately preserving SGR colour so captured nmap/NetExec output and `tools.py`'s bold label still render correctly. `.nessus` files cannot carry an ESC byte at all (it is invalid XML), so the remaining surface is tool output, NetExec workspace values and file names.

## [2.11.3] - 2026-10-29

### Changed
- **Type checking moved to mypy 2.x** (`mypy>=2.4,<3`, from an unbounded `>=1.0`). mypy 2.0 turned `--local-partial-types` and `--strict-bytes` on by default and redefined `--allow-redefinition`; since CI runs mypy with `continue-on-error: true`, the old unbounded floor meant a silent jump to 2.x could have changed the reported baseline without ever failing a build. The floor is now bounded on both sides, and **the codebase is clean under it — 0 errors across 39 files, down from 14.** The fixes were type-level, not behavioral:
  - `onboarding.py` narrows `scan_ids` inline and derives `is_multi` from the result instead of computing it separately (verified equivalent for `None` / empty / single / multi inputs).
  - `ops.py` declares `http.server` and `threading` under `TYPE_CHECKING` so `start_ips_server()`'s return annotation resolves. Both were already imported lazily inside the function, and `from __future__ import annotations` meant the annotation was never evaluated at run time.
  - `cerno.py` initializes `all_scan_ids` before the scan-selection loop rather than relying on a previous iteration having bound it — defensive only, as the existing `scan_id != 0` guard already prevented an unbound read — and renames a `names` local that held both a `str` and a `list[str]` within one function scope.
  - Three no-longer-needed `# type: ignore` comments removed (`ops.py`, `fs.py`, `render.py`). The two `cast()` calls in `analysis.py` are deliberately kept, with a narrow `redundant-cast` ignore, because pyright — unlike mypy 2.x — does not narrow the union from the preceding `isinstance` check; removing them traded 2 mypy warnings for 4 pyright errors.
  - The dead `[[tool.mypy.overrides]]` section for `tests.*` removed: it duplicated the global `disallow_untyped_defs` setting and `warn_unused_configs` reported it as unused.

### Added
- **`tests/test_onboarding.py`** (6 tests) covering the first-run workflow guidance and context-aware tips for `scan_ids` being `None`, single, or multi — including that a multi-scan selection aggregates Critical counts across every selected scan and pluralizes its wording. These paths previously had no test coverage.

## [2.11.2] - 2026-10-29

### Changed
- **`typer` floor raised to `>=0.27,<1`** (from `>=0.12,<1`). Typer 0.26 vendored Click and dropped it as an external dependency, and 0.27 changed how metavars are printed in `--help`; pinning above both makes the vendored layout a guarantee, which the traceback fix below depends on. Typer 0.27.3 additionally escapes terminal control characters in *its own* error messages (unknown command / unknown option). Cerno's **command and option surface is unchanged** — same commands, same flags, same argument parsing — and `--install-completion` / `--show-completion` still work (Typer requires `shellingham` unconditionally). One **cosmetic** difference is visible in `--help`: 0.27's metavar change renders required arguments brace-wrapped in the usage line, so `cerno import nessus [OPTIONS] {nessus}` and `cerno scan compare [OPTIONS] {scan1} {scan2}` replace the previous rendering. This comes from Typer's own `make_metavar` override (`typer/core.py`), affects the usage line only, and changes no invocation — `cerno scan compare A B` still parses two positionals exactly as before.

### Fixed
- **Rich tracebacks no longer dump Typer framework frames.** `cerno.py` passed `suppress=["typer", "click"]` to `rich.traceback.install()`, but Rich treats a *string* suppress entry as a filesystem path rather than a module name — so those resolved to `./typer` and `./click` relative to the working directory, directories that do not exist, and **no frames were ever suppressed**. The module object is now passed instead (`suppress=[typer]`), which resolves to the installed package and transitively covers the Click that Typer vendors, so a crash in a CLI command shows Cerno's frames rather than the framework's. A new guard test asserts that every suppress entry is a module object and resolves to a directory that exists, so the string form cannot silently return.

## [2.11.1] - 2026-10-29

### Changed
- **`rich` dependency moved to `>=14.3,<16`** (from `>=13.7,<15`), so installs now resolve Rich 15.x. Rich 15.0.0's only breaking change is dropping Python 3.8, which Cerno never supported (it requires 3.11+). **No rendering behavior changes:** all 181 tests that assert on rendered output — including exact ANSI byte sequences and `Text` span internals — pass unchanged. This is a maintenance change rather than a feature one: none of Rich 15.0.0's fixes touch code paths Cerno uses (`Text.from_ansi`, `isatty` and Markdown rendering are unused, and neither `console.print(..., end=...)` call site is an *empty* print), and `TTY_COMPATIBLE=1` already worked under 14.3. The value is that the old `<15` cap had pinned Cerno a major version behind since April 2026 and would have blocked any future 15.x bug or security fix.
- **Three regression guards added for Cerno's deepest Rich couplings** (`tests/test_color_scheme.py::TestRichCouplingGuards`). `ansi.py` overrides `Console.get_style()`, imports the semi-private `rich.default_styles.DEFAULT_STYLES`, and assigns Rich's private global `rich._console` so bare `Prompt`/`Confirm`/`Progress` calls inherit the color scheme. Each of these fails *silently* on a Rich upgrade — the palette reverts to Rich's defaults with no exception raised and no existing test failing — so all three are now asserted directly instead of being inferred from rendered output.

## [2.11.0] - 2026-10-29

### Changed
- **Dev-dependency floors raised to the versions actually in use:** `pytest-cov>=7.0` (from `>=4.0`), `pytest-mock>=3.15` (from `>=3.10`), `pytest-timeout>=2.4` (from `>=2.1`), `black>=26.3` (from `>=23.0`), `pyright>=1.1.408` (from `>=1.1.389`) and `types-PyYAML>=6.0.12.20260906` (from `>=6.0`). The old floors were three to four years stale; the `black>=23.0` floor in particular let a contributor format with a Black whose stable style predates the current one and produce spurious reformatting diffs. Runtime dependencies are unchanged by this entry. Development-only — no effect on installed CLI behavior.
- **Dependabot batches the dev/test toolchain into a single monthly PR** (`pytest*`, `black`, `mypy`, `pyright`, `types-*`) instead of opening one per package. Runtime dependencies remain individual PRs so each can be reviewed and smoke-tested on its own.

### Removed
- **Three unused runtime dependencies dropped: `beautifulsoup4`, `requests` and `colorama`.** None of them was imported anywhere in Cerno — `.nessus` and nmap XML are parsed with the stdlib `xml.etree`, the remote-scan server is built on stdlib `http.server` + `ssl` (`ops.py:start_ips_server()`), and ANSI colors are generated in `ansi.py` without `colorama`. Removing them also drops the transitive `soupsieve`, `urllib3`, `certifi`, `charset-normalizer` and `idna`, so an install pulls roughly nine fewer packages and no longer ships a CA bundle that Cerno never consults. No functional change; a clean install was verified to import every module and run the CLI. **Action required:** reinstall to prune the now-unused packages (`pipx reinstall cerno`, or `pip install -e ".[dev]"` for development).

## [2.10.0] - 2026-10-28

### Changed
- **Migrated the MCP server to the `mcp` Python SDK 2.x** (dependency floor raised to `>=2,<3` from `>=1.9,<2`; v1 is now maintenance-only). The SDK's v1→v2 rename of `FastMCP` to `MCPServer` is adopted internally (`mcp_server/server.py` now imports from `mcp.server.mcpserver`), tool annotations use the new snake_case fields (`read_only_hint`/`idempotent_hint`/`destructive_hint`/`open_world_hint`), and the cross-interface contract test drives the server through the new in-memory `mcp.Client`. No change to the Cerno MCP tool/resource/prompt surface or behavior. **Action required:** reinstall so the new SDK is pulled in (`pipx reinstall cerno`, or `pip install -e ".[dev]"` for development).

### Fixed
- **MCP tool errors no longer come back as a bare "Error executing tool &lt;name&gt;" with no reason.** The mcp 2.x SDK masks any plain exception a tool raises (keeping the message server-side only), so after the migration every not-found / invalid-input / scope-refusal message (e.g. `get_finding_detail` on a non-existent id) was swallowed — mcp 1.x had surfaced them. `build_server` now translates the adapters' deliberate `ValueError`s into the SDK's `ToolError`/`ResourceError`, so the client again receives the descriptive text (e.g. `No finding with id 999999`) while genuine crashes stay masked. Affects every id-lookup and refusal tool/resource uniformly; the pure adapter functions are unchanged.

## [2.9.0] - 2026-10-28

### Added
- **Record a verification verdict from the TUI:** the finding view has a new `[R]` key that prompts for a verdict (Confirmed / False Positive / Unable to Verify) plus an optional note and writes it to the finding's append-only verdict history. A Confirmed or False Positive verdict offers to move the finding to Done. This is the TUI counterpart to the MCP `set_finding_verdict` tool; previously verdicts could only be recorded over MCP or by auto-ingest.
- **MCP verification guidance (soft, never blocking):** the server now sends connect-time `instructions` describing Cerno's verification loop (check the mapped workflow first and say when none exists → move to In Progress → run attributed commands → ingest → record a verdict → move review state → offer a workflow contribution), adapted to whether mutations are enabled. `execute_command`, `set_review_state` and `set_finding_verdict` responses now carry a `next_steps` list with the state-aware next action, and a new `verify_finding` prompt walks a client through the whole loop for one finding.
- **MCP target scope enforcement:** `execute_command` / `start_execution` / `execute_batch` now refuse IP or CIDR targets that fall outside the engagement scope — the hosts from imported scans plus any ranges in the new `mcp_scope_extra` config key. Unresolved bare hostnames are allowed but returned in `scope_warnings`. Controlled by the new `mcp_enforce_scope` config key (default `true`); set it to `false` to disable the check. `get_capabilities` and the startup gating line report the scope state.
- **MCP tool annotations:** every tool now advertises advisory annotations (`readOnlyHint` for read/generate tools, `idempotentHint` for ingest/verdict/state tools, `destructiveHint`+`openWorldHint` for the execution tools), so MCP clients can auto-approve reads and warn before running commands. `reveal_credential` is deliberately left unannotated so it is never auto-approved with ordinary reads.

### Changed
- **Minimum `mcp` dependency raised to `>=1.9`** (from `>=1.2`) for tool-annotation and server-instruction support.

### Fixed
- **MCP `execute_command` / `start_execution` / `execute_batch` no longer drop the structured response on timeout:** a command that exceeded its `timeout` raised a bare error, losing `next_steps`, `scope_warnings`, `ingested` and any partial output. The timeout path now returns the same structured envelope as a completed run — with `timed_out: true`, `exit_code` 124, the captured partial `stdout`/`stderr`, pre-run `scope_warnings`, and a `next_steps` hint to narrow the target/ports or raise the timeout — while still killing the process at the deadline. Scope and allow/deny refusals still short-circuit before the run, unchanged.

## [2.8.0] - 2026-10-27

### Changed
- **MCP batch runs 3 commands at a time by default:** `mcp_batch_concurrency` now defaults to `3` instead of `1`, so enabling `mcp_allow_batch` no longer also requires raising concurrency to get any parallelism. Both the config value and `execute_batch`'s per-call `concurrency` argument are now clamped to [1, 8] (previously the argument had no upper bound). A config file that already sets `mcp_batch_concurrency` keeps its value; set it to `1` when routing through a single SOCKS pivot (proxychains) or under strict rate limits, or run `cerno config reset mcp_batch_concurrency` to adopt the new default.

### Fixed
- **A large MCP batch no longer blocks other executions:** queued `execute_batch` items each held a worker thread while waiting their turn, so an `execute_command` or `start_execution` call made during a batch of more than about a dozen findings waited until most of the batch had finished. Queued items now wait without holding a thread (`mcp_server/jobs.py:JobRegistry.start()`), and other executions start immediately.

## [2.7.0] - 2026-10-27

### Changed
- **The MCP `execute_command` allowlist now includes common recon utilities by default:** besides `nmap`, `nxc`, `netexec` and `msfconsole`, the default `mcp_exec_allowlist` now allows `curl`, `wget`, `dig`, `host`, `nslookup`, `whois`, `ping`, `traceroute`, `ssh-audit`, `sslscan`, `testssl*`, `whatweb`, `showmount`, `rpcinfo`, `snmpwalk` and `onesixtyone`. Bundled workflow steps that use these tools (e.g. `ssh-audit`, `wget`) are now marked executable by `prepare_workflow` / `plan_batch` (and run by `execute_batch`) instead of manual-only. Shells, binaries with built-in command escapes (`find`, `ssh`, `nc`, `smbclient`, …) and active-attack tools are deliberately left out; see `docs/MCP.md`. A config file that already sets `mcp_exec_allowlist` keeps its list; run `cerno config reset mcp_exec_allowlist` to adopt the new default.

## [2.6.1] - 2026-10-27

### Changed
- **MCP gating is fully visible:** `get_capabilities` now reports `batch_enabled` (true only when both `mcp_allow_execution` and `mcp_allow_batch` are on, matching when `execute_batch` is registered) and `batch_concurrency`. The startup gating line in `~/.cerno/cerno.log` now shows batch, credential-injection and credential-reveal state alongside execution and mutations, and the `cerno mcp --help` text lists every gating flag.
- **`cerno scan delete` warning is complete:** it now lists everything the delete removes (findings and host:port data, discovered services, sessions, verification verdicts and evidence, per-finding Claude chat history), and notes that tool executions, artifacts and their ingested results are kept.

### Fixed
- **Remote scan mode suggested a command that doesn't exist:** after a pivot-side nmap run, Cerno told you to run `cerno import nmap …`. It now shows only the `scp` step, copying all `-oA` outputs into your configured `results_root`.
- **Session statistics never showed the per-severity table:** the breakdown was built but not printed. It now prints, ordered Critical → Info and labelled as all-session Done counts.
- **Findings-list help showed the wrong sort mode:** `[?]` described `[S]` as a host-count/name toggle and labelled the default severity sort as "Name". It now names the active mode (Severity, Plugin ID, Name or Hosts) like the footer does, and describes the full cycle.
- **`cerno reset` left files behind:** `proxychains4.conf`, `config.yaml.backup` and the database's `-wal`/`-shm` files survived, so `~/.cerno` was never removed. They are now deleted too.
- **CLI help text and messages:** `cerno scan --help` mentions compare and history, `cerno workflow --help` no longer advertises a "view" command, `cerno review --help` marks `--export-root` as ignored, `cerno config show` describes `default_tool` (now listing `metasploit`), `nxc_enrichment_enabled` and the remote-scan HTTPS server accurately, the onboarding tour says `[1-5]` for severities, and the import error now says "Import failed" instead of "Export failed".
- **Documentation brought up to date with 2.x:** `docs/MCP.md` (all 46 tools, the verdict/results resources, every gating flag, the verification loop, jobs/batch and credentials), README (keyboard shortcuts, commands, a full config-key reference), `docs/CUSTOM_WORKFLOWS.md` (workflow `<TARGET>`-style placeholders instead of the custom-command `{TCP_IPS}` set), `docs/DATABASE.md` and `schema.sql` (schema v4: all 25 tables, 11 views and indexes; broken example queries fixed), `docs/TOOL_SYSTEM_GUIDE.md`, `docs/ADDING_TOOLS_QUICKSTART.md`, `docs/ERROR_HANDLING.md`, `TESTING.md`, the demo README, and docstrings across the codebase.

## [2.6.0] - 2026-10-27

### Added
- **`color_scheme` config key (`light` | `dark`):** selects the palette for the terminal background. `cerno config set` now rejects values outside a key's allowed choices (e.g. `cerno config set color_scheme purple` lists `light, dark`).

### Changed
- **Colors now default to a light (white) terminal background:** yellow, cyan, white, bright and default ANSI colors were hard to read on white backgrounds. Under the default `light` scheme every color is swapped for a darker variant (e.g. yellow → dark orange, cyan → teal, white → default text) across the whole TUI and CLI. That covers tables, panels, markup, prompts, progress bars and `✓`/`⚠`/`✗` messages, in one place (`ansi.CernoConsole`, `ansi.initialize_colors`, palette in `constants.LIGHT_BG_COLOR_MAP`). **On a dark terminal, run `cerno config set color_scheme dark`** to get the previous colors back exactly.

## [2.5.0] - 2026-10-27

### Added
- **Reset a single config setting:** `cerno config reset <key>` restores one key to its default and leaves the rest of `config.yaml` alone. Unlike `config set`, it handles nullable keys (e.g. `custom_workflows_path` goes back to unset) and list keys (`mcp_exec_allowlist` gets its default list back, not an empty deny-all list). `cerno config reset` with no key still resets the whole file with a backup. New helper `config.reset_config_key()`.

## [2.4.0] - 2026-10-27

### Added
- **Workflow contribution loop (MCP):** turn the commands you actually ran to verify a finding into a workflow you can contribute to the bundled `workflow_mappings.yaml`. New always-on tools: `get_workflow_candidate` drafts a sanitized entry, and `export_workflow_contribution` writes it as a local, PR-ready YAML file with steps for opening a PR against `develop`. Nothing is ever submitted. A candidate exists when the plugin has no workflow (`"new"`) or you ran a non-baseline command the mapped workflow lacks (`"enhanced"`: existing steps kept, new commands appended, `possibly_superseded` flagged). Running the mapped workflow unchanged, or only Cerno's baseline nmap/nxc commands, yields none. Hosts, ports, credentials, target/output files and proxychains wrappers are templated or stripped (`<TARGET>`/`<PORT>`/`<USERNAME>`/`<PASSWORD>`/`<DOMAIN>`), and a fail-closed leak scan (IP literals, the scan's host names, scan names, NetExec domains and non-dictionary usernames, credential secret values, NT/LM:NT hash literals, local paths) refuses any export that still contains engagement data. Plugin-derived `workflow_name`/`description` are never checked for usernames, and dictionary usernames (`anonymous`, `root`, `admin` …) never count. Secret values are resolved from the NetExec workspace in memory only to compare against, and are never logged, returned or echoed in a hit. Export also requires a `confirmed`/`false_positive` verdict, and review/verdict notes are never included. New core module `cerno_pkg/workflow_contrib.py`, plus `ToolExecution.get_by_finding()`, `Finding.get_host_identifiers()`, `Host.identifiers_for_scans()` and `exec_chain.split_wrappers()`.
- **`workflow_candidate` verdict hint:** `set_finding_verdict`, `get_finding_verdict` and `cerno://finding/{id}/verdict` now include `workflow_candidate: {available, reason}`. Drafting is best-effort and can never break a verdict call.
- **`contribution_export_dir` config key:** where exported contributions are written (default `<results_root>/contributions`).
- **`<DOMAIN>` workflow placeholder:** `prepare_workflow` fills `<DOMAIN>` from the selected credential's domain and reports it unresolved otherwise. New helper `workflow_prep.canonicalize_placeholders()`.

### Changed
- **TUI tool runs are attributed to their finding:** commands run from the review TUI now record `finding_id` in `tool_executions` (`tools.py:run_tool_workflow`), so they feed verified-fact stats, verdict suggestions and workflow contributions, the same as MCP runs.
- **MCP execution guidance:** the `execute_command`/`start_execution` descriptions and the `triage_finding`/`exploit_plan` prompts now tell clients to always pass `finding_id` when verifying a finding.

### Fixed
- **Stale repository links:** `docs/CUSTOM_WORKFLOWS.md` linked to `DefensiveOrigins/cerno`. It now points to `ridgebackinfosec/cerno` (PRs target `develop`).

## [2.3.2] - 2026-10-26

### Changed
- **Proxy settings say `proxychains4`:** `cerno config show` now labels the proxy section **Proxychains4**, and the help text for `proxychains_enabled`/`proxychains_host`/`proxychains_port` names `proxychains4`, the binary Cerno actually runs. The key names are unchanged, so existing `config.yaml` files keep working. `--no-proxy` help, proxy config error messages, the MCP `execute_command` description (`use_proxy`), README and `docs/MCP.md` (new config-table row for the proxy keys) also name `proxychains4` explicitly.

### Fixed
- **proxychains4 version not shown:** the proxychains4 row in the Tool Availability table showed a generic "Available", and MCP `check_tools` reported `version: null`. proxychains4 has no `--version` flag (it tried to exec a program named `--version`), so Cerno now reads the proxychains-ng version from its startup banner via the new `ops.get_proxychains4_version()`. The probe runs the Python interpreter under a throwaway config and opens no network connections. When proxy mode is active, the row shows both, e.g. `v4.17 · SOCKS5 127.0.0.1:9000 (active)`.

## [2.3.1] - 2026-10-26

### Fixed
- **MCP ignored `custom_workflows_path`:** every MCP workflow lookup loaded only the bundled `workflow_mappings.yaml`. `get_workflow`, `prepare_workflow`, `list_workflow_gaps`, `query_findings(has_workflow=…)`, `plan_batch`/`execute_batch` (`has_workflow` predicate and the `"workflow"` strategy), the `cerno://finding/{id}/workflow` resource and the finding prompts now merge your custom workflows over the bundled ones (custom wins on conflict), as `cerno review` does. New shared factory `workflow_mapper.build_workflow_mapper(config)`, which is also the default in `query.run_finding_query` and `workflow_prep.prepare_workflow`. It is built per call, so edits to the YAML are picked up, and a missing or malformed custom file leaves the bundled set and never writes to stdout (the MCP JSON-RPC channel).
- **MCP ignored `default_netexec_protocol`:** `generate_netexec_cmd`'s `protocol` is now optional. When it is omitted, the configured default is used, else `smb` (same as the TUI). An explicit protocol still wins and is still validated, and an invalid configured value is rejected with an error naming the key. `plan_batch`/`execute_batch` also accept a bare `"netexec"` strategy that uses the same default.
- **MCP ignored `nmap_default_profile`:** when `nse_option` is omitted, `generate_nmap_cmd` (and the `"nmap"` batch strategy) now applies the configured NSE profile's scripts. `nse_option=""` explicitly means no scripts, and an unknown profile name applies none. `udp` is now optional: when it is omitted, a UDP profile (SNMP/IPMI) adds `-sU`. New helper `tools.find_nse_profile()`.
- **MCP ignored `default_page_size`:** `list_findings`, `query_findings` and `search_findings` now default `limit` to the configured page size (minimum 8, as in the TUI) when set, else 500. An explicit `limit` still wins.

### Changed
- **Explicit MCP config contract:** new `config.MCP_NOT_APPLICABLE_KEYS` lists the TUI-only keys the MCP server intentionally ignores (`no_color`, `term_override`, `default_tool`, `claude_assistant_enabled`, `pivot_interface`, `pivot_http_port`, `top_ports_count`). A new guard test fails if a config key is added without deciding how the MCP treats it. `docs/MCP.md` gains a "Config defaults" table.

## [2.3.0] - 2026-10-23

### Added
- **Workflow-gap report (MCP):** a new always-on `list_workflow_gaps(scan_ids, severity_min=None)` read tool answering "which findings have NO verification workflow?" — the complement of `query_findings(has_workflow=True)`. It reuses the composite query layer (`FindingQuery(has_workflow=False, merged=True)`) and the workflow mapper (no new query logic), returning one representative row per unmapped plugin, worst-first (severity desc, then Metasploit-backed first) so MSF-backed criticals like MS17-010 surface at the top of the triage list.
- **Findings notes (MCP):** `review_notes` is now readable and append-only. New always-on `get_notes(finding_id)` returns the notes as timestamped `entries` plus the `raw` string; new `add_note(finding_id, note)` (gated by `mcp_allow_mutations`) appends a timestamped note and returns the full list. `Finding.update_review_state(notes=…)` / `set_review_state(notes=…)` now **append** rather than overwrite, so manual notes and review-state notes no longer clobber each other (`models.py` gains `Finding.append_note`). No schema change — reuses the existing `findings.review_notes` column (no re-import).

## [2.2.0] - 2026-10-23

### Added
- **Scoped batch (MCP):** operate on a whole finding *query* instead of one finding. `plan_batch(strategy, …query predicates…)` (always on, read-only) generates the verification command for every matched finding — `strategy` is `"nmap"`, `"netexec:<proto>"`, `"msf"`, or `"workflow"` (first runnable workflow command) — and returns a reviewable plan classifying each as executable-via-`execute_command` or manual, skipping already-resolved findings (review_state done, or a confirmed/false_positive verdict) when `skip_done`. `execute_batch(…)` then runs the runnable, non-skipped items, each as a tracked/cancellable job attributed to its finding and auto-ingested, capped at `mcp_batch_concurrency` with an `mcp_batch_timeout` per command and the exec policy re-validated per command. `execute_batch` is registered only when both `mcp_allow_execution` and the new `mcp_allow_batch` are enabled (plan/dry-run needs neither). New module `cerno_pkg/batch.py`; new config keys `mcp_allow_batch` (bool, default false), `mcp_batch_concurrency` (int, default 1), `mcp_batch_timeout` (int, default 300). The job registry gained a shared-semaphore concurrency gate.
- **Async job model (MCP):** long scans no longer have to block the tool call. When `mcp_allow_execution` is on, four new tools run beside `execute_command`: `start_execution(command, …)` validates the exec policy + cred gate up front and returns a `job_id` immediately; `get_execution_status(job_id)` reports `running`/`done`/`failed`/`cancelled` with elapsed time and a stdout/stderr tail; `cancel_execution(job_id)` kills the run's whole process group (SIGTERM→SIGKILL); `list_jobs()` lists this process's jobs newest-first. Jobs are an in-memory runtime registry (no schema change, not persisted across a server restart), but every completed run is still written to `tool_executions` and auto-ingested exactly as the synchronous path, because both now share one `_run_and_record` body (the only difference is the runner — a cancellable `ops.start_process` spawn with `start_new_session=True` for the async path). New module `cerno_pkg/mcp_server/jobs.py`; new `ops.start_process`.
- **Runnable workflows (MCP):** a new always-on `prepare_workflow(finding_id, use_credential=None)` tool that fills the verification workflow mapped to a finding's plugin with the finding's real hosts/ports and marks each filled command executable-via-`execute_command` vs manual-only. Placeholders are normalized to a canonical vocabulary (`<TARGET>`/`<PORT>`/`<USERNAME>`/`<PASSWORD>`/`<INTERFACE>`) in `workflow_mappings.yaml`, with a variant map so historical/`--custom-workflows` YAMLs (`IP_address`/`$IP`/`<target>`/`<user>`…) still fill. Credential commands reuse the Tier 1 `@cred:<ref>@` placeholder (no secret is ever placed in the returned command; `<USERNAME>` filled from the ref, `<PASSWORD>` left as the gated placeholder); `<INTERFACE>` and any un-fillable token are surfaced in `unresolved_placeholders` and mark their command manual. Non-cerno-runnable steps (responder, ntlmrelayx, ssh-audit, uninstalled tools, prose steps) come back `executable=false` with a `manual_reason`, checked against `mcp_exec_allowlist`/`mcp_exec_denylist` plus a PATH-installed test. New shared module `cerno_pkg/workflow_prep.py`; the allow/deny glob matching is now shared via `cerno_pkg/exec_chain.py` (`matches_any`, non-raising `is_runnable`) so the workflow eligibility check and the `execute_command` policy cannot drift.
- **Composite finding query (MCP):** a new always-on `query_findings` tool with AND-combined predicates — `scan_ids`, `severity_int`, `severity_min`, `review_state`, `verdict` (`confirmed`/`false_positive`/`unable`/`none`), `cve`, `port`, `service`, `host`, `plugin_name`, `has_metasploit`, `has_workflow`, `merged`, plus `limit`/`offset`. It answers multi-predicate intents (e.g. "unreviewed criticals with an MSF module on port 23, not yet verdicted") in one call instead of several `list_findings`/`search_findings` calls with client-side joining; each row carries its `scan_name` and a `has_workflow` flag. Predicates are a fixed, parameterized set (no free-form SQL): most compile to bound WHERE clauses over the normalized host/port/service tables and the current-verdict view, while `cve` uses a SQL pre-filter with an exact case-insensitive Python confirm (so `CVE-2021-1` never matches `CVE-2021-10`) and `has_workflow` consults the workflow mapper (resolving grouped comma-separated plugin keys). New shared module `cerno_pkg/query.py` (`FindingQuery` + `run_finding_query`), reused by the MCP adapter and available to the TUI. `list_findings`/`search_findings` are retained as conveniences.

### Fixed
- The cached NetExec manager went stale after a scan import: `get_nxc_manager()` is a module-level singleton, so scans imported into a running process (e.g. via the MCP `import_nessus` tool) weren't reflected by `list_nxc_credentials` / `get_host_nxc` / `generate_netexec_cmd(use_credential=…)` until a restart. `import_nessus_file` now calls the existing `reset_nxc_manager()` after a successful DB write, so the next `get_nxc_manager()` rebuilds against the new hosts; this covers the CLI and MCP import paths (both route through `import_nessus_file`) and is a safe no-op when nxc is disabled or the manager was never built (`nessus_import.py`).
- `prepare_workflow` emitted malformed commands for multi-host findings: `<TARGET>` (and variants) was always filled with the hosts space-joined, so a single-target step on a finding with two hosts became e.g. `telnet 198.51.100.21 198.51.100.33 23`. It now resolves each command's target binary and only joins hosts for multi-target binaries (`nmap`, `masscan`, `nxc`, `netexec`); every other single-target command expands to one filled command per host (`telnet <h1> 23`, `telnet <h2> 23`), each classified executable/manual independently. Single-host findings and `@cred:<ref>@` handling are unchanged (`workflow_prep.py`).

## [2.1.0] - 2026-10-22

### Added
- Audited credential reveal, a deliberate opt-in path to a credential's cleartext now that injected secrets are masked everywhere else. Local CLI: `cerno creds list` (refs/usernames/`secret_kind`, never values) and `cerno creds reveal <ref>` (prints cleartext behind a SENSITIVE warning, works on the operator's own box regardless of MCP flags). MCP tool `reveal_credential(ref)` is registered only when the new `mcp_allow_cred_reveal` config is enabled (default `false`, independent of `mcp_allow_cred_injection`); `get_capabilities` reports `cred_reveal_enabled`. Every reveal (CLI or MCP) writes a `cred_reveal` audit row to `tool_executions` recording the ref + timestamp — never the secret value (`cerno_pkg/creds.py`).

### Security
- `execute_command` now scrubs resolved credential secrets from the on-disk output files it registers as artifacts. A cred-injected nxc run writes its full argv — including the resolved `-H <hash>`/`-p <pass>` — into its `--log` file, which was registered unscrubbed and recoverable via `read_artifact`; the secret is now masked in that file (and defensively in nmap `-oA` outputs) before registration, fail-closed (a file that can't be scrubbed is not registered). `command_text` masking and stdout/stderr scrubbing are unchanged. Known limitation: the secret is still present in the tool's argv in the process table (`ps`) for the run's duration — nxc accepts credentials only via argv.

### Fixed
- NetExec workspace reads are now thread-safe. The MCP server runs each tool body on an `asyncio.to_thread` worker, but `nxc_db` cached SQLite connections on a module-level singleton and a connection may only be used on its creating thread — so credential resolution and host enrichment (`resolve_credential_secret`, `list_credential_refs`, `get_host_nxc`, `list_nxc_credentials`) intermittently raised `ProgrammingError`, which was swallowed and surfaced as a false "Could not resolve credential … to a usable secret". Connections are now opened per call (the workspace DBs are tiny), and a real DB/access error during resolution is logged and raised instead of being misreported as "no secret" (`nxc_db.py`).
- `cerno config show` and `config set` now derive every setting from the `CernoConfig` dataclass fields + per-field metadata (section/help/kind) instead of hand-maintained key lists. This fixes `mcp_allow_cred_injection` being invisible in `config show` and silently dropped by `config set`/`save_config`, and the latent `pivot_http_port` miscoercion (stored as a string). Adding a config field now surfaces it in load/save/show/set automatically; a drift-guard test fails if a new field lacks the required metadata (`config.py:iter_config_fields`/`build_config_rows`, `tests/test_config.py`).

## [2.0.0] - 2026-10-22

### Added
- **Result ingestion (MCP):** tool output is now parsed back into the database as structured, provenance-stamped facts. A new `ingest_results(execution_id)` tool (gated by `mcp_allow_mutations`) parses an nmap run's XML artifact into open ports (`verified_ports`) and NSE vuln-script verdicts (`nse_script_results`, e.g. `smb-vuln-ms17-010` = VULNERABLE), and re-reads the NetExec workspace into a security-flag snapshot (`nxc_flag_observations`). `execute_command` auto-ingests best-effort when both execution and mutations are enabled (and returns an `ingest_hint` otherwise). Ingestion is idempotent per execution and never errors on empty/partial/failed runs. New module `cerno_pkg/ingest.py` + pure parser `cerno_pkg/nmap_parse.py`.
- **Finding verdicts + evidence (MCP):** a verification verdict (`confirmed` / `false_positive` / `unable`), distinct from `review_state`, recorded with history and linked to the execution/artifact/NSE result that proves it. New tools `set_finding_verdict(...)` (gated by `mcp_allow_mutations`) and `get_finding_verdict(finding_id)` (read); `get_finding_detail` now carries the current `verdict`, a non-binding `suggested_verdict` derived from ingested NSE evidence (never auto-applied), and live-verified fact counts. New resources `cerno://finding/{id}/verdict` and `cerno://finding/{id}/results`.
- **Credential-aware generation (MCP):** `generate_netexec_cmd(finding_id, protocol, use_credential=<ref>)` injects a known NetExec credential, emitting a `@cred:<ref>@` placeholder for the secret. `list_nxc_credentials` now returns a non-secret `ref` + `secret_kind` per credential. The real password/hash is resolved **server-side at execution time only** (`nxc_db.resolve_credential_secret`), never returned by generation or stored; it is masked in the logged `command_text` and scrubbed from returned stdout/stderr. New config `mcp_allow_cred_injection` (default `false`) gates the substitution independently of `mcp_allow_execution`; `get_capabilities` reports it.

### Changed
- **BREAKING:** database schema bumped to version 4 (new `verified_ports`, `nse_script_results`, `nxc_flag_observations`, `finding_verdicts`, `verdict_evidence` tables; `verdict_types` / `nse_verdicts` / `port_states` lookup tables; `v_finding_current_verdict` / `v_finding_verified_stats` / `v_nse_results_with_verdict` views). No migration system — existing users must back up and delete `~/.cerno/cerno.db`, then re-import their scans (`initialize_database()` raises `SchemaVersionError` on an older DB with re-import instructions).

### Security
- `tool_executions.command_text` masks a literal secret after an auth flag (`-p`/`--password`/`-H`/`--hash`) as defense-in-depth, but **only for nxc/netexec runs** (resolved via the shared `exec_chain` binary resolver), so a cleartext password/hash is never persisted while nmap's `-p <ports>` is left intact.

### Fixed
- MCP result ingestion never ran: `ingest_execution` dispatched on `tool_executions.tool_name`, but the MCP server logs every `execute_command` run as `tool_name="mcp"`, so ingestion always hit the "no ingester" branch and populated nothing. Dispatch now resolves the real target binary from `command_text` (unwrapping sudo/proxychains4/etc. via the new shared `cerno_pkg/exec_chain` resolver), so an `mcp`-labelled `nmap`/`nxc` run ingests correctly; an empty run returns a benign skip. The same resolver now backs the `execute_command` allow/deny policy so the two cannot drift.
- MCP execution audit corrupted nmap's ports: `command_text` masking blanket-masked the token after `-p`, which is nxc's password flag but also nmap's ports flag, so `nmap ... -p 445` was logged as `-p ********`. Masking now targets only the `@cred:<ref>@` placeholder (the sole secret-bearing token before resolution) plus the nxc/netexec-scoped literal-secret masking above; nmap port specs are preserved.
- Re-ingesting an execution reassigned fact-row primary keys and silently nulled verdict evidence: ingestion deleted-and-reinserted `verified_ports`/`nse_script_results`/`nxc_flag_observations`, so a `verdict_evidence.nse_result_id` citation was nulled (ON DELETE SET NULL) on the next `ingest_results` of the same execution. Ingestion now reconciles rows in place keyed on their logical UNIQUE columns — matched rows are updated (PK preserved), new rows inserted, and only rows absent from the current output are pruned — so evidence links survive and re-ingest stays idempotent (`ingest.py:_reconcile_execution_rows`).

## [1.12.6] - 2026-10-21

### Fixed
- MCP `generate_netexec_cmd` accepted any `protocol` string and emitted an unrunnable command (e.g. `nxc bogus_proto ...`). It now validates against `constants.NETEXEC_PROTOCOLS` (case-insensitive, normalized to lowercase) and raises a clear error listing the valid protocols.
- MCP `execute_command` only registered nmap `-oA` outputs as artifacts; a netexec run's `--log` file was never captured, so `get_finding_artifacts`/`list_artifacts` stayed empty and `read_artifact` couldn't retrieve it. Post-run registration now also records a `--log <path>` file as a `log` artifact (nmap handling unchanged). `host_count`/`ports` remain null for non-nmap runs (no equivalent flags to parse).

## [1.12.5] - 2026-10-21

### Fixed
- MCP `check_tools` reported installed tools (`msfconsole`, `proxychains4`) as `installed:false` despite being on PATH, disagreeing with the TUI. Two causes: `ops.get_tool_version()` ignored stderr on a zero exit (e.g. `msfconsole --version` exits 0 and prints the version only to stderr), so it now always parses combined stdout+stderr; and `check_tools` tied install status to version parsing, so it now derives `installed` from PATH presence (`ops.resolve_cmd`) with `version` best-effort, matching the TUI's availability check.

## [1.12.4] - 2026-10-21

### Fixed
- MCP `generate_nmap_cmd` put NSE script names into the command without the `--script` flag (e.g. `nmap -A smb-security-mode -iL ...`), so nmap treated them as targets and the command didn't run. `nse_option` now accepts bare script names or categories (comma- or space-separated), `--script=X` or `--script X`, and always produces a single `--script=a,b` argument. Other flags in `nse_option` are rejected with an error (`tools.py:normalize_nse_option()`, used by `build_nmap_cmd()`).
- MCP `execute_command` ran nmap and logged the execution but never registered the `-oA` output files as artifacts, so `get_finding_artifacts` and `list_artifacts` stayed empty, and `host_count`/`ports` were never recorded. It now registers the nmap `-oA` outputs (via `ops.log_artifacts_for_nmap`) and records `host_count` (from `-iL`) and `ports` (from `-p`), even when no hosts were up. To stop a re-run from silently overwriting a prior run's output, `execute_command` refuses to run when the `-oA` files already exist, and each `generate_nmap_cmd`/`generate_netexec_cmd` call now writes to a unique per-call output directory (`_mcp/<finding_id>/run-XXXXXX/`).

## [1.12.3] - 2026-10-20

### Fixed
- MCP command builders `generate_nmap_cmd`, `generate_netexec_cmd` and `generate_msf_search` failed on every call from real MCP clients (e.g. Claude CLI) with `Output validation error: None is not of type 'string'`. The three tools shared one output type covering all their fields, and FastMCP sent each tool's missing fields as `null`, which the schema rejected. Each tool now has its own output schema (`NmapCommand`, `NetexecCommand`, `MsfSearchCommand` in `mcp_server/server.py`).
- MCP `list_artifacts` / `get_finding_artifacts` no longer fail output validation when an artifact has no artifact type (`ArtifactInfo.artifact_type` is now nullable).

## [1.12.2] - 2026-10-19

### Added
- NetExec context now shows every protocol NetExec saw a host on, even when no credentials are tied to it. A new "Seen via" line in the `[N]` per-host view lists protocols with ports and banners (e.g. `SMB, SSH (22, 2222 · SSH-2.0-OpenSSH_9.6), RDP (3389)`). Per-protocol host attributes come through MCP `get_host_nxc` as `protocol_details` (`nxc_db.py:NxcHostData.protocol_details`).
- New NetExec security flags: **LDAP signing not required** (ldap.db) and **RDP NLA disabled** (rdp.db), in the per-host view, the NetExec Context summary, and MCP `security_flag_counts` (`ldap_signing_disabled`, `rdp_nla_disabled`). Only explicit results count; hosts NetExec didn't check are not flagged.
- Credentials NetExec dumped from a host (`pillaged_from_hostid`, e.g. SAM/LSA) are tied to that host and marked "dumped" (`NxcCredential.pillaged`).
- Failed SMB configuration checks (NetExec `conf_checks_results`) show as security flags per host (`NxcHostData.failed_checks`).
- Demo NetExec workspace adds `ldap.db` and `rdp.db`, and all demo databases are now built from the real NetExec 1.5.1 schemas (`scripts/create_demo_nxc_workspace.py`).

### Fixed
- NetExec enrichment silently returned nothing for every protocol except SMB. Cerno's queries didn't match the schemas NetExec actually creates (e.g. ssh `hosts` has no `hostname`; ldap/mssql/rdp/winrm/nfs/vnc/wmi have `ip` but no `host`; ftp/nfs relations use different column names), and the errors were swallowed. Queries are now built from per-protocol specs matching NetExec 1.5.1 and check optional columns at runtime. Query failures are logged at DEBUG instead of being hidden (`nxc_db.py:_PROTOCOL_SPECS`, `_query_protocol_host()`).
- NetExec lookups now include every `hosts` row for an IP, not only the first, so services on multiple ports (e.g. SSH on 22 and 2222) and their credentials are no longer dropped.
- A NetExec credential with repeated admin/logged-in relation rows is listed once instead of repeating.
- NetExec SMB share counts no longer double-count a host when several users can access the same share (shares are collapsed per name).

## [1.12.1] - 2026-10-19

### Added
- Finding preview panel shows a `Plugin Details:` link to the plugin's Tenable page again (e.g. `https://tenable.com/plugins/nessus/41028`). It is an OSC 8 hyperlink to the full `https://www.tenable.com/...` URL, so Ctrl+click opens it in supporting terminals, and it still appears with `no_color` on. Plugins without a stored URL fall back to one built from the plugin ID (`render.py:display_finding_preview()`).

## [1.12.0] - 2026-10-19

### Added
- Findings list `[I]` toggle: show only In Progress findings, press again for all statuses. It combines with the name filter (`[F]`), group filters, sorting, paging, and bulk `[M]`, and works in every findings-list scope (single or multi-select severities, Metasploit, Workflow Mapped, multi-scan merged). The status line shows `[FILTER] Status: In Progress` while it is on, and `[V]`/`[A]` scopes include the status. `[C]` now clears both the name and status filters (`cerno.py:browse_file_list()`, `tui.py:filter_finding_candidates()`).

### Fixed
- README findings-list shortcuts: `[V]` is View hosts, not a severity filter.

## [1.11.2] - 2026-10-17

### Fixed
- Silenced two CodeQL `py/incomplete-url-substring-sanitization` false positives in `tests/test_models.py` by rewriting list-membership assertions (`"example.com" in hosts`) as `.count(...) == 1` checks. Test-only; no production code was affected.

## [1.11.1] - 2026-10-17

### Fixed
- Review file list: the clipboard-copy fallback no longer crashes with `NameError` when copying fails; it now prints the payload for manual copy as intended (`cerno.py:browse_file_list()`).

## [1.11.0] - 2026-10-17

### Added
- New `mcp_exec_denylist` config key: binaries the MCP `execute_command` tool may **never** run. It always wins over `mcp_exec_allowlist` and is checked against every binary in the command chain, so denying `sudo` blocks privilege escalation. Default: destructive commands (`rm, rmdir, dd, shred, wipefs, mkfs*, fdisk, sfdisk, parted, shutdown, reboot, halt, poweroff`). Set via `cerno config set mcp_exec_denylist "rm,dd,sh"`.
- `mcp_exec_allowlist` accepts `"*"` to permit any binary not in the denylist. Entries in both lists are glob patterns matched on the binary's basename (e.g. `mkfs*` matches `mkfs.ext4`). `cerno config set` warns when the allowlist is set to `*` or emptied.
- MCP `execute_command` supports `sudo <allowed-binary>`, e.g. for nmap SYN scans. sudo runs non-interactively and is refused if it would prompt for a password.
- MCP `get_capabilities` reports `exec_denylist`. `cerno config show` lists the denylist, and the server's startup log line summarizes both lists.

### Changed
- **An empty `mcp_exec_allowlist` now denies every command.** Previously it silently fell back to the default set.
- `proxychains4` was removed from the default `mcp_exec_allowlist`. Wrappers are now unwrapped and the target is checked; `use_proxy=true` still routes through proxychains4.
- The default allow/deny lists are defined once (`config.DEFAULT_MCP_EXEC_ALLOWLIST` / `DEFAULT_MCP_EXEC_DENYLIST`).

### Fixed
- `mcp_exec_allowlist` hand-edited into `config.yaml` as a string (e.g. `mcp_exec_allowlist: nmap,nxc`) was matched by substring, so `map` passed. List keys are now coerced to lists on load (`config.coerce_str_list()`).

### Security
- MCP `execute_command` now unwraps leading wrapper binaries before checking policy, so the real target is what the denylist/allowlist see. Covers `sudo`, `doas`, `proxychains4`, `proxychains`, `env`, `nice`, `nohup`, `timeout`, `stdbuf`, `setsid`, `ionice`, and `time`. Previously an allowlisted (or wildcard-allowed) wrapper could smuggle a denied binary past the denylist, e.g. `["proxychains4", "bash", "-c", …]`, `["env", "rm", …]`, or `["timeout", "60", "rm", …]`. A wrapper whose command is packed into an option value (`env -S "rm -rf /"`) is rejected (fail closed).

## [1.10.0] - 2026-10-17

### Changed
- `cerno scan list` now defaults to a **compact, 80-column-readable** table (Scan Name · Hosts · Findings · Crit · High · Done % · Last Reviewed). Use `--wide`/`--details` for the full per-severity breakdown, or `--json` for machine-readable output (scripting).
- User-facing wording now says **"finding"** instead of "file" where the database-backed product has no per-finding files (finding-list prompt and filter help, the "returning to finding menu" interrupts, the filtered-findings comparison/overlap headers, and CVE-extraction labels). Genuine file references (`.nessus`, config, logs, artifacts) are unchanged.

### Fixed
- `cerno --version` (and the review banner) now report the version from the repo's `pyproject.toml` when running from a source checkout / editable install, instead of stale installed package metadata; pipx/wheel installs still use their installed metadata.

## [1.9.0] - 2026-10-17

### Changed
- **Claude Assistant is now opt-in.** `claude_assistant_enabled` defaults to `false`. Because the assistant sends finding names, plugin metadata, affected hosts, ports, CVEs, workflow steps, and Nessus plugin output to the local `claude` CLI, the TUI now shows a data-path disclosure on first use and persists the choice when the operator consents (press `[A]` → confirm). Enable ahead of time with `cerno config set claude_assistant_enabled true`.

### Fixed
- A missing external tool no longer exits the review session. The tool picker lists tools whose binary is absent as `(not installed: …)`, never selects them, and never makes one the Enter-default; launching one shows an inline error and returns to the tool menu (`ops.ensure_cmd()` replaces a hard `sys.exit`, with a `SystemExit` guard around the tool run as a backstop).
- Tool availability now uses OR semantics across acceptable binaries, so `netexec` shows as available when either `nxc` or `netexec` is installed (previously required both).

## [1.8.0] - 2026-10-17

### Added
- MCP server: `search_findings` — search findings across **all** scans at once (by plugin name / severity / Metasploit), no `scan_ids` needed; each result carries its `scan_name`.
- MCP server: `top_hosts` — hosts ordered worst-severity-first for prioritization.
- MCP server: `get_capabilities` — reports which gated capabilities are live (`execution_enabled`, `mutations_enabled`, `exec_allowlist`, `nxc_available`) so a client can self-orient without a failed call.
- MCP server: `get_finding_artifacts` — artifact files generated by executions attributed to a finding (findings → tool_executions → artifacts).
- MCP server: `execute_command` now accepts an optional `finding_id` to attribute a run to a finding, enabling `get_finding_artifacts` to find its output (`ops.log_tool_execution()` gained a `finding_id` parameter).
- New `mcp_exec_allowlist` config key (default: `nmap, nxc, netexec, msfconsole, proxychains4`) restricting which binaries the MCP `execute_command` tool may run; an empty list falls back to the built-in default set. Set via `cerno config set mcp_exec_allowlist "nmap,nxc"`.

### Changed
- MCP server: `list_findings` gained `merged` (dedup multi-scan results by plugin, matching the TUI), `limit`, and `offset` for paging.
- MCP server: `get_finding_detail` caps per-host output at `max_hosts` (default 100) and reports `affected_total` / `affected_truncated`, protecting client context on large scans.
- MCP server: `triage_scope` prompt now accepts multiple scans (comma-separated `scan_ids`), merging and deduplicating by plugin like the TUI aggregate assistant.
- MCP server: `execute_command` clamps `timeout` to [1, 3600] seconds and rejects binaries not in `mcp_exec_allowlist`.
- MCP server: added structured output schemas to `get_finding_hosts`, `list_executions`, `list_artifacts`, `find_affected_by_cve`, and the three `generate_*` tools.

## [1.7.2] - 2026-10-17

### Changed
- Dependabot version-update PRs now target the `develop` branch instead of `main` (`.github/dependabot.yml`: `target-branch: "develop"`)

## [1.7.1] - 2026-10-17

### Changed
- Consistent review-status wording across the TUI. Status changes all use **Move**: "Move to In Progress", "Move to Done", "Move back to Unreviewed", and the findings-list bulk action "Move to next status (N)" (was "Advance"). Confirmations and summaries use the same words ("Moved 2 to In Progress, 1 to Done.").
- Done list is now opened with **`[D]`** (was `[R]`), and inside it `[U] Undo completion` is replaced by `[M] Move back to Unreviewed`. The view is called "Done list" everywhere (header, help, footer, empty state), replacing "Done Findings (Undo Available)" and the stale "reviewed list".
- Severity, Metasploit/Workflow rows and the workflow picker now show **Unreviewed (%) · In Progress (%) · Done (%) · Total** instead of "Not done / Done", so in-progress work is visible (`Finding.count_by_scan_severity()` now returns four counts; new `models.count_review_states()`).
- Findings list "State" column renamed **Status**, with icons and a legend (`○` Unreviewed, `◐` In Progress).
- Status colours are consistent everywhere (Unreviewed cyan, In Progress blue, Done magenta — kept apart from the severity palette) via new `REVIEW_STATE_STYLES` / `REVIEW_STATE_ICONS` / `REVIEW_MOVE_LABELS` constants.
- Session summary rows are now "Moved to In Progress", "Moved to Done", "Total status changes", and the list status line reads "Unreviewed N · In Progress N" with "Session: 3m (+1 In Progress, +0 Done)".
- `fs.advance_review_state()` and `fs.undo_review_complete()` replaced by `fs.move_review_state(finding, target=None)`.

## [1.7.0] - 2026-10-16

### Added
- **Enforced review workflow**: `unreviewed` → `in_progress` → `done`, and `done` → `unreviewed` to reset. No other transitions are allowed; the rules live in one table (`constants.py:REVIEW_TRANSITIONS`) and are enforced by `Finding.transition_review_state()` for both the TUI and MCP (`InvalidReviewTransition`, a `ValueError`, on a disallowed change).
- Finding view `[M]` now advances one step and its label follows the state: "Mark in progress" → "Mark done" (dimmed once done). Marking in progress keeps you in the finding view (`fs.py:advance_review_state()`).
- Findings list `[M] Advance (N)` moves every filtered finding one step; the confirm prompt shows how many go unreviewed → in progress and in progress → done.
- "State" column in the findings list (`◐` in progress, `✓` done) and an "Unreviewed (N) · In progress (N)" status line.
- `REVIEW_STATES`, `REVIEW_TRANSITIONS`, `REVIEW_STATE_LABELS` and `REVIEW_STATE_*` constants (`constants.py`).

### Changed
- **BREAKING — re-import required.** Finding review states are now `unreviewed` / `in_progress` / `done` (previously `pending` / `reviewed` / `completed` / `skipped`). Database schema is version 3 (stored in `PRAGMA user_version`; `review_state` is now `NOT NULL DEFAULT 'unreviewed'`). A database from an earlier version is rejected at startup with instructions instead of failing later with a constraint error. To upgrade: back up and delete `~/.cerno/cerno.db`, then re-import your scans with `cerno import nessus <file>` (review progress from the old database is not carried over). Reinstall any pipx copy too (`pipx install --force <repo>`), since older versions cannot detect a newer database.
  - `v_session_stats` columns `files_reviewed` / `files_completed` / `files_skipped` → `files_in_progress` / `files_done`.
  - `Scan.get_all_with_stats()` / MCP `list_scans` field `reviewed_count` → `done_count`; `cerno scan list` column "Reviewed" → "Done".
  - MCP `set_review_state` accepts only `unreviewed`, `in_progress`, `done` and only along the workflow (e.g. `unreviewed` → `done` is rejected).
  - `[U]` in the Done list resets a finding to `unreviewed`.
  - `fs.mark_review_complete()` replaced by `fs.advance_review_state()`.
  - TUI labels updated: "Done Findings", severity table "Not done/Done (%)", scan header and onboarding show Unreviewed / In progress / Done, session summary shows "In Progress" / "Marked Done".

### Removed
- `skipped` review state and the "Findings Skipped (empty)" session tally (findings with no hosts are reported and left `unreviewed`).

### Fixed
- Finding view no longer prints a spurious "Invalid action choice." after `[M]` fails or the finding is already done (`fs.py:handle_finding_view()`).

## [1.6.3] - 2026-10-16

### Added
- `CONTRIBUTING.md` — dev setup, the "PRs target `develop`" rule, and the TUI ↔ MCP shared-core contract that keeps both interfaces working.
- `tests/test_mcp_contract.py` — cross-interface regression guard: freezes the MCP tool/resource/prompt inventory (tripwire), drives every category through the real MCP path (`call_tool`/`read_resource`/`get_prompt`) against a seeded DB, and asserts prompts never fall back to the default database.

### Changed
- Restructured `README.md` for flow and learnability: added a Table of Contents, a "How It Works" overview, and a one-line user-benefit lead for each feature; merged the duplicated Requirements into Installation; moved Releases/About-the-Name below the usage sections; surfaced the MCP server under Features; fixed an incorrect screenshot alt text. No content removed.

## [1.6.2] - 2026-10-16

### Fixed
- CI test failures across the OS/Python matrix:
  - MCP output-schema `TypedDict`s now import from `typing_extensions`, fixing a `PydanticUserError` that broke `build_server` on Python 3.11 (`cerno_pkg/mcp_server/server.py`).
  - `build_aggregate_context()` accepts an optional `conn`, and the MCP `triage_scope` prompt threads it through, so host/port lookups use the caller's connection instead of the default database (fixes `no such table` under tests/CI; `cerno_pkg/claude_assistant.py`).
  - `get_interface_ip()` degrades gracefully where `fcntl` is unavailable (Windows) instead of raising `ModuleNotFoundError` (`cerno_pkg/ops.py`).
  - Marked the Unix-only `get_interface_ip` dotted-quad and proxychains4 shell-wrap tests `skipif(win32)` (`tests/test_ops.py`).

## [1.6.1] - 2026-10-16

### Documentation
- Added `docs/MCP.md` — full MCP server reference (tools/resources/prompts, gating) with Claude CLI setup for both pipx and development/editable installs, plus verify/manage commands.
- README: added an MCP capability bullet, condensed the MCP Server section to a quick-start that links to `docs/MCP.md`, and added `docs/MCP.md` to the documentation index.

## [1.6.0] - 2026-10-15

### Added
- MCP server: **NetExec enrichment** tools/resource — `get_host_nxc` (credentials, shares, security flags for a host), `list_nxc_credentials` (deduplicated creds across hosts), and resource `cerno://host/{ip}/nxc`. Available when a NetExec workspace is configured (honors `nxc_enrichment_enabled`).
- MCP server: `find_affected_by_cve` — reverse CVE lookup returning affected findings/hosts across scans (exact, case-insensitive match).
- MCP server: `read_artifact` — read back the contents of a generated artifact file (e.g. nmap output) by id, capped with a `truncated` flag.
- MCP server: read-only config awareness — `get_config` tool and `cerno://config` resource expose all current settings with resolved paths.

### Changed
- MCP server: `execute_command` now emits progress heartbeats while a command runs, so long scans show liveness in progress-capable clients.
- MCP server: core read tools (`list_scans`, `list_findings`, `get_finding_detail`, `list_hosts`, `list_services`, `list_cves`) now declare structured output schemas for cleaner client-side parsing.
- Docs: clarified that enabling `mcp_allow_mutations` unlocks `import_nessus` and `set_review_state` (import remains gated as a DB-writing operation).

## [1.5.0] - 2026-10-15

### Added
- MCP server: **resources** — operator-pinnable context under `cerno://` URIs: `cerno://scans`, `cerno://scan/{id}/hosts`, `cerno://scan/{id}/cves`, `cerno://finding/{id}/output` (raw per-host plugin output), `cerno://finding/{id}/workflow`. Read-only, always available.
- MCP server: **prompt templates** — `triage_finding`, `exploit_plan`, and `triage_scope`, reusing the same context builders and report-brief wording as the in-TUI `[A]` assistant. (Both features only appear in MCP clients that render resources/prompts; the read tools remain the fallback.)

### Changed
- `cerno mcp` now logs its active execution/mutation gating state at startup (to `~/.cerno/cerno.log`, never stdout), and `cerno mcp --help` plus the README document that gating flags are read once at startup — reconnect/restart the server to apply changes (`cerno_pkg/mcp_server/server.py:gating_summary()`).

## [1.4.2] - 2026-10-15

### Changed
- Claude Assistant is no longer marked BETA (the feature is now considered stable). Removed the BETA label from the `[A]` TUI action labels, the chat panel title, the `claude_assistant_enabled` config description, docstrings, and docs. (The MCP server remains BETA.)
- NetExec Database Integration is no longer marked Beta (feature is now considered stable); removed the Beta label from the README section heading and note.

## [1.4.1] - 2026-10-15

### Added
- MCP server: three more read/generate tools — `list_cves` (unique CVEs across a scan mapped to their plugins, from cached `plugins.cves`), `list_services` (host/port/protocol/service-name inventory from `host_services`), and `generate_msf_search` (msfconsole search command for a finding's Metasploit modules).

### Changed
- `cerno config show` now groups settings under category headers (Paths, Review & Display, Tools & Workflows, Logging, NetExec, Claude Assistant, MCP Server, Proxychains, Remote Scan Mode) instead of a flat alphabetical list, marks settings changed from their default with a `▶` and a "changed" status (defaults dimmed), reports a count of changed settings, and no longer truncates long path values (`cerno.py:config_show()`).

## [1.4.0] - 2026-10-15

### Added
- **MCP server (BETA)**: new `cerno mcp` command exposes Cerno's scan database and tooling over the Model Context Protocol via local stdio transport, so any MCP client (Claude Code, Claude Desktop, etc.) can query findings and drive an engagement. Register it with `claude mcp add cerno -- cerno mcp` (`cerno_pkg/mcp_server/`).
  - Read + command-generation tools (always available): `list_scans`, `list_findings`, `get_finding_detail`, `get_finding_hosts`, `list_hosts`, `get_web_targets`, `host_history`, `compare_scans`, `get_workflow`, `check_tools`, `list_executions`, `list_artifacts`, `generate_nmap_cmd`, `generate_netexec_cmd`.
  - Execution tool `execute_command` (runs a command non-interactively, captures output, logs to `tool_executions`) gated behind new config flag `mcp_allow_execution` (default `false`).
  - Mutation tools `set_review_state` and `import_nessus` gated behind new config flag `mcp_allow_mutations` (default `false`). When a flag is off, the corresponding tools are not registered.
- New `ops.run_command_captured()` helper: non-interactive command execution that captures output without writing to stdout (used by the MCP server; keeps the stdio JSON-RPC channel clean).

## [1.3.46] - 2026-10-15

### Changed
- Proxy mode now runs tools via `proxychains4 -q`, hiding proxychains4's per-connection output. A magenta `[PROXY] proxychains4 → SOCKS5 host:port` line and a `Running via proxychains4` spinner make routing explicit; enabling `debug_logging` restores full proxychains4 output for troubleshooting (`ops.py:run_command_with_progress()`, `ProxyConfig.quiet`).

## [1.3.45] - 2026-10-15

### Fixed
- Reviewing multiple scans together now updates "Last Reviewed" for every selected scan instead of only the first, and returning to the scan list now records all selected scans in the session (`session.py:save_session()`).

## [1.3.44] - 2026-10-15

### Fixed
- Compare hosts (`[H]`), overlapping analysis (`[O]`), the aggregate host view (`[V]`) and Claude aggregate context now include hosts from all selected scans in multi-scan review instead of only the first scan, so comparison and overlap groups reflect the true cross-scan host set (`models.py:Finding.get_by_scan_ids_merged()`, `analysis.py`).

## [1.3.43] - 2026-10-15

### Fixed
- Host search (`[H]`) during multi-scan review now looks up the host across all selected scans instead of only the first, so hosts that appear only in later scans are found and their findings are no longer dropped from the filtered view (`models.py:Host.get_plugin_ids_for_scan()`).

## [1.3.42] - 2026-09-17

### Added
- Added a banner image to the top of README.md.

## [1.3.41] - 2026-06-10

### Added
- Added `cerno demo` to prepare bundled synthetic demo data, importing initial and expanded Nessus scans and configuring the included NetExec workspace for review demos.
- Added synthetic demo Nessus fixtures and NetExec workspace databases for cloned-repo and packaged installs, including `pipx` installs.

### Fixed
- Re-importing or overwriting a scan with the same name now refreshes scan metadata and replaces scan-derived findings/host services cleanly instead of silently failing on duplicate finding rows.
- Nessus imports now preserve bare IPv6 scan targets instead of misparsing the final IPv6 segment as a port.
- Nmap proxy mode now suppresses UDP scanning and uses TCP targets so generated proxychains4 commands match the UI warning that UDP is unsupported through SOCKS.
- Clipboard copy fallback now tries every available platform tool before reporting failure, so one broken backend no longer blocks later working backends.
- Scan deletion wording now accurately states that tool execution and artifact history is retained with deleted links cleared.

## [1.3.40] - 2026-04-23

### Added
- Workflow verification context now included in per-finding Claude assistant conversations (if available from workflow mappings) — displays workflow name, description, steps with commands/notes, and references (`cerno_pkg/claude_assistant.py:build_finding_context()`)

## [1.3.39] - 2026-04-23

### Changed
- Claude assistant exit changed from `Q` to `Ctrl+C` (`tui.py`, `cerno.py`)
- Claude assistant history clear changed from `C` to `/clear` command (`cerno.py`, `render.py`)

## [1.3.38] - 2026-04-23

### Changed
- Claude assistant controls hint keys styled cyan to match Cerno UI conventions (`render.py:render_claude_panel()`)

## [1.3.37] - 2026-04-23

### Changed
- Claude assistant controls hint updated to accurately reflect multi-line input: `[Enter] new line  [Alt+Enter] submit  [C] clear history  [Q] back` (`render.py:render_claude_panel()`)

## [1.3.36] - 2026-04-23

### Fixed
- Restored `handle_finding_list_actions` logic truncated by misplaced `ask_claude_multiline` definition — finding selection returned `None`, causing `TypeError: cannot unpack non-iterable NoneType object` (`cerno_pkg/tui.py`)

## [1.3.35] - 2026-04-22

### Changed
- Claude assistant prompt now supports multi-line input; `Enter` inserts a newline, `Ctrl+Enter` submits (`cerno.py`, `cerno_pkg/tui.py`)
- Added `prompt_toolkit>=3.0` dependency to support multi-line input

## [1.3.34] - 2026-04-22

### Changed
- Claude assistant panel replaced the Rich bordered Panel with a "soft panel": thick magenta Rules (`━`) at top and bottom, content printed line-by-line with `soft_wrap=True` — terminal handles visual wrapping so Ctrl+Shift+C copy-paste to Word produces no spurious newlines (`render.py:render_claude_panel()`)

## [1.3.33] - 2026-04-21

### Changed
- Claude assistant panel now uses plain `cyan`/`magenta` labels and unstyled body text; removes brightness-based contrast (dim/white) that was unreadable on light terminals (`render.py:_build_claude_panel_renderables()`)
- Removed duplicate "Ask Claude:" prompt from inside the panel — input prompt from `Prompt.ask()` below the panel is sufficient

## [1.3.32] - 2026-04-21

### Changed
- `render_claude_panel()` in `render.py` now renders conversation history inside a Rich bordered Panel with `bold magenta` border; prior exchanges are dimmed and the latest user+assistant exchange renders at full brightness; Rule separators appear between exchanges
- Claude Assistant waiting spinner upgraded from `_console_global.status()` to `Progress` with `SpinnerColumn` + `TimeElapsedColumn` in `browse_claude_chat()` and `browse_claude_chat_aggregate()` (`cerno.py`); spinner appears below the panel and disappears when the response arrives

## [1.3.31] - 2026-04-21

### Fixed
- `[E] CVEs (N)` in findings list footer was showing the filtered finding count instead of unique CVE count (`cerno.py`, `render.py:render_actions_footer()`)

### Added
- `[V] View hosts (N)` in findings list footer now shows unique host count across all filtered findings (`cerno.py`, `render.py:render_actions_footer()`)

## [1.3.30] - 2026-04-21

### Fixed
- `ImportError: cannot import name 'copy_to_clipboard' from 'cerno_pkg.render'` in `[V]` host view — moved import to `cerno_pkg.tools` (`cerno.py`)

## [1.3.29] - 2026-04-21

### Fixed
- `AttributeError: 'Finding' object has no attribute 'host_count'` when sending a message to Claude from the findings selection menu (`claude_assistant.py:build_aggregate_context()`)

### Changed
- `[V]` host view in findings list now matches single-finding host view UX: grouped format by default, Copy/Change format/Back post-view menu, Raw/Hosts-only/Grouped format options with clipboard support

## [1.3.28] - 2026-04-21

### Added
- `[V]` action in findings list shows a deduplicated host→ports view across all current candidates (respects severity, name, and group filters)

### Changed
- Aggregate Claude context trimmed to a concise signal-only format: numbered one-line-per-finding entries with severity, host count, CVEs, and MSF flag — raw host:port lists and pre-computed group analysis removed
- Skill prompt updated with `[H]`/`[O]`/`[V]` guidance so Claude redirects host-overlap questions to the appropriate actions

## [1.3.27] - 2026-04-21

### Added
- Aggregate Claude context now includes per-finding host:port lists (capped at 20 entries each) and pre-computed identical/overlapping host:port group analysis, enabling Claude to answer H/O-style questions conversationally (`claude_assistant.py:build_aggregate_context()`)

## [1.3.26] - 2026-04-21

### Changed
- Claude Assistant responses now render with `soft_wrap=True` so terminal-selected text copies without spurious newlines (`render.py:render_claude_panel()`)

## [1.3.25] - 2026-04-21

### Fixed
- `tui.py`: Remove redundant confirmation prompt when bulk-marking findings as review complete — one confirmation now instead of two

## [1.3.24] - 2026-04-21

### Changed
- `workflow_mappings.yaml`: Renamed "Deprecated SSL/TLS Encryption" workflow to "Weak SSL/TLS Configurations"; added 9 plugins (26928, 31705, 42873, 65821, 78479, 81606, 83738, 83875, 89058) bringing total to 12; updated description and notes to cover weak/anonymous/export cipher suites and specific vulnerabilities (POODLE, FREAK, Logjam) in addition to deprecated protocol versions

## [1.3.23] - 2026-04-21

### Added
- `workflow_mappings.yaml`: New "SSH Service Verification" workflow grouping plugins 90317 (password auth accepted), 70658 (CBC ciphers enabled), 153953 (weak KEX algorithms), and 71049 (weak MACs) — steps cover nmap with `ssh2-enum-algos,ssh-hostkey,sshv1,ssh-auth-methods`, ssh-audit, password auth verification, and Metasploit user enumeration

## [1.3.22] - 2026-04-17

### Fixed
- `render.py`: Remove leading spaces from CVEs in separated-by-finding bulk CVE list output

## [1.3.21] - 2026-04-17

### Fixed
- `render.py`: Remove leading spaces from CVEs in combined bulk CVE list for clean copy/paste into reports

## [1.3.20] - 2026-04-17

### Fixed
- `claude_assistant.py`: `TypeError` when Claude subprocess times out — `log_error()` was called with two positional args but only accepts one; fixed to use f-string interpolation
- `claude_assistant.py`: Increased default `ask_claude()` timeout from 30s to 120s to prevent premature `TimeoutExpired` errors on slow Claude responses

## [1.3.19] - 2026-04-17

### Changed
- Report Brief Mode in `cerno-assistant.md`: ports for the same host are now grouped on a single line, comma-separated (e.g. `192.168.56.4:80,443,8080`) rather than one line per host:port combination
- Report Brief Mode in `cerno-assistant.md`: single-host findings now name the host inline in the prose rather than listing it below

## [1.3.18] - 2026-04-17

### Changed
- Report Brief Mode in `cerno-assistant.md`: removed Nessus severity rating from output (analyst determines severity independently); replaced inline host list with a plain line-per-host block after the prose ("across the N systems below"), or "across X systems (listed in Appendix C)" for 100+ hosts; hosts output with no leading dash to avoid Word bullet formatting conflicts

## [1.3.17] - 2026-04-16

### Changed
- Claude Assistant per-finding context now includes Nessus plugin output (raw scanner text per host) so Claude can reference specific version strings, banners, and paths from the scan; capped at 5 hosts × 600 chars each with truncation notice (`claude_assistant.py:build_finding_context`, `run_exchange`)

## [1.3.16] - 2026-04-16

### Changed
- Remote scan server status message updated from "HTTP server running" to "HTTPS server running" for clarity (`tools.py`)
- Remote scan server status message updated from "serving IP list" to "serving target list" (`tools.py`)
- Served target file URL path renamed from `/ips.txt` to `/targets.txt` in HTTPS server and curl one-liner (`ops.py`)
- Proxy indicator badge renamed from `[PROXY]` to `[PROXY ENABLED]` in review session status line and finding action footer (`cerno.py`, `render.py`)

### Fixed
- Remote scan UDP mode: `build_nmap_remote_oneliner()` now accepts a `udp` parameter and emits `-sU` instead of hardcoded `-sS` when a UDP scan is requested; caller in `tools.py` passes `udp=bool(udp_ports)` (`ops.py`, `tools.py`)
- Claude Assistant report brief trigger word changed from `summarize`/`scenario` to `report`; removed the unverified-finding caveat from both the system prompt and the injected query (`claude_assistant.py`, `cerno-assistant.md`)

## [1.3.15] - 2026-04-16

### Changed
- Remote scan mode server upgraded from HTTP to HTTPS: self-signed certificate generated at startup via `openssl req`, server socket wrapped with `ssl.SSLContext` (TLS 1.2+ enforced), server now binds to the configured `pivot_interface` IP only instead of `0.0.0.0` — limiting exposure to other networks (`ops.py`, `start_ips_server`)
- Remote scan curl one-liner updated to `curl -sk https://` to match the HTTPS server; `-k` skips self-signed cert verification on the pivot (`ops.py`, `build_nmap_remote_oneliner`)

## [1.3.14] - 2026-04-16

### Added
- Claude Assistant: typing `summarize` or `scenario` in the chat prompt now generates a past-tense pentest report brief for the current finding or scope — mentions affected systems/ports, severity, any mapped Metasploit modules, and flags the finding as unverified (`claude_assistant.py`, `cerno.py`, `cerno_pkg/skills/cerno-assistant.md`)

## [1.3.13] - 2026-04-16

### Fixed
- Remote scan mode HTTP server now fully releases its port after shutdown — `server.server_close()` is called alongside `server.shutdown()`, and `allow_reuse_address = True` is set so the port is immediately reclaimable; previously the socket remained bound, causing `Address already in use` on the second remote command invocation (`ops.py`, `tools.py`)
- `pivot_interface` and `pivot_http_port` now appear in `cerno config show` output (`cerno.py`)

## [1.3.12] - 2026-04-16

### Fixed
- `build_nmap_remote_oneliner` function was written to `ops.py` during v1.3.11 implementation but never committed — caused `ImportError` on `pipx upgrade cerno` since `tools.py` imported it but the installed package lacked the definition

## [1.3.11] - 2026-04-16

### Added
- Remote Scan Mode for nmap: `[R] Toggle Remote Mode` in the nmap options menu hosts the target list via a temporary HTTP server and generates a `curl | sudo nmap -sS` one-liner for the operator to run directly on a pivot host — enabling full SYN scans without proxychains4 constraints (`tools.py`, `ops.py`)
- Interface picker: on first remote mode activation with no `pivot_interface` configured, prompts user to select from detected network interfaces and saves the choice to `~/.cerno/config.yaml` automatically (`tools.py`)
- `get_interface_ip(interface)` and `list_interfaces()` utilities in `ops.py` for detecting IPv4 address from a named network interface using `fcntl`/`socket`
- `start_ips_server(ips_path, port)` in `ops.py`: minimal HTTP server serving only `GET /ips.txt` — no directory listing, 404 for all other paths, request logging suppressed
- `build_nmap_remote_oneliner()` in `ops.py`: constructs the `curl -s http://<ip>:<port>/ips.txt | sudo nmap -sS -A -iL -` one-liner with optional port and NSE flags; no `-Pn` (not needed without proxychains4)
- `pivot_interface` (default: `null`) and `pivot_http_port` (default: `8877`) config fields (`config.py`)
- `CommandResult.is_remote`, `CommandResult.cleanup`, `CommandResult.remote_output_path` fields for display-only remote workflow results that cerno shows but does not execute (`tool_context.py`)
- Post-scan guidance: after the operator dismisses the remote command screen, cerno prints `scp` and `cerno import nmap` commands to retrieve and import results

## [1.3.10] - 2026-04-16

### Fixed
- Claude Assistant now correctly reports Metasploit module names for findings with mapped MSF modules — `metasploit_names` was not included in the `get_by_scan_with_plugin` and `get_by_scan_ids_merged` SELECT queries, so `Plugin` objects always had `metasploit_names=None` and the context block always showed "Metasploit Modules: None" even when `has_metasploit=True` (`models.py`)

## [1.3.9] - 2026-04-15

### Fixed
- `[PROXY]` badge now appears in finding action footer (`render_finding_actions_footer`) when focused on a specific finding — previously only shown in the findings list menu
- `[PROXY]` badge now appears in the Execution Summary panel (`command_review_menu`) as "Proxy: proxychains4 ACTIVE" before confirming tool execution — previously invisible at command preview step

## [1.3.8] - 2026-04-15

### Changed
- Trimmed CLAUDE.md by 29% (279 lines) — removed generic Python principles, verbose packaging examples, release workflow internals, and test pattern boilerplate to improve Claude Code context efficiency

## [1.3.7] - 2026-04-15

### Added
- proxychains4 integration: route all tool executions (nmap, netexec, Metasploit, custom) through a SOCKS5 proxy via proxychains4
  - New config fields: `proxychains_enabled` (default: false), `proxychains_host` (default: 127.0.0.1), `proxychains_port` (default: 9000)
  - Cerno manages its own `~/.cerno/proxychains4.conf` — system config is not touched
  - `--proxy` / `--no-proxy` flags on `cerno review` to override config per session
  - nmap proxy adjustments: `-Pn` added automatically, sudo dropped, limitations note shown
  - `[PROXY]` badge (magenta) in review session status line when proxy is active
  - proxychains4 row in startup tool availability table with active/inactive state

### Documentation
- README: added proxychains4 integration section under Features
- README: Commands section updated with `cerno import nessus <directory>`, `cerno review --proxy/--no-proxy/--check`, `cerno scan compare`, `cerno scan history`, `cerno reset`, and `cerno config get`
- README: Keyboard Shortcuts expanded from 9 to 25 shortcuts, split into findings-list view and finding-detail view contexts
- README: Configuration section updated with proxychains4 config keys and `cerno config get`
- README: Troubleshooting section updated with `cerno reset` as full environment reset option

## [1.3.6] - 2026-04-14

### Fixed
- Fixed "Getting Started" and "Tips" panels showing single-scan statistics when reviewing multiple scans simultaneously (`onboarding.py:show_workflow_guidance()`, `onboarding.py:_show_context_aware_tips()`)
- Fixed `scan.scan_name` variable reference bug at the `show_workflow_guidance()` call site (`cerno.py`) — now correctly uses `selected_scan.scan_name`

## [1.3.5] - 2026-04-13

### Added
- `cerno import nessus` now accepts a directory path; recursively discovers `.nessus` files, lists staged imports with file sizes, and prompts for confirmation before importing each in sequence with progress tracking and a final summary

## [1.3.4] - 2026-04-13

### Added
- `cerno reset` command to purge `~/.cerno` and return to a fresh installation state, with type-to-confirm safety prompt

## [1.3.3] - 2026-04-10

### Added
- Bundled `cerno_pkg/skills/cerno-assistant.md` skill prompt ships with the package — Claude Assistant now works out of the box after `pipx install`

### Changed
- `load_skill_prompt()` in `claude_assistant.py` now reads the bundled skill only, with inline fallback if the file is missing (previously only checked the gitignored repo-root path, so `pipx` installs always fell back to the minimal inline prompt)
- `pyproject.toml` package-data updated to include `skills/*.md` so the skill file is included in the wheel

## [1.3.2] - 2026-04-07

### Added
- Claude Assistant aggregate chat at severity selection menu (`[A]` key): discuss all findings across selected scan(s); context includes severity breakdown, review state, MSF/CVE summary, and up to 50 findings (highest severity first)
- Claude Assistant aggregate chat at findings list (`[A]` key in action footer): discuss the current findings in scope (filtered by severity, name filter, or group filter); context adapts to whatever filter is active
- `browse_claude_chat_aggregate()` in `cerno.py` — shared chat loop for both aggregate entry points
- `build_aggregate_context()` and `run_aggregate_exchange()` in `cerno_pkg/claude_assistant.py`
- `ClaudeAggregateConversationTurn` model in `cerno_pkg/models.py` — conversation persistence keyed by `context_key` string
- `claude_aggregate_conversations` table in SQLite schema (`cerno_pkg/database.py`) with index on `context_key`

### Changed
- Documentation updates: README and CLAUDE.md updated for Claude Assistant feature (all three scopes, keyboard shortcuts, config option, requirements)

## [1.3.1] - 2026-04-07

### Changed
- Tool availability table now includes `claude (assistant)` row showing Claude Code CLI install status and version (`render.py:render_tool_availability_table()`)

## [1.3.0] - 2026-04-01

### Added
- Claude Assistant (BETA): interactive AI chat panel for findings, opened with `[A]` in the review TUI
  - On-demand overlay panel powered by `claude -p` (Claude Code CLI); no API key required
  - Persistent per-finding conversation history stored in SQLite (`claude_conversations` table, FK to `findings` with CASCADE delete)
  - Structured finding context injected automatically into every prompt (plugin name/ID, severity, CVSS, CVEs, MSF modules, affected hosts, review state, multi-scan note)
  - Gated on `claude` CLI availability (same pattern as nmap/netexec/msfconsole checks); `[A]` shown grayed out when claude is installed but assistant is disabled
  - Custom skill file (`.claude/skills/cerno-assistant.md`) used as system prompt for all exchanges
  - Config toggle: `claude_assistant_enabled` (default: `true`); disable with `cerno config set claude_assistant_enabled false`
  - `✦` (magenta) indicator in findings list for findings with existing conversation history; column only shown when history exists (no visual noise on fresh scans)
  - BETA notice shown once per panel open; "resumed · N exchanges · Xh ago" header on re-open
  - `[C]` to clear history, `[Esc/Q]` to return to finding review
- New module `cerno_pkg/claude_assistant.py`: availability check, context builder, prompt formatter, subprocess caller, exchange orchestrator
- `ClaudeConversationTurn` model (`models.py`): dataclass + `get_by_finding()`, `add()`, `clear()`, `finding_has_history()` class methods
- `render_claude_panel()` in `render.py`: chat overlay with dimmed history, input prompt, and controls hint
- `claude_assistant_enabled` config field in `CernoConfig` (default: `True`)

## [1.2.31] - 2026-04-01

### Fixed
- Finding host counts, affected hosts, plugin output, and view formats now aggregate across all selected scans in multi-scan review mode (`cerno_pkg/models.py`, `cerno.py`)
  - Added transient `extra_finding_ids: list[int]` field to `Finding` dataclass; set by `browse_file_list` before opening a finding so all downstream queries cover every selected scan
  - `get_hosts_and_ports()`, `get_all_host_port_lines()`, `get_port_distribution()`, and `get_plugin_outputs_by_host()` now expand `WHERE finding_id = ?` to `WHERE finding_id IN (...)` using `extra_finding_ids` when populated; DISTINCT ensures no duplicate host/port rows
  - `get_counts_for()` in `browse_file_list` now queries `COUNT(DISTINCT host_id)` across all finding_ids from `all_instances` in multi-scan mode, fixing host counts in the findings list table
- Session statistics severity breakdown now aggregates across all selected scans in multi-scan mode using `COUNT(DISTINCT plugin_id)` (`cerno.py:show_session_statistics()`)

## [1.2.30] - 2026-04-01

### Fixed
- Workflow findings sub-level breadcrumb now reflects all selected scans in multi-scan mode (`cerno.py:browse_workflow_groups()`)
  - `browse_workflow_groups()` accepts new `scans` param (full list of selected scans); passes it to `browse_file_list()` so the inner findings view uses multi-scan mode and shows the correct breadcrumb
  - Post-review workflow refresh query now uses `Finding.get_by_scan_ids_merged()` for multi-scan instead of single-scan `get_by_scan_with_plugin()`

## [1.2.29] - 2026-04-01

### Fixed
- Findings list and workflow group breadcrumbs now reflect all selected scans in multi-scan review mode (`cerno.py`)
  - `browse_file_list()` breadcrumb shows "ScanA + ScanB" or "N scans" instead of only the primary scan name
  - `browse_workflow_groups()` accepts new `scan_label` param and uses it in the breadcrumb when provided; call site passes `_scan_label` built from all selected scans

## [1.2.28] - 2026-04-01

### Fixed
- Scan Overview now reflects all selected scans in multi-scan review mode; previously only the primary scan's hosts, ports, and finding counts were shown (`cerno_pkg/session.py:show_scan_summary()`)
  - Host/port queries use `IN (scan_ids)` for multi-scan; empty-findings count deduplicates by `plugin_id`
  - Finding counts use `COUNT(DISTINCT plugin_id)` across all selected scans via `Finding.count_by_scan()` and `count_reviewed_in_scan()`
  - Header displays all scan names (e.g. "Scan Overview — ScanA + ScanB" or comma-separated for 3+)
- Severity selection breadcrumb/header now shows all selected scan names instead of only the primary scan (e.g. "ScanA + ScanB > Choose severity" or "3 scans > Choose severity") (`cerno.py`)

## [1.2.27] - 2026-04-01

### Fixed
- Severity menu now correctly aggregates findings across all selected scans in multi-scan review mode; previously only the primary (first) scan's findings were counted and displayed (`cerno.py`, `cerno_pkg/models.py`, `cerno_pkg/render.py`)
  - `Finding.get_severity_dirs_for_scan()` and `Finding.count_by_scan_severity()` accept new `scan_ids` param; multi-scan uses `IN (...)` clause and `COUNT(DISTINCT plugin_id)` for accurate deduplication
  - MSF and Workflow Mapped virtual groups now use `Finding.get_by_scan_ids_merged()` for multi-scan count queries
  - `render_severity_table()` and `count_severity_findings()` thread `scan_ids` through to model layer

## [1.2.26] - 2026-03-31

### Changed
- Updated CLAUDE.md to document multi-scan review architecture: `session_scans` junction table, `Finding.get_by_scan_ids_merged()` query method, `ReviewContext` field count (15 fields), multi-scan session resume behavior, and multi-scan syntax in Common Commands

## [1.2.25] - 2026-03-31

### Added
- Multi-scan review mode: users can now select multiple scans at the review prompt using single numbers, ranges (e.g. `1-3`), or comma-separated lists (e.g. `1,3,5`); findings from all selected scans are presented in a merged, deduplicated view (`cerno.py`, `cerno_pkg/tui.py`)
- New `parse_scan_selection()` function in `tui.py` for parsing multi-scan index input (mirrors `parse_severity_selection()` pattern)
- New `Finding.get_by_scan_ids_merged()` classmethod in `models.py` for cross-scan plugin deduplication; returns one representative Finding per plugin_id and a dict of all instances across scans
- "Scans" column in finding list table showing `"All N"` or `"M of N"` scan coverage per plugin when reviewing multiple scans (`render.py:render_finding_list_table()`)
- Review state broadcasts across all selected scans: marking a finding as reviewed/completed/skipped updates that finding in ALL selected scans containing the same plugin (`cerno.py:browse_file_list()`)
- New `session_scans` junction table in SQLite schema for tracking which scans belong to a multi-scan session (`database.py`)
- Multi-scan session persistence: `save_session()` and `load_session()` in `session.py` now store and restore additional scan IDs via `session_scans` table
- New `scan_ids: list[int]` field on `ReviewContext` dataclass in `tool_context.py` for multi-scan context propagation

## [1.2.24] - 2026-02-05

### Added
- Service mapping during Nessus import: `svc_name` and `protocol` from ReportItem elements are now captured in a new `host_services` table, enabling per-host, per-port service identification (`database.py`, `nessus_import.py`)
- New `v_http_services` SQL view for querying HTTP/HTTPS services discovered per scan
- Nuclei tool suggestion after import: automatically generates `http_urls.txt` from discovered web services and suggests a `nuclei -list` command alongside EyeWitness/gowitness (`cerno.py`)
- Query helper `get_http_urls_for_scan()` in `models.py`

## [1.2.23] - 2026-01-28

### Changed
- Host display and tool target files now use original scan target (FQDN or IP) instead of resolved IP address, fixing tool failures on external network scans where Nessus target was an FQDN (`models.py: get_hosts_and_ports(), get_all_host_port_lines(), get_plugin_outputs_by_host()`)

## [1.2.22] - 2026-01-28

### Added
- Added module info prompt after Metasploit search completes - users can now paste a module path and run/copy `msfconsole info` command without leaving the TUI (tools.py)

### Fixed
- Fixed character encoding corruption in error messages (mojibake `â€"` replaced with proper em-dash `—`)
- Fixed `LOGURU_AVAILABLE` redefinition warning in logging_setup.py
- Added proper type annotation guard for `os.geteuid()` on Windows (ops.py)
- Fixed keyboard shortcut consistency: `[n]` → `[N]` in Metasploit command prompt (tools.py)
- Fixed all 28 mypy type errors across 11 files for clean static type checking
  - Added proper type annotations and casts for database row access
  - Fixed union type handling in nessus_import.py for CVE/MSF lists
  - Added explicit type annotations for complex data structures
  - Removed unreachable code paths detected by type checker
- Fixed incorrect command suggestion in scan delete error (`'cerno list'` → `'cerno scan list'`)
- Fixed hardcoded `[red]` Rich markup in mark-all warning to respect `no_color` config setting (tui.py)
- Fixed silent CVE extraction failures - now reports failure count and logs details (render.py)

### Changed
- Removed dead code: unused Metasploit web scraping imports (`requests`, `BeautifulSoup`) from tools.py
- Removed duplicate `print_action_menu()` function from tools.py (now imports from render.py)
- Added `types-PyYAML` to dev dependencies for better type checking
- Improved error messages with recovery suggestions for database and config failures
- Added Troubleshooting, Contributing, and Windows compatibility sections to README.md
- Improved finding review action menu with responsive layout that adapts to terminal width (render.py, fs.py)
- Improved tool action menus (nmap configuration, command review) with responsive layout (tools.py, render.py)

## [1.2.21] - 2026-01-22

### Added
- **Cross-scan comparison**: New `cerno scan compare <scan1> <scan2>` command to compare findings between two scans
  - Identifies new, resolved, and persistent vulnerabilities by comparing plugin presence
  - Tracks host changes: new hosts, removed hosts, persistent hosts
  - Summary panel with severity breakdown for each category
  - Optional `--severity` filter to focus on high/critical findings
- **Host vulnerability history**: New `cerno scan history <host_ip>` command to view vulnerability timeline for a specific host
  - Shows timeline of all scans where the host appeared
  - Displays severity breakdown per scan with trend indicators
  - Tracks finding count changes over time
- New SQL views for efficient cross-scan queries:
  - `v_scan_plugin_summary`: Plugin presence per scan with affected host/port counts
  - `v_host_scan_findings`: Per-host statistics broken down by scan
- New `cerno_pkg/cross_scan.py` module with data structures and analysis functions
- Composite index on `findings(scan_id, plugin_id)` for faster comparison queries

### Changed
- **BREAKING**: Hosts table schema redesigned for FQDN-targeted external scans
  - New columns: `ip_address` (resolved IP), `scan_target` (what was scanned), `scan_target_type`, `netbios_name`, `fqdn`, `reverse_dns`
  - Composite unique constraint: `(ip_address, scan_target)` - enables load-balanced scenarios
  - Nessus import now parses `<HostProperties>` tags (host-ip, netbios-name, host-fqdn, host-rdns)
  - **Requires database deletion and re-import of scans** (`rm ~/.cerno/cerno.db`)
- Host queries now use `ip_address` instead of `host_address` throughout codebase

### Fixed
- Fixed host metadata capture for FQDN-targeted scans (previously lost resolved IP)
- `reverse_dns` column now properly populated from Nessus data (was always NULL before)
- Fixed `v_host_scan_findings` view severity counts - was counting junction table rows instead of distinct plugins per severity
- Fixed color bleeding in scan comparison tables by using `Text` objects instead of markup strings

### Documentation
- Updated `docs/DATABASE.md` with new hosts table schema and query examples
- Updated `schema.sql` with new hosts table structure and v_host_findings view
- Updated CLAUDE.md anti-pattern examples to use new column names

## [1.2.20] - 2026-01-19

### Changed
- Improved severity selection table UX with visual separation between severity levels and special filters
  - Added horizontal separator line between severity levels (1-5) and special filters section
  - Metasploit Module and Workflow Mapped rows now use letter indices (`M`, `W`) instead of numbers
  - Special Filters section only appears when data exists (hidden when no Metasploit modules or workflow mappings)
  - Dynamic tip message reflects available options (e.g., "Use numbers (1-5), M, W, or combine")
  - Selection now accepts `M`, `W` letters alongside numbers (e.g., `1-3,M` or `M,W`)

## [1.2.19] - 2026-01-16

### Changed
- Enhanced NetExec per-host breakdown display (`[N]` action) with Rich formatting
  - Replaced plain text output with styled Rich panels, tables, and color-coded elements
  - Each host now displays in its own bordered panel with hostname in title
  - Credentials shown in organized table with Protocol, Identity, Type, and Admin columns
  - Admin access highlighted with green checkmark (✓)
  - Shares displayed in table with color-coded access levels (RW=green, R=cyan, W=yellow)
  - Security flags (signing disabled, SMBv1, Zerologon, PetitPotam) highlighted in red with warning icon
  - Added new `rich_pager()` function for paginating Rich renderables
  - Multiple hosts now fit per page; pagination groups hosts to fill available space without splitting any host's panel across pages

### Fixed
- Fixed action menu not updating dynamically during finding review after running tools
  - NetExec `[N]` action now appears immediately after running NetExec via `[T]`
  - Previously required backing out and re-entering the finding to see new actions

## [1.2.18] - 2026-01-15

### Fixed
- remove row striping from finding list table

## [1.2.17] - 2026-01-15

### Changed
- Reordered file list table columns: Severity now appears before Plugin ID for better visual hierarchy
- Added Severity to sorting rotation: `[S]` now cycles through Severity → Plugin ID → Name → Hosts
- Smart default sorting: mixed severity views (All, MSF, multi-select) default to Severity sort (Critical at top), single severity views default to Plugin ID sort

## [1.2.16] - 2026-01-15

### Added
- Host search action `[H]` in severity menu to filter all findings by affected host
  - Enter an IP address or hostname (partial matching supported)
  - Shows filtered severity counts for the specified host
  - Filter carries through to findings selection menu
  - Use `[C]` to clear the host filter and restore full scan view

## [1.2.15] - 2026-01-15

### Fixed
- correct action menu separator display in finding view
- add NXC config options to config show display

### Added
- docs: add NetExec database integration to README

## [1.2.14] - 2026-01-15

### Added
- **[BETA]** NetExec database integration for enriching finding displays with credential, access, and security configuration data (nxc_db.py)
  - Automatic detection of NetExec workspace at `~/.nxc/workspaces/default/` with configurable override via `nxc_workspace_path` config option
  - Summary panel shows credentials, shares, and security flags (SMB signing, Zerologon, PetitPotam) across affected hosts
  - Per-host breakdown available via `[N]` action in finding view menu
  - Supports SMB, SSH, LDAP, MSSQL, RDP, WinRM, FTP, NFS, VNC, and WMI protocol databases
- New configuration options: `nxc_workspace_path` and `nxc_enrichment_enabled` in config.yaml

## [1.2.13] - 2026-01-14

### Added
- Comprehensive custom workflows documentation in docs/CUSTOM_WORKFLOWS.md covering YAML schema reference, multi-plugin workflows, placeholder system (7 placeholders), configuration integration, merge behavior, best practices, complete examples, and troubleshooting
- README.md updated with link to custom workflows guide for users seeking detailed documentation beyond the quick start example

## [1.2.12] - 2026-01-13

### Changed
- Removing extra guidance references

## [1.2.11] - 2026-01-13

### Fixed
- Resolved empty state "limbo bug" where users were stuck when no findings matched the current filter - now displays empty state message within normal menu flow with all actions available (cerno.py:browse_file_list())

### Changed
- Additional tips screen redesigned with Rich UI - cyan-bordered panel with styled keyboard shortcuts and section headers for consistent visual design (onboarding.py:show_additional_tips())
- Empty state messages updated to clarify that all normal menu actions remain available (render.py:render_empty_state())

## [1.2.10] - 2026-01-13

### Changed
- Removed broken workflow emoji
- Removed excess comparison and overlap analysis tables
- Workflow guidance redesigned with Rich UI components - cyan-bordered panel, styled statistics, responsive keyboard shortcut grid, and yellow-bordered tips panel for improved visual appeal (onboarding.py:show_workflow_guidance())
- Workflow guidance now only displays on first-time scan review - skips if any session exists for the scan (onboarding.py:show_workflow_guidance())

## [1.2.9] - 2026-01-13

### Fixed
- Onboarding verbiage

### Changed
- removed tool execution breadcrumbs

## [1.2.8] - 2026-01-13

### Fixed
- Fixed SQL query bug in onboarding tips causing `OperationalError: no such column: severity_int` (onboarding.py:223-230)
- Corrected query to JOIN findings with plugins table to access severity_int data

## [1.2.7] - 2026-01-12

### Added
- **Scan context header** - Added comprehensive scan metadata display at top of severity menu showing scan name, import time, and review progress statistics (render.py:render_scan_context_header())
- **Pagination progress bar** - Visual progress bar in status line showing current position in paginated results: `[████░░░░░░] Page 1/5` (render.py:render_pagination_indicator())
- **First page hint** - Added helpful message on first page when more results exist: "→ N more findings available (press N for next page)" (cerno.py:497-499)
- **Empty state messages** - Context-aware helpful messages when no findings match filters, with actionable suggestions for resolution (render.py:render_empty_state(), cerno.py:489-503)
- **Comparison context** - Explanatory text before comparison and overlapping analysis results explaining what groups mean and how to use them (render.py:450-464, tui.py:531-537)
- **Progress timing feedback** - Elapsed time display for operations exceeding 0.5s threshold (render.py:show_progress())
- **Guided tour mode** - Interactive 4-step walkthrough for first-time users covering importing scans, reviewing findings, running tools, and tracking progress (onboarding.py:show_guided_tour())
- **Workflow guidance** - Context-aware best practices and keyboard shortcuts shown after scan selection with smart tips based on scan state (onboarding.py:show_workflow_guidance())
- **Tool execution breadcrumbs** - Visual progress indicators during tool workflow showing current stage: Select → Configure → Review → Execute → Results (render.py:render_tool_progress_breadcrumb(), tools.py:1048,979,1160,1224,1278)

### Changed
- **Adaptive severity labels** - Severity labels now adapt to terminal width: full labels (≥120 chars), abbreviations (80-119 chars), or single-char indicators (<80 chars) for improved scannability (render.py:273-299)
- **Table row striping** - Enabled alternating row dimming in finding list tables to improve readability of dense data (render.py:216)
- **Unified MSF/workflow indicators** - Finding preview panel now shows both Metasploit and Workflow availability in subtitle with full names, module counts for multiple MSF modules, and 40-char truncation for long names (render.py:1241-1267)
- **First-time user experience** - Users with no imported scans now see guided tour before being prompted to import (cerno.py:894)
- **Scan review flow** - Workflow guidance automatically appears after scan selection with context-aware tips based on scan state (cerno.py:1011)

## [1.2.6] - 2026-01-12

### Added
- Tool availability check at `cerno review` startup showing installation status and versions for all tools (ops.py:get_tool_version(), render.py:render_tool_availability_table(), cerno.py:main())
- `--check` flag for `cerno review` to display tool availability without entering review mode
- Automatic adaptation when new tools are added to TOOL_REGISTRY - no manual updates needed

### Fixed
- Corrected metasploit tool configuration to require `msfconsole` binary (tool_definitions.py:94) - was incorrectly marked as having no system requirements despite executing msfconsole commands

## [1.2.5] - 2026-01-11

### Documentation
- Added `cerno workflow list` command to README.md Commands section
- Added new "Keyboard Shortcuts" section to README.md documenting all interactive review keybindings ([S], [O], [W], [F], [V], [C], [U], [?])
- Updated docs/DATABASE.md "Last Updated" reference from v1.0.0 to v1.2.4

## [1.2.4] - 2026-01-11

### Fixed
- Fixed session persistence bug where early exits (pressing 'q' or Ctrl+C) bypassed session saving - added try/finally block to guarantee session save on all exit paths (cerno.py:814-1191)
- Fixed "Last Reviewed" timestamp always showing "never" after reviewing scans
- Fixed multiple scan sessions not being saved when using 'back' to return to scan menu - added session save at top of scan selection loop

## [1.2.3] - 2026-01-11

### Fixed
- Incomplete fix attempt for session persistence (code was unreachable - superseded by v1.2.4)

## [1.2.2] - 2026-01-11

### Fixed
- Fixed workflow count display to show distinct workflows instead of total plugin ID entries (workflow_mapper.py:count())

### Changed
- Improved keybinding mnemonics: Sort now uses [S] instead of [O], Overlapping uses [O] instead of [I] (render.py, tui.py)

## [1.2.1] - 2026-01-11

### Fixed
- Fixed jarring yellow-on-red filter indicators - changed to readable bold cyan/yellow text (cerno.py)

## [1.2.0] - 2026-01-10

### Added
- Added startup help hint on first review showing "Press [?] for help" banner (cerno.py:browse_file_list())
- Added active filter visual indicators with bold yellow-on-red badges in status line (cerno.py)
- Added severity column to all finding list tables (render.py:render_finding_list_table())
- Added workflow availability badges to finding preview panels (render.py:display_finding_preview())
- Added next sort mode indicator in status line showing upcoming sort order (cerno.py)
- Added CVE distribution preview before format selection showing count per finding (render.py:display_bulk_cve_results())
- Added pre-flight execution summary showing targets, scripts, and output directory (tools.py:command_review_menu())
- Added post-execution summary panel with duration, exit code, files generated, and next steps (tools.py:run_tool_orchestration())
- Added consolidated nmap configuration screen combining NSE profile, custom scripts, and UDP options (tools.py:configure_nmap_options())
- Added port distribution to finding preview showing host count per port (models.py:get_port_distribution(), render.py:display_finding_preview())
- Added session time indicator to status line with elapsed time and review counts (cerno.py:browse_file_list())
- Added Metasploit module names to preview panel subtitles (render.py:display_finding_preview())
- Added `cerno workflow list` CLI command to display all available workflows with descriptions (cerno.py:workflow_list())

### Changed
- Changed bulk mark confirmation from typing "mark" to standard Y/N confirmation (tui.py)
- Improved "Superset" terminology to "Overlapping Findings" throughout UI (render.py, analysis.py, tui.py)
- Enhanced group filter descriptions to include context (e.g., "Group #1: Identical host:port combinations")
- Streamlined nmap workflow to use single configuration screen instead of 3 sequential prompts
- Enhanced filter prompts with inline examples (e.g., 'apache', 'ssl', 'windows') for better discoverability (tui.py)
- Improved large group pagination indicator with bold yellow message "Showing 8 of X findings - Press [D] to view all" (render.py)
- Changed severity table unreviewed count color from green/yellow/red to neutral cyan for progress tracking (render.py:unreviewed_cell())
- Enhanced workflow display with prominent "Press Enter to continue" hint in bold yellow (fs.py:display_workflow())
- Added terminal width warning on first review for terminals <80 chars (cerno.py:browse_file_list())
- Added confirmation feedback when clearing filters with [C] key (tui.py)

### Fixed
- Fixed ExecutionMetadata type error in post-execution summary (use attribute access instead of dict access)

## [1.1.2] - 2026-01-10

### Fixed
- Resolved all 224 Pylance/Pyright type checking warnings (reduced from 224 to 0)
  - Fixed 20 unused variable warnings by renaming to `_` prefix convention
  - Fixed 5 private usage warnings by making tool workflow builders semi-public
  - Fixed 140 unused import warnings in `cerno_pkg/__init__.py` by adding explicit `__all__` list
  - Removed 56 unused imports from `cerno.py` after refactoring
  - Added type ignore comments for intentional test-only private API usage

### Changed
- Made tool workflow builder functions semi-public in `cerno_pkg/tools.py`
  - Renamed `_build_nmap_workflow` → `build_nmap_workflow`
  - Renamed `_build_netexec_workflow` → `build_netexec_workflow`
  - Renamed `_build_custom_workflow` → `build_custom_workflow`
  - These functions are part of the tool registry pattern and accessed via tool_definitions.py

### Documentation
- Added explicit `__all__` list to `cerno_pkg/__init__.py` documenting public API (140 exports)
- Improved code quality with proper unused variable naming (`_var` convention)
- Updated Version Increment SOP in CLAUDE.md to check `pyproject.toml` instead of git tags
  - Git tags are only created on release (main branch merge), not on every version bump
  - Always check `pyproject.toml` for current version

## [1.1.1] - 2026-01-09

### Changed
- Enhanced Version Increment SOP in CLAUDE.md with mandatory incremental changelog updates and user confirmation workflow
  - Added "Incremental Changelog Updates" section requiring [Unreleased] updates after all code changes
  - Updated "Version Increment SOP" with 4-phase process: gather changes, present for approval, update atomically, validate
  - Modified "Documentation" principle to mandate [Unreleased] section updates for user-visible changes
  - Version increments now require reviewing git history, [Unreleased] section, and user confirmation before proceeding

### Documentation
- Integrated pyright for type checking in development workflow (CLAUDE.md)
  - Added pyright to dev dependencies in pyproject.toml
  - Documented dual type checking philosophy (mypy + pyright)
  - Added pyrightconfig.json configuration reference
- Added comprehensive version increment SOP to CLAUDE.md
  - Documents 4-phase process for version bumps with user confirmation
  - Includes changelog gathering from multiple sources
  - Ensures atomic updates to pyproject.toml and CHANGELOG.md

## [1.1.0] - 2026-01-10

### Added
- **Terminal responsiveness** with adaptive layouts for different screen widths
  - Terminal width detection utility (`ansi.py:get_terminal_width()`) with graceful fallback to 80 chars
  - Responsive action footer: 2-column grid for wide terminals (≥100 chars), single-column for narrow (<100 chars)
  - Responsive status line: adapts layout based on width (single-line ≥120, two-line 80-119, multi-line <80)
- **Smart CVE format selection** with preview and auto-defaults
  - Shows "Found N unique CVE(s) across M finding(s)" preview before format selection
  - Auto-selects combined format for 1-2 findings, separated format for 3+ findings
  - Manual override still available
- **Group filter descriptions** for better context
  - Enhanced tuple from `(index, plugin_ids)` to `(index, plugin_ids, description)`
  - Status line now shows "Group #1: Identical host:port combinations (N)" instead of cryptic "Group #1 (N)"
- **Page size configuration support** via `config.yaml`
  - Users can set `default_page_size: 20` to override auto-detection
  - Falls back to 12 if terminal height detection fails (logs debug hint)
- **Comparison groups pager** for large result sets
  - Groups with >8 findings show "... (+N more - press [D] to view details)"
  - [D] option displays full list in pager without truncation

### Changed
- **Streamlined file detail view workflow** (reduced from 4 steps to 1-2 steps)
  - View action now defaults to grouped format immediately (no format prompt)
  - Post-view menu offers Copy/Change format/Back options
  - Menu shows "[V] View host(s) (grouped)" to indicate default format
- **Improved visual hierarchy** for Metasploit indicators
  - Moved ⚡ indicator from first content line to panel subtitle
  - Cleaner separation between metadata and plugin data
- **Clarified completed findings section** to reduce confusion
  - Renamed from "Reviewed findings (read-only)" to "Completed Findings (Undo Available)"
  - Updated action from "Undo review-complete" to "Undo completion"
  - Enhanced help text explaining management view purpose

### Documentation
- Added "Terminal Responsiveness" section to CLAUDE.md documenting all UI improvements
- Documented group filter tuple enhancement and backward compatibility approach
- Added page size configuration examples

## [1.0.2] - 2026-01-09

### Added
- Automated GitHub release workflow triggered by version changes in `pyproject.toml`
- Changelog extraction script (`scripts/extract_changelog.py`) for generating release notes
- GitHub Actions workflow (`.github/workflows/release.yml`) that:
  - Detects version changes on push to main (PR merges or direct commits)
  - Validates semantic versioning format
  - Creates annotated git tags automatically
  - Generates GitHub Releases marked as "latest"
  - Extracts release notes from CHANGELOG.md
  - Builds and attaches distribution artifacts (wheel and sdist)

### Changed
- Updated README.md with new "Releases" section explaining automated release process
- Expanded CLAUDE.md "Version Management" section with detailed workflow documentation

## [1.0.1] - 2026-01-09

### Documentation
- Added "About the Name" section to README explaining Cerno etymology and pronunciation
- Includes Latin origin (*cernō* - to discern, distinguish, perceive)
- Provides pronunciation guide (KEHR-noh / IPA: [ˈkɛr.noː]) with audio sample link
- Explains connection between name meaning and tool purpose

## [1.0.0] - 2026-01-09

### Initial Release
- First public release of Cerno (from Latin "cernō" - to discern, perceive, understand)
- Modern CLI for Nessus findings review and security tool orchestration
- SQLite-backed persistence with normalized database schema
- Rich TUI for interactive review with keyboard navigation
- Integration with nmap, NetExec, and Metasploit
- Workflow orchestration and session tracking
- Cross-scan host analysis capabilities
- Configuration management via `~/.cerno/config.yaml`
- Comprehensive test suite with 85%+ coverage
