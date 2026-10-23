# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `proxychains4` was removed from the default `mcp_exec_allowlist`. Wrappers are now unwrapped and the target is checked; `use_proxy=true` still routes through proxychains.
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
  - Marked the Unix-only `get_interface_ip` dotted-quad and proxychains shell-wrap tests `skipif(win32)` (`tests/test_ops.py`).

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
- Nmap proxy mode now suppresses UDP scanning and uses TCP targets so generated proxychains commands match the UI warning that UDP is unsupported through SOCKS.
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
- Remote Scan Mode for nmap: `[R] Toggle Remote Mode` in the nmap options menu hosts the target list via a temporary HTTP server and generates a `curl | sudo nmap -sS` one-liner for the operator to run directly on a pivot host — enabling full SYN scans without proxychains constraints (`tools.py`, `ops.py`)
- Interface picker: on first remote mode activation with no `pivot_interface` configured, prompts user to select from detected network interfaces and saves the choice to `~/.cerno/config.yaml` automatically (`tools.py`)
- `get_interface_ip(interface)` and `list_interfaces()` utilities in `ops.py` for detecting IPv4 address from a named network interface using `fcntl`/`socket`
- `start_ips_server(ips_path, port)` in `ops.py`: minimal HTTP server serving only `GET /ips.txt` — no directory listing, 404 for all other paths, request logging suppressed
- `build_nmap_remote_oneliner()` in `ops.py`: constructs the `curl -s http://<ip>:<port>/ips.txt | sudo nmap -sS -A -iL -` one-liner with optional port and NSE flags; no `-Pn` (not needed without proxychains)
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
