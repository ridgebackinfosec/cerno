# MCP Server (BETA)

`cerno mcp` exposes your Cerno scan database and tooling over the
[Model Context Protocol](https://modelcontextprotocol.io), so any MCP client
(Claude CLI, Claude Desktop, etc.) can query findings, build target lists,
generate tool commands, and — when explicitly enabled — execute tools and
update review state.

It speaks over **stdio** (stdin/stdout), so it is **launched by the client**,
not run directly in a terminal. The database is local and operator-specific, so
stdio keeps the server off the network entirely.

By default the server is **read-only**: execution and mutation tools are not
registered until you opt in (see [Gating](#gating)).

---

## Adding to Claude CLI

Use `claude mcp add <name> -- <command> [args]`. The command must point at the
`cerno` that has the `mcp` subcommand (v1.4.0+).

### pipx install (recommended)

`cerno` is on your PATH, so:

```bash
claude mcp add cerno -- cerno mcp
```

### Development / editable install

`claude` resolves whatever `cerno` is first on PATH — which may be a different
(e.g. stale pipx) install without the `mcp` command. Point at your dev venv's
`cerno` binary explicitly:

```bash
# Use the absolute path to your checkout's venv binary
claude mcp add cerno -- /abs/path/to/cerno/.venv/bin/cerno mcp
```

Alternative (runs the script directly — must use the dev venv's Python so
dependencies import):

```bash
claude mcp add cerno -- /abs/path/to/cerno/.venv/bin/python /abs/path/to/cerno/cerno.py mcp
```

> Replace `/abs/path/to/cerno` with your actual checkout path. The console
> script (`cerno = "cerno:app"`) is installed into the active venv's `bin/`, so
> the venv path is the reliable way to target a dev build.

### Scope

`claude mcp add` defaults to **local** scope (just you, this project). Add
`-s project` to share via a checked-in `.mcp.json`, or `-s user` to make it
available in all your projects:

```bash
claude mcp add -s user cerno -- cerno mcp
```

---

## Verify & manage

```bash
claude mcp list            # show configured servers and connection status
claude mcp remove cerno    # remove the server
```

Inside a `claude` session, `/mcp` shows server status and lists the tools,
resources, and prompts Cerno exposes.

> **Applying gating changes:** the gating flags are read **once at server
> startup**. After `cerno config set mcp_allow_execution/mcp_allow_mutations …`,
> reconnect — `claude mcp remove cerno` then re-add, or restart the client — for
> the change to take effect. The active gating state is logged to
> `~/.cerno/cerno.log` on startup.

---

## Capabilities

### Tools

| Category | Tools | Gated by |
| --- | --- | --- |
| Read | `list_scans`, `list_findings`, `search_findings`, `get_finding_detail`, `get_finding_hosts`, `list_hosts`, `top_hosts`, `list_services`, `get_web_targets`, `list_cves`, `find_affected_by_cve`, `host_history`, `compare_scans`, `get_workflow`, `check_tools`, `list_executions`, `list_artifacts`, `get_finding_artifacts`, `read_artifact`, `get_config`, `get_capabilities` | always available |
| NetExec | `get_host_nxc`, `list_nxc_credentials` (credentials, shares, security flags; needs a configured NetExec workspace) | always available |
| Generate | `generate_nmap_cmd`, `generate_netexec_cmd`, `generate_msf_search` (return commands, do not run them) | always available |
| Contribute | `get_workflow_candidate` (draft a sanitized workflow from the commands run against a finding), `export_workflow_contribution` (write it as a local, PR-ready YAML file; never submits). See [Workflow contributions](#workflow-contributions) | always available |
| Execute | `execute_command` (runs a command, captures output, logs it; reports progress). Target binary must match `mcp_exec_allowlist` and no binary in the chain may match `mcp_exec_denylist` (common wrappers such as `sudo`/`env`/`timeout` are unwrapped); `timeout` clamped to [1, 3600]s; optional `finding_id` attributes the run (then surfaced by `get_finding_artifacts`, verdict evidence and [workflow contributions](#workflow-contributions); always pass it when verifying a finding). For an nmap command (`-oA` present) it registers the output files as artifacts and records `host_count`/`ports` even when no hosts are up, and refuses to overwrite an existing run's `-oA` output (use a fresh `generate_nmap_cmd` path) | `mcp_allow_execution` |
| Mutate | `set_review_state` (`unreviewed` → `in_progress` → `done` → `unreviewed`; other changes rejected), `import_nessus` | `mcp_allow_mutations` |

Notes:

- `list_findings` takes `merged` (dedup multi-scan results by plugin, matching
  the TUI), `limit`, and `offset` for paging.
- `generate_nmap_cmd` takes `nse_option` as NSE script names or categories,
  comma-separated (e.g. `smb-security-mode,smb2-security-mode` or `vuln`); a
  `--script=` prefix is optional and is added for you. Other nmap flags are rejected.
- `search_findings` searches **all** scans at once (no `scan_ids`); each result
  carries its `scan_name`.
- `get_finding_detail` caps per-host output at `max_hosts` (default 100) and
  reports `affected_total` / `affected_truncated`.
- `get_capabilities` reports which gated capabilities are live, so a client can
  self-orient without a failed call.

#### Config defaults

The server applies your `~/.cerno/config.yaml` the same way the TUI does. An
explicit tool argument always wins, then the config value, then the built-in
default:

| Config key | MCP effect |
|---|---|
| `custom_workflows_path` | Merged over the bundled workflows (custom wins on conflict) for `get_workflow`, `prepare_workflow`, `list_workflow_gaps`, `query_findings(has_workflow=…)`, `plan_batch`/`execute_batch`, the `cerno://finding/{id}/workflow` resource, and the finding prompts |
| `default_netexec_protocol` | Protocol for `generate_netexec_cmd` when `protocol` is omitted (else `smb`), and for the bare `"netexec"` batch strategy |
| `nmap_default_profile` | NSE scripts for `generate_nmap_cmd` when `nse_option` is omitted (`nse_option=""` = no scripts); a UDP profile (SNMP/IPMI) also turns on `-sU` unless `udp` is given |
| `default_page_size` | Default `limit` for `list_findings`, `query_findings`, `search_findings` (minimum 8; else 500). Page past it with `offset` |
| `results_root` | Where `_mcp/<finding_id>/run-*/` target files and run outputs are written |
| `custom_workflows_path` (contributions) | Also decides "new" vs "enhanced" vs nothing-to-contribute for `get_workflow_candidate` and the `workflow_candidate` verdict hint |
| `contribution_export_dir` | Where `export_workflow_contribution` writes files (default `<results_root>/contributions`) |
| `proxychains_enabled` / `proxychains_host` / `proxychains_port` | `execute_command(use_proxy=true)` wraps the run in `proxychains4 -q -f ~/.cerno/proxychains4.conf` (SOCKS5 host:port) when `proxychains_enabled` is on; otherwise `use_proxy` is ignored. `check_tools` reports the installed proxychains-ng version |

These keys are TUI-only and intentionally ignored by the server:
`no_color`, `term_override`, `default_tool`, `claude_assistant_enabled`,
`pivot_interface`, `pivot_http_port`, `top_ports_count`
(`config.MCP_NOT_APPLICABLE_KEYS`).
Config is read when the server starts, so reconnect after changing it. Edits to
the custom workflow YAML file itself are picked up on the next call.

### Resources

Operator-pinnable context (read-only), attachable in clients that render MCP
resources:

- `cerno://scans` — scan index (JSON)
- `cerno://scan/{id}/hosts` — discovered `host:port` lines
- `cerno://scan/{id}/cves` — unique CVEs mapped to plugins (JSON)
- `cerno://finding/{id}/output` — raw per-host plugin output
- `cerno://finding/{id}/workflow` — verification workflow for the finding's plugin
- `cerno://config` — all current (read-only) config settings
- `cerno://host/{ip}/nxc` — NetExec enrichment for a host

### Prompts

One-click templates in clients that render MCP prompts:

- `triage_finding` — draft a pentest-report brief for a finding
- `exploit_plan` — outline the fastest viable exploitation/verification path

Both finding prompts tell the client to pass `finding_id` on every execution and
to offer `get_workflow_candidate` when a verdict reports a candidate.
- `triage_scope` — report brief across one or more scans (comma-separated
  `scan_ids`, e.g. `1,3`; merged and deduplicated by plugin), optionally one severity

---

## Gating

Both flags default to `false`, so the server is read-only out of the box.
Enable the capabilities you want:

```bash
cerno config set mcp_allow_execution true        # permit execute_command
cerno config set mcp_allow_mutations true        # permit set_review_state / import_nessus
cerno config set mcp_exec_allowlist "nmap,nxc"   # restrict which binaries execute_command may run ("*" = any)
cerno config set mcp_exec_denylist "rm,dd,sh"    # binaries execute_command may never run (always wins)
```

- When a flag is off, the corresponding tools are **not registered** and never
  appear in the client.
- Enabling `mcp_allow_mutations` unlocks both `set_review_state` and
  `import_nessus` (importing writes scans/findings to the database, so it is
  treated as a mutation).
- `execute_command` policy, applied on every call even when execution is enabled:
  1. Leading wrapper binaries (and their options) are unwrapped, so
     `["sudo", "-n", "proxychains4", "-q", "nmap", …]` yields the chain
     `sudo → proxychains4 → nmap` and a hidden target like `["env", "rm", …]`
     exposes `rm`. Recognised wrappers: `sudo`, `doas`, `proxychains4`,
     `proxychains` (legacy name, unwrapped only as a guardrail; Cerno itself
     runs `proxychains4`), `env`, `nice`, `nohup`, `timeout`, `stdbuf`, `setsid`,
     `ionice`, `time`. A wrapper left with nothing to run — including one whose
     command is packed into an option value, e.g. `env -S "rm -rf /"` — is
     rejected (fail closed). `taskset` / `chrt` are intentionally not unwrapped
     (their positional MASK/PRIORITY grammar is ambiguous), so treat them like
     any other target binary.
  2. If **any** binary in the chain matches `mcp_exec_denylist`, the call is
     rejected. The denylist always wins over the allowlist, and adding `sudo` to it
     blocks privilege escalation. Default: `rm, rmdir, dd, shred, wipefs, mkfs*,
     fdisk, sfdisk, parted, shutdown, reboot, halt, poweroff`.
  3. The target (last binary) must match `mcp_exec_allowlist` (default `nmap, nxc,
     netexec, msfconsole`). Wrappers need no entry. `"*"` permits anything not
     denied, and **an empty list denies everything**.
- Entries in both lists are glob patterns (`fnmatch`, case-sensitive) matched
  against the binary's **basename**, so `/usr/bin/rm` and `rm` are treated alike.
- The denylist guards against mistakes; it is **not a security boundary**. With
  `"*"`, `sh -c "rm …"`, `python3 -c …`, or `find -delete` still run unless those
  binaries are denied too. Prefer an explicit allowlist when it matters.
- `sudo` runs non-interactively. If sudo would prompt for a password, the call is
  refused (pre-authenticate with `sudo -v`).
- `get_capabilities` reports both lists as configured.

---

## Workflow contributions

When you verify a finding with a method the bundled `workflow_mappings.yaml`
doesn't cover, Cerno can turn the commands you actually ran into a workflow
you can contribute upstream.

1. **Run with attribution.** Pass `finding_id` to `execute_command` /
   `start_execution`. TUI tool runs are attributed automatically.
2. **Record a verdict.** `set_finding_verdict` and `get_finding_verdict` return
   `workflow_candidate: {available, reason}`. It is available only when the
   verdict is `confirmed` or `false_positive` and either the plugin has no
   workflow (`reason: "new"`) or you ran a command the mapped workflow lacks
   (`reason: "enhanced"`). Cerno's own baseline commands (nmap without NSE
   scripts, bare nxc with auth/`--shares`) never count as divergence, and running
   the mapped workflow unchanged yields nothing.
3. **Review the draft.** `get_workflow_candidate(finding_id)` returns the entry
   with hosts → `<TARGET>`, finding ports → `<PORT>`, nxc `-u`/`-d`/`-p`/`-H` →
   `<USERNAME>`/`<DOMAIN>`/`<PASSWORD>`, `-iL`/target files → `<TARGET>`, output
   paths (`-oA`, `--log`) dropped and proxychains/timeout wrappers stripped. It
   also lists `review_hints`, `possibly_superseded` (enhanced only: existing
   commands for the same tool that you didn't run; never auto-replaced),
   `excluded` runs and `leak_warnings`. Only successful runs (exit code 0) count.
4. **Export.** `export_workflow_contribution(finding_id, workflow=None)` writes
   `<contribution_export_dir>/<plugin_id>-<timestamp>.yaml`. Pass an edited
   `workflow` (`workflow_name`, `description`, `steps[{title, commands, notes}]`,
   `references`) to polish titles and notes. Its commands are sanitized again, and
   the plugin_id always comes from the finding. The file never overwrites an
   existing one, loads as-is via `--custom-workflows`, and its header carries the
   steps for opening a PR against `develop`.

**Safety:** export requires a `confirmed`/`false_positive` verdict and runs a
**fail-closed leak scan** over every field and the serialized file. Every field is
checked for:

- IPv4/IPv6 literals;
- every host name/IP in the finding's scan(s), scan names and NetExec domains;
- NetExec credential secret values and NT/`LM:NT` hash literals;
- local paths (`~`, `/home/`, `/tmp/`, `.cerno`, `C:\` …).

NetExec usernames are flagged in commands, step titles, notes and references, but
not in `workflow_name`/`description`. Those come from plugin metadata, and a plugin
like "FTP Anonymous Login" shouldn't collide with an `anonymous` credential.
Dictionary usernames (`anonymous`, `root`, `admin`, `guest` …) never count as
engagement data. Contributed commands also get a strict check for any absolute
path. Secret values are resolved from the NetExec workspace in memory, only to
compare against. They are never logged or returned, and a hit reads
"credential secret value (redacted)". Any hit refuses the export and writes
nothing. Review notes and verdict notes are never included.
Nothing is ever sent anywhere; you submit the PR yourself. Known limitation:
MCP-logged commands are space-joined, so an argument that contained spaces
can't be restored exactly. Check quoted NSE expressions before you submit.

---

## Caveats

- **Resources and prompts only appear in clients that render them** (e.g. Claude
  Desktop). Tool-only clients ignore them; the read tools provide the same data.
- The server writes nothing to **stdout** (that is the JSON-RPC channel). All
  diagnostics go to `~/.cerno/cerno.log`.
- NetExec tools require a configured, existing workspace
  (`nxc_workspace_path`) with `nxc_enrichment_enabled` on; otherwise they return
  `{"available": false}`.
