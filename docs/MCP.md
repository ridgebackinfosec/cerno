# MCP Server (BETA)

`cerno mcp` exposes your Cerno scan database and tooling over the
[Model Context Protocol](https://modelcontextprotocol.io), so any MCP client
(Claude CLI, Claude Desktop, etc.) can query findings, build target lists,
generate tool commands, and — when explicitly enabled — execute tools and
update review state.

It speaks over **stdio** (stdin/stdout), so it is **launched by the client**,
not run directly in a terminal. The database is local and operator-specific, so
stdio keeps the server off the network entirely.

By default the server is **read-only**: execution, mutation, batch and
credential-reveal tools are not registered until you opt in (see
[Gating](#gating)).

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
> startup**. After `cerno config set mcp_allow_<flag> …`,
> reconnect — `claude mcp remove cerno` then re-add, or restart the client — for
> the change to take effect. The active gating state is logged to
> `~/.cerno/cerno.log` on startup.

---

## Capabilities

### Tools

| Category | Tools | Gated by |
| --- | --- | --- |
| Read | `list_scans`, `list_findings`, `search_findings`, `query_findings`, `get_finding_detail`, `get_finding_hosts`, `list_hosts`, `top_hosts`, `list_services`, `get_web_targets`, `list_cves`, `find_affected_by_cve`, `host_history`, `compare_scans`, `get_workflow`, `list_workflow_gaps`, `check_tools`, `list_executions`, `list_artifacts`, `get_finding_artifacts`, `read_artifact`, `get_finding_verdict`, `get_notes`, `get_config`, `get_capabilities` | always available |
| NetExec | `get_host_nxc`, `list_nxc_credentials` (credentials as refs, never secrets; shares; security flags; needs a configured NetExec workspace) | always available |
| Generate | `generate_nmap_cmd`, `generate_netexec_cmd`, `generate_msf_search`, `prepare_workflow`, `plan_batch` (return commands or a dry-run plan; never run anything) | always available |
| Contribute | `get_workflow_candidate` (draft a sanitized workflow from the commands run against a finding), `export_workflow_contribution` (write it as a local, PR-ready YAML file; never submits). See [Workflow contributions](#workflow-contributions) | always available |
| Execute | `execute_command` (runs a command, captures output, logs it; reports progress). Target binary must match `mcp_exec_allowlist` and no binary in the chain may match `mcp_exec_denylist` (common wrappers such as `sudo`/`env`/`timeout` are unwrapped); `timeout` clamped to [1, 3600]s; optional `finding_id` attributes the run (then surfaced by `get_finding_artifacts`, verdict evidence and [workflow contributions](#workflow-contributions); always pass it when verifying a finding). For an nmap command (`-oA` present) it registers the output files as artifacts and records `host_count`/`ports` even when no hosts are up, and refuses to overwrite an existing run's `-oA` output (use a fresh `generate_nmap_cmd` path). `start_execution`, `get_execution_status`, `cancel_execution`, `list_jobs`: the same run as a background job. See [Jobs and batch](#jobs-and-batch) | `mcp_allow_execution` |
| Batch | `execute_batch` (runs every runnable command from a `plan_batch` query) | `mcp_allow_execution` **and** `mcp_allow_batch` |
| Mutate | `set_review_state` (`unreviewed` → `in_progress` → `done` → `unreviewed`; other changes rejected), `add_note` (append-only), `set_finding_verdict`, `ingest_results`, `import_nessus` | `mcp_allow_mutations` |
| Reveal | `reveal_credential` (returns a credential's **cleartext** secret; audited) | `mcp_allow_cred_reveal` |

Notes:

- `list_findings` takes `merged` (dedup multi-scan results by plugin, matching
  the TUI), `limit`, and `offset` for paging.
- `query_findings` AND-combines optional predicates: `scan_ids` (omit for all
  scans), `severity_int`/`severity_min`, `review_state`, `verdict`
  (`confirmed`/`false_positive`/`unable`/`none`), `cve` (exact id), `port`,
  `service`, `host`, `plugin_name`, `has_metasploit`, `has_workflow`, plus
  `merged`/`limit`/`offset`. `plan_batch`/`execute_batch` take the same predicates.
- `list_workflow_gaps(scan_ids, severity_min)` lists findings with **no** mapped
  workflow, worst first (the complement of `query_findings(has_workflow=True)`).
- `generate_nmap_cmd` takes `nse_option` as NSE script names or categories,
  comma-separated (e.g. `smb-security-mode,smb2-security-mode` or `vuln`); a
  `--script=` prefix is optional and is added for you. Other nmap flags are rejected.
- `generate_netexec_cmd` and `prepare_workflow` take `use_credential=<ref>` (a
  ref from `list_nxc_credentials`); see [Credentials](#credentials).
- `prepare_workflow(finding_id)` fills the finding's mapped workflow
  (`<TARGET>`/`<PORT>`/`<USERNAME>`/`<PASSWORD>`/`<INTERFACE>`/`<DOMAIN>`) and marks
  each command executable or manual (with a reason).
- `search_findings` searches **all** scans at once (no `scan_ids`); each result
  carries its `scan_name`.
- `get_finding_detail` caps per-host output at `max_hosts` (default 100) and
  reports `affected_total` / `affected_truncated`.
- `get_capabilities` reports which gated capabilities are live (execution,
  mutations, batch, credential injection/reveal, the exec allow/deny lists and
  NetExec availability), so a client can self-orient without a failed call.

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
| `mcp_batch_concurrency` / `mcp_batch_timeout` | Defaults for `execute_batch`'s `concurrency` (default 1) and `per_command_timeout` (default 300s, clamped to [1, 3600]) |
| `nxc_workspace_path` / `nxc_enrichment_enabled` | NetExec workspace for `get_host_nxc`, `list_nxc_credentials`, credential refs, `@cred:` injection, `reveal_credential` and nxc ingest. With enrichment off, all of these report NetExec as unavailable |
| `log_path` / `debug_logging` | Where (and how verbosely) the server logs; stdout is reserved for JSON-RPC |
| `proxychains_enabled` / `proxychains_host` / `proxychains_port` | `execute_command(use_proxy=true)` wraps the run in `proxychains4 -q -f ~/.cerno/proxychains4.conf` (SOCKS5 host:port) when `proxychains_enabled` is on; otherwise `use_proxy` is ignored. `check_tools` reports the installed proxychains-ng version |

These keys are TUI-only and intentionally ignored by the server:
`no_color`, `color_scheme`, `term_override`, `default_tool`, `claude_assistant_enabled`,
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
- `cerno://finding/{id}/verdict` — current verification verdict, history and evidence (JSON)
- `cerno://finding/{id}/results` — live-verified open ports and NSE verdicts ingested from runs (JSON)
- `cerno://config` — all current (read-only) config settings
- `cerno://host/{ip}/nxc` — NetExec enrichment for a host

### Prompts

One-click templates in clients that render MCP prompts:

- `triage_finding` — draft a pentest-report brief for a finding
- `exploit_plan` — outline the fastest viable exploitation/verification path
- `triage_scope` — report brief across one or more scans (comma-separated
  `scan_ids`, e.g. `1,3`; merged and deduplicated by plugin), optionally one severity

Both finding prompts tell the client to pass `finding_id` on every execution and
to offer `get_workflow_candidate` when a verdict reports a candidate.

---

## Gating

Every gating flag defaults to `false`, so the server is read-only out of the
box. Enable only the capabilities you want:

```bash
cerno config set mcp_allow_execution true        # execute_command + background jobs
cerno config set mcp_allow_mutations true        # set_review_state, add_note, set_finding_verdict, ingest_results, import_nessus
cerno config set mcp_allow_batch true            # execute_batch (also needs mcp_allow_execution)
cerno config set mcp_allow_cred_injection true   # resolve @cred:<ref>@ placeholders at run time
cerno config set mcp_allow_cred_reveal true      # reveal_credential (returns cleartext)
cerno config set mcp_exec_allowlist "nmap,nxc"   # restrict which binaries execute_command may run ("*" = any)
cerno config set mcp_exec_denylist "rm,dd,sh"    # binaries execute_command may never run (always wins)
```

| Flag | Unlocks |
| --- | --- |
| `mcp_allow_execution` | `execute_command`, `start_execution`, `get_execution_status`, `cancel_execution`, `list_jobs` |
| `mcp_allow_mutations` | `set_review_state`, `add_note`, `set_finding_verdict`, `ingest_results`, `import_nessus` (importing writes scans/findings, so it counts as a mutation). With execution also on, runs are auto-ingested best-effort |
| `mcp_allow_batch` | `execute_batch`, only when `mcp_allow_execution` is also on. It authorizes the fan-out across a query; every command still passes the exec policy, the credential gate and the per-command timeout |
| `mcp_allow_cred_injection` | `execute_command`/`start_execution`/`execute_batch` may resolve `@cred:<ref>@` placeholders to real secrets server-side. Independent of execution |
| `mcp_allow_cred_reveal` | `reveal_credential`. Strictly more sensitive than injection, and gated separately: injection being on does **not** enable reveal |

- When a flag is off, the corresponding tools are **not registered** and never
  appear in the client.
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
  3. The target (last binary) must match `mcp_exec_allowlist`. Wrappers need no
     entry. `"*"` permits anything not denied, and **an empty list denies
     everything**. The default is the core tools plus low-impact recon utilities:
     - core: `nmap, nxc, netexec, msfconsole`
     - HTTP fetch: `curl, wget`
     - DNS / registry: `dig, host, nslookup, whois`
     - reachability: `ping, traceroute`
     - protocol auditing: `ssh-audit, sslscan, testssl*, whatweb`
     - RPC / NFS / SNMP: `showmount, rpcinfo, snmpwalk, onesixtyone`

     Deliberately left out (add them yourself if you want them): shells and
     interpreters, binaries with built-in command escapes (`find`, `awk`, `sed`,
     `xargs`, `tar`, `git`, `ssh`, `nc`/`ncat`/`socat`, `tcpdump`, and
     `smbclient`/`rpcclient`, whose `!` command runs a local shell), and
     active-attack or noisy tools (`responder`, `ntlmrelayx.py`, `hping3`, `ffuf`,
     `gobuster`, `feroxbuster`, `nuclei`). Even the defaults aren't inert: `curl`
     can write files (`-o`) and read or upload local ones (`file://`, `-T`), and
     `wget --use-askpass` runs a program. Because `sudo` isn't denied by default,
     any allowed binary can run as root; add `sudo` to the denylist to prevent that.
- Entries in both lists are glob patterns (`fnmatch`, case-sensitive) matched
  against the binary's **basename**, so `/usr/bin/rm` and `rm` are treated alike.
- The denylist guards against mistakes; it is **not a security boundary**. With
  `"*"`, `sh -c "rm …"`, `python3 -c …`, or `find -delete` still run unless those
  binaries are denied too. Prefer an explicit allowlist when it matters.
- `sudo` runs non-interactively. If sudo would prompt for a password, the call is
  refused (pre-authenticate with `sudo -v`).
- `get_capabilities` reports both lists as configured.

---

## Verification loop

Turn a finding into a recorded, evidence-backed verdict:

1. **Run with attribution.** `execute_command(command, finding_id=…)` (or
   `start_execution`). Generate the command first with `generate_nmap_cmd`,
   `generate_netexec_cmd` or `prepare_workflow`.
2. **Ingest the output.** `ingest_results(execution_id)` parses nmap XML into
   verified open ports and NSE vuln verdicts, and NetExec runs into a
   security-flag snapshot. It is idempotent, and empty or partial runs return a
   `skipped_reason` instead of an error. When mutations are on, executions are
   ingested automatically (best-effort).
3. **Review the evidence.** `cerno://finding/{id}/results` and
   `get_finding_detail` show what was verified; `get_finding_verdict` also
   returns a non-binding `suggested_verdict` from NSE evidence (never applied
   automatically).
4. **Record the verdict.** `set_finding_verdict(finding_id, verdict, note,
   execution_id|artifact_id|nse_result_id)` with `confirmed`, `false_positive` or
   `unable`. Verdicts are append-only history and separate from review state.
   The result carries a `workflow_candidate` hint (see
   [Workflow contributions](#workflow-contributions)).

Use `add_note`/`get_notes` for free-text notes. Notes are append-only and
timestamped, and `set_review_state(notes=…)` appends rather than overwrites.

---

## Jobs and batch

- **Background jobs** (`mcp_allow_execution`): `start_execution` takes the same
  arguments as `execute_command` but returns a `job_id` immediately; poll
  `get_execution_status(job_id)` for status and an output tail, and
  `cancel_execution(job_id)` kills the job's process group. Jobs live in memory
  and are lost when the server restarts, but every completed run is still logged
  to `tool_executions`.
- **Batch:** `plan_batch(strategy, …query predicates…)` is an always-on dry run.
  `strategy` is `"nmap"`, `"netexec:<proto>"` (bare `"netexec"` = configured
  default protocol, else `smb`), `"msf"` or `"workflow"`. Each item shows the
  generated command and whether it is runnable or manual; findings already
  resolved are skipped when `skip_done` (default). Review the plan, then
  `execute_batch` with the same arguments runs the runnable items as tracked,
  attributed jobs, at most `mcp_batch_concurrency` at a time with
  `mcp_batch_timeout` per command.

---

## Credentials

- `list_nxc_credentials` returns **refs** (plus username, domain and secret
  kind), never secret values.
- Pass a ref as `use_credential` to `generate_netexec_cmd`, `prepare_workflow` or
  `plan_batch`. The returned command carries an `@cred:<ref>@` placeholder instead
  of the secret.
- With `mcp_allow_cred_injection` on, the execution tools resolve the placeholder
  server-side at run time. The secret is masked in the logged `command_text` and
  scrubbed from stdout/stderr and from registered `--log`/`-oA` artifact files.
  With it off, a command containing a placeholder is refused.
- `reveal_credential(ref)` (`mcp_allow_cred_reveal`) returns the cleartext. Every
  reveal is audited to `tool_executions` (`tool_name='cred_reveal'`, ref only, never
  the value). The local `cerno creds list` / `cerno creds reveal <ref>` CLI offers
  the same without the MCP flag.

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
