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
| Execute | `execute_command` (runs a command, captures output, logs it; reports progress). Binary must be in `mcp_exec_allowlist`; `timeout` clamped to [1, 3600]s; optional `finding_id` attributes the run (then surfaced by `get_finding_artifacts`) | `mcp_allow_execution` |
| Mutate | `set_review_state` (`unreviewed` → `in_progress` → `done` → `unreviewed`; other changes rejected), `import_nessus` | `mcp_allow_mutations` |

Notes:

- `list_findings` takes `merged` (dedup multi-scan results by plugin, matching
  the TUI), `limit`, and `offset` for paging.
- `search_findings` searches **all** scans at once (no `scan_ids`); each result
  carries its `scan_name`.
- `get_finding_detail` caps per-host output at `max_hosts` (default 100) and
  reports `affected_total` / `affected_truncated`.
- `get_capabilities` reports which gated capabilities are live, so a client can
  self-orient without a failed call.

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
- `triage_scope` — report brief across one or more scans (comma-separated
  `scan_ids`, e.g. `1,3`; merged and deduplicated by plugin), optionally one severity

---

## Gating

Both flags default to `false`, so the server is read-only out of the box.
Enable the capabilities you want:

```bash
cerno config set mcp_allow_execution true        # permit execute_command
cerno config set mcp_allow_mutations true        # permit set_review_state / import_nessus
cerno config set mcp_exec_allowlist "nmap,nxc"   # restrict which binaries execute_command may run
```

- When a flag is off, the corresponding tools are **not registered** and never
  appear in the client.
- Enabling `mcp_allow_mutations` unlocks both `set_review_state` and
  `import_nessus` (importing writes scans/findings to the database, so it is
  treated as a mutation).
- `mcp_exec_allowlist` (default `nmap, nxc, netexec, msfconsole, proxychains4`)
  bounds `execute_command` even when execution is enabled: the basename of
  `command[0]` must be listed, so "execution on" is not "arbitrary command
  execution on". An empty list falls back to the built-in default set.

---

## Caveats

- **Resources and prompts only appear in clients that render them** (e.g. Claude
  Desktop). Tool-only clients ignore them; the read tools provide the same data.
- The server writes nothing to **stdout** (that is the JSON-RPC channel). All
  diagnostics go to `~/.cerno/cerno.log`.
- NetExec tools require a configured, existing workspace
  (`nxc_workspace_path`) with `nxc_enrichment_enabled` on; otherwise they return
  `{"available": false}`.
