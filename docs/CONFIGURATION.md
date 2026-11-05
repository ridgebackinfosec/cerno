# Configuration

Every Cerno setting lives in one YAML file, `~/.cerno/config.yaml`, created with
defaults on first run. There are no environment variables — if it is
configurable, it is in this file.

```bash
cerno config show                    # All settings with their current values
cerno config get <key>               # One value
cerno config set <key> <value>       # Change a setting
cerno config reset <key>             # Reset one setting to its default
cerno config reset                   # Reset everything (writes a backup first)
```

Changes take effect on the next command. The one exception is the MCP server,
which reads its gating flags once at startup — see
[Notes on specific settings](#notes-on-specific-settings).

List-valued keys take CSV on the command line:

```bash
cerno config set mcp_exec_allowlist "nmap,nxc,nuclei"
```

---

## All settings

The table below is generated from `cerno_pkg/config.py`, the same source
`cerno config show` renders from, so the two cannot disagree about which
settings exist. Defaults shown are the values you get on a fresh install.

<!-- BEGIN GENERATED: config-table -->
| Setting | Default | Purpose |
| --- | --- | --- |
| **Paths** | | |
| `results_root` | `~/.cerno/artifacts` | Directory for tool output |
| `log_path` | `~/.cerno/cerno.log` | Log file location |
| **Review & Display** | | |
| `default_page_size` | `auto` | Items per page in lists |
| `top_ports_count` | `5` | Top ports to show |
| `no_color` | `False` | Disable ANSI colors |
| `color_scheme` | `light` | Terminal background: light or dark |
| `term_override` | `(not set)` | Force terminal type |
| **Tools & Workflows** | | |
| `default_tool` | `(not set)` | Pre-select: nmap/netexec/metasploit/custom |
| `default_netexec_protocol` | `smb` | Default: smb/ssh/ftp/etc |
| `nmap_default_profile` | `(not set)` | NSE profile name |
| `custom_workflows_path` | `(not set)` | Path to custom workflows YAML |
| `nuclei_templates_path` | `~/nuclei-templates` | nuclei templates directory (-ud) |
| `nuclei_profile` | `~/nuclei-templates/profiles/pentest.yml` | nuclei profile YAML (-profile) |
| `nuclei_user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0` | User-Agent nuclei sends (-H) |
| `nuclei_concurrency` | `10` | nuclei template concurrency (-c) |
| **Logging** | | |
| `debug_logging` | `False` | Enable DEBUG logs |
| **NetExec Integration** | | |
| `nxc_workspace_path` | `~/.nxc/workspaces/default/` | NetExec workspace directory |
| `nxc_enrichment_enabled` | `True` | NetExec enrichment, cred refs and nxc ingest |
| **Claude Assistant** | | |
| `claude_assistant_enabled` | `False` | Enable Claude Assistant |
| **MCP Server** | | |
| `mcp_allow_execution` | `False` | Allow MCP server to execute commands |
| `mcp_allow_mutations` | `False` | Allow MCP server to mutate state |
| `mcp_allow_cred_injection` | `False` | Allow execute_command to resolve @cred placeholders to real secrets |
| `mcp_allow_cred_reveal` | `False` | Allow the MCP reveal_credential tool to return cleartext secrets |
| `mcp_exec_allowlist` | `nmap, nxc, netexec, msfconsole, nuclei, curl, wget, dig, host, nslookup, whois, ping, traceroute, ssh-audit, sslscan, testssl*, whatweb, showmount, rpcinfo, snmpwalk, onesixtyone` | Binaries execute_command may run |
| `mcp_exec_denylist` | `rm, rmdir, dd, shred, wipefs, mkfs*, fdisk, sfdisk, parted, shutdown, reboot, halt, poweroff` | Binaries execute_command may never run |
| `mcp_allow_batch` | `False` | Allow execute_batch to run a whole query's commands |
| `mcp_batch_concurrency` | `3` | Max commands execute_batch runs at once |
| `mcp_batch_timeout` | `300` | Per-command timeout (s) for execute_batch |
| `contribution_export_dir` | `<results_root>/contributions` | Directory for exported workflow contributions |
| `mcp_enforce_scope` | `True` | Refuse execute_command targets outside the scan hosts / scope |
| `mcp_scope_extra` | `(none)` | Extra in-scope CIDRs / IPs / hostnames for execute_command |
| **Proxychains4** | | |
| `proxychains_enabled` | `False` | Route tools through proxychains4 (SOCKS5) |
| `proxychains_host` | `127.0.0.1` | proxychains4 SOCKS5 proxy host |
| `proxychains_port` | `9000` | proxychains4 SOCKS5 proxy port |
| **Remote Scan Mode** | | |
| `pivot_interface` | `(not set)` | Interface for remote scan HTTPS server |
| `pivot_http_port` | `8877` | Port for remote scan HTTPS server |
<!-- END GENERATED: config-table -->

---

## Notes on specific settings

Most settings are adequately described by the table. These few are not.

### `color_scheme`

Colors are tuned for a **light** terminal background by default. On a dark
terminal the classic palette reads better:

```bash
cerno config set color_scheme dark    # light (default) | dark
```

This remaps every color in one place, so both Rich output and raw ANSI follow it.

### `mcp_exec_allowlist` / `mcp_exec_denylist`

Glob patterns matched against the **basename of the target binary**, after
wrappers like `sudo`, `env`, `timeout` and `proxychains4` are unwrapped — so
`/usr/bin/rm` and `rm` are treated alike, and a wrapper needs no entry of its
own.

- `"*"` permits anything not denied; an **empty list denies everything**.
- The denylist is checked against *every* binary in the chain and always wins.
- It is a guardrail, not a security boundary. With `"*"`, a shell or interpreter
  can still run a denied program unless you deny that too.

Both are only consulted when `mcp_allow_execution` is on. The full default list
and its rationale are in [MCP.md](MCP.md#execution-policy).

### `mcp_batch_concurrency` / `mcp_batch_timeout`

Concurrency is clamped to 1–8 regardless of what you set. Lower it to `1` when
everything routes through a single SOCKS pivot — nmap and nuclei are already
internally parallel, so stacking batch concurrency on top mostly produces
timeouts. The timeout is **per command**, not for the batch.

### `mcp_allow_cred_injection` vs `mcp_allow_cred_reveal`

Two different powers, gated separately on purpose:

- **Injection** resolves `@cred:<ref>@` placeholders to real secrets at run
  time, server-side. The secret is never logged, returned, or written to an
  artifact — it is masked in `command_text` and scrubbed from output.
- **Reveal** hands the cleartext secret back to the caller.

Enabling injection does **not** enable reveal. The local `cerno creds reveal`
CLI works regardless of the flag, and every reveal is audited.

### `mcp_enforce_scope` / `mcp_scope_extra`

In scope means every host in an imported scan, plus anything in
`mcp_scope_extra`. An out-of-scope IP or CIDR literal is refused; a bare
hostname that cannot be resolved is allowed with a warning rather than blocked.

### MCP gating flags are read once

`mcp_allow_execution`, `mcp_allow_mutations`, `mcp_allow_batch` and the two
credential flags are read when the server starts. After changing one, reconnect
the client (remove and re-add, or restart it) — a running session keeps the
tools it was built with.

### `nxc_workspace_path`

Set to `""` to disable NetExec integration entirely. When disabled — or when
`nxc_enrichment_enabled` is `false` — `cerno creds`, the MCP credential tools,
credential injection and nxc ingest all go with it.

---

## Example output

<details>
<summary>Example output of <code>cerno config show</code></summary>

<!-- BEGIN GENERATED: config-show -->
```text

Current Configuration
Config file: ~/.cerno/config.yaml

                                                  Configuration Values                                                  
┏━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃   ┃ Setting                  ┃ Value                                ┃ Description                          ┃ Status  ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│   │ Paths                    │                                      │                                      │         │
│   │ results_root             │ ~/.cerno/ar │ Directory for tool output            │ default │
│   │                          │ tifacts                              │                                      │         │
│   │ log_path                 │ ~/.cerno/ce │ Log file location                    │ default │
│   │                          │ rno.log                              │                                      │         │
├───┼──────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────┤
│   │ Review & Display         │                                      │                                      │         │
│   │ default_page_size        │ auto                                 │ Items per page in lists              │ default │
│   │ top_ports_count          │ 5                                    │ Top ports to show                    │ default │
│   │ no_color                 │ False                                │ Disable ANSI colors                  │ default │
│   │ color_scheme             │ light                                │ Terminal background: light or dark   │ default │
│   │ term_override            │ (not set)                            │ Force terminal type                  │ default │
├───┼──────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────┤
│   │ Tools & Workflows        │                                      │                                      │         │
│   │ default_tool             │ (not set)                            │ Pre-select:                          │ default │
│   │                          │                                      │ nmap/netexec/metasploit/custom       │         │
│   │ default_netexec_protocol │ smb                                  │ Default: smb/ssh/ftp/etc             │ default │
│   │ nmap_default_profile     │ (not set)                            │ NSE profile name                     │ default │
│   │ custom_workflows_path    │ (not set)                            │ Path to custom workflows YAML        │ default │
│   │ nuclei_templates_path    │ ~/nuclei-templates                   │ nuclei templates directory (-ud)     │ default │
│   │ nuclei_profile           │ ~/nuclei-templates/profiles/pentest. │ nuclei profile YAML (-profile)       │ default │
│   │                          │ yml                                  │                                      │         │
│   │ nuclei_user_agent        │ Mozilla/5.0 (Windows NT 10.0; Win64; │ User-Agent nuclei sends (-H)         │ default │
│   │                          │ x64; rv:132.0) Gecko/20100101        │                                      │         │
│   │                          │ Firefox/132.0                        │                                      │         │
│   │ nuclei_concurrency       │ 10                                   │ nuclei template concurrency (-c)     │ default │
├───┼──────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────┤
│   │ Logging                  │                                      │                                      │         │
│   │ debug_logging            │ False                                │ Enable DEBUG logs                    │ default │
├───┼──────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────┤
│   │ NetExec Integration      │                                      │                                      │         │
│ ▶ │ nxc_workspace_path       │ /path/to/cerno/docs/demo/nxc-wo │ NetExec workspace directory          │ changed │
│   │                          │ rkspace                              │                                      │         │
│   │ nxc_enrichment_enabled   │ True                                 │ NetExec enrichment, cred refs and    │ default │
│   │                          │                                      │ nxc ingest                           │         │
├───┼──────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────┤
│   │ Claude Assistant         │                                      │                                      │         │
│   │ claude_assistant_enabled │ False                                │ Enable Claude Assistant              │ default │
├───┼──────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────┤
│   │ MCP Server               │                                      │                                      │         │
│   │ mcp_allow_execution      │ False                                │ Allow MCP server to execute commands │ default │
│   │ mcp_allow_mutations      │ False                                │ Allow MCP server to mutate state     │ default │
│   │ mcp_allow_cred_injection │ False                                │ Allow execute_command to resolve     │ default │
│   │                          │                                      │ @cred placeholders to real secrets   │         │
│   │ mcp_allow_cred_reveal    │ False                                │ Allow the MCP reveal_credential tool │ default │
│   │                          │                                      │ to return cleartext secrets          │         │
│   │ mcp_exec_allowlist       │ nmap, nxc, netexec, msfconsole,      │ Binaries execute_command may run     │ default │
│   │                          │ nuclei, curl, wget, dig, host,       │                                      │         │
│   │                          │ nslookup, whois, ping, traceroute,   │                                      │         │
│   │                          │ ssh-audit, sslscan, testssl*,        │                                      │         │
│   │                          │ whatweb, showmount, rpcinfo,         │                                      │         │
│   │                          │ snmpwalk, onesixtyone                │                                      │         │
│   │ mcp_exec_denylist        │ rm, rmdir, dd, shred, wipefs, mkfs*, │ Binaries execute_command may never   │ default │
│   │                          │ fdisk, sfdisk, parted, shutdown,     │ run                                  │         │
│   │                          │ reboot, halt, poweroff               │                                      │         │
│   │ mcp_allow_batch          │ False                                │ Allow execute_batch to run a whole   │ default │
│   │                          │                                      │ query's commands                     │         │
│   │ mcp_batch_concurrency    │ 3                                    │ Max commands execute_batch runs at   │ default │
│   │                          │                                      │ once                                 │         │
│   │ mcp_batch_timeout        │ 300                                  │ Per-command timeout (s) for          │ default │
│   │                          │                                      │ execute_batch                        │         │
│   │ contribution_export_dir  │ <results_root>/contributions         │ Directory for exported workflow      │ default │
│   │                          │                                      │ contributions                        │         │
│   │ mcp_enforce_scope        │ True                                 │ Refuse execute_command targets       │ default │
│   │                          │                                      │ outside the scan hosts / scope       │         │
│   │ mcp_scope_extra          │ (none)                               │ Extra in-scope CIDRs / IPs /         │ default │
│   │                          │                                      │ hostnames for execute_command        │         │
├───┼──────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────┤
│   │ Proxychains4             │                                      │                                      │         │
│   │ proxychains_enabled      │ False                                │ Route tools through proxychains4     │ default │
│   │                          │                                      │ (SOCKS5)                             │         │
│   │ proxychains_host         │ 127.0.0.1                            │ proxychains4 SOCKS5 proxy host       │ default │
│   │ proxychains_port         │ 9000                                 │ proxychains4 SOCKS5 proxy port       │ default │
├───┼──────────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┼─────────┤
│   │ Remote Scan Mode         │                                      │                                      │         │
│   │ pivot_interface          │ (not set)                            │ Interface for remote scan HTTPS      │ default │
│   │                          │                                      │ server                               │         │
│   │ pivot_http_port          │ 8877                                 │ Port for remote scan HTTPS server    │ default │
└───┴──────────────────────────┴──────────────────────────────────────┴──────────────────────────────────────┴─────────┘

1 setting(s) changed from default (marked ▶).
Edit config: ~/.cerno/config.yaml
Change values: cerno config set <key> <value>
Reset one setting: cerno config reset <key>
Reset to defaults: cerno config reset
```
<!-- END GENERATED: config-show -->

</details>

---

## See also

- [MCP server](MCP.md) — the `mcp_*` keys in depth, with the execution policy
- [Custom workflows](CUSTOM_WORKFLOWS.md) — `custom_workflows_path`
- [Architecture](ARCHITECTURE.md) — where configuration sits in the layer map
