# Cerno

A **TUI tool** for reviewing Nessus scan findings and orchestrating security tools (**nmap**, **NetExec**, custom commands). Import `.nessus` files into a SQLite database for organized, persistent vulnerability verification and exploitation.

**Key capabilities:**
- 🔍 Interactive TUI for browsing/reviewing vulnerability findings
- 💾 SQLite-backed persistence (cross-scan tracking, session resume)
- ⚡ One-command tool launches (nmap NSE scripts, NetExec, custom workflows)
- 📊 CVE extraction, Metasploit module search, host comparison

---

## Quick Start

```bash
# Install with pipx (recommended)
pipx install git+https://github.com/ridgebackinfosec/cerno.git

# Import a Nessus scan
cerno import nessus scan.nessus

# Review findings interactively
cerno review
```

**That's it!** See [Common Commands](#commands) for more.

<p align="center">
  <img src="docs/images/severity-selection.png" alt="Severity selection screen showing color-coded review progress" width="50%">
  <br>
  <em>Start your review with an overview of findings by severity level</em>
</p>

---

## About the Name

**Cerno** comes from the Latin verb *cernō*, meaning:
- To discern, distinguish, perceive
- To separate, sift through
- To decide, determine, resolve

The name reflects this tool's core purpose: **to help security professionals discern what matters** in large vulnerability scans. Just as *cernō* means to sift through and distinguish the important from the noise, Cerno helps you:

- **Discern** which findings require immediate action vs. can be deferred
- **Separate** findings by severity, host, and exploitability
- **Perceive** patterns across hosts and identify verification paths
- **Determine** the most efficient approach to vulnerability validation
- **Resolve** findings through organized, tracked remediation workflows

In penetration testing and vulnerability management, clarity through careful examination is essential—that's Cerno.


**Pronunciation:** In Classical Latin, *cerno* is pronounced **KEHR-noh** (IPA: [ˈkɛr.noː])—the 'c' as a hard 'k' sound, the 'e' as in 'bed', and the 'o' as in 'no' (long). [Audio sample](https://www.howtopronounce.com/latin/cerno)

---

## Installation

**Recommended (pipx):**
```bash
pipx install git+https://github.com/ridgebackinfosec/cerno.git
cerno --help
```

**Alternative (pip):**
```bash
pip install git+https://github.com/ridgebackinfosec/cerno.git
```

**Development:**
```bash
git clone https://github.com/ridgebackinfosec/cerno.git
cd cerno
pip install -e .
```

**Shell completion:**
```bash
cerno --install-completion  # Enable tab completion for your shell
```

---

## Releases

Cerno uses **automated releases** triggered by version changes in [pyproject.toml](pyproject.toml).

**How it works:**
- When `pyproject.toml` version is updated and merged to `main`, GitHub Actions automatically:
  - Creates a git tag (e.g., `v1.0.1`)
  - Generates a GitHub Release marked as "latest"
  - Extracts release notes from [CHANGELOG.md](CHANGELOG.md)
  - Attaches built wheel and source distribution

**View releases:** [github.com/ridgebackinfosec/cerno/releases](https://github.com/ridgebackinfosec/cerno/releases)

**For contributors:** To create a new release, update the version in `pyproject.toml` and add an entry to `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/) format. The release workflow runs automatically when changes are merged to `main`.

---

## Requirements

- **Python 3.11+**
- **Optional tools:** `nmap`, `nxc`/`netexec`, `msfconsole` (only if you use them)
- **Linux recommended** (clipboard tools: `xclip`, `xsel`, or `wl-copy`)

---

## Configuration

**Configuration file** (`~/.cerno/config.yaml`):

Auto-created with defaults on first run. All settings managed via config file.

```bash
cerno config show        # View all settings with current values
cerno config set <key> <value>  # Change a setting
cerno config reset       # Reset to defaults (creates backup)
```

<p align="center">
  <img src="docs/images/default-config-values.png" alt="Finding browser with pagination and keyboard shortcuts" width="800">
  <br>
  <em>Show all configuration values using "cerno config show"</em>
</p>

---

## Features

### 🔍 Interactive TUI for browsing/reviewing vulnerability findings

Rich tables with paged views, keyboard-driven navigation, and real-time filtering.

<p align="center">
  <img src="docs/images/finding-browser.png" alt="Finding browser with pagination and keyboard shortcuts" width="800">
  <br>
  <em>Browse findings with paged tables and comprehensive keyboard shortcuts</em>
</p>

**Key capabilities:**
- Browse by severity, preview plugin details, clipboard copy
- Grouped view (`host:port,port`) or raw file view
- Multi-select operations, reversible review states

---

### 📊 Intelligence & Research

Extract CVEs, search Metasploit modules, and compare findings across hosts.

<p align="center">
  <img src="docs/images/plugin-detail.png" alt="Plugin detail panel with Metasploit indicator" width="800">
  <br>
  <em>View plugin details with Metasploit module availability and metadata</em>
</p>

**Features:**
- **CVE extraction** - CVEs imported from .nessus file (press `[E]`)
- **Metasploit search** - Find relevant modules by CVE/description
- **Workflow mappings** - Plugin-specific verification/exploitation steps (press `[W]`)
- **Host comparison** - Compare findings across hosts to find identical combinations and superset relationships

<p align="center">
  <img src="docs/images/host-comparison.png" alt="Host comparison showing identical host:port combinations" width="70%">
  <br>
  <em>Compare findings to identify identical host:port combinations across plugins</em>
</p>

<p align="center">
  <img src="docs/images/superset-analysis.png" alt="Superset analysis showing coverage relationships" width="800">
  <br>
  <em>Analyze superset relationships to find which findings cover others</em>
</p>

---

### ⚡ One-command tool launches

Launch nmap NSE scripts, NetExec, Metasploit, or custom commands with placeholder substitution.

<p align="center">
  <img src="docs/images/tool-orchestration.png" alt="Tool selection and command generation" width="70%">
  <br>
  <em>Select tools and review generated commands before execution</em>
</p>

**Features:**
- Launch **nmap** (NSE profiles, UDP), **NetExec**, or custom commands
- Placeholder substitution for flexible templating
- Execution logging & artifact tracking

---

### 💾 SQLite-backed persistence

**Session Management:**
- Auto-save/resume interrupted reviews
- Reversible review-complete (undo with `[U]`)
- Session statistics (duration, per-severity breakdown)

**Database:** SQLite-backed persistence at `~/.cerno/cerno.db` tracks scans, findings, sessions, tool executions, and artifacts. Cross-scan tracking enables host history queries. See [docs/DATABASE.md](docs/DATABASE.md) for schema details.

---

## Commands

```bash
# Import and review
cerno import nessus <scan.nessus>
cerno review [--custom-workflows PATH]

# Manage scans
cerno scan list
cerno scan delete <scan_name>

# Configuration
cerno config show | reset | get <key> | set <key> <value>
```

---

## Custom Workflows

Add plugin-specific verification workflows with `--custom-workflows` (merges & supplements with defaults) or `--custom-workflows-only` (replaces defaults):

```bash
cerno review --custom-workflows my_workflows.yaml
```

**Example workflow YAML:**
```yaml
version: "1.0"
workflows:
  - plugin_id: "57608"
    workflow_name: "SMB Signing Not Required"
    steps:
      - title: "Verify SMB signing"
        commands: ["netexec smb <target> -u <user> -p <pass>"]
```

**Custom command placeholders:** `{TCP_IPS}`, `{UDP_IPS}`, `{TCP_HOST_PORTS}`, `{PORTS}`, `{WORKDIR}`, `{RESULTS_DIR}`, `{OABASE}`

<p align="center">
  <img src="docs/images/workflow-display.png" alt="Custom workflow verification steps" width="70%">
  <br>
  <em>View plugin-specific verification workflows with commands and references</em>
</p>

---

## Documentation

- [Database schema & queries](docs/DATABASE.md)
- [Adding custom tools](docs/ADDING_TOOLS_QUICKSTART.md)
- [Tool system guide](docs/TOOL_SYSTEM_GUIDE.md)
- [Error handling](docs/ERROR_HANDLING.md)

---

## License

This tool orchestrates local utilities and includes Nessus XML parsing functionality adapted from
[DefensiveOrigins/NessusPluginHosts](https://github.com/DefensiveOrigins/NessusPluginHosts).
Respect all dependencies' licenses and your organization's policies.
