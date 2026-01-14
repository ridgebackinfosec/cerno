# Custom Workflows Guide

## Table of Contents

- [Introduction](#introduction)
- [Quick Start](#quick-start)
- [YAML Schema Reference](#yaml-schema-reference)
- [Multi-Plugin Workflows](#multi-plugin-workflows)
- [Placeholder System](#placeholder-system)
- [Configuration Integration](#configuration-integration)
- [Merge Behavior](#merge-behavior)
- [Best Practices](#best-practices)
- [Complete Examples](#complete-examples)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)

---

## Introduction

### What are Custom Workflows?

Custom workflows are plugin-specific verification procedures that guide security professionals through the process of validating and exploiting vulnerabilities discovered in Nessus scans. Each workflow provides:

- **Structured verification steps** with specific commands and tools
- **Contextual notes** explaining what to look for and why
- **Reference URLs** to vulnerability databases, exploit guides, and documentation

### When to Use Custom Workflows

Use custom workflows when you need to:

- **Standardize verification procedures** across your team
- **Document preferred tools and techniques** for specific vulnerabilities
- **Add workflows for plugins** not covered in the bundled set
- **Override bundled workflows** with organization-specific procedures
- **Create multi-step verification guides** that combine multiple tools

### Display-Only vs Executable Commands

Workflows are **display-only** - they provide guidance but do not execute automatically. This design allows you to:

- Review commands before execution
- Modify commands for your specific environment
- Copy commands to your clipboard
- Use workflows as checklists for manual verification

Commands can contain placeholders (e.g., `{TCP_IPS}`, `{PORTS}`) that Cerno automatically expands with scan-specific data when you run tools interactively.

---

## Quick Start

### Basic Usage

Use the `--custom-workflows` flag to supplement the bundled workflows with your own:

```bash
cerno review --custom-workflows my_workflows.yaml
```

Or use `--custom-workflows-only` to replace the bundled workflows entirely:

```bash
cerno review --custom-workflows-only my_workflows.yaml
```

### Viewing Workflows in the TUI

When reviewing findings:

1. Navigate to a plugin finding
2. Press **[W]** to view the associated workflow
3. The workflow displays in a formatted panel with steps, commands, and references
4. Press **Enter** to return to the review menu

### Simple Example Workflow

Create a file called `my_workflows.yaml`:

```yaml
version: "1.0"

workflows:
  - plugin_id: "10863"
    workflow_name: "SSL Certificate Expiry Check"
    description: "Verify SSL certificate expiration dates and validity periods"
    steps:
      - title: "Check certificate details with OpenSSL"
        commands:
          - "echo | openssl s_client -connect {TCP_HOST_PORTS} 2>/dev/null | openssl x509 -noout -dates"
        notes: "Look for notBefore and notAfter dates. Certificates expiring within 30 days should be flagged."

      - title: "Enumerate all certificates in chain"
        commands:
          - "nmap --script ssl-cert -p {PORTS} {TCP_IPS}"
        notes: "Verify the entire certificate chain for validity and trust issues."

    references:
      - "https://www.tenable.com/plugins/nessus/10863"
      - "https://www.openssl.org/docs/man1.1.1/man1/s_client.html"
```

Save this file and run:

```bash
cerno review --custom-workflows my_workflows.yaml
```

When you review plugin 10863, press **[W]** to see your custom workflow.

---

## YAML Schema Reference

### Complete Field Documentation

```yaml
version: "1.0"  # Required: Schema version (currently always "1.0")

workflows:      # Required: List of workflow definitions
  - plugin_id: "12345"           # Required: Plugin ID(s) - string, can be comma-separated
    workflow_name: "Workflow Name"  # Required: Human-readable workflow name
    description: "Brief description"  # Required: What this workflow verifies

    steps:                        # Required: List of verification steps (at least 1)
      - title: "Step title"       # Required: Step description
        commands:                 # Required: List of commands (can be empty list [])
          - "command 1"
          - "command 2"
        notes: "Additional context"  # Optional: Notes explaining what to look for

    references:                   # Optional: List of reference URLs
      - "https://example.com"
      - "https://another-reference.com"
```

### Field Details

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Schema version (currently "1.0") |
| `workflows` | list | Yes | List of workflow definitions |
| `plugin_id` | string | Yes | Nessus plugin ID (can be comma-separated for multi-plugin workflows) |
| `workflow_name` | string | Yes | Human-readable workflow name (used as unique identifier) |
| `description` | string | Yes | Brief description of what the workflow verifies |
| `steps` | list | Yes | List of verification steps (minimum 1 step required) |
| `steps[].title` | string | Yes | Title/description of this step |
| `steps[].commands` | list | Yes | List of commands to execute (can be empty list) |
| `steps[].notes` | string | Optional | Additional notes or context for this step |
| `references` | list | Optional | List of reference URLs (documentation, exploits, etc.) |

### Data Types and Formats

- **Strings**: Use quotes for strings containing special characters or colons
- **Lists**: Use YAML list syntax with `-` prefix
- **Empty lists**: Use `[]` for steps without commands (display-only)
- **Plugin IDs**: Always strings (quoted), even though they look numeric
- **URLs**: Standard HTTP/HTTPS URLs in reference list

---

## Multi-Plugin Workflows

### Why Use Multi-Plugin Workflows?

Some verification procedures apply to multiple related plugins. Instead of duplicating workflows, you can map a single workflow to multiple plugin IDs.

### Comma-Separated Plugin IDs

Use comma-separated plugin IDs in the `plugin_id` field:

```yaml
workflows:
  - plugin_id: "20007,104743,157288"
    workflow_name: "Deprecated SSL/TLS Encryption"
    description: "Deprecated encryption protocol versions should be removed from support unless absolutely necessary."
    steps:
      - title: "Enumerate the supported encryption protocol versions and algorithms"
        commands:
          - "sudo nmap -A --script=ssl-enum-ciphers,ssl-cert,ssl-date {TCP_IPS}"
        notes: "SSLv2, SSLv3, and TLSv1.0 are all considered deprecated and should not be supported anymore. TLSv1.1 is also outdated but not of terrible concern."

    references:
      - "https://www.tenable.com/plugins/nessus/20007"
      - "https://www.tenable.com/plugins/nessus/104743"
      - "https://www.tenable.com/plugins/nessus/157288"
```

### How Multi-Plugin Workflows Work

- The workflow is registered internally for **each individual plugin ID**
- Pressing **[W]** on any of the related plugins shows the **same workflow**
- The workflow's `plugin_id` field preserves the original comma-separated string
- Include all relevant plugin URLs in the `references` section

### When to Use Multi-Plugin Workflows

Use multi-plugin workflows when:

- Multiple plugins detect the same underlying issue (e.g., SSLv2, SSLv3, TLSv1.0)
- The verification procedure is identical across related vulnerabilities
- You want to maintain a single source of truth for a verification technique

---

## Placeholder System

### Available Placeholders

Cerno provides 7 placeholders that are automatically expanded when you use them in workflow commands:

| Placeholder | Description | Example Value |
|-------------|-------------|---------------|
| `{TCP_IPS}` | Path to file containing TCP host IP addresses (one per line) | `/home/user/.cerno/artifacts/scan1/tcp_ips.txt` |
| `{UDP_IPS}` | Path to file containing UDP host IP addresses (one per line) | `/home/user/.cerno/artifacts/scan1/udp_ips.txt` |
| `{TCP_HOST_PORTS}` | Path to file containing host:port combinations (one per line) | `/home/user/.cerno/artifacts/scan1/tcp_sockets.txt` |
| `{PORTS}` | Comma-separated port list string | `80,443,8080,8443` |
| `{WORKDIR}` | Working directory for temporary files | `/home/user/.cerno/artifacts/scan1/workdir` |
| `{RESULTS_DIR}` | Directory for final results/output | `/home/user/.cerno/artifacts/scan1/High` |
| `{OABASE}` | Output file base path (for -oA style nmap outputs) | `/home/user/.cerno/artifacts/scan1/High/plugin_12345` |

### How Placeholders are Expanded

Placeholders use simple string replacement - Cerno replaces `{PLACEHOLDER}` with the actual value before displaying or executing commands.

**Important**: Placeholders are expanded based on the current finding context (scan, severity, affected hosts/ports).

### Example Commands Using Placeholders

From the bundled workflows and custom command examples:

```bash
# HTTP enumeration with httpx
httpx -l {TCP_IPS} -silent -o {OABASE}.urls.txt

# Vulnerability scanning with Nuclei
nuclei -l {OABASE}.urls.txt -o {OABASE}.nuclei.txt

# Parallel nmap scanning
cat {TCP_IPS} | xargs -I{} sh -c 'echo {}; nmap -Pn -p {PORTS} {}'

# Port-specific SSL enumeration
nmap --script ssl-enum-ciphers -p {PORTS} {TCP_IPS}

# Responder with specific interface
responder -I eth0 -A > {RESULTS_DIR}/responder.log
```

### Placeholder Best Practices

1. **Use `{TCP_IPS}` for tool input files** - Most tools accept file input with `-iL` or similar flags
2. **Use `{OABASE}` for consistent output naming** - Creates predictable output filenames
3. **Use `{PORTS}` for port-specific scans** - Ensures you only scan affected ports
4. **Use `{RESULTS_DIR}` for final output** - Keeps results organized by severity
5. **Use `{WORKDIR}` for intermediate files** - Temporary files that don't need to persist

---

## Configuration Integration

### Using `custom_workflows_path` Config Key

Instead of passing `--custom-workflows` every time, set a default path in your configuration:

```bash
# Set default custom workflows path
cerno config set custom_workflows_path /path/to/my_workflows.yaml

# Now 'cerno review' automatically loads your workflows
cerno review
```

View your current configuration:

```bash
cerno config show
```

Reset to defaults:

```bash
cerno config reset
```

### When to Use Config vs CLI Flags

| Scenario | Recommended Approach |
|----------|---------------------|
| **Personal workflows** you use for all scans | Set `custom_workflows_path` config |
| **Project-specific workflows** for one engagement | Use `--custom-workflows` flag |
| **Testing new workflows** before committing | Use `--custom-workflows` flag |
| **Team-shared workflows** in version control | Document the flag in runbooks/scripts |
| **Completely replacing** bundled workflows | Use `--custom-workflows-only` flag |

### Configuration File Location

The configuration file is stored at:

- **Linux/macOS**: `~/.cerno/config.yaml`
- **Windows**: `C:\Users\<username>\.cerno\config.yaml`

---

## Merge Behavior

### `--custom-workflows` (Supplement Mode)

Supplements the bundled workflows with your custom workflows:

- **Bundled workflows are loaded first**
- **Custom workflows are loaded second**
- **If a plugin ID exists in both**, the custom workflow **overrides** the bundled one
- **All other bundled workflows remain available**

Example:

```bash
# Your custom workflows override bundled ones for matching plugin IDs
# All other bundled workflows remain available
cerno review --custom-workflows my_workflows.yaml
```

**Use case**: Adding new workflows or overriding specific bundled workflows while keeping the rest.

### `--custom-workflows-only` (Replace Mode)

Replaces the bundled workflows entirely:

- **Only your custom workflows are loaded**
- **Bundled workflows are completely ignored**
- **Plugins without custom workflows have no workflow available**

Example:

```bash
# ONLY your workflows are available - bundled workflows ignored
cerno review --custom-workflows-only my_workflows.yaml
```

**Use case**: Complete control over workflows, organizational policy requires custom workflows only.

### Override Behavior Details

When a plugin ID exists in both bundled and custom workflows:

1. **Custom workflow wins** - The entire workflow is replaced (not merged)
2. **Workflow name uniqueness** - Internally tracked by `workflow_name` to avoid duplicates
3. **Multi-plugin workflows** - Each plugin ID in a comma-separated list is registered separately

---

## Best Practices

### Organizing Large Workflow Files

For workflows covering 20+ plugins, consider:

1. **Group by category** using YAML comments:

```yaml
version: "1.0"

workflows:
  # ===== SSL/TLS Vulnerabilities =====

  - plugin_id: "20007,104743,157288"
    workflow_name: "Deprecated SSL/TLS Encryption"
    # ... workflow details ...

  # ===== SMB Vulnerabilities =====

  - plugin_id: "57608"
    workflow_name: "SMB Signing Not Required"
    # ... workflow details ...
```

2. **Split into multiple files** and combine:

```bash
# Load multiple workflow files (last file's conflicts win)
cerno review \
  --custom-workflows ssl_workflows.yaml \
  --custom-workflows smb_workflows.yaml
```

3. **Use version control** (Git) to track changes and share with team

### Naming Conventions for workflow_name

Use clear, descriptive names:

- ✅ **Good**: "SMB Signing Not Required", "Deprecated SSL/TLS Encryption"
- ❌ **Bad**: "Plugin 57608", "SSL Issue", "Check This"

**Why**: `workflow_name` is used as the unique identifier and displayed prominently in the TUI.

### Writing Clear Descriptions and Notes

**Descriptions** should briefly state what the workflow verifies:

```yaml
description: "Remote SMB server does not enforce message signing"  # Good
description: "SMB issue"  # Bad - too vague
```

**Notes** should explain what to look for and why it matters:

```yaml
notes: "Check output for 'Message signing: disabled' or similar. This indicates the server is vulnerable to NTLM relay attacks."  # Good
notes: "Run this command"  # Bad - doesn't add value
```

### Including Reference URLs

Always include:

1. **Tenable plugin URL** - Official vulnerability details
2. **Exploit/technique guides** - How to exploit or verify
3. **Mitigation documentation** - How to fix the issue

```yaml
references:
  - "https://www.tenable.com/plugins/nessus/57608"
  - "https://attack.mitre.org/techniques/T1557/001/"
  - "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always"
```

### When to Use Commands vs Notes

| Scenario | Use Commands | Use Notes |
|----------|--------------|-----------|
| **Concrete tool execution** | ✅ Yes | Optional (explain what to look for) |
| **Manual verification steps** | ❌ No | ✅ Yes (describe the manual process) |
| **Conceptual guidance** | ❌ No | ✅ Yes (explain the approach) |
| **Multiple tool options** | ✅ Yes (list all options) | ✅ Yes (explain when to use each) |

Example - Manual verification:

```yaml
- title: "Wireshark Analysis"
  commands: []  # No commands - this is manual
  notes: "Open the pcap file in Wireshark and find where the cleartext credentials were captured. Screenshot it and put it in your report."
```

---

## Complete Examples

### Example 1: Simple Single-Plugin Workflow

Basic workflow for verifying SNMP default community strings:

```yaml
version: "1.0"

workflows:
  - plugin_id: "41028"
    workflow_name: "SNMP Default Community Strings"
    description: "Default SNMP community string usage could allow for configuration read through SNMP queries and possibly a full SNMP MIB tree walk."

    steps:
      - title: "Enumerate SNMP info against the internal scope"
        commands:
          - "sudo nmap -sU -sV -p161 -T4 --script \"snmp* and not snmp-brute\" {TCP_IPS}"
        notes: ""

      - title: "Specifically use snmp-brute to verify this issue and to check for additional commonly used SNMP community strings"
        commands:
          - "sudo nmap -sU -sV -p161 -T4 --script snmp-brute {TCP_IPS}"
        notes: ""

    references:
      - "https://www.tenable.com/plugins/nessus/41028"
      - "https://www.blackhillsinfosec.com/snmp-strings-attached/"
```

### Example 2: Multi-Plugin Workflow

Single workflow mapped to multiple related plugins:

```yaml
version: "1.0"

workflows:
  - plugin_id: "20007,104743,157288"
    workflow_name: "Deprecated SSL/TLS Encryption"
    description: "Deprecated encryption protocol versions should be removed from support unless absolutely necessary."

    steps:
      - title: "Enumerate the supported encryption protocol versions and algorithms"
        commands:
          - "sudo nmap -A --script=ssl-enum-ciphers,ssl-cert,ssl-date {TCP_IPS}"
        notes: "SSLv2, SSLv3, and TLSv1.0 are all considered deprecated and should not be supported anymore. TLSv1.1 is also outdated but not of terrible concern."

    references:
      - "https://www.tenable.com/plugins/nessus/20007"
      - "https://www.tenable.com/plugins/nessus/104743"
      - "https://www.tenable.com/plugins/nessus/157288"
```

### Example 3: Workflow with Placeholders

Using multiple placeholders for flexible command generation:

```yaml
version: "1.0"

workflows:
  - plugin_id: "40984"
    workflow_name: "Investigate Browsable Web Directories"
    description: "Check for any filenames and content with confidential data."

    steps:
      - title: "Download browsable directory contents"
        commands:
          - "cd {WORKDIR}"
          - "wget -nc -r -l inf -i browsable.urls -P {RESULTS_DIR}/browsable"
        notes: "Downloads all files from browsable directories for offline analysis"

      - title: "Scan for secrets with Trufflehog"
        commands:
          - "trufflehog filesystem --json \"{RESULTS_DIR}/browsable\" > {OABASE}_trufflehog.json"
        notes: "Searches downloaded files for API keys, passwords, tokens, and other secrets"

    references:
      - "https://www.tenable.com/plugins/nessus/40984"
      - "https://www.blackhillsinfosec.com/rooting-for-secrets-with-trufflehog/"
```

### Example 4: Display-Only Workflow (Notes Without Commands)

Workflow providing guidance without executable commands:

```yaml
version: "1.0"

workflows:
  - plugin_id: "42263"
    workflow_name: "Unencrypted Telnet Server"
    description: "The primary risk posed by unencrypted network protocols is that an attacker can eavesdrop on communication and extract any information in it, such as confidential data and credentials."

    steps:
      - title: "Verify Telnet usage"
        commands:
          - "sudo nmap -A -p 23 {TCP_IPS}"
        notes: ""

      - title: "Intercept cleartext traffic for proof-of-concept"
        commands:
          - "tcpdump tcp port 23 and dst {TCP_IPS} -i eth0 -w {OABASE}_telnet.pcap -tttt"
          - "telnet {TCP_IPS} 23"
        notes: "Start tcpdump to capture packets then trigger a telnet connection. Enter any credentials you want. We're just trying to prove the capturing."

      - title: "Wireshark Analysis"
        commands: []  # No automated commands - manual analysis required
        notes: "Open the pcap file in Wireshark and find where the cleartext credentials were captured. Screenshot it and put it in your report."

    references:
      - "https://www.tenable.com/plugins/nessus/42263"
```

### Example 5: Complex Multi-Step Workflow

Comprehensive workflow with multiple tools and detailed notes:

```yaml
version: "1.0"

workflows:
  - plugin_id: "57608"
    workflow_name: "SMB Signing Not Required"
    description: "Remote SMB server does not enforce message signing"

    steps:
      - title: "Verify SMB signing is disabled"
        commands:
          - "netexec smb {TCP_IPS} -u guest -p ''"
          - "nmap -p445 --script smb-security-mode {TCP_IPS}"
        notes: "Check output for 'Message signing: disabled' or similar. NetExec shows signing status in its output banner."

      - title: "Test NTLM relay attack feasibility"
        commands:
          - "responder -I eth0 -A"
          - "ntlmrelayx.py -tf {WORKDIR}/relay_targets.txt -smb2support"
        notes: "Start Responder in analyze mode to capture NTLM authentication attempts. Use ntlmrelayx to relay captured hashes to target systems. Create relay_targets.txt with hosts from {TCP_IPS}."

      - title: "Enumerate accessible shares"
        commands:
          - "netexec smb {TCP_IPS} -u <username> -p <password> --shares"
          - "smbclient -L //{TCP_IPS} -U <username>"
        notes: "List available SMB shares and permissions. If you've relayed credentials, use those to enumerate further access."

    references:
      - "https://www.tenable.com/plugins/nessus/57608"
      - "https://attack.mitre.org/techniques/T1557/001/"
      - "https://www.blackhillsinfosec.com/smb-relay-demystified-and-ntlmv2-pwnage-with-python/"
```

---

## Troubleshooting

### YAML Syntax Errors

**Symptom**: Error message when loading workflows:

```
Failed to parse workflow YAML: my_workflows.yaml
Syntax error: mapping values are not allowed here
```

**Common causes**:

1. **Missing quotes around strings with colons**:

```yaml
# ❌ Wrong - colon in unquoted string
description: Error: This will fail

# ✅ Correct - quoted string
description: "Error: This will fail"
```

2. **Incorrect indentation** (YAML requires consistent spaces, not tabs):

```yaml
# ❌ Wrong - inconsistent indentation
steps:
  - title: "Step 1"
      commands:
      - "command"

# ✅ Correct - consistent 2-space indentation
steps:
  - title: "Step 1"
    commands:
      - "command"
```

3. **Missing required fields**:

```yaml
# ❌ Wrong - missing 'commands' field
steps:
  - title: "Step 1"
    notes: "Some notes"

# ✅ Correct - include commands (can be empty)
steps:
  - title: "Step 1"
    commands: []
    notes: "Some notes"
```

**Solution**: Validate YAML syntax:

```bash
python -c "import yaml; yaml.safe_load(open('my_workflows.yaml'))"
```

### Workflow Not Appearing in TUI

**Symptom**: Press **[W]** but see "No workflow available for this plugin"

**Possible causes**:

1. **Plugin ID mismatch** - Check that your `plugin_id` matches exactly:

```bash
# Find the plugin ID for a finding
cerno review  # Navigate to finding, check displayed plugin ID
```

2. **Workflow file not loaded** - Verify you passed the `--custom-workflows` flag:

```bash
# ❌ Wrong - workflows not loaded
cerno review

# ✅ Correct - explicitly load workflows
cerno review --custom-workflows my_workflows.yaml
```

3. **Workflow replaced by bundled workflow** - Your custom workflow might be overridden:

```bash
# Use --custom-workflows-only to ensure your workflow is used
cerno review --custom-workflows-only my_workflows.yaml
```

4. **YAML syntax error** - Check logs for parsing errors:

```bash
# Enable debug logging
cerno config set debug_logging true
cerno review --custom-workflows my_workflows.yaml
tail -f ~/.cerno/cerno.log
```

### Placeholder Not Expanding

**Symptom**: Command shows literal `{TCP_IPS}` instead of file path

**Cause**: Placeholders are only expanded in **custom commands** (when you choose "Custom" tool option), not in workflow display.

**Expected behavior**:

- **Workflow display**: Shows placeholders as-is (e.g., `{TCP_IPS}`)
- **Custom commands**: Expands placeholders to actual values
- **Copied commands**: Placeholders remain as-is (you must manually replace)

**Solution**: If you need expanded values, use the **Copy** option in the TUI and manually replace placeholders with the actual file paths shown in Cerno's output.

### File Not Found Errors

**Symptom**: Error when loading workflows:

```
Additional workflow file not found: /path/to/my_workflows.yaml
```

**Solution**:

1. **Check file path**:

```bash
ls -l /path/to/my_workflows.yaml
```

2. **Use absolute paths** in config:

```bash
# ❌ Relative paths may not work from all directories
cerno config set custom_workflows_path ./my_workflows.yaml

# ✅ Use absolute paths
cerno config set custom_workflows_path /home/user/workflows/my_workflows.yaml
```

3. **Verify file permissions**:

```bash
chmod 644 my_workflows.yaml
```

### Common YAML Formatting Mistakes

| Mistake | Symptom | Fix |
|---------|---------|-----|
| **Tab characters** | "found character '\\t'" | Use spaces only (2-space indentation) |
| **Missing dash for list items** | "expected a single document" | Add `-` before each list item |
| **Unquoted plugin IDs with commas** | Parsed as separate values | Quote plugin_id: `"20007,104743"` |
| **Windows line endings (\\r\\n)** | Parsing errors | Convert to Unix (\\n) with `dos2unix` |
| **Missing colon after key** | "mapping values not allowed" | Ensure `key: value` format |

---

## Advanced Topics

### Listing All Workflows

View all available workflows (bundled + custom):

```bash
# List all workflows
cerno workflow list

# With custom workflows
cerno workflow list --custom-workflows my_workflows.yaml
```

Output shows:

- Plugin ID(s)
- Workflow name
- Description

### Reloading Workflows (Auto-Reload on File Modification)

Cerno automatically reloads workflow files when they're modified:

1. **During review session**: Workflow files are checked for modifications before each access
2. **No restart required**: Edit your workflow YAML, save, and immediately use it
3. **Modification tracking**: Uses file modification time (`mtime`) to detect changes

This enables rapid workflow development:

```bash
# Terminal 1: Start review
cerno review --custom-workflows my_workflows.yaml

# Terminal 2: Edit workflows while review is running
vim my_workflows.yaml

# Terminal 1: Press [W] - sees updated workflow immediately
```

### Organizing Workflows by Category

For large workflow collections, use YAML comments to organize by category:

```yaml
version: "1.0"

workflows:
  # =============================================================================
  # SSL/TLS VULNERABILITIES
  # =============================================================================

  - plugin_id: "20007,104743,157288"
    workflow_name: "Deprecated SSL/TLS Encryption"
    # ...

  # =============================================================================
  # SMB VULNERABILITIES
  # =============================================================================

  - plugin_id: "57608"
    workflow_name: "SMB Signing Not Required"
    # ...

  # =============================================================================
  # WEB APPLICATION VULNERABILITIES
  # =============================================================================

  - plugin_id: "40984"
    workflow_name: "Investigate Browsable Web Directories"
    # ...
```

### Sharing Workflows Across Teams

Best practices for sharing workflows:

1. **Use version control** (Git):

```bash
# Initialize repository
cd ~/workflows
git init
git add cerno_workflows.yaml
git commit -m "Initial workflow collection"

# Share with team
git remote add origin https://github.com/yourteam/cerno-workflows.git
git push -u origin main
```

2. **Document workflow usage** in README:

```markdown
# Team Cerno Workflows

## Installation

```bash
git clone https://github.com/yourteam/cerno-workflows.git ~/cerno-workflows
cerno config set custom_workflows_path ~/cerno-workflows/workflows.yaml
```

3. **Use consistent naming conventions** across team

4. **Review workflows in pull requests** before merging

5. **Tag releases** for stable workflow versions:

```bash
git tag -a v1.0 -m "Initial stable release"
git push --tags
```

6. **Include examples** and troubleshooting in repository

---

## Additional Resources

- **Bundled workflows**: See `cerno_pkg/workflow_mappings.yaml` for 8 complete examples
- **Configuration guide**: Run `cerno config show` to see all available settings
- **Main documentation**: See [README.md](../README.md) for general Cerno usage
- **Tool system guide**: See [TOOL_SYSTEM_GUIDE.md](TOOL_SYSTEM_GUIDE.md) for tool integration details
- **Database schema**: See [DATABASE.md](DATABASE.md) for database design principles

---

## Contributing

Found an issue or want to improve this guide? Contributions welcome:

- **Issues**: [GitHub Issues](https://github.com/DefensiveOrigins/cerno/issues)
- **Pull Requests**: [GitHub Pull Requests](https://github.com/DefensiveOrigins/cerno/pulls)

---

**Last Updated**: 2026-01-14
