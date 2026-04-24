"""Claude Assistant integration (BETA) — interactive AI chat for Nessus findings.

Provides on-demand AI-assisted analysis via the Claude CLI (`claude -p`) at three scopes:

  - Per-finding:  [A] in finding detail view → build_finding_context() + run_exchange()
                  History keyed to finding_id in claude_conversations table.

  - Severity menu: [A] at severity selection → build_aggregate_context() + run_aggregate_exchange()
                   Context covers all findings in the selected scan(s).

  - Findings list: [A] in findings list footer → build_aggregate_context() + run_aggregate_exchange()
                   Context covers the current candidates (respects severity/name/group filters).
                   History keyed by a deterministic context_key in claude_aggregate_conversations.

Availability gate: only active when `claude` is on PATH and claude_assistant_enabled=True
in user config. Matches the pattern used for nmap/netexec/msfconsole availability checks.

Aggregate context caps at 50 findings, ordered Critical→Info, with a note on what was
excluded when the cap is hit.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .logging_setup import log_debug, log_error

if TYPE_CHECKING:
    from .models import ClaudeAggregateConversationTurn, ClaudeConversationTurn, Finding, Plugin
    from .workflow_mapper import Workflow


BETA_NOTICE = (
    "[bold yellow]Claude Assistant (BETA)[/bold yellow]\n"
    "[dim]Responses may be inaccurate. Always verify before acting on suggestions.[/dim]"
)

# Keywords that trigger a pentest report brief instead of a freeform question
REPORT_BRIEF_TRIGGERS: frozenset[str] = frozenset({"report"})

# Expanded prompt sent to Claude when a report brief trigger is detected
REPORT_BRIEF_QUERY = (
    "Write a brief finding summary suitable for inclusion in a penetration test report. "
    "Requirements: write entirely in past tense; mention the specific affected systems "
    "(IP addresses or hostnames) and ports from the context; include the finding name and "
    "severity; if any Metasploit modules are listed in the context, name them; keep it to "
    "2–3 sentences. "
    "Use plain prose only — no markdown, no headers, no bullet points."
)

# Minimal fallback prompt if skill file cannot be found (e.g. pipx install)
_FALLBACK_SKILL_PROMPT = """
You are a security analysis assistant embedded in Cerno, a CLI tool for reviewing
Nessus vulnerability scan findings. Help analysts assess exploitability and plan
verification steps. Be concise (2-4 sentences), actionable, and flag uncertainty.
Only suggest nmap, netexec, or msfconsole for verification. Do not use markdown
headers or bullet walls in responses.
""".strip()

# Module-level availability cache (computed once per process)
_claude_available: bool | None = None


def check_claude_available() -> bool:
    """Return True if the 'claude' CLI is on PATH.

    Result is cached for the lifetime of the process.

    Returns:
        True if claude binary is found, False otherwise
    """
    global _claude_available
    if _claude_available is None:
        _claude_available = shutil.which("claude") is not None
    return _claude_available


def load_skill_prompt() -> str:
    """Load the cerno-assistant skill file as a system prompt string.

    Reads the bundled skill at cerno_pkg/skills/cerno-assistant.md.
    Falls back to a minimal inline prompt if the file is not found.

    Returns:
        Skill file contents, or minimal fallback prompt string
    """
    try:
        pkg_dir = Path(__file__).parent
        skill_path = pkg_dir / "skills" / "cerno-assistant.md"
        if skill_path.exists():
            content = skill_path.read_text(encoding="utf-8")
            log_debug(f"Loaded skill prompt from {skill_path} ({len(content)} chars)")
            return content
        log_debug("Bundled skill file not found, using fallback prompt")
    except Exception as exc:
        log_error(f"Failed to load skill file: {exc}")
    return _FALLBACK_SKILL_PROMPT


def build_finding_context(
    plugin: Plugin,
    finding: Finding,
    hosts: list[str],
    plugin_outputs: list[tuple[str, int | None, str | None]] | None = None,
    workflow: "Workflow | None" = None,
) -> str:
    """Assemble a structured context block describing the finding.

    Args:
        plugin: Plugin database object with metadata
        finding: Finding database object with review state
        hosts: List of affected host strings (host:port format)
        plugin_outputs: Optional list of (host, port, plugin_output) tuples from
            finding_affected_hosts. When provided, the raw Nessus scanner output
            is appended to the context so Claude can reference specific banners,
            version strings, and paths discovered during the scan.
        workflow: Optional Workflow object containing verification steps and references
            to include in the context. Steps with empty ``notes`` string omit the Notes line.

    Returns:
        Formatted context string to prepend to the prompt
    """
    lines: list[str] = ["=== Finding Context ==="]
    lines.append(f"Plugin ID: {plugin.plugin_id}")
    lines.append(f"Plugin Name: {plugin.plugin_name}")

    severity_labels = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    sev_label = severity_labels.get(plugin.severity_int, str(plugin.severity_int))
    lines.append(f"Severity: {sev_label} ({plugin.severity_int})")

    if plugin.cvss3_score is not None:
        lines.append(f"CVSS3 Score: {plugin.cvss3_score}")
    elif plugin.cvss2_score is not None:
        lines.append(f"CVSS2 Score: {plugin.cvss2_score}")

    if plugin.cves:
        cve_list = plugin.cves if isinstance(plugin.cves, list) else [plugin.cves]
        lines.append(f"CVEs: {', '.join(str(c) for c in cve_list)}")
    else:
        lines.append("CVEs: None")

    if plugin.has_metasploit and plugin.metasploit_names:
        msf_list = (
            plugin.metasploit_names
            if isinstance(plugin.metasploit_names, list)
            else [plugin.metasploit_names]
        )
        lines.append(f"Metasploit Modules: {', '.join(str(m) for m in msf_list)}")
    else:
        lines.append("Metasploit Modules: None")

    lines.append(f"Review State: {finding.review_state}")

    if hosts:
        host_display = hosts[:10]
        lines.append(f"Affected Hosts ({len(hosts)} total):")
        for h in host_display:
            lines.append(f"  {h}")
        if len(hosts) > 10:
            lines.append(f"  ... and {len(hosts) - 10} more")
    else:
        lines.append("Affected Hosts: (none recorded)")

    # Note if this is a multi-scan representative finding
    if finding.extra_finding_ids:
        scan_count = 1 + len(finding.extra_finding_ids)
        lines.append(f"Note: This finding appears in {scan_count} selected scans.")

    if plugin_outputs:
        MAX_HOSTS = 5
        MAX_CHARS = 600
        lines.append("")
        lines.append("=== Nessus Plugin Output ===")
        shown = plugin_outputs[:MAX_HOSTS]
        for host, port, output in shown:
            label = f"{host}:{port}" if port else host
            lines.append(f"Host: {label}")
            if output:
                text = output.strip()
                if len(text) > MAX_CHARS:
                    text = text[:MAX_CHARS] + f"\n... [truncated, {len(output) - MAX_CHARS} chars omitted]"
                lines.append(text)
            else:
                lines.append("(no plugin output recorded)")
        if len(plugin_outputs) > MAX_HOSTS:
            lines.append(f"... and {len(plugin_outputs) - MAX_HOSTS} more host(s) omitted")

    if workflow is not None:
        lines.append("")
        lines.append("=== Verification Workflow ===")
        lines.append(f"Workflow: {workflow.workflow_name}")
        if workflow.description:
            lines.append(f"Description: {workflow.description}")
        for i, step in enumerate(workflow.steps, start=1):
            lines.append("")
            lines.append(f"Step {i}: {step.title}")
            if step.commands:
                lines.append("Commands:")
                for cmd in step.commands:
                    lines.append(f"  {cmd}")
            if step.notes:
                lines.append(f"Notes: {step.notes}")
        if workflow.references:
            lines.append("")
            lines.append("References:")
            for ref in workflow.references:
                lines.append(f"  {ref}")
        lines.append("=== End Workflow ===")

    lines.append("=== End Context ===")
    return "\n".join(lines)


def format_prompt(
    skill: str,
    context: str,
    turns: "list[Any]",
    question: str,
) -> str:
    """Build the full prompt string for `claude -p`.

    Format:
        <skill>

        <context>

        [Human: ...\nAssistant: ...]*
        Human: <question>

    Args:
        skill: Skill file contents (system guidance)
        context: Structured finding context block
        turns: Prior conversation turns (alternating user/assistant)
        question: Current user question

    Returns:
        Complete prompt string
    """
    parts: list[str] = [skill, "", context, ""]

    for turn in turns:
        role_label = "Human" if turn.role == "user" else "Assistant"
        parts.append(f"{role_label}: {turn.content}")

    parts.append(f"Human: {question}")

    prompt = "\n".join(parts)
    log_debug(
        f"claude_assistant: built prompt ({len(prompt)} chars, {len(turns)} prior turns)"
    )
    return prompt


def ask_claude(prompt: str, timeout: int = 120) -> tuple[str, int]:
    """Invoke `claude -p '<prompt>'` and return the response.

    Uses subprocess with a timeout. Captures stdout only; stderr is discarded
    to avoid polluting the TUI.

    Args:
        prompt: Full prompt string to pass to claude -p
        timeout: Subprocess timeout in seconds (default: 120)

    Returns:
        Tuple of (response_text, exit_code). response_text is empty string on error.
    """
    try:
        result = subprocess.run(
            ["claude", "-p", prompt],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        response = result.stdout.strip()
        log_debug(
            f"claude_assistant: response received ({len(response)} chars, "
            f"exit_code={result.returncode})"
        )
        return response, result.returncode
    except subprocess.TimeoutExpired:
        log_error(f"claude_assistant: subprocess timed out after {timeout}s")
        return "(Claude did not respond in time. Try again.)", 1
    except FileNotFoundError:
        log_error("claude_assistant: 'claude' binary not found")
        return "(claude CLI not found. Check PATH.)", 127
    except Exception as exc:
        log_error(f"claude_assistant: unexpected error: {exc}")
        return f"(Error contacting Claude: {exc})", 1


def run_exchange(
    conn: object,
    finding_id: int,
    plugin: Plugin,
    finding: Finding,
    hosts: list[str],
    question: str,
    workflow: "Workflow | None" = None,
) -> str:
    """Perform a full Claude exchange: load history, build prompt, call claude, persist.

    Args:
        conn: SQLite database connection
        finding_id: Finding ID (representative ID for multi-scan mode)
        plugin: Plugin database object
        finding: Finding database object
        hosts: Affected host strings
        question: User question text
        workflow: Optional Workflow object containing verification steps and references

    Returns:
        Claude's response text (or an error message)
    """
    from .models import ClaudeConversationTurn  # local import avoids circular dep

    import sqlite3 as _sqlite3

    assert isinstance(conn, _sqlite3.Connection)

    turns = ClaudeConversationTurn.get_by_finding(conn, finding_id)
    skill = load_skill_prompt()
    plugin_outputs = finding.get_plugin_outputs_by_host(conn)
    context = build_finding_context(plugin, finding, hosts, plugin_outputs, workflow=workflow)
    prompt = format_prompt(skill, context, turns, question)

    response, exit_code = ask_claude(prompt)

    if exit_code == 0 and response:
        # Persist both turns
        ClaudeConversationTurn.add(conn, finding_id, "user", question)
        ClaudeConversationTurn.add(conn, finding_id, "assistant", response)

    return response


def build_aggregate_context(
    scan_names: list[str],
    scope_description: str,
    findings_with_plugins: list[tuple[Any, Any]],
) -> str:
    """Assemble a context block summarising a collection of findings.

    Used for severity-menu and findings-list aggregate conversations where the
    analyst wants to discuss a broad scope rather than a single finding.

    Args:
        scan_names: Display names of the selected scan(s)
        scope_description: Human-readable description of what's in scope
        findings_with_plugins: List of (Finding, Plugin) tuples in scope

    Returns:
        Formatted context string to prepend to the prompt
    """
    from collections import Counter

    severity_labels = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    total = len(findings_with_plugins)

    lines: list[str] = ["=== Aggregate Findings Context ==="]
    lines.append(f"Scans: {', '.join(scan_names)}")
    lines.append(f"Scope: {scope_description}")
    lines.append(f"Total findings in scope: {total}")

    # Severity breakdown
    sev_counts: Counter[int] = Counter()
    for _finding, plugin in findings_with_plugins:
        sev_counts[plugin.severity_int] += 1
    if sev_counts:
        lines.append("Severity breakdown:")
        for sev_int in sorted(sev_counts.keys(), reverse=True):
            label = severity_labels.get(sev_int, str(sev_int))
            lines.append(f"  {label}: {sev_counts[sev_int]}")

    # Review state breakdown
    state_counts: Counter[str] = Counter()
    for finding, _plugin in findings_with_plugins:
        state_counts[finding.review_state] += 1
    if state_counts:
        lines.append("Review state:")
        for state, count in state_counts.most_common():
            lines.append(f"  {state}: {count}")

    # MSF summary
    msf_count = sum(1 for _f, p in findings_with_plugins if p.has_metasploit)
    if msf_count:
        lines.append(f"MSF-exploitable: {msf_count}")

    # Total unique CVE count
    all_cves: set[str] = set()
    for _f, plugin in findings_with_plugins:
        if plugin.cves:
            cve_list = plugin.cves if isinstance(plugin.cves, list) else [plugin.cves]
            all_cves.update(str(c) for c in cve_list)
    if all_cves:
        lines.append(f"Unique CVEs: {len(all_cves)}")

    # Findings list (capped at 50, sorted Critical→Info, one line per finding)
    cap = 50
    sorted_findings = sorted(
        findings_with_plugins, key=lambda fp: fp[1].severity_int, reverse=True
    )
    lines.append(f"Findings ({min(total, cap)} of {total}, highest severity first):")
    for i, (finding, plugin) in enumerate(sorted_findings[:cap], 1):
        sev_label = severity_labels.get(plugin.severity_int, str(plugin.severity_int))
        hosts, _ = finding.get_hosts_and_ports()
        host_count = len(hosts)
        msf_flag = "yes" if plugin.has_metasploit else "no"
        cve_str = "none"
        if plugin.cves:
            cve_list = plugin.cves if isinstance(plugin.cves, list) else [plugin.cves]
            shown = [str(c) for c in cve_list[:3]]
            cve_str = ", ".join(shown)
            if len(cve_list) > 3:
                cve_str += f" +{len(cve_list) - 3} more"
        lines.append(
            f"[{i}] {sev_label:<8} | {plugin.plugin_name} (ID:{plugin.plugin_id})"
            f" | {host_count} hosts | CVEs: {cve_str} | MSF: {msf_flag}"
        )
    if total > cap:
        lowest_shown = sorted_findings[cap - 1][1].severity_int
        lowest_label = severity_labels.get(lowest_shown, str(lowest_shown))
        lines.append(f"[Excluded: {total - cap} findings below {lowest_label} severity not shown]")

    lines.append("=== End Context ===")
    return "\n".join(lines)


def run_aggregate_exchange(
    conn: object,
    context_key: str,
    scope_description: str,
    scan_names: list[str],
    findings_with_plugins: list[tuple[Any, Any]],
    question: str,
) -> str:
    """Full aggregate exchange: load history → build prompt → call claude → persist.

    Args:
        conn: SQLite database connection
        context_key: Deterministic key identifying this conversation scope
        scope_description: Human-readable scope for display and context
        scan_names: Names of the selected scan(s)
        findings_with_plugins: List of (Finding, Plugin) tuples in scope
        question: User question text

    Returns:
        Claude's response text (or an error message)
    """
    from .models import ClaudeAggregateConversationTurn

    import sqlite3 as _sqlite3

    assert isinstance(conn, _sqlite3.Connection)

    turns = ClaudeAggregateConversationTurn.get_by_context(conn, context_key)
    skill = load_skill_prompt()
    context = build_aggregate_context(scan_names, scope_description, findings_with_plugins)
    prompt = format_prompt(skill, context, turns, question)

    response, exit_code = ask_claude(prompt)

    if exit_code == 0 and response:
        ClaudeAggregateConversationTurn.add(conn, context_key, "user", question)
        ClaudeAggregateConversationTurn.add(conn, context_key, "assistant", response)

    return response
