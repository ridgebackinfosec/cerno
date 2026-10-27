"""Workflow contribution feedback loop: draft, sanitize and export workflows.

When a finding is verified (verdict ``confirmed`` / ``false_positive``), the
commands actually run against it (``tool_executions`` rows attributed to the
finding) are turned into a candidate verification workflow for the bundled
``workflow_mappings.yaml``:

- **new** — the plugin has no mapped workflow; the trail becomes one.
- **enhanced** — the plugin is mapped but at least one non-baseline command run
  is absent from it; the existing steps are kept and the new commands appended.
- **skip** (``None``) — the existing workflow was used unchanged (or only Cerno's
  own baseline commands were run).

Safety invariant: nothing is ever submitted. Commands are *genericized* (hosts →
``<TARGET>``, ports → ``<PORT>``, credentials → ``<USERNAME>``/``<PASSWORD>``/
``<DOMAIN>``, output/target-file paths dropped or templated) and every exported
field must pass a fail-closed leak scan (residual IPs, the engagement's host
names, scan names, NetExec usernames/domains, local paths). Free-form review and
verdict notes are never read. Export is a local YAML file only.

The functions here are pure apart from the DB readers (``build_leak_context``,
``assess_candidate``, and ``build_candidate``/``candidate_from_override``, which
read the finding's hosts/ports); the MCP adapters live in ``mcp_server/server.py``.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

import yaml

from .exec_chain import split_wrappers
from .models import Finding, Host, Plugin, Scan, ToolExecution
from .workflow_mapper import Workflow, WorkflowMapper
from .workflow_prep import canonicalize_placeholders

#: Verdicts that mark a finding verified, so its trail is worth contributing.
CONTRIBUTABLE_VERDICTS = frozenset({"confirmed", "false_positive"})

REPO_URL = "https://github.com/ridgebackinfosec/cerno"
WORKFLOWS_URL = f"{REPO_URL}/blob/develop/cerno_pkg/workflow_mappings.yaml"
CONTRIBUTING_URL = f"{REPO_URL}/blob/develop/CONTRIBUTING.md"

SUBMISSION_INSTRUCTIONS = (
    f"1. Fork {REPO_URL} and create a branch from develop.\n"
    "2. Merge the workflows entry from the exported file into "
    f"cerno_pkg/workflow_mappings.yaml ({WORKFLOWS_URL}); for an enhancement, "
    "update the existing entry in place.\n"
    "3. Test it locally: cerno review --custom-workflows <exported file>, then press "
    "[W] on a matching finding.\n"
    "4. Run pytest, black cerno_pkg/ and mypy cerno_pkg/ --ignore-missing-imports.\n"
    "5. Open a pull request against the develop branch (not main); see "
    f"CONTRIBUTING.md ({CONTRIBUTING_URL})."
)

_TARGET = "<TARGET>"
_PORT = "<PORT>"
_USERNAME = "<USERNAME>"
_PASSWORD = "<PASSWORD>"
_DOMAIN = "<DOMAIN>"

_SECRET_MASK = "********"
#: Same token shape as ``mcp_server.server._CRED_PLACEHOLDER_RE`` (kept local so the
#: core module never imports the MCP server).
_CRED_PLACEHOLDER_RE = re.compile(r"@cred:[^@]+@")

#: Wrappers kept in an exported command (bundled workflows use ``sudo nmap``);
#: every other wrapper (proxychains4, timeout, env, ...) is environment-specific.
_KEPT_WRAPPERS = ("sudo", "doas")

#: tool_executions rows that are audit events, not commands.
_NON_COMMAND_TOOLS = frozenset({"cred_reveal"})

_NMAP_OUTPUT_FLAGS = frozenset({"-oA", "-oX", "-oN", "-oG", "-oS", "-oM"})
_NMAP_PORT_VALUE_RE = re.compile(r"^[0-9TUS:,\-]+$")
_NXC_BINARIES = frozenset({"nxc", "netexec"})
_NXC_DROP_WITH_VALUE = frozenset({"--log"})
_NXC_VALUE_SUBST = {
    "-u": _USERNAME,
    "--username": _USERNAME,
    "-d": _DOMAIN,
    "--domain": _DOMAIN,
    "-p": _PASSWORD,
    "--password": _PASSWORD,
    "-H": _PASSWORD,
    "--hash": _PASSWORD,
}
_NXC_BASELINE_VALUE_FLAGS = frozenset(set(_NXC_VALUE_SUBST) | {"--gen-relay-list"})
_NXC_BASELINE_FLAGS = frozenset({"--shares", "--local-auth"})
_RELAY_LIST_NAME = "relay_targets.txt"

#: Identifiers this short, or this generic, are never treated as engagement data
#: (a scan called "smb" must not make every ``nxc smb`` command a "leak").
_MIN_IDENTIFIER_LEN = 3
#: Dictionary usernames that collide with ordinary plugin/workflow wording
#: ("FTP Anonymous Login"); never engagement data, so never a leak.
_GENERIC_USERNAMES = frozenset(
    {
        "anonymous", "admin", "administrator", "root", "guest", "user", "test",
        "ftp", "nobody", "demo", "default", "operator", "support", "backup",
        "postgres", "mysql", "oracle",
    }
)  # fmt: skip
_GENERIC_WORDS = (
    frozenset(
        {
            "nmap", "nxc", "netexec", "smb", "ssh", "ldap", "ldaps", "rdp", "winrm",
            "mssql", "wmi", "vnc", "nfs", "http", "https", "target", "port",
            "local", "localhost", "domain", "workgroup",
        }
    )  # fmt: skip
    | _GENERIC_USERNAMES
)
_ALLOWED_IPS = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})

#: Secret values shorter than this are not matched (too collision-prone).
_MIN_SECRET_LEN = 4
#: NT hash, or LM:NT pair, as dumped by secretsdump/nxc.
_HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?::[0-9A-Fa-f]{32})?(?![0-9A-Fa-f])"
)
#: Path prefixes that identify the operator's own machine (checked even in
#: plugin-derived fields, where generic ``/`` paths like ``/cgi-bin/`` are normal).
_LOCAL_PATH_PREFIXES = ("~", "/home/", "/root/", "/Users/", "/tmp/", "/mnt/", "/media/")
_WORD_EDGE = "A-Za-z0-9_"

_IPV4_RE = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9])")
_IPV6_RE = re.compile(
    r"(?<![0-9A-Za-z:])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![0-9A-Za-z:])"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class LeakContext:
    """Engagement identifiers that must never appear in an exported workflow.

    ``extra`` holds other identifiers (e.g. NetExec domains); ``usernames`` are
    kept separate because plugin-derived fields are never checked for them.
    ``secrets`` are credential values held in memory for comparison only — they
    are excluded from ``repr`` and never echoed in a hit.
    """

    host_identifiers: list[str] = field(default_factory=list)
    scan_names: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list, repr=False)

    def identifiers(self, *, include_usernames: bool = True) -> list[str]:
        """Checkable identifiers: long enough, not generic, not IPs (IPs are
        caught by the literal scan, which also catches ones not in the DB).
        Usernames are added only when ``include_usernames``."""
        out: list[str] = []
        seen: set[str] = set()
        pool = [*self.host_identifiers, *self.scan_names, *self.extra]
        if include_usernames:
            pool.extend(self.usernames)
        for ident in pool:
            text = (ident or "").strip()
            key = text.lower()
            if (
                len(text) < _MIN_IDENTIFIER_LEN
                or key in _GENERIC_WORDS
                or key in seen
                or _is_ip(text)
            ):
                continue
            seen.add(key)
            out.append(text)
        return out

    def checkable_secrets(self) -> list[str]:
        """Secret values worth matching: long enough and not a dictionary word
        (an anonymous-FTP password of ``anonymous`` is not a secret)."""
        return [
            s
            for s in dict.fromkeys(self.secrets)
            if s and len(s) >= _MIN_SECRET_LEN and s.lower() not in _GENERIC_WORDS
        ]


@dataclass
class CandidateStep:
    title: str
    commands: list[str]
    notes: str = ""


@dataclass
class Candidate:
    """A drafted (or operator-edited) workflow entry ready for review/export."""

    finding_id: int
    plugin_id: int
    yaml_plugin_id: str  # the entry's plugin_id (keeps a multi-ID entry intact)
    reason: str  # "new" | "enhanced"
    workflow_name: str
    description: str
    steps: list[CandidateStep]
    references: list[str]
    new_commands: list[str] = field(default_factory=list)
    possibly_superseded: list[str] = field(default_factory=list)
    review_hints: list[str] = field(default_factory=list)
    existing_commands: list[str] = field(default_factory=list)
    source_execution_ids: list[int] = field(default_factory=list)

    def to_entry(self) -> dict:
        """The ``workflows[]`` entry, in workflow_mappings.yaml key order."""
        return {
            "plugin_id": self.yaml_plugin_id,
            "workflow_name": self.workflow_name,
            "description": self.description,
            "steps": [
                {"title": s.title, "commands": list(s.commands), "notes": s.notes}
                for s in self.steps
            ],
            "references": list(self.references),
        }


@dataclass
class Assessment:
    """Result of assessing a finding's trail: the candidate (or None) plus the
    executions dropped because they still leaked engagement data."""

    candidate: Optional[Candidate]
    excluded: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tokenizing helpers
# ---------------------------------------------------------------------------


def _split(text: str) -> list[str]:
    """Shell-split ``text``; fall back to whitespace split for unbalanced quotes.

    MCP ``command_text`` is space-joined argv (not shell-quoted), so a value that
    originally contained spaces cannot be recovered exactly — a known limitation.
    """
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _join(tokens: Iterable[str]) -> str:
    """Re-join tokens, double-quoting only those containing whitespace."""
    return " ".join(f'"{t}"' if any(ch.isspace() for ch in t) else t for t in tokens)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    return True


def _binary_of(tokens: Sequence[str]) -> str:
    """Basename of the command's real binary (``netexec`` folded into ``nxc``)."""
    _, argv = split_wrappers(tokens)
    if not argv:
        return ""
    name = Path(argv[0]).name
    return "nxc" if name in _NXC_BINARIES else name


def _host_pattern(identifiers: Sequence[str]) -> Optional[re.Pattern[str]]:
    """Boundary-anchored, longest-first alternation of host identifiers.

    The boundaries stop ``10.0.0.1`` matching inside ``10.0.0.10`` and ``dc01``
    matching inside ``dc01x``; ``dc01.corp.local`` is tried before ``dc01``.
    """
    idents = sorted({i for i in identifiers if i}, key=len, reverse=True)
    if not idents:
        return None
    alt = "|".join(re.escape(i) for i in idents)
    return re.compile(
        rf"(?<![A-Za-z0-9_.\-])(?:{alt})(?![A-Za-z0-9_\-]|\.[A-Za-z0-9])",
        re.IGNORECASE,
    )


def _generic_port_value(value: str, ports: frozenset[str]) -> str:
    """``<PORT>`` when every element of an nmap port spec is a finding port."""
    if value == _PORT:
        return value
    elements = [e.split(":", 1)[-1] for e in value.split(",") if e]
    if elements and ports and all(e in ports for e in elements):
        return _PORT
    return value


def _looks_like_file(token: str) -> bool:
    return "/" in token or "\\" in token or token.endswith((".txt", ".list", ".lst"))


# ---------------------------------------------------------------------------
# Sanitizer
# ---------------------------------------------------------------------------


def genericize_command(
    command_text: str, hosts: Sequence[str], ports: Sequence[object]
) -> str:
    """Turn a real, logged command into a reusable workflow command.

    The inverse of ``workflow_prep``'s fill: each of the finding's host
    identifiers → ``<TARGET>`` (runs collapsed to one), finding ports in port
    positions → ``<PORT>``, nxc ``-u``/``-d``/``-p``/``-H`` values →
    ``<USERNAME>``/``<DOMAIN>``/``<PASSWORD>``, masked secrets and
    ``@cred:<ref>@`` → ``<PASSWORD>``. nmap ``-iL <file>`` and nxc's positional
    target file become ``<TARGET>``; nmap ``-o*`` and nxc ``--log`` outputs are
    dropped; ``--gen-relay-list <path>`` gets a generic file name. Environment
    wrappers (proxychains4, timeout, env, ...) are stripped; sudo/doas are kept.

    Args:
        command_text: Logged command (already credential-masked).
        hosts: Every identifier of the finding's hosts (IP/FQDN/NetBIOS/...).
        ports: The finding's ports.

    Returns:
        The genericized command string. Anything not recognized is left as-is for
        the leak scan to judge.
    """
    port_set = frozenset(str(p) for p in ports if str(p))
    wrappers, argv = split_wrappers(_split(command_text))
    if not argv:
        return command_text.strip()
    kept = [w for w in dict.fromkeys(wrappers) if w in _KEPT_WRAPPERS]
    binary = Path(argv[0]).name
    is_nmap = binary == "nmap"
    is_nxc = binary in _NXC_BINARIES

    out: list[str] = [binary]
    i = 1
    while i < len(argv):
        tok = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else None
        if is_nmap:
            if tok in _NMAP_OUTPUT_FLAGS:
                i += 2
                continue
            if tok[:3] in _NMAP_OUTPUT_FLAGS and len(tok) > 3:
                i += 1
                continue
            if tok == "-iL" and nxt is not None:
                out.append(_TARGET)
                i += 2
                continue
            if tok == "-p" and nxt is not None:
                out += ["-p", _generic_port_value(nxt, port_set)]
                i += 2
                continue
            if (
                tok.startswith("-p")
                and len(tok) > 2
                and _NMAP_PORT_VALUE_RE.match(tok[2:])
            ):
                generic = _generic_port_value(tok[2:], port_set)
                out += ["-p", generic] if generic == _PORT else [tok]
                i += 1
                continue
        if is_nxc:
            if tok in _NXC_DROP_WITH_VALUE:
                i += 2
                continue
            if tok == "--gen-relay-list" and nxt is not None:
                out += [tok, _RELAY_LIST_NAME]
                i += 2
                continue
            if tok in _NXC_VALUE_SUBST and nxt is not None:
                out += [tok, _NXC_VALUE_SUBST[tok]]
                i += 2
                continue
            if tok == "--port" and nxt is not None:
                out += [tok, _PORT if nxt in port_set else nxt]
                i += 2
                continue
            if i == 2 and not tok.startswith("-") and _looks_like_file(tok):
                out.append(_TARGET)  # positional target file after the protocol
                i += 1
                continue
        out.append(tok)
        i += 1

    pattern = _host_pattern(hosts)
    generic_tokens: list[str] = []
    for tok in out:
        tok = tok.replace(_SECRET_MASK, _PASSWORD)
        tok = _CRED_PLACEHOLDER_RE.sub(_PASSWORD, tok)
        if pattern is not None:
            tok = pattern.sub(_TARGET, tok)
            tok = re.sub(r"\[<TARGET>\]", _TARGET, tok)
        tok = re.sub(
            r"<TARGET>:(\d{1,5})(?!\d)",
            lambda m: f"{_TARGET}:{_PORT}" if m.group(1) in port_set else m.group(0),
            tok,
        )
        tok = re.sub(r"<TARGET>(?:,<TARGET>)+", _TARGET, tok)
        if tok == _TARGET and generic_tokens and generic_tokens[-1] == _TARGET:
            continue  # collapse "h1 h2 h3" → one <TARGET>
        generic_tokens.append(tok)
    return _join(kept + generic_tokens)


# ---------------------------------------------------------------------------
# Leak scan (fail closed)
# ---------------------------------------------------------------------------


def _path_hits(text: str, *, local_only: bool = False) -> list[str]:
    """Filesystem-path hits. ``local_only`` flags only operator-machine markers
    (``~``, ``/home/``, ``/tmp/``, ``.cerno``, ``C:\\`` …), not any absolute path."""
    hits: list[str] = []
    for token in text.split():
        for part in token.split("="):
            part = part.strip("\"'(),;")
            if local_only:
                flagged = part.startswith(_LOCAL_PATH_PREFIXES)
            else:
                flagged = part.startswith("~") or (
                    part.startswith("/") and not part.startswith("//")
                )
            if flagged or ".cerno" in part or re.match(r"^[A-Za-z]:\\", part):
                hits.append(f"local path {part!r}")
    return hits


def scan_for_leaks(
    text: str,
    ctx: LeakContext,
    *,
    check_paths: bool = True,
    check_usernames: bool = True,
    local_paths_only: bool = False,
) -> list[str]:
    """Return every engagement-data hit in ``text`` (empty list = clean).

    Always flags IPv4/IPv6 literals (except 0.0.0.0/127.0.0.1/::/::1), the
    engagement's host names, scan names and NetExec domains (case-insensitive,
    word-bounded), credential secret values (case-sensitive) and NT / LM:NT hash
    literals — secrets and hashes are never echoed in the hit. Non-generic
    NetExec usernames are flagged when ``check_usernames``; dictionary usernames
    (``anonymous``, ``root`` …) never are. Paths: ``check_paths`` flags any
    absolute/``~``/``.cerno``/``C:\\`` path, ``local_paths_only`` only the
    operator-machine markers. Fail closed: any hit means the text must not be
    exported.
    """
    hits: list[str] = []
    for m in _IPV4_RE.finditer(text):
        value = m.group(1)
        if value not in _ALLOWED_IPS and _is_ip(value):
            hits.append(f"IPv4 literal {value!r}")
    for m in _IPV6_RE.finditer(text):
        value = m.group(1)
        if value not in _ALLOWED_IPS and ":" in value and _is_ip(value):
            hits.append(f"IPv6 literal {value!r}")
    for ident in ctx.identifiers(include_usernames=check_usernames):
        if re.search(
            rf"(?<![{_WORD_EDGE}]){re.escape(ident)}(?![{_WORD_EDGE}])",
            text,
            re.IGNORECASE,
        ):
            hits.append(f"engagement identifier {ident!r}")
    for secret in ctx.checkable_secrets():
        if re.search(
            rf"(?<![{_WORD_EDGE}]){re.escape(secret)}(?![{_WORD_EDGE}])", text
        ):
            hits.append("credential secret value (redacted)")
            break
    if _HASH_RE.search(text):
        hits.append("password hash literal (redacted)")
    if check_paths:
        hits.extend(_path_hits(text))
    elif local_paths_only:
        hits.extend(_path_hits(text, local_only=True))
    return list(dict.fromkeys(hits))


def scan_candidate(candidate: Candidate, ctx: LeakContext) -> list[str]:
    """Leak-scan every exportable field of a candidate, plus the serialized file.

    Every field is checked for IPs, host/scan/domain identifiers, secret values,
    hash literals and operator-machine paths (custom workflows may carry real
    data). ``workflow_name``/``description`` come from plugin metadata, so they
    are never checked for usernames. Contributed commands additionally get the
    strict path check; commands copied verbatim from the existing workflow don't
    (bundled steps legitimately reference e.g. ``/usr/share/wordlists``).

    Returns:
        ``"<field>: <hit>"`` strings; empty means safe to export.
    """
    existing = set(candidate.existing_commands)
    hits: list[str] = []

    def check(
        label: str, text: str, *, paths: bool = False, usernames: bool = True
    ) -> None:
        hits.extend(
            f"{label}: {h}"
            for h in scan_for_leaks(
                text,
                ctx,
                check_paths=paths,
                check_usernames=usernames,
                local_paths_only=True,
            )
        )

    check("plugin_id", candidate.yaml_plugin_id)
    check("workflow_name", candidate.workflow_name, usernames=False)
    check("description", candidate.description, usernames=False)
    for i, step in enumerate(candidate.steps):
        check(f"steps[{i}].title", step.title)
        check(f"steps[{i}].notes", step.notes)
        for j, cmd in enumerate(step.commands):
            check(f"steps[{i}].commands[{j}]", cmd, paths=cmd not in existing)
    for k, ref in enumerate(candidate.references):
        check(f"references[{k}]", ref)
    for k, cmd in enumerate(candidate.possibly_superseded):
        check(f"possibly_superseded[{k}]", cmd)

    # Whole-file re-scan (header included). Usernames were checked per field —
    # re-checking here would re-flag the plugin-derived name/description.
    seen = {h.split(": ", 1)[1] for h in hits}
    for h in scan_for_leaks(
        to_yaml_fragment(candidate), ctx, check_paths=False, check_usernames=False
    ):
        if h not in seen:
            hits.append(f"fragment: {h}")
    return hits


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------


def is_baseline_command(generic: str) -> bool:
    """True for Cerno's own default commands, which never count as "divergence".

    Baseline = nmap with no NSE scripts (``--script``/``-sC``), or nxc/netexec
    with nothing beyond protocol, target, auth flags, ``--shares``,
    ``--local-auth`` and ``--gen-relay-list``.
    """
    _, argv = split_wrappers(_split(generic))
    if not argv:
        return False
    binary = _binary_of(argv)
    rest = argv[1:]
    if binary == "nmap":
        return not any(t.startswith("--script") or t == "-sC" for t in rest)
    if binary == "nxc":
        i = 1  # skip protocol
        while i < len(rest):
            tok = rest[i]
            if tok == _TARGET or tok in _NXC_BASELINE_FLAGS:
                i += 1
            elif tok in _NXC_BASELINE_VALUE_FLAGS:
                i += 2
            else:
                return False
        return True
    return False


def _compare_key(generic: str) -> tuple[str, tuple[str, ...]]:
    """Order-insensitive key for "is this the same command?".

    Canonicalizes placeholder dialects, drops wrappers, folds netexec→nxc,
    splits ``--script=x`` / ``-pX`` and sorts comma lists in script values.
    """
    _, argv = split_wrappers(_split(canonicalize_placeholders(generic)))
    if not argv:
        return ("", ())
    binary = _binary_of(argv)
    tokens: list[str] = []
    for tok in argv[1:]:
        if tok.startswith("--script="):
            tokens += ["--script", tok.split("=", 1)[1]]
        elif binary == "nmap" and tok.startswith("-p") and len(tok) > 2:
            tokens += ["-p", tok[2:]]
        else:
            tokens.append(tok)
    for idx in range(1, len(tokens)):
        if tokens[idx - 1] == "--script":
            tokens[idx] = ",".join(sorted(tokens[idx].split(",")))
    return (binary, tuple(sorted(tokens)))


def _derive_step_title(binary: str, commands: Sequence[str]) -> str:
    if binary == "nmap":
        scripts: list[str] = []
        for cmd in commands:
            toks = _split(cmd)
            for idx, tok in enumerate(toks):
                value = None
                if tok.startswith("--script="):
                    value = tok.split("=", 1)[1]
                elif tok == "--script" and idx + 1 < len(toks):
                    value = toks[idx + 1]
                if value:
                    scripts += [s for s in value.split(",") if s and s not in scripts]
        return f"Run NSE scripts: {', '.join(scripts)}" if scripts else "Scan with nmap"
    if binary == "nxc":
        protos: list[str] = []
        for cmd in commands:
            _, argv = split_wrappers(_split(cmd))
            if len(argv) > 1 and argv[1] not in protos:
                protos.append(argv[1])
        return (
            f"Check with NetExec ({', '.join(protos)})"
            if protos
            else "Check with NetExec"
        )
    return f"Run {binary}" if binary else "Run command"


def _references(plugin: Optional[Plugin]) -> list[str]:
    refs: list[str] = []
    if plugin is not None:
        if plugin.plugin_url:
            refs.append(plugin.plugin_url)
        for cve in plugin.cves or []:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
    return refs


def _workflow_commands(workflow: Workflow) -> list[str]:
    return [cmd for step in workflow.steps for cmd in step.commands]


# ---------------------------------------------------------------------------
# DB-backed builders
# ---------------------------------------------------------------------------


def build_leak_context(
    finding: Finding,
    conn: sqlite3.Connection,
    extra: Sequence[str] = (),
    usernames: Sequence[str] = (),
    secrets: Sequence[str] = (),
) -> LeakContext:
    """Collect the engagement identifiers for a finding's scan(s).

    Host identifiers span every host in the finding's scan(s) (not just the
    finding's own), so a command touching another in-scope host is refused rather
    than silently templated. ``extra`` (e.g. NetExec domains), ``usernames`` and
    ``secrets`` are best-effort values supplied by the caller; secrets are only
    compared, never stored or echoed.
    """
    ids = [fid for fid in [finding.finding_id, *finding.extra_finding_ids] if fid]
    scan_ids: list[int] = [finding.scan_id] if finding.scan_id else []
    if ids:
        placeholders = ",".join("?" * len(ids))
        rows = conn.execute(
            f"SELECT DISTINCT scan_id FROM findings WHERE finding_id IN ({placeholders})",
            tuple(ids),
        ).fetchall()
        scan_ids = list(dict.fromkeys(scan_ids + [r[0] for r in rows]))
    names = []
    for sid in scan_ids:
        scan = Scan.get_by_id(sid, conn)
        if scan is not None:
            names.append(scan.scan_name)
    return LeakContext(
        host_identifiers=Host.identifiers_for_scans(scan_ids, conn),
        scan_names=names,
        extra=[e for e in extra if e],
        usernames=[u for u in usernames if u],
        secrets=[s for s in secrets if s],
    )


def _finding_hosts_ports(
    finding: Finding, conn: sqlite3.Connection
) -> tuple[list[str], list[str]]:
    identifiers = finding.get_host_identifiers(conn)
    _, ports_str = finding.get_hosts_and_ports(conn)
    return identifiers, [p for p in ports_str.split(",") if p]


def assess_candidate(
    finding: Finding,
    conn: sqlite3.Connection,
    mapper: WorkflowMapper,
    ctx: Optional[LeakContext] = None,
) -> Assessment:
    """Draft a candidate from the finding's execution trail (see module docstring).

    Only successful runs (``exit_code == 0``) count; audit rows are skipped. A
    genericized command that still trips the leak scan is excluded (reported in
    ``Assessment.excluded``) rather than exported.
    """
    if finding.finding_id is None:
        raise ValueError("Cannot assess an unsaved finding")
    ctx = ctx or build_leak_context(finding, conn)
    hosts, ports = _finding_hosts_ports(finding, conn)

    commands: list[str] = []
    keys: set[tuple[str, tuple[str, ...]]] = set()
    source_ids: list[int] = []
    excluded: list[dict] = []
    for execution in ToolExecution.get_by_finding(finding.finding_id, conn):
        if execution.exit_code != 0 or execution.tool_name in _NON_COMMAND_TOOLS:
            continue
        generic = genericize_command(execution.command_text, hosts, ports)
        hits = scan_for_leaks(generic, ctx)
        if hits:
            excluded.append(
                {"execution_id": execution.execution_id, "reason": "; ".join(hits)}
            )
            continue
        key = _compare_key(generic)
        if not key[0] or key in keys:
            continue
        keys.add(key)
        commands.append(generic)
        if execution.execution_id is not None:
            source_ids.append(execution.execution_id)

    plugin = Plugin.get_by_id(finding.plugin_id, conn)
    plugin_name = plugin.plugin_name if plugin else f"Plugin {finding.plugin_id}"
    existing = mapper.get_workflow(str(finding.plugin_id))

    if existing is None:
        if not commands:
            return Assessment(None, excluded)
        groups: dict[str, list[str]] = {}
        for cmd in commands:
            groups.setdefault(_binary_of(_split(cmd)), []).append(cmd)
        steps = [
            CandidateStep(
                title=_derive_step_title(binary, cmds),
                commands=cmds,
                notes="Contributed from a Cerno-verified run.",
            )
            for binary, cmds in groups.items()
        ]
        hints = [
            "Rename the workflow and step titles to describe the check "
            "(e.g. 'Confirm SMBv1 is enabled').",
            "Add step notes explaining how to read the output (what proves "
            "vulnerable vs. not).",
            "Confirm every command is generic and runnable against any target.",
        ]
        if excluded:
            hints.append(
                f"{len(excluded)} command(s) were excluded because they still held "
                "engagement data after sanitizing; re-add by hand only in generic form."
            )
        return Assessment(
            Candidate(
                finding_id=finding.finding_id,
                plugin_id=finding.plugin_id,
                yaml_plugin_id=str(finding.plugin_id),
                reason="new",
                workflow_name=plugin_name,
                description=f"Verify: {plugin_name}",
                steps=steps,
                references=_references(plugin),
                new_commands=list(commands),
                review_hints=hints,
                source_execution_ids=source_ids,
            ),
            excluded,
        )

    existing_cmds = _workflow_commands(existing)
    existing_keys = {
        _compare_key(genericize_command(canonicalize_placeholders(c), hosts, ports))
        for c in existing_cmds
    }
    new = [
        c for c in commands
        if not is_baseline_command(c) and _compare_key(c) not in existing_keys
    ]  # fmt: skip
    if not new:
        return Assessment(None, excluded)

    new_binaries = {_binary_of(_split(c)) for c in new}
    superseded = [
        raw
        for raw in existing_cmds
        if _compare_key(
            genericize_command(canonicalize_placeholders(raw), hosts, ports)
        )
        not in keys
        and _binary_of(_split(canonicalize_placeholders(raw))) in new_binaries
    ]
    steps = [
        CandidateStep(title=s.title, commands=list(s.commands), notes=s.notes)
        for s in existing.steps
    ]
    steps.append(
        CandidateStep(
            title="Additional verification (contributed)",
            commands=new,
            notes="Contributed from a Cerno-verified run.",
        )
    )
    hints = ["Give the contributed step a descriptive title and notes."]
    if superseded:
        hints.append(
            "Decide in the PR whether the contributed command should replace any "
            "possibly_superseded command."
        )
    return Assessment(
        Candidate(
            finding_id=finding.finding_id,
            plugin_id=finding.plugin_id,
            yaml_plugin_id=existing.plugin_id,
            reason="enhanced",
            workflow_name=existing.workflow_name,
            description=existing.description,
            steps=steps,
            references=list(existing.references or []),
            new_commands=new,
            possibly_superseded=superseded,
            review_hints=hints,
            existing_commands=existing_cmds,
            source_execution_ids=source_ids,
        ),
        excluded,
    )


def build_candidate(
    finding: Finding,
    conn: sqlite3.Connection,
    mapper: WorkflowMapper,
    ctx: Optional[LeakContext] = None,
) -> Optional[Candidate]:
    """The drafted candidate for a finding, or None (nothing new to contribute)."""
    return assess_candidate(finding, conn, mapper, ctx).candidate


def _require_str(value: object, name: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(
            f"workflow.{name} must be a {'non-empty ' if not allow_empty else ''}string"
        )
    return value


def _require_str_list(value: object, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"workflow.{name} must be a list of strings")
    return list(value)


def candidate_from_override(
    finding: Finding,
    workflow: dict,
    base: Optional[Candidate],
    conn: sqlite3.Connection,
    mapper: WorkflowMapper,
) -> Candidate:
    """Build a candidate from an operator/Claude-edited workflow dict.

    Validates the shape (``workflow_name``, ``description``, ``steps`` [{title,
    commands, notes}], ``references``); the plugin_id is never taken from the
    override. Commands not copied verbatim from the existing workflow are
    genericized again, so pasting a real command is sanitized. Free text (names,
    titles, notes) is NOT rewritten — it must pass the leak scan as written.
    """
    if not isinstance(workflow, dict):
        raise ValueError("workflow must be an object")
    if finding.finding_id is None:
        raise ValueError("Cannot build a candidate for an unsaved finding")
    existing = mapper.get_workflow(str(finding.plugin_id))
    existing_cmds = _workflow_commands(existing) if existing else []
    hosts, ports = _finding_hosts_ports(finding, conn)

    raw_steps = workflow.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("workflow.steps must be a non-empty list")
    steps: list[CandidateStep] = []
    new_commands: list[str] = []
    for i, raw in enumerate(raw_steps):
        if not isinstance(raw, dict):
            raise ValueError(f"workflow.steps[{i}] must be an object")
        cmds: list[str] = []
        for cmd in _require_str_list(raw.get("commands", []), f"steps[{i}].commands"):
            if cmd in existing_cmds:
                cmds.append(cmd)
            else:
                generic = genericize_command(cmd, hosts, ports)
                cmds.append(generic)
                new_commands.append(generic)
        steps.append(
            CandidateStep(
                title=_require_str(
                    raw.get("title", ""), f"steps[{i}].title", allow_empty=False
                ),
                commands=cmds,
                notes=_require_str(raw.get("notes", "") or "", f"steps[{i}].notes"),
            )
        )

    if base is not None:
        yaml_plugin_id, reason = base.yaml_plugin_id, base.reason
    elif existing is not None:
        yaml_plugin_id, reason = existing.plugin_id, "enhanced"
    else:
        yaml_plugin_id, reason = str(finding.plugin_id), "new"

    return Candidate(
        finding_id=finding.finding_id,
        plugin_id=finding.plugin_id,
        yaml_plugin_id=yaml_plugin_id,
        reason=reason,
        workflow_name=_require_str(
            workflow.get("workflow_name"), "workflow_name", allow_empty=False
        ),
        description=_require_str(workflow.get("description", ""), "description"),
        steps=steps,
        references=_require_str_list(workflow.get("references", []), "references"),
        new_commands=new_commands,
        possibly_superseded=list(base.possibly_superseded) if base else [],
        existing_commands=existing_cmds,
        source_execution_ids=list(base.source_execution_ids) if base else [],
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def to_yaml_fragment(candidate: Candidate) -> str:
    """Serialize a candidate as a one-entry workflow file with a PR how-to header.

    The output is a complete ``version``/``workflows`` document, so it loads as-is
    via ``WorkflowMapper.load_additional_workflows`` / ``--custom-workflows``.
    """
    header = [
        f"# Cerno workflow contribution: plugin {candidate.yaml_plugin_id} ({candidate.reason})",
        "# Drafted by Cerno from a verified finding's execution trail. Hosts, ports and",
        "# credentials are replaced with <TARGET>/<PORT>/<USERNAME>/<PASSWORD>/<DOMAIN>.",
        "# REVIEW BEFORE SUBMITTING. To contribute:",
        *(f"#   {line}" for line in SUBMISSION_INSTRUCTIONS.splitlines()),
    ]
    if candidate.possibly_superseded:
        header.append(
            "# Existing commands possibly superseded by the contributed step:"
        )
        header.extend(f"#   - {cmd}" for cmd in candidate.possibly_superseded)
    body = yaml.safe_dump(
        {"version": "1.0", "workflows": [candidate.to_entry()]},
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=1000,
    )
    return "\n".join(header) + "\n" + body
