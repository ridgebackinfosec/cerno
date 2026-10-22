"""Fill a finding's mapped verification workflow and mark what is runnable.

``prepare_workflow`` bridges the display-only workflow library
(``workflow_mappings.yaml`` via :class:`WorkflowMapper`) to actual execution: it
substitutes each step command's placeholders with the finding's real
hosts/ports (and, for credentialed commands, the Tier 1 ``@cred:<ref>@``
placeholder — never a real secret) and marks each filled command as
executable-via-``execute_command`` or manual-only.

The placeholder vocabulary is normalized in the bundled YAML to the canonical
``<TARGET>``/``<PORT>``/``<USERNAME>``/``<PASSWORD>``/``<INTERFACE>`` tokens, but
a variant map is kept so historical and ``--custom-workflows`` YAMLs (which may
still use ``IP_address``/``$IP``/``<target>``/``<user>`` etc.) fill correctly too.

Nothing here resolves or returns a secret: credential placeholders stay in the
``@cred:<ref>@`` form, gated and masked by ``execute_command`` at run time.
"""

from __future__ import annotations

import shlex
import sqlite3
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from .config import CernoConfig, load_config
from .database import db_transaction
from .exec_chain import is_runnable, resolve_target_binary
from .models import Finding
from .tools import credential_placeholder
from .workflow_mapper import Workflow, WorkflowMapper

#: Canonical placeholder token per logical role.
_CANONICAL = {
    "TARGET": "<TARGET>",
    "PORT": "<PORT>",
    "USERNAME": "<USERNAME>",
    "PASSWORD": "<PASSWORD>",
    "INTERFACE": "<INTERFACE>",
}

#: Every token (canonical + historical variant) that fills a given role. No token
#: is a substring of another in this set, so token-by-token replacement is safe.
_VARIANT_TOKENS: dict[str, list[str]] = {
    "TARGET": ["<TARGET>", "<target>", "IP_address", "$IP"],
    "PORT": ["<PORT>", "<port>", "$PORT"],
    "USERNAME": ["<USERNAME>", "<username>", "<user>"],
    "PASSWORD": ["<PASSWORD>", "<password>"],
    "INTERFACE": ["<INTERFACE>", "<interface>"],
}


@dataclass
class PreparedCommand:
    """One workflow step command, filled and classified for execution."""

    raw: str
    filled: str
    executable: bool
    manual_reason: Optional[str] = None
    target_binary: Optional[str] = None
    needs_credential: bool = False


@dataclass
class PreparedStep:
    title: str
    notes: str
    commands: list[PreparedCommand]


@dataclass
class PreparedWorkflow:
    finding_id: int
    plugin_id: int
    workflow_name: str
    description: str
    steps: list[PreparedStep]
    unresolved_placeholders: list[str] = field(default_factory=list)


def _default_is_installed(name: str) -> bool:
    from .ops import resolve_cmd

    return resolve_cmd([name]) is not None


def _fill_command(
    raw: str, values: dict[str, Optional[str]]
) -> tuple[str, list[str], bool]:
    """Substitute placeholder tokens in ``raw``.

    Returns ``(filled, unresolved_canonical_tokens, needs_credential)``. A role
    whose value is None (no data) is normalized to its canonical token and
    recorded as unresolved, so the operator sees exactly what to fill in.
    """
    filled = raw
    unresolved: list[str] = []
    needs_credential = any(
        tok in raw for role in ("USERNAME", "PASSWORD") for tok in _VARIANT_TOKENS[role]
    )
    for role, tokens in _VARIANT_TOKENS.items():
        if not any(tok in filled for tok in tokens):
            continue
        value = values.get(role)
        if value is None:
            # Normalize any variant to the canonical marker; leave it in place.
            for tok in tokens:
                filled = filled.replace(tok, _CANONICAL[role])
            unresolved.append(_CANONICAL[role])
        else:
            for tok in tokens:
                filled = filled.replace(tok, value)
    return filled, unresolved, needs_credential


def _classify(
    filled: str,
    unresolved: list[str],
    allowlist: Sequence[str],
    denylist: Sequence[str],
    is_installed: Callable[[str], bool],
) -> tuple[bool, Optional[str], Optional[str]]:
    """Return ``(executable, manual_reason, target_binary)`` for a filled command."""
    if unresolved:
        return False, f"unresolved placeholder {', '.join(unresolved)}", None
    try:
        argv = shlex.split(filled)
    except ValueError:
        return False, "unparseable command", None
    if not argv:
        return False, "empty command", None
    target = resolve_target_binary(argv)
    ok, reason = is_runnable(argv, allowlist, denylist)
    if not ok:
        return False, reason, target
    if target is not None and not is_installed(target):
        return False, f"{target!r} is not installed", target
    return True, None, target


def prepare_workflow(
    finding_id: int,
    *,
    credential: Optional[dict] = None,
    allowlist: Optional[Sequence[str]] = None,
    denylist: Optional[Sequence[str]] = None,
    config: Optional[CernoConfig] = None,
    workflow_mapper: Optional[WorkflowMapper] = None,
    is_installed: Optional[Callable[[str], bool]] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> Optional[PreparedWorkflow]:
    """Fill the workflow mapped to a finding's plugin and classify each command.

    Args:
        finding_id: Finding whose hosts/ports fill the placeholders.
        credential: Optional non-secret spec ``{username, domain?, secret_kind,
            ref}`` (as returned by the MCP credential resolution); ``<USERNAME>``
            → ``username`` and ``<PASSWORD>`` → ``@cred:<ref>@``.
        allowlist/denylist: Exec policy globs; default to the config's
            ``mcp_exec_allowlist``/``mcp_exec_denylist``.
        config: Config source for the default allow/deny lists.
        workflow_mapper: Mapper to resolve the plugin's workflow (default: bundled
            + custom).
        is_installed: Predicate for "binary on PATH" (injectable for tests).
        conn: Database connection.

    Returns:
        A :class:`PreparedWorkflow`, or None if no workflow is mapped to the
        finding's plugin.
    """
    mapper = workflow_mapper or WorkflowMapper()
    checker = is_installed or _default_is_installed

    with db_transaction(conn) as c:
        finding = Finding.get_by_id(finding_id, c)
        if finding is None:
            raise ValueError(f"No finding with id {finding_id}")
        plugin_id = finding.plugin_id
        workflow: Optional[Workflow] = mapper.get_workflow(str(plugin_id))
        if workflow is None:
            return None
        hosts, ports_str = finding.get_hosts_and_ports(c)

    if allowlist is None or denylist is None:
        cfg = config or load_config()
        allowlist = cfg.mcp_exec_allowlist if allowlist is None else allowlist
        denylist = cfg.mcp_exec_denylist if denylist is None else denylist

    values: dict[str, Optional[str]] = {
        "TARGET": " ".join(hosts) if hosts else None,
        "PORT": ports_str or None,
        "USERNAME": credential.get("username") if credential else None,
        "PASSWORD": (
            credential_placeholder(credential["ref"])
            if credential and credential.get("ref")
            else None
        ),
        "INTERFACE": None,  # no DB source; always operator-supplied
    }

    unresolved_all: list[str] = []
    steps: list[PreparedStep] = []
    for step in workflow.steps:
        prepared_cmds: list[PreparedCommand] = []
        for raw in step.commands:
            filled, unresolved, needs_cred = _fill_command(raw, values)
            executable, reason, target = _classify(
                filled, unresolved, allowlist, denylist, checker
            )
            for tok in unresolved:
                if tok not in unresolved_all:
                    unresolved_all.append(tok)
            prepared_cmds.append(
                PreparedCommand(
                    raw=raw,
                    filled=filled,
                    executable=executable,
                    manual_reason=reason,
                    target_binary=target,
                    needs_credential=needs_cred,
                )
            )
        steps.append(
            PreparedStep(title=step.title, notes=step.notes, commands=prepared_cmds)
        )

    return PreparedWorkflow(
        finding_id=finding_id,
        plugin_id=plugin_id,
        workflow_name=workflow.workflow_name,
        description=workflow.description,
        steps=steps,
        unresolved_placeholders=unresolved_all,
    )
