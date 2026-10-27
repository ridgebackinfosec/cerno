"""Scoped batch: generate a verification command per finding matched by a query,
review the plan, then (gated) execute the batch.

This operates on a :class:`cerno_pkg.query.FindingQuery` (the composite query
layer) rather than a single finding, matching how engagements run ("verify all
unreviewed criticals", "nxc smb every signing-disabled host"):

* :func:`plan_batch` is a **read-only dry run** — it returns the generated command
  and an executable/manual classification for every matched finding, so the plan
  can be reviewed before anything runs. It is always available.
* :func:`execute_batch` runs only the runnable, non-skipped items, each through
  the job registry (``mcp_server.jobs``; bounded concurrency, per-command timeout), attributed
  to its finding and auto-ingested — identical to a single ``execute_command``.
  Every command is re-validated against the exec policy at run time (defense in
  depth), and the MCP layer registers ``execute_batch`` only when both
  ``mcp_allow_execution`` and ``mcp_allow_batch`` are set.

Command generation reuses the single-finding ``generate_*``/``prepare_workflow``
adapters (so target-file writing, cred placeholders and NSE handling match),
keyed off a ``strategy``: ``"nmap"``, ``"netexec:<proto>"`` (bare ``"netexec"``
uses the config ``default_netexec_protocol``, else smb), ``"msf"`` or
``"workflow"`` (first executable workflow command).
"""

from __future__ import annotations

import asyncio
import shlex
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .config import CernoConfig, load_config
from .database import db_transaction, query_one
from .exec_chain import is_runnable, resolve_target_binary
from .models import Finding, Plugin
from .query import FindingQuery, run_finding_query


@dataclass
class BatchItem:
    """One finding's generated command and its execution classification."""

    finding_id: int
    plugin_id: int
    plugin_name: str
    tool: str
    generated_command: Optional[list[str]] = None
    executable: bool = False
    skip_reason: Optional[str] = None


@dataclass
class BatchPlan:
    strategy: str
    total: int = 0
    runnable: int = 0
    skipped: int = 0
    items: list[BatchItem] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "total": self.total,
            "runnable": self.runnable,
            "skipped": self.skipped,
            "items": [
                {
                    "finding_id": i.finding_id,
                    "plugin_id": i.plugin_id,
                    "plugin_name": i.plugin_name,
                    "tool": i.tool,
                    "generated_command": i.generated_command,
                    "executable": i.executable,
                    "skip_reason": i.skip_reason,
                }
                for i in self.items
            ],
        }


def _default_is_installed(name: str) -> bool:
    from .ops import resolve_cmd

    return resolve_cmd([name]) is not None


def _generate_command(
    finding_id: int,
    strategy: str,
    plugin: Plugin,
    use_credential: Optional[str],
    config: Optional[CernoConfig],
    conn: Optional[sqlite3.Connection],
) -> tuple[Optional[list[str]], str]:
    """Generate the command for one finding under ``strategy``.

    Reuses the single-finding MCP generation adapters (lazy import avoids a
    batch<->server cycle). Returns ``(argv_or_None, tool_label)``.
    """
    from .mcp_server.server import (
        tool_generate_msf_search,
        tool_generate_netexec_cmd,
        tool_generate_nmap_cmd,
        tool_prepare_workflow,
    )

    if strategy == "nmap":
        res = tool_generate_nmap_cmd(finding_id, config=config, conn=conn)
        return list(res["command"]), "nmap"
    if strategy == "netexec" or strategy.startswith("netexec:"):
        # Bare "netexec" -> protocol None -> config default_netexec_protocol / smb.
        proto = strategy.split(":", 1)[1] if ":" in strategy else None
        res = tool_generate_netexec_cmd(
            finding_id, proto, use_credential=use_credential, config=config, conn=conn
        )
        return list(res["command"]), "netexec"
    if strategy == "msf":
        cmd = tool_generate_msf_search(finding_id, conn=conn)["command"]
        return (shlex.split(cmd) if cmd else None), "msf"
    if strategy == "workflow":
        prep = tool_prepare_workflow(
            finding_id, use_credential=use_credential, config=config, conn=conn
        )
        if prep:
            for step in prep["steps"]:
                for cmd in step["commands"]:
                    if cmd["executable"]:
                        return shlex.split(cmd["filled"]), "workflow"
        return None, "workflow"
    raise ValueError(f"Unknown batch strategy {strategy!r}")


def _resolved_skip_reason(finding: Finding, conn: sqlite3.Connection) -> Optional[str]:
    """Return a skip reason if a finding is already resolved, else None."""
    if finding.review_state == "done":
        return "review_state is done"
    row = query_one(
        conn,
        "SELECT verdict_label FROM v_finding_current_verdict WHERE finding_id = ?",
        (finding.finding_id,),
    )
    if row is not None and row["verdict_label"] in ("confirmed", "false_positive"):
        return f"verdict is {row['verdict_label']}"
    return None


def _classify(
    argv: Optional[list[str]],
    allowlist,
    denylist,
    is_installed: Callable[[str], bool],
) -> tuple[bool, Optional[str]]:
    """Return ``(executable, reason_if_not)`` for a generated command."""
    if not argv:
        return False, "no command generated"
    ok, reason = is_runnable(argv, allowlist, denylist)
    if not ok:
        return False, reason
    target = resolve_target_binary(argv)
    if target is not None and not is_installed(target):
        return False, f"{target!r} is not installed"
    return True, None


def plan_batch(
    query: FindingQuery,
    strategy: str,
    *,
    use_credential: Optional[str] = None,
    skip_done: bool = True,
    allowlist=None,
    denylist=None,
    is_installed: Optional[Callable[[str], bool]] = None,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
) -> BatchPlan:
    """Build a reviewable batch plan (read-only): one classified item per match.

    A finding already resolved (review_state done, or a confirmed/false_positive
    verdict) is skipped when ``skip_done``; otherwise a command is generated and
    classified executable vs manual against the allow/deny policy + installed
    check. Nothing is executed.
    """
    cfg = config or load_config()
    allow = cfg.mcp_exec_allowlist if allowlist is None else allowlist
    deny = cfg.mcp_exec_denylist if denylist is None else denylist
    checker = is_installed or _default_is_installed

    plan = BatchPlan(strategy=strategy)
    with db_transaction(conn) as c:
        for finding, plugin in run_finding_query(query, c, config=cfg):
            fid = finding.finding_id
            if fid is None:
                continue
            item = BatchItem(
                finding_id=fid,
                plugin_id=plugin.plugin_id,
                plugin_name=plugin.plugin_name,
                tool=strategy,
            )
            resolved = _resolved_skip_reason(finding, c) if skip_done else None
            if resolved is not None:
                item.skip_reason = resolved
            else:
                argv, tool_label = _generate_command(
                    fid, strategy, plugin, use_credential, cfg, c
                )
                item.tool = tool_label
                item.generated_command = argv
                item.executable, item.skip_reason = _classify(
                    argv, allow, deny, checker
                )
            plan.items.append(item)

    plan.total = len(plan.items)
    plan.runnable = sum(1 for i in plan.items if i.executable)
    plan.skipped = plan.total - plan.runnable
    return plan


#: Hard ceiling on simultaneous batch commands (per-call arg and config alike);
#: each item is already an internally parallel scanner.
_MAX_BATCH_CONCURRENCY = 8


def _batch_cap(concurrency: Optional[int], config: CernoConfig) -> int:
    """Resolve batch concurrency: explicit arg > config, clamped to [1, 8]."""
    requested = concurrency if concurrency is not None else config.mcp_batch_concurrency
    return min(_MAX_BATCH_CONCURRENCY, max(1, requested))


async def execute_batch(
    query: FindingQuery,
    strategy: str,
    *,
    use_credential: Optional[str] = None,
    skip_done: bool = True,
    concurrency: Optional[int] = None,
    per_command_timeout: Optional[int] = None,
    config: Optional[CernoConfig] = None,
    conn: Optional[sqlite3.Connection] = None,
    registry: Optional[Any] = None,
) -> dict:
    """Run the runnable items of a batch plan through the job registry.

    Each runnable item is started as a tracked, cancellable job attributed to its
    finding (and auto-ingested), with a shared semaphore capping concurrency at
    ``mcp_batch_concurrency`` (clamped to [1, 8]) and a per-command
    ``mcp_batch_timeout``. Returns the
    plan plus per-item run results once all have finished. Gating
    (``mcp_allow_batch``) is enforced at the MCP registration layer.
    """
    from .mcp_server.jobs import get_registry

    cfg = config or load_config()
    reg = registry or get_registry()
    cap = _batch_cap(concurrency, cfg)
    timeout = (
        per_command_timeout
        if per_command_timeout is not None
        else cfg.mcp_batch_timeout
    )

    plan = plan_batch(
        query,
        strategy,
        use_credential=use_credential,
        skip_done=skip_done,
        config=cfg,
        conn=conn,
    )

    gate = asyncio.Semaphore(cap)
    started: list[tuple[int, Any]] = []  # (finding_id, job)
    for item in plan.items:
        if not item.executable or item.generated_command is None:
            continue
        job = reg.start(
            command=item.generated_command,
            tool_name="mcp-batch",
            config=cfg,
            finding_id=item.finding_id,
            timeout=timeout,
            gate=gate,
        )
        started.append((item.finding_id, job))

    for _, job in started:
        await job._task

    results = [
        {
            "finding_id": fid,
            "job_id": job.job_id,
            "status": job.status,
            "exit_code": job.exit_code,
            "execution_id": job.execution_id,
        }
        for fid, job in started
    ]
    skipped = [
        {"finding_id": i.finding_id, "skip_reason": i.skip_reason}
        for i in plan.items
        if not i.executable
    ]
    return {
        "strategy": strategy,
        "plan": plan.as_dict(),
        "results": results,
        "skipped": skipped,
    }
