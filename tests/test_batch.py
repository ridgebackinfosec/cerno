"""Tests for the scoped batch: plan_batch (reviewable dry run) and execute_batch
(gated fan-out over a finding query).

plan_batch classification is driven with injected allow/deny lists + an injected
installed-check so it is deterministic. execute_batch is exercised through the
real job registry against an on-disk DB, with command generation monkeypatched to
a benign ``sh`` command so execution is deterministic and tests orchestration
(scope, skip_done, attribution, concurrency, gating), not tool generation.
"""

import asyncio
import sqlite3

import pytest

import cerno_pkg.batch as batch
import cerno_pkg.database as database
from cerno_pkg.batch import execute_batch, plan_batch
from cerno_pkg.config import CernoConfig
from cerno_pkg.models import Finding, FindingVerdict, Host, Plugin, Port, Scan
from cerno_pkg.query import FindingQuery


def _add_affected(conn, finding_id, host_id, port):
    conn.execute(
        "INSERT INTO finding_affected_hosts (finding_id, host_id, port_number, plugin_output) "
        "VALUES (?, ?, ?, 'x')",
        (finding_id, host_id, port),
    )


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    """On-disk DB (so the job path's own connection sees the data), seeded with
    three critical findings; F2 is already done, F3 already confirmed."""
    dbfile = tmp_path / "cerno.db"
    conn = sqlite3.connect(str(dbfile))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(database.SCHEMA_SQL_TABLES)
    conn.executemany(
        "INSERT INTO severity_levels VALUES (?,?,?,?)",
        [(4, "Critical", 4, "#8B0000"), (0, "Info", 0, "#4682B4")],
    )
    conn.executemany(
        "INSERT INTO verdict_types (label, description) VALUES (?, ?)",
        [("confirmed", "tp"), ("false_positive", "fp"), ("unable", "n")],
    )
    conn.executescript(database.SCHEMA_SQL_VIEWS)
    conn.commit()

    scan = Scan(scan_name="e", export_root=str(tmp_path)).save(conn)
    for pid, name in [(101, "A"), (102, "B"), (103, "C")]:
        Plugin(plugin_id=pid, plugin_name=name, severity_int=4).save(conn)
    f1 = Finding(scan_id=scan, plugin_id=101).save(conn)
    f2 = Finding(scan_id=scan, plugin_id=102, review_state="done").save(conn)
    f3 = Finding(scan_id=scan, plugin_id=103).save(conn)
    h = Host.get_or_create("10.0.0.9", "10.0.0.9", "ipv4", conn=conn)
    for p in (445,):
        Port.get_or_create(p, conn=conn)
    for fid in (f1, f2, f3):
        _add_affected(conn, fid, h, 445)
    FindingVerdict.set(f3, "confirmed", conn=conn)
    conn.commit()
    conn.close()

    monkeypatch.setattr(database, "DATABASE_PATH", dbfile)
    return {"dbfile": dbfile, "scan": scan, "f1": f1, "f2": f2, "f3": f3}


def _conn(dbfile):
    c = sqlite3.connect(str(dbfile))
    c.row_factory = sqlite3.Row
    return c


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_plan_marks_executable_by_allowlist_and_installed(seeded):
    # Generation is real (nmap), but classification uses injected lists + checker.
    c = _conn(seeded["dbfile"])
    try:
        plan = plan_batch(
            FindingQuery(scan_ids=[seeded["scan"]]),
            strategy="nmap",
            allowlist=["nmap"],
            denylist=[],
            is_installed=lambda n: True,
            skip_done=False,
            conn=c,
        )
    finally:
        c.close()
    assert plan.total == 3
    assert all(
        item.generated_command and item.generated_command[0] == "nmap"
        for item in plan.items
    )
    assert plan.runnable == 3


def test_plan_marks_manual_when_not_allowlisted(seeded):
    c = _conn(seeded["dbfile"])
    try:
        plan = plan_batch(
            FindingQuery(scan_ids=[seeded["scan"]]),
            strategy="nmap",
            allowlist=["sh"],  # nmap not allowed
            denylist=[],
            is_installed=lambda n: True,
            skip_done=False,
            conn=c,
        )
    finally:
        c.close()
    assert plan.runnable == 0
    assert all("allowlist" in (i.skip_reason or "") for i in plan.items)


def test_plan_skip_done_skips_done_and_verdicted(seeded):
    c = _conn(seeded["dbfile"])
    try:
        plan = plan_batch(
            FindingQuery(scan_ids=[seeded["scan"]]),
            strategy="nmap",
            allowlist=["nmap"],
            denylist=[],
            is_installed=lambda n: True,
            skip_done=True,
            conn=c,
        )
    finally:
        c.close()
    # F2 (done) and F3 (confirmed) are skipped; only F1 is runnable.
    runnable = [i for i in plan.items if i.executable]
    assert {i.finding_id for i in runnable} == {seeded["f1"]}
    skipped = {i.finding_id: i.skip_reason for i in plan.items if not i.executable}
    assert seeded["f2"] in skipped and seeded["f3"] in skipped


def _patch_sh_generation(monkeypatch):
    def fake_gen(finding_id, strategy, plugin, use_credential, config, conn):
        return ["sh", "-c", f"echo ran {finding_id}"], "sh"

    monkeypatch.setattr(batch, "_generate_command", fake_gen)


def test_execute_runs_runnable_items_and_attributes_findings(seeded, monkeypatch):
    _patch_sh_generation(monkeypatch)
    cfg = CernoConfig(
        mcp_exec_allowlist=["sh"], mcp_allow_execution=True, mcp_allow_batch=True
    )

    async def go():
        return await execute_batch(
            FindingQuery(scan_ids=[seeded["scan"]]),
            strategy="sh",
            skip_done=True,
            concurrency=2,
            config=cfg,
        )

    result = _run(go())
    # Only F1 runs (F2 done, F3 confirmed are skipped).
    assert {r["finding_id"] for r in result["results"]} == {seeded["f1"]}
    assert {s["finding_id"] for s in result["skipped"]} == {seeded["f2"], seeded["f3"]}

    c = _conn(seeded["dbfile"])
    try:
        rows = c.execute(
            "SELECT finding_id, exit_code FROM tool_executions WHERE finding_id = ?",
            (seeded["f1"],),
        ).fetchall()
    finally:
        c.close()
    assert len(rows) == 1 and rows[0]["exit_code"] == 0


def test_execute_without_skip_done_runs_all(seeded, monkeypatch):
    _patch_sh_generation(monkeypatch)
    cfg = CernoConfig(
        mcp_exec_allowlist=["sh"], mcp_allow_execution=True, mcp_allow_batch=True
    )

    async def go():
        return await execute_batch(
            FindingQuery(scan_ids=[seeded["scan"]]),
            strategy="sh",
            skip_done=False,
            concurrency=1,
            config=cfg,
        )

    result = _run(go())
    assert {r["finding_id"] for r in result["results"]} == {
        seeded["f1"],
        seeded["f2"],
        seeded["f3"],
    }


def test_execute_reruns_the_policy_per_command(seeded, monkeypatch):
    # A generated command outside the allowlist must not run (defense in depth,
    # even though plan would have flagged it).
    def bad_gen(finding_id, strategy, plugin, use_credential, config, conn):
        return ["rm", "-rf", "/tmp/x"], "rm"

    monkeypatch.setattr(batch, "_generate_command", bad_gen)
    cfg = CernoConfig(
        mcp_exec_allowlist=["sh"], mcp_allow_execution=True, mcp_allow_batch=True
    )

    async def go():
        return await execute_batch(
            FindingQuery(scan_ids=[seeded["scan"]]),
            strategy="x",
            skip_done=False,
            config=cfg,
        )

    result = _run(go())
    # Nothing was runnable (rm not allowlisted); no executions logged.
    assert result["results"] == []
    c = _conn(seeded["dbfile"])
    try:
        n = c.execute("SELECT COUNT(*) FROM tool_executions").fetchone()[0]
    finally:
        c.close()
    assert n == 0


# -- concurrency: default, clamp, gate-in-event-loop ---------------------------


def test_default_batch_concurrency_is_three():
    assert CernoConfig().mcp_batch_concurrency == 3


@pytest.mark.parametrize(
    "arg, configured, expected",
    [
        (None, 3, 3),  # config default
        (None, 50, 8),  # config clamped
        (100, 3, 8),  # per-call arg clamped
        (2, 3, 2),  # arg wins over config within the clamp
        (0, 3, 1),  # floor
        (-5, 3, 1),
    ],
)
def test_batch_cap_clamps_arg_and_config(arg, configured, expected):
    cfg = CernoConfig(mcp_batch_concurrency=configured)
    assert batch._batch_cap(arg, cfg) == expected


def _exec_cfg(tmp_path):
    return CernoConfig(
        mcp_exec_allowlist=["sh"],
        mcp_allow_execution=True,
        results_root=str(tmp_path / "artifacts"),
    )


def _peak_overlap(intervals):
    events = sorted([(s, 1) for s, _ in intervals] + [(e, -1) for _, e in intervals])
    cur = peak = 0
    for _, delta in events:
        cur += delta
        peak = max(peak, cur)
    return peak


def test_gate_bounds_simultaneous_jobs(seeded, tmp_path):
    from cerno_pkg.mcp_server.jobs import JobRegistry

    cfg = _exec_cfg(tmp_path)
    marks = tmp_path / "marks"
    marks.mkdir()

    async def go():
        reg = JobRegistry()
        gate = asyncio.Semaphore(2)
        jobs = [
            reg.start(
                command=[
                    "sh",
                    "-c",
                    f"date +%s.%N > {marks}/{i}.s; sleep 0.3; date +%s.%N > {marks}/{i}.e",
                ],
                tool_name="t",
                config=cfg,
                gate=gate,
            )
            for i in range(4)
        ]
        for j in jobs:
            await j._task

    _run(go())
    intervals = [
        (float((marks / f"{i}.s").read_text()), float((marks / f"{i}.e").read_text()))
        for i in range(4)
    ]
    assert _peak_overlap(intervals) == 2


def test_queued_batch_jobs_do_not_starve_other_executions(seeded, tmp_path):
    """Jobs waiting on the batch gate must not hold executor threads, or a
    single execution started mid-batch queues behind the whole batch."""
    from concurrent.futures import ThreadPoolExecutor

    from cerno_pkg.mcp_server.jobs import JobRegistry

    cfg = _exec_cfg(tmp_path)

    async def go():
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(max_workers=4))
        reg = JobRegistry()
        gate = asyncio.Semaphore(1)
        batch_jobs = [
            reg.start(
                command=["sh", "-c", "sleep 0.4"],
                tool_name="t",
                config=cfg,
                gate=gate,
            )
            for _ in range(10)
        ]
        await asyncio.sleep(0.05)
        single = reg.start(command=["sh", "-c", "true"], tool_name="t", config=cfg)
        try:
            await asyncio.wait_for(asyncio.shield(single._task), timeout=1.5)
            finished_early = True
        except asyncio.TimeoutError:
            finished_early = False
        for j in batch_jobs:
            reg.cancel(j.job_id)
        await asyncio.gather(single._task, *(j._task for j in batch_jobs))
        return finished_early, single.status

    finished_early, status = _run(go())
    assert finished_early
    assert status == "done"


def test_job_cancelled_while_queued_never_runs(seeded, tmp_path):
    from cerno_pkg.mcp_server.jobs import JobRegistry

    cfg = _exec_cfg(tmp_path)

    async def go():
        reg = JobRegistry()
        gate = asyncio.Semaphore(1)
        first = reg.start(
            command=["sh", "-c", "sleep 0.3"], tool_name="t", config=cfg, gate=gate
        )
        queued = reg.start(
            command=["sh", "-c", "true"], tool_name="t", config=cfg, gate=gate
        )
        reg.cancel(queued.job_id)
        await asyncio.gather(first._task, queued._task)
        return first, queued

    first, queued = _run(go())
    assert first.status == "done"
    assert queued.status == "cancelled"
    assert queued.execution_id is None
    c = _conn(seeded["dbfile"])
    try:
        n = c.execute("SELECT COUNT(*) FROM tool_executions").fetchone()[0]
    finally:
        c.close()
    assert n == 1
