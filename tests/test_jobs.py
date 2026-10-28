"""Tests for the async job model: start/status/cancel/list over a cancellable,
process-group runner.

Jobs are driven directly against the real ``JobRegistry`` (no MCP transport),
with ``DATABASE_PATH`` pointed at a temp on-disk DB so ``_run_and_record`` logs
its ``tool_executions`` row the same way the synchronous path does. Commands use
``sh`` (reliably present) with an allowlist of ``["sh"]``.
"""

import asyncio
import os
import sqlite3

import pytest

import cerno_pkg.database as database
from cerno_pkg.config import CernoConfig
from cerno_pkg.mcp_server.jobs import JobRegistry


@pytest.fixture
def exec_db(tmp_path, monkeypatch):
    dbfile = tmp_path / "cerno.db"
    conn = sqlite3.connect(str(dbfile))
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.executescript(database.SCHEMA_SQL_TABLES)
    conn.commit()
    conn.close()
    monkeypatch.setattr(database, "DATABASE_PATH", dbfile)
    return dbfile


@pytest.fixture
def cfg():
    return CernoConfig(mcp_exec_allowlist=["sh"], mcp_allow_execution=True)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _count_executions(dbfile):
    conn = sqlite3.connect(str(dbfile))
    try:
        return conn.execute("SELECT COUNT(*) FROM tool_executions").fetchone()[0]
    finally:
        conn.close()


def test_start_runs_to_completion_and_logs_execution(exec_db, cfg):
    async def go():
        reg = JobRegistry()
        job = reg.start(command=["sh", "-c", "echo hello"], tool_name="mcp", config=cfg)
        await job._task
        return job

    job = _run(go())
    assert job.status == "done"
    assert job.exit_code == 0
    assert job.execution_id is not None
    assert _count_executions(exec_db) == 1


def test_get_and_list_report_the_job(exec_db, cfg):
    async def go():
        reg = JobRegistry()
        job = reg.start(command=["sh", "-c", "true"], tool_name="mcp", config=cfg)
        await job._task
        return reg, job.job_id

    reg, job_id = _run(go())
    status = reg.get(job_id).status_dict()
    assert status["job_id"] == job_id
    assert status["status"] == "done"
    listed = {j.job_id for j in reg.list_jobs()}
    assert job_id in listed


def test_cancel_terminates_the_process_group(exec_db, cfg):
    async def go():
        reg = JobRegistry()
        job = reg.start(
            command=["sh", "-c", "sleep 30"], tool_name="mcp", config=cfg, timeout=60
        )
        # Wait until the child has actually spawned.
        for _ in range(200):
            if job._proc is not None:
                break
            await asyncio.sleep(0.02)
        pid = job._proc.pid
        reg.cancel(job.job_id)
        await job._task
        return job, pid

    job, pid = _run(go())
    assert job.status == "cancelled"
    # The process group is gone once the child has been reaped.
    with pytest.raises(ProcessLookupError):
        os.getpgid(pid)


def test_start_rejects_a_command_outside_the_allowlist(exec_db, cfg):
    async def go():
        reg = JobRegistry()
        reg.start(command=["nmap", "-sS", "10.0.0.1"], tool_name="mcp", config=cfg)

    with pytest.raises(ValueError, match="allowlist"):
        _run(go())


def test_denylisted_command_is_rejected(exec_db):
    bad_cfg = CernoConfig(
        mcp_exec_allowlist=["*"], mcp_exec_denylist=["rm"], mcp_allow_execution=True
    )

    async def go():
        reg = JobRegistry()
        reg.start(command=["rm", "-rf", "/tmp/x"], tool_name="mcp", config=bad_cfg)

    with pytest.raises(ValueError, match="denylist"):
        _run(go())


def test_job_timeout_returns_structured_result(exec_db, cfg):
    """A job that exceeds its per-command timeout finishes 'done' with a structured
    result marked timed_out (not a bare failure)."""

    async def go():
        reg = JobRegistry()
        job = reg.start(
            command=["sh", "-c", "sleep 5"], tool_name="mcp", timeout=1, config=cfg
        )
        await job._task
        return job

    job = _run(go())
    assert job.status == "done"
    assert job.error is None
    assert job.result is not None
    assert job.result["timed_out"] is True
    assert job.result["next_steps"]
