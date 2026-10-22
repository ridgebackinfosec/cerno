"""In-memory async job model for long-running MCP executions.

``execute_command`` is synchronous (it blocks the tool call up to the clamped
timeout). Long scans and scoped batches need a fire-and-poll model with
cancellation: ``start_execution`` returns a ``job_id`` immediately and the work
runs on the event loop via ``asyncio.to_thread``; the caller then polls
``get_execution_status`` / ``list_jobs`` and may ``cancel_execution``.

State is a **runtime-only registry** in the server process: there is no schema
change and jobs do not survive a server restart (only the live
running/cancelled state is ephemeral — every completed run is still written to
``tool_executions`` by the shared ``_run_and_record`` body, so audit history is
durable). Cancellation kills the child's whole process group (the runner spawns
with ``start_new_session=True``), so nmap/nxc and their children terminate
cleanly.
"""

from __future__ import annotations

import asyncio
import atexit
import os
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from ..config import CernoConfig
from ..logging_setup import log_error, log_info
from ..ops import ExecutionMetadata, start_process

#: Terminal job states (a finish callback must not override a cancel).
_TERMINAL = {"done", "failed", "cancelled"}

#: Seconds to wait after SIGTERM before escalating to SIGKILL on cancel/timeout.
_KILL_GRACE = 3


def _terminate(proc: "subprocess.Popen[str]") -> None:
    """Terminate a process group: SIGTERM, then SIGKILL after a grace window."""
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=_KILL_GRACE)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass


@dataclass
class Job:
    """One async execution. ``_proc``/``_task`` are runtime-only, never serialized."""

    job_id: str
    tool_name: str
    command: list[str]  # masked (placeholder) form, safe to display
    finding_id: Optional[int] = None
    status: str = "running"  # running | done | failed | cancelled
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None
    execution_id: Optional[int] = None
    exit_code: Optional[int] = None
    error: Optional[str] = None
    result: Optional[dict] = None
    _proc: Any = None
    _task: Any = None
    _cancel_requested: bool = False

    def status_dict(self) -> dict:
        """JSON-serializable status snapshot (with a short stdout/stderr tail)."""
        end = self.ended_at if self.ended_at is not None else time.time()
        tail = None
        err_tail = None
        if self.result is not None:
            tail = (self.result.get("stdout") or "")[-2000:]
            err_tail = (self.result.get("stderr") or "")[-2000:]
        return {
            "job_id": self.job_id,
            "tool_name": self.tool_name,
            "command": " ".join(self.command),
            "finding_id": self.finding_id,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed_seconds": round(end - self.started_at, 3),
            "exit_code": self.exit_code,
            "execution_id": self.execution_id,
            "error": self.error,
            "stdout_tail": tail,
            "stderr_tail": err_tail,
        }


class JobRegistry:
    """Thread-safe registry of in-flight and finished jobs for one server process."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(
        self,
        *,
        command: list[str],
        tool_name: str,
        config: CernoConfig,
        finding_id: Optional[int] = None,
        use_proxy: bool = False,
        timeout: int = 300,
        gate: Optional[threading.Semaphore] = None,
    ) -> Job:
        """Validate, register, and launch a job; returns immediately with the Job.

        The exec policy / cred-gate is checked synchronously (so a bad command
        fails fast here, before scheduling). The run itself executes on the event
        loop via ``asyncio.to_thread`` and is not awaited. ``gate`` (a shared
        ``threading.Semaphore``) caps how many jobs run their subprocess at once —
        used by ``execute_batch`` to bound concurrency across a batch.
        """
        from .server import _mask_command_text, _preflight_exec

        _preflight_exec(command, config)
        job = Job(
            job_id=uuid.uuid4().hex,
            tool_name=tool_name,
            command=_mask_command_text(command).split(" "),
            finding_id=finding_id,
        )
        with self._lock:
            self._jobs[job.job_id] = job
        loop = asyncio.get_running_loop()
        job._task = loop.create_task(
            asyncio.to_thread(
                self._run_job,
                job,
                command,
                tool_name,
                use_proxy,
                timeout,
                finding_id,
                config,
                gate,
            )
        )
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self, limit: int = 50) -> list[Job]:
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)
        return jobs[:limit] if limit is not None and limit >= 0 else jobs

    def cancel(self, job_id: str) -> Job:
        """Cancel a running job (kill its process group); no-op if already done."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError(f"No job with id {job_id!r}")
            if job.status in _TERMINAL:
                return job
            job._cancel_requested = True
            job.status = "cancelled"
            proc = job._proc
        if proc is not None:
            _terminate(proc)
        return job

    def cancel_all(self) -> None:
        """Best-effort cancel of every running job (used on server shutdown)."""
        with self._lock:
            running = [j for j in self._jobs.values() if j.status == "running"]
        for job in running:
            try:
                self.cancel(job.job_id)
            except Exception:  # shutdown cleanup must never raise
                pass

    # -- worker-thread body ------------------------------------------------

    def _make_runner(self, job: Job):
        """A cancellable runner: spawns, registers the proc, then communicates."""

        def runner(
            run_command: list, timeout: int, proxy: Any
        ) -> tuple[ExecutionMetadata, str, str]:
            proc, used_sudo = start_process(run_command, proxy_config=proxy)
            with self._lock:
                job._proc = proc
                cancel_now = job._cancel_requested
            if cancel_now:
                _terminate(proc)
            start = time.time()
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                _terminate(proc)
                stdout, stderr = proc.communicate()
            meta = ExecutionMetadata(
                exit_code=proc.returncode,
                duration_seconds=time.time() - start,
                used_sudo=used_sudo,
            )
            return meta, stdout or "", stderr or ""

        return runner

    def _run_job(
        self,
        job: Job,
        command: list[str],
        tool_name: str,
        use_proxy: bool,
        timeout: int,
        finding_id: Optional[int],
        config: CernoConfig,
        gate: Optional[threading.Semaphore] = None,
    ) -> None:
        # Imported lazily to avoid a jobs<->server import cycle at module load.
        from .server import _run_and_record

        # A cancel that arrived while queued on the gate should skip the run.
        if gate is not None:
            gate.acquire()
        try:
            if job._cancel_requested:
                with self._lock:
                    job.ended_at = time.time()
                return
            result = _run_and_record(
                command,
                tool_name=tool_name,
                use_proxy=use_proxy,
                timeout=timeout,
                finding_id=finding_id,
                config=config,
                conn=None,
                runner=self._make_runner(job),
            )
            with self._lock:
                job.result = result
                job.execution_id = result.get("execution_id")
                job.exit_code = result.get("exit_code")
                job.ended_at = time.time()
                if job.status != "cancelled":
                    job.status = "done"
            log_info(f"job {job.job_id} finished: status={job.status}")
        except Exception as exc:  # a failed run must not crash the event loop
            log_error(f"job {job.job_id} failed: {exc}")
            with self._lock:
                job.error = str(exc)
                job.ended_at = time.time()
                if job.status != "cancelled":
                    job.status = "failed"
        finally:
            if gate is not None:
                gate.release()


_REGISTRY: Optional[JobRegistry] = None


def get_registry() -> JobRegistry:
    """Return the process-wide job registry, creating it (and its shutdown hook)."""
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = JobRegistry()
        atexit.register(_REGISTRY.cancel_all)
    return _REGISTRY
