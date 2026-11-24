from __future__ import annotations

import contextlib
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import settings
from .processes import spawn_command, terminate_process_tree
from .security import redact_secrets, redacted_command_for_audit, truncate_head_tail


@dataclass
class BackgroundJob:
    job_id: str
    command: str
    cwd: str
    log_path: Path
    process: subprocess.Popen[bytes]
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, BackgroundJob] = {}
        self._lock = threading.RLock()

    def _prune(self) -> None:
        now = time.time()
        finished = [
            job_id
            for job_id, job in self._jobs.items()
            if job.process.poll() is not None
            and job.finished_at is not None
            and now - job.finished_at > settings.job_retention_seconds
        ]
        for job_id in finished:
            job = self._jobs.pop(job_id)
            with contextlib.suppress(OSError):
                job.log_path.unlink()

    def start(self, command: str, cwd: Path) -> dict[str, Any]:
        settings.jobs_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            settings.jobs_dir.chmod(0o700)
        with self._lock:
            self._prune()
            running = sum(job.process.poll() is None for job in self._jobs.values())
            if running >= settings.max_concurrent_jobs:
                raise RuntimeError("The background-job concurrency limit has been reached")
            job_id = uuid.uuid4().hex
            log_path = settings.jobs_dir / f"{job_id}.log"
            with log_path.open("wb") as log_file:
                process = spawn_command(command, cwd, stdout=log_file, stderr=subprocess.STDOUT)
            job = BackgroundJob(job_id, command, str(cwd), log_path, process)
            self._jobs[job_id] = job
            threading.Thread(target=self._watch, args=(job,), daemon=True).start()
        return {"job_id": job_id, "status": "running", "pid": process.pid}

    def _watch(self, job: BackgroundJob) -> None:
        job.process.wait()
        job.finished_at = time.time()
        with job.log_path.open("ab") as log_file:
            log_file.write(f"\n[mcp job exited with code {job.process.returncode}]\n".encode())

    def _get(self, job_id: str) -> BackgroundJob:
        if len(job_id) != 32 or any(character not in "0123456789abcdef" for character in job_id):
            raise KeyError("Invalid job id")
        with self._lock:
            try:
                return self._jobs[job_id]
            except KeyError as exc:
                raise KeyError("Unknown or expired background job") from exc

    def poll(self, job_id: str, offset_bytes: int = 0, max_bytes: int = 8192) -> dict[str, Any]:
        job = self._get(job_id)
        if offset_bytes < 0:
            raise ValueError("offset_bytes cannot be negative")
        max_bytes = max(256, min(max_bytes, 65536))
        file_size = job.log_path.stat().st_size if job.log_path.exists() else 0
        reset_offset = offset_bytes > file_size
        actual_offset = 0 if reset_offset else offset_bytes
        data = b""
        if job.log_path.exists():
            with job.log_path.open("rb") as log_file:
                log_file.seek(actual_offset)
                data = log_file.read(max_bytes)
                next_offset = log_file.tell()
        else:
            next_offset = 0
        output, truncated, _ = truncate_head_tail(
            redact_secrets(data.decode("utf-8", errors="replace")), max_bytes
        )
        return_code = job.process.poll()
        return {
            "job_id": job_id,
            "status": "running" if return_code is None else "exited",
            "exit_code": return_code,
            "elapsed_seconds": round(time.time() - job.started_at, 2),
            "output": output,
            "output_truncated": truncated,
            "next_offset": next_offset,
            "offset_reset": reset_offset,
        }

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            self._prune()
            items: list[dict[str, Any]] = []
            now = time.time()
            for job in self._jobs.values():
                return_code = job.process.poll()
                items.append(
                    {
                        "job_id": job.job_id,
                        "status": "running" if return_code is None else "exited",
                        "exit_code": return_code,
                        "pid": job.process.pid,
                        "cwd": job.cwd,
                        "command": redacted_command_for_audit(job.command)[:200],
                        "elapsed_seconds": round(now - job.started_at, 2),
                    }
                )
            return items

    def kill(self, job_id: str, signal_name: str = "SIGTERM") -> dict[str, Any]:
        if signal_name not in {"SIGTERM", "SIGKILL"}:
            raise ValueError("signal_name must be SIGTERM or SIGKILL")
        job = self._get(job_id)
        if job.process.poll() is not None:
            return {
                "job_id": job_id,
                "status": "already_exited",
                "exit_code": job.process.returncode,
            }
        terminate_process_tree(job.process, force=signal_name == "SIGKILL")
        return {"job_id": job_id, "status": "signal_sent", "signal": signal_name}


job_manager = JobManager()
