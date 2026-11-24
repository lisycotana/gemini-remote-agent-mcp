from __future__ import annotations

import sys
import time

import pytest
from mcp.server.fastmcp import FastMCP

from remote_agent_mcp.config import settings
from remote_agent_mcp.jobs import JobManager
from remote_agent_mcp.tools.exec import register_exec_and_git_tools


@pytest.fixture
def exec_tools() -> dict[str, object]:
    server = FastMCP("test")
    register_exec_and_git_tools(server)
    return server._tool_manager._tools


def test_run_command_and_timeout(exec_tools: dict[str, object]) -> None:
    command = f'"{sys.executable}" -c "print(\'mcp-output\')"'
    completed = exec_tools["run_command"].fn(command=command)  # type: ignore[attr-defined]
    assert completed["exit_code"] == 0, repr(completed)
    assert "mcp-output" in completed["output"]
    sleeping = f'"{sys.executable}" -c "import time; time.sleep(30)"'
    timed_out = exec_tools["run_command"].fn(command=sleeping, timeout_sec=1)  # type: ignore[attr-defined]
    assert timed_out["timed_out"] is True


def test_background_job_poll_and_kill() -> None:
    manager = JobManager()
    command = f'"{sys.executable}" -u -c "import time; print(\'job-ready\'); time.sleep(30)"'
    started = manager.start(command, settings.resolved_workspace)
    output = ""
    for _ in range(50):
        polled = manager.poll(started["job_id"])
        output = polled["output"]
        if "job-ready" in output:
            break
        time.sleep(0.1)
    assert "job-ready" in output
    assert manager.kill(started["job_id"])["status"] == "signal_sent"
    for _ in range(50):
        if manager.poll(started["job_id"])["status"] == "exited":
            break
        time.sleep(0.1)
    assert manager.poll(started["job_id"])["status"] == "exited"


def test_git_status_and_guarded_restore(exec_tools: dict[str, object]) -> None:
    import subprocess

    root = settings.resolved_workspace
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    (root / "tracked.txt").write_text("original\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=root, check=True)
    (root / "tracked.txt").write_text("modified\n", encoding="utf-8")
    (root / "untracked.txt").write_text("keep\n", encoding="utf-8")
    status = exec_tools["git_status_diff"].fn()  # type: ignore[attr-defined]
    assert " M tracked.txt" in status["status"]
    assert "?? untracked.txt" in status["status"]
    with pytest.raises(RuntimeError, match="disabled"):
        exec_tools["git_restore"].fn(paths=["tracked.txt"], confirm_destructive=True)  # type: ignore[attr-defined]
    settings.enable_git_restore = True
    with pytest.raises(ValueError, match="confirm_destructive"):
        exec_tools["git_restore"].fn(paths=["tracked.txt"])  # type: ignore[attr-defined]
    result = exec_tools["git_restore"].fn(paths=["tracked.txt"], confirm_destructive=True)  # type: ignore[attr-defined]
    assert result["restored"] is True
    assert (root / "tracked.txt").read_text(encoding="utf-8") == "original\n"
    assert (root / "untracked.txt").exists()
