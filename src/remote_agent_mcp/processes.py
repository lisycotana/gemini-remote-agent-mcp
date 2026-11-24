from __future__ import annotations

import os
import shutil
import signal
import subprocess
from pathlib import Path

from .security import build_sandbox_argv, sanitized_env


def popen_kwargs() -> dict[str, object]:
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def terminate_process_tree(process: subprocess.Popen[object], *, force: bool = False) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                [shutil.which("taskkill") or "taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                timeout=10,
                check=False,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        pass


def spawn_command(command: str, cwd: Path, **kwargs: object) -> subprocess.Popen[bytes]:
    if "env" not in kwargs:
        kwargs["env"] = sanitized_env()
    return subprocess.Popen(
        build_sandbox_argv(command, cwd),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        **popen_kwargs(),
        **kwargs,
    )
