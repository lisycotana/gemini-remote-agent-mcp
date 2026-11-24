from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from remote_agent_mcp.config import Settings, settings


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path: Path) -> Iterator[Settings]:
    fresh = Settings(
        workspace_root=tmp_path / "workspace",
        audit_log_path=tmp_path / "state" / "audit.jsonl",
        jobs_dir=tmp_path / "state" / "jobs",
        auth_enabled=False,
        sandbox_mode="none",
    )
    fresh.resolved_workspace.mkdir()
    tracked_fields = settings.model_fields_set | set(type(settings).model_fields)
    previous = {field: getattr(settings, field) for field in tracked_fields}
    object.__setattr__(settings, "__dict__", dict(fresh.__dict__))
    object.__setattr__(settings, "__pydantic_fields_set__", set(fresh.__pydantic_fields_set__))
    yield settings
    object.__setattr__(settings, "__dict__", previous)
    object.__setattr__(settings, "__pydantic_fields_set__", set(tracked_fields))
