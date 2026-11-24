from __future__ import annotations

from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import FastMCP

from remote_agent_mcp.config import settings
from remote_agent_mcp.security import file_sha256
from remote_agent_mcp.tools.files import register_file_tools


@pytest.fixture
def file_tools() -> dict[str, object]:
    server = FastMCP("test")
    register_file_tools(server)
    return server._tool_manager._tools


def call(tools: dict[str, object], name: str, **arguments: object) -> object:
    return SimpleNamespace(**tools[name].fn(**arguments))  # type: ignore[attr-defined]


def test_edit_file_diff_and_optimistic_lock(file_tools: dict[str, object]) -> None:
    target = settings.resolved_workspace / "main.py"
    target.write_text("def answer():\n    return 41\n", encoding="utf-8")
    original_hash = file_sha256(target)
    preview = call(
        file_tools,
        "edit_file",
        path="main.py",
        old_string="41",
        new_string="42",
        expected_sha256=original_hash,
        dry_run=True,
    )
    assert preview.applied is False  # type: ignore[attr-defined]
    assert "-    return 41" in preview.diff  # type: ignore[attr-defined]
    assert "41" in target.read_text(encoding="utf-8")

    result = call(
        file_tools,
        "edit_file",
        path="main.py",
        old_string="41",
        new_string="42",
        expected_sha256=original_hash,
    )
    assert result.applied is True  # type: ignore[attr-defined]
    assert "42" in target.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="changed"):
        call(
            file_tools,
            "edit_file",
            path="main.py",
            old_string="42",
            new_string="43",
            expected_sha256=original_hash,
        )


def test_create_and_overwrite_return_diff(file_tools: dict[str, object]) -> None:
    created = call(file_tools, "write_file", path="new.txt", content="alpha\n")
    assert created.applied is True  # type: ignore[attr-defined]
    current_hash = file_sha256(settings.resolved_workspace / "new.txt")
    with pytest.raises(FileExistsError):
        call(file_tools, "write_file", path="new.txt", content="beta\n")
    with pytest.raises(ValueError, match="expected_sha256"):
        call(file_tools, "write_file", path="new.txt", content="beta\n", overwrite=True)
    overwritten = call(
        file_tools,
        "write_file",
        path="new.txt",
        content="beta\n",
        overwrite=True,
        expected_sha256=current_hash,
    )
    assert "-alpha" in overwritten.diff  # type: ignore[attr-defined]
    assert "+beta" in overwritten.diff  # type: ignore[attr-defined]


def test_discovery_read_and_search(file_tools: dict[str, object]) -> None:
    source = settings.resolved_workspace / "src"
    source.mkdir()
    (source / "app.py").write_text("first\nneedle\nlast\n", encoding="utf-8")
    (source / ".env").write_text("token=hidden", encoding="utf-8")
    assert "src/app.py" in call(file_tools, "list_directory").entries  # type: ignore[attr-defined]
    assert call(file_tools, "find_files", pattern="**/*.py").matches == ["src/app.py"]  # type: ignore[attr-defined]
    assert "src" in call(file_tools, "find_files", pattern="**/*.py").matches[0]  # type: ignore[attr-defined]
    search = call(file_tools, "grep_search", pattern="needle", path="src")
    assert "app.py:2:needle" in search.matches  # type: ignore[attr-defined]
    read = call(file_tools, "read_file", path="src/app.py", start_line=2, end_line=2)
    assert read.content.endswith("2 | needle")  # type: ignore[attr-defined]
    assert read.range == [2, 2]  # type: ignore[attr-defined]


def test_read_rejects_binary_file(file_tools: dict[str, object]) -> None:
    (settings.resolved_workspace / "binary.dat").write_bytes(b"\x00\x01")
    with pytest.raises(ValueError, match="Binary"):
        call(file_tools, "read_file", path="binary.dat")
