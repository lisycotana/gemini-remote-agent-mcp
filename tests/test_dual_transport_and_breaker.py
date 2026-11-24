from __future__ import annotations

import json

import pytest
from mcp.server.fastmcp import FastMCP

from remote_agent_mcp.circuit_breaker import circuit_breaker
from remote_agent_mcp.cli_helpers import generate_client_config, run_preflight_check
from remote_agent_mcp.config import settings
from remote_agent_mcp.security import SandboxError
from remote_agent_mcp.tools.files import register_file_tools


@pytest.fixture(autouse=True)
def reset_breaker() -> None:
    circuit_breaker.reset()


def test_read_only_mode_blocks_mutations() -> None:
    settings.read_only_mode = True
    circuit_breaker.check("read_file", mutating=False)
    with pytest.raises(SandboxError, match="MCP_READ_ONLY_MODE"):
        circuit_breaker.check("write_file", mutating=True, fingerprint={"path": "a.txt"})


def test_rate_limit_and_repeat_mutation_breaker() -> None:
    settings.max_tool_calls_per_minute = 3
    for _ in range(3):
        circuit_breaker.check("list_directory")
    with pytest.raises(SandboxError, match="MCP_MAX_TOOL_CALLS_PER_MINUTE"):
        circuit_breaker.check("list_directory")

    circuit_breaker.reset()
    settings.max_tool_calls_per_minute = 0
    settings.max_repeat_mutations = 2
    circuit_breaker.check("run_command", mutating=True, fingerprint={"cmd": "echo hi"})
    circuit_breaker.check("run_command", mutating=True, fingerprint={"cmd": "echo hi"})
    with pytest.raises(SandboxError, match="MCP_MAX_REPEAT_MUTATIONS"):
        circuit_breaker.check("run_command", mutating=True, fingerprint={"cmd": "echo hi"})


def test_read_file_tail_lines() -> None:
    target = settings.resolved_workspace / "log.txt"
    target.write_text("\n".join(f"line-{i}" for i in range(1, 21)) + "\n", encoding="utf-8")
    mcp = FastMCP("test")
    register_file_tools(mcp)
    read_fn = mcp._tool_manager._tools["read_file"].fn
    result = read_fn(path="log.txt", tail_lines=3)
    assert result["range"] == [18, 20]
    assert "line-18" in result["content"]
    assert "line-20" in result["content"]
    assert "line-17" not in result["content"]


def test_preflight_check_and_client_configs() -> None:
    report = run_preflight_check()
    assert report["ok"] is True
    assert report["workspace_exists"] is True

    for client in ("gemini-cli", "gemini-cli-http", "claude-desktop", "cursor", "gemini-web"):
        parsed = json.loads(generate_client_config(client))
        assert isinstance(parsed, dict)
