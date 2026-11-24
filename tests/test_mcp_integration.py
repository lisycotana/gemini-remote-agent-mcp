from __future__ import annotations

import json
import socket
import threading

import anyio
import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.testclient import TestClient

from remote_agent_mcp.server import create_asgi_app

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def unwrap(result) -> dict:  # noqa: ANN001, ANN201
    assert not result.isError, result.content
    if result.structuredContent is not None:
        return result.structuredContent
    return json.loads(result.content[0].text)


async def test_streamable_http_mcp_tool_round_trip() -> None:
    from remote_agent_mcp.config import settings

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    settings.transport_allowed_hosts = [f"127.0.0.1:{port}"]
    settings.transport_allowed_origins = [f"http://127.0.0.1:{port}"]
    app = create_asgi_app()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            if server.started:
                break
            await anyio.sleep(0.05)
        assert server.started
        async with (
            httpx.AsyncClient(base_url=base_url, timeout=15) as http_client,
            streamable_http_client(f"{base_url}/mcp", http_client=http_client) as (
                read,
                write,
                _,
            ),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
            assert len(tools.tools) == 15
            created = unwrap(
                await session.call_tool("write_file", {"path": "hello.txt", "content": "hello\n"})
            )
            assert created["applied"] is True
            read_result = unwrap(await session.call_tool("read_file", {"path": "hello.txt"}))
            assert "hello" in read_result["content"]
            edited = unwrap(
                await session.call_tool(
                    "edit_file",
                    {
                        "path": "hello.txt",
                        "old_string": "hello",
                        "new_string": "hello MCP",
                        "expected_sha256": read_result["sha256"],
                    },
                )
            )
            assert "+hello MCP" in edited["diff"]
            traversed = await session.call_tool("read_file", {"path": "../outside.txt"})
            assert traversed.isError
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        assert not thread.is_alive()


def test_health_check_is_public() -> None:
    with TestClient(create_asgi_app()) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
