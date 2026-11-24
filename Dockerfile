FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ripgrep \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin mcp-runner

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN pip install --no-cache-dir uv \
    && uv pip install --system --no-cache .

RUN mkdir -p /workspace /var/lib/remote-agent-mcp/jobs /var/log/remote-agent-mcp \
    && chown -R mcp-runner:mcp-runner /workspace /var/lib/remote-agent-mcp /var/log/remote-agent-mcp

USER mcp-runner
ENV MCP_WORKSPACE_ROOT=/workspace \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8000 \
    MCP_AUDIT_LOG_PATH=/var/log/remote-agent-mcp/audit.jsonl \
    MCP_JOBS_DIR=/var/lib/remote-agent-mcp/jobs

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"

CMD ["remote-agent-mcp"]
