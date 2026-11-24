[English](README.md) | **简体中文**

# Gemini Remote Agent MCP

一个供 Gemini 网页端 **Custom App / MCP 连接器**使用的远程开发工具服务。它直接在目标机器的工作区内提供 12 个标准 MCP 工具，不依赖浏览器插件，也不是 SSH 封装。

## 功能与安全边界

- 文件：目录枚举、Glob 查找、ripgrep 搜索、带行号分段读取、精确 Diff 编辑、原子写入。
- 命令：短命令超时终止、后台任务增量日志、进程树终止、并发任务限制。
- Git：分支状态、已暂存/未暂存 Diff、默认关闭且需要显式确认的受限恢复。
- 安全：工作区路径约束、敏感文件过滤、返回内容脱敏、JSONL 审计、OAuth JWT 与按工具 Scope 检查。

**命令工具能执行任意 Shell 命令。文件路径校验不是命令沙箱。** `MCP_SANDBOX_MODE=none` 仅用于可信本机开发；公开部署请使用低权限 Linux 用户、OAuth 和 `bwrap`，并限制该用户对宿主机其他文件的访问。脱敏不能替代最小权限或数据防泄漏系统。

## 本地启动

需要 Python 3.11+、[uv](https://docs.astral.sh/uv/) 和 ripgrep；Windows 与 Linux 均可用于本地开发。

如果项目位于包含非 ASCII 字符的 Windows 路径中，建议使用 `uv sync --no-install-project` 安装依赖；测试配置会直接使用 `src/`，打包部署则使用纯 ASCII 路径，避免 Python 当前可编辑安装的 Unicode 路径问题。

```bash
cp .env.example .env
# 至少修改 MCP_WORKSPACE_ROOT；本机测试先设 MCP_AUTH_ENABLED=false、MCP_SANDBOX_MODE=none
uv sync
uv run remote-agent-mcp
# 中文路径的本机环境若上方入口报 ModuleNotFoundError，改用：
# PowerShell: $env:PYTHONPATH = "$PWD/src"
# Linux/macOS: export PYTHONPATH="$PWD/src"
uv run --no-project python -m remote_agent_mcp.server
```

服务入口为 `http://127.0.0.1:8000/mcp`，健康检查为 `/healthz`。非回环监听且未启用 OAuth 时，服务拒绝启动。不要把无鉴权的端口通过隧道暴露到公网。

Windows 本机稳定运行：首次执行 `scripts\install-autostart.ps1`，以后登录 Windows 会自动启动看门狗。看门狗在进程退出 5 秒后自动拉起服务；`scripts\watch-connection.ps1` 显示本机、Funnel 和公网健康状态。运行日志在 `%LOCALAPPDATA%\GeminiRemoteMCP\`，不包含 OAuth 令牌。

公网连接器建议启用 `MCP_STATELESS_HTTP=true` 和 `MCP_JSON_RESPONSE=true`（`start-local.ps1` 已默认启用）。每次工具调用由独立 HTTP 请求完成，不依赖长期 SSE 或内存会话；OAuth 刷新令牌仍负责登录续期。真正的长期可用性来自进程自动恢复、健康检查和最小权限，而不是无限延长会话。

```bash
uv run pytest
uv run ruff check .
npx @modelcontextprotocol/inspector
# Inspector: Transport = Streamable HTTP, URL = http://127.0.0.1:8000/mcp
```

> 若当前 Windows 路径含中文等非 ASCII 字符，`uv run remote-agent-mcp` 的可编辑安装入口可能受 Python Unicode 路径问题影响。可设置上面的 `PYTHONPATH` 后启动；Linux 生产部署不受此问题影响。

## 工具约定

| 工具 | 用途 | OAuth Scope |
| --- | --- | --- |
| `list_directory`, `find_files`, `grep_search`, `read_file` | 探查工作区 | `mcp:read` |
| `edit_file`, `write_file` | 修改或新建 UTF-8 文件 | `mcp:write` |
| `run_command`, `start_bg_job`, `poll_bg_job`, `kill_bg_job` | 执行与任务控制 | `mcp:exec` |
| `git_status_diff` | 审计变更 | `mcp:read` |
| `git_restore` | 丢弃已跟踪文件的工作区修改 | `mcp:write` |

编辑已存在文件时，先调用 `read_file`，再将返回的 `sha256` 作为 `expected_sha256`。局部编辑优先用 `edit_file`；`write_file` 需要额外指定 `overwrite=true`。`git_restore` 不删除未跟踪文件，默认禁用，启用后仍需 `confirm_destructive=true`。后台任务记录只保存在当前服务进程内，重启后不能轮询旧任务。

## 公网与 Gemini 接入

### 1. OAuth 授权服务器

在 Auth0 等 OIDC 提供方创建一个 API，Identifier 使用 `MCP_OAUTH_AUDIENCE`（推荐 `https://mcp.example.com/mcp`），定义 `mcp:read`、`mcp:write`、`mcp:exec` 权限。创建支持 Authorization Code + PKCE 的应用，不启用隐式流。按 Gemini 添加连接器时显示的回调地址配置应用，并获取自己的 `sub`。

`.env` 必须设置：

```dotenv
MCP_AUTH_ENABLED=true
MCP_RESOURCE_URL=https://mcp.example.com/mcp
MCP_OAUTH_ISSUER=https://YOUR_TENANT.us.auth0.com/
MCP_OAUTH_AUDIENCE=https://mcp.example.com/mcp
MCP_ALLOWED_USER_SUBS=auth0|YOUR_SUBJECT
MCP_TRANSPORT_ALLOWED_HOSTS=["mcp.example.com","127.0.0.1:*"]
MCP_TRANSPORT_ALLOWED_ORIGINS=["https://mcp.example.com","http://127.0.0.1:*"]
```

本服务只验证资源服务器 JWT，并发布 RFC 9728 元数据；授权码、PKCE、Client Secret 和令牌签发给外部 OIDC 提供方处理。缺少 `mcp:read` 会拒绝所有工具，写和执行 Scope 分别拒绝对应工具组。`MCP_REQUIRE_OAUTH_SCOPES=false` 仅供确实无法颁发 Scope 的受控兼容场景。

### 2. Linux 隔离与守护进程

```bash
sudo apt install ripgrep bubblewrap git
sudo useradd --system --home /opt/remote-agent-mcp --shell /usr/sbin/nologin mcp-runner
# 仅给 mcp-runner 必要项目的读写权限，不给 SSH 私钥、sudo 或其他项目权限
```

根据实际路径修改 `deploy/remote-agent-mcp.service` 后安装。服务使用 `NoNewPrivileges`、`PrivateTmp`、`ProtectSystem=strict` 和最小可写目录。`bwrap` 默认只绑定工作区为可写，系统目录只读，并默认断网；如果构建确实需要网络，才设 `MCP_SANDBOX_DISABLE_NET=false`。需要专有 GPU、conda 或额外运行时目录时，要按主机实际环境扩展只读绑定并重新做隔离测试。

### 3. HTTPS 隧道

`deploy/cloudflared-config.yml` 是隧道入口示例；真正推荐在 Cloudflare Dashboard 创建隧道并将公开主机名指向 `http://127.0.0.1:8000`。验证：

```bash
curl http://127.0.0.1:8000/healthz
curl -i https://mcp.example.com/mcp
curl https://mcp.example.com/.well-known/oauth-protected-resource/mcp
```

### 4. Gemini Custom App

1. 在 Gemini 网页端打开 **Settings → Connected apps**，选择 **Add custom app**。
2. 填入 `https://mcp.example.com/mcp`。
3. 若服务端不支持 Dynamic Client Registration，在 **Advanced features** 中填写预注册的 OAuth Client ID/Secret，完成授权。
4. 确认连接后，先要求“列出目录并读取入口文件，不要修改”，再测试 dry-run Diff，最后测试命令。对话中用 `@` 选择该 Custom App；Google 也提供 Developer Mode 用于验证 Schema 和调试。

截至 2026-11-23，[Google 官方连接说明](https://support.google.com/gemini/answer/17209137)要求：美国地区、18 岁以上的个人 Google 账号、英文界面、开启 History；工作/学校账号暂不支持。官方也说明目前写操作需要手动确认。功能开放范围可能变化，以页面实际显示为准。该项目提供工具调用体验，不会把 Gemini 网页变成带文件树、行内 Accept/Reject 或交互式终端的 IDE。

## 设计与测试

- `docs/PLAN.md`：实施边界与验收计划。
- `docs/SECURITY.md`：部署检查清单和事件响应。
- `tests/test_mcp_integration.py`：通过官方 MCP 客户端走真实 Streamable HTTP 的工具闭环。
