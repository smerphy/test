# ephorate-mcp

Policy-gate, audit, and control **MCP tool calls** for any MCP-speaking agent —
Claude Desktop, IDE agents, agent frameworks — **without changing the agent**.

The proxy sits between the agent's MCP client and one or more upstream MCP
servers. On every `tools/call` it evaluates the call against Ephorate policy and
allows / transforms / denies / requires-approval, emitting the same
tamper-evident audit chain and honoring the quarantine kill-switch as the SDK.
It's a thin MCP adapter around `ephorate.EphorateClient`, so it reuses the engine,
audit shipping, approval flow, and quarantine you already run.

## How it works

```
agent MCP client ──JSON-RPC──▶ ephorate-mcp ──JSON-RPC──▶ upstream MCP server(s)
                                    │
                                    ▼  EphorateClient.evaluate()
                       audit chain → control plane · quarantine check · approvals
```

| Decision | Behavior |
|----------|----------|
| allow | forward unchanged |
| transform | forward with rewritten arguments |
| deny | return an MCP tool error (`isError`) with the reason |
| require_approval | broker via the control plane; forward on approve, else deny |

Tools the policy denies outright are hidden from `tools/list`
(`hide_denied_tools`). Everything is audited on the per-`(agent, session)` hash
chain.

## Install & run

```bash
pip install "ephorate-mcp[runtime]"          # [runtime] pulls the MCP transport
ephorate-mcp --check --config ephorate-mcp.yaml   # validate config (no runtime)
ephorate-mcp --config ephorate-mcp.yaml            # run (stdio or streamable-http)
```

Two listen modes (set `listen.transport`):

- **stdio** — sidecar; the agent launches `ephorate-mcp` as its MCP server
  command instead of the upstream server.
- **streamable-http** — deployment mode; serves a Starlette ASGI app (mounted at
  `listen.path`, default `/mcp`) via uvicorn on `listen.bind`. Point the agent's
  MCP client at `http://<bind><path>`. Embed the app in your own ASGI stack with
  `ephorate_mcp.server.build_asgi_app(config)`.

See `ephorate-mcp.example.yaml` for a full config.

## Production (streamable-HTTP gateway)

For a shared HTTP gateway (many agents → one proxy):

- **Downstream auth + per-session identity.** Set `listen.auth_tokens` (bearer
  token → agent_id). Unauthenticated requests get `401`; each call is attributed
  to the token's agent and the `Mcp-Session-Id` session, so audit attribution,
  quarantine, and UEBA baselines stay correct across concurrent agents. Without
  tokens the proxy runs single-identity (fine for the stdio sidecar).
- **Config secrets** come from the environment: `${VAR}` in the YAML is expanded
  on load, so API keys / upstream tokens live in the process env, not on disk.
- **Health + metrics:** `GET /healthz` (liveness), `/readyz` (503 until
  upstreams connect), and `/metrics` (Prometheus: calls by decision, upstream
  errors, auth rejections).
- **DNS-rebinding protection:** set `listen.allowed_hosts` / `allowed_origins`
  for a public endpoint. **Upstream resilience:** a dropped upstream is
  reconnected and the call retried once.
- **Graceful shutdown** flushes the audit shipper on the lifespan/exit path;
  mount a **persistent volume** for `audit_log_path` so locally-buffered events
  survive a restart.
- **Container:** `docker build -f mcp-proxy/Dockerfile -t ephorate-mcp .` (runs
  unprivileged, healthcheck on `/healthz`). Terminate TLS at your ingress.

## Design

The policy core (`ephorate_mcp.gate`, `ephorate_mcp.config`) has **no MCP runtime
dependency** and is fully unit-tested; the transport wiring
(`ephorate_mcp.server`) imports the optional `mcp` package lazily and is
validated against real MCP servers in staging. `on_error: deny` is the default
(fail-closed — it's a security control); set `allow` for availability-first
deployments.

v1 covers: stdio + streamable-HTTP upstreams, aggregation/namespacing, tool
filtering, and allow/deny/transform/approval + quarantine. Tool-output DLP and
dynamic policy reload are on the roadmap (see the control-plane spec).
