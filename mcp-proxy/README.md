# praetor-mcp

Policy-gate, audit, and control **MCP tool calls** for any MCP-speaking agent —
Claude Desktop, IDE agents, agent frameworks — **without changing the agent**.

The proxy sits between the agent's MCP client and one or more upstream MCP
servers. On every `tools/call` it evaluates the call against Praetor policy and
allows / transforms / denies / requires-approval, emitting the same
tamper-evident audit chain and honoring the quarantine kill-switch as the SDK.
It's a thin MCP adapter around `praetor.PraetorClient`, so it reuses the engine,
audit shipping, approval flow, and quarantine you already run.

## How it works

```
agent MCP client ──JSON-RPC──▶ praetor-mcp ──JSON-RPC──▶ upstream MCP server(s)
                                    │
                                    ▼  PraetorClient.evaluate()
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
pip install "praetor-mcp[runtime]"          # [runtime] pulls the MCP transport
praetor-mcp --check --config praetor-mcp.yaml   # validate config (no runtime)
praetor-mcp --config praetor-mcp.yaml            # run (stdio or streamable-http)
```

Two listen modes (set `listen.transport`):

- **stdio** — sidecar; the agent launches `praetor-mcp` as its MCP server
  command instead of the upstream server.
- **streamable-http** — deployment mode; serves a Starlette ASGI app (mounted at
  `listen.path`, default `/mcp`) via uvicorn on `listen.bind`. Point the agent's
  MCP client at `http://<bind><path>`. Embed the app in your own ASGI stack with
  `praetor_mcp.server.build_asgi_app(config)`.

See `praetor-mcp.example.yaml` for a full config.

## Design

The policy core (`praetor_mcp.gate`, `praetor_mcp.config`) has **no MCP runtime
dependency** and is fully unit-tested; the transport wiring
(`praetor_mcp.server`) imports the optional `mcp` package lazily and is
validated against real MCP servers in staging. `on_error: deny` is the default
(fail-closed — it's a security control); set `allow` for availability-first
deployments.

v1 covers: stdio + streamable-HTTP upstreams, aggregation/namespacing, tool
filtering, and allow/deny/transform/approval + quarantine. Tool-output DLP and
dynamic policy reload are on the roadmap (see the control-plane spec).
