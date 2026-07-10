# Ephorate

The control plane for autonomous AI agents. Ephorate governs every action
your Claude and MCP agents take — policy-enforced, audited, and reversible —
so you can ship autonomy without ceding control.

_Agents act. Ephorate decides._

Four capabilities share one control plane:

1. **Monitoring & alerting** — `AnthropicMonitor` wraps your
   `anthropic.Anthropic` client and ships a metric event per Claude API
   call (model, tokens, cache tokens, latency, cost, stop reason,
   tools used, errors). The control plane stores them, exposes a
   dashboard, and evaluates threshold **alert rules** (cost spikes,
   p99 latency, error rate, per-model breakdowns) routed to Slack,
   PagerDuty, generic webhooks.
2. **Runtime policy enforcement** — between the model and its tools,
   evaluates a declarative policy on every tool call and returns
   `allow` · `deny` · `transform` · `require_approval` with a
   tamper-evident audit log of every decision. Ships starter
   compliance bundles for NIST AI RMF, ISO/IEC 42001, EU AI Act, an
   `agent_abuse_patterns` hardening bundle (36 rules), and a
   `prompt_injection` bundle (18 rules) detecting prompt-injection,
   jailbreak, and indirect-injection / data-exfil patterns
   (OWASP LLM01/LLM02/LLM06). Candidate bundles can be **backtested**
   against recorded audit history before rollout.
3. **Detection & response (SIEM / EDR)** — a detection engine correlates
   the audit + metric stream into **security findings** (prompt-injection
   attempts, repeated-denial bursts, injection→exfil kill-chains,
   approval-abuse probing, new-tool/UEBA anomalies, threat-intel hits), each
   mapped to MITRE ATLAS / OWASP LLM with a triage lifecycle (open →
   triaging → resolved / false-positive). Findings drive **response**:
   - a **per-entity quarantine** isolates an agent or session (the SDK denies
     its tool calls inline via `QuarantineGuard`), manually or automatically
     on a CRITICAL finding;
   - a **global kill-switch** halts every agent org-wide in one click, with
     time-boxed **break-glass** grants for the remediation agent you trust;
   - **SOAR response playbooks** run a matched finding's actions in priority
     order (quarantine, notify connectors, forward to your SIEM, tag, set
     status, assign) — every run recorded and auditable;
   - findings above a per-org severity threshold are **forwarded** to external
     SIEM/SOAR systems as OCSF-flavored events.

   Orgs also author their own **detection-as-code** rules (`/detection-rules`)
   — a bounded, structured match (no code/regex, never a ReDoS/RCE vector) run
   alongside the built-ins.
4. **Governance** — **live compliance posture** maps the org's current
   controls to NIST AI RMF, the EU AI Act, and the OWASP LLM Top 10, grading
   each control satisfied / partial / gap with remediation (alongside
   point-in-time evidence reports with PDF export). **Cost governance**
   (FinOps) meters every agent's LLM spend and enforces per-agent quotas and
   org budgets inline — over budget, the next call is denied.

Two ways to put Ephorate in front of your agents: the **SDKs** (Python / TS
middleware) or the **MCP proxy** — a drop-in stdio / streamable-HTTP gateway
that governs any MCP client without code changes.

These layers feed the same audit + reports surface so security, SRE, and
compliance teams work off one source of truth. Apache 2.0.

## Layout

```
engine/          policy engine (Python): types, predicate AST, evaluator,
                 parser, CLI, JSON-schema export, starter compliance bundles
sdk-python/      ephorate: Anthropic/OpenAI middleware, audit log, approval flow,
                 quarantine guard, control-plane shipping
sdk-typescript/  @ephorate/sdk: TS port with feature parity for the runtime path
mcp-proxy/       ephorate-mcp: MCP gateway (stdio + streamable-HTTP) wrapping the
                 policy gate — bearer auth, per-session identity, health probes,
                 Prometheus metrics, tool-output DLP
control-plane/   FastAPI + SQLAlchemy + Alembic + Celery: ingestion, search,
                 approvals, findings, quarantine/kill-switch, SOAR, compliance,
                 FinOps, compliance reports (with PDF), OAuth
web/             Next.js 15 control-plane console (light + dark themes)
docs/            Nextra docs site
examples/        end-to-end demo agents
```

## Quickstart (Python SDK gating an Anthropic agent)

```bash
pip install ephorate anthropic
```

```python
from ephorate import EphorateClient, load_bundle  # noqa
from ephorate.middleware.anthropic import gate_response

client = EphorateClient(
    bundle_path="policy.yaml",
    audit_log_path="audit.jsonl",
    control_plane_url="https://ephorate.example.com",  # optional
    api_key="cp-xxx",
    org_slug="acme",
    default_agent_id="research-bot",
)

# In your agent loop:
gated_response = gate_response(
    anthropic_response, client=client, session_id=session_id
)
```

### Or govern an MCP server without code changes

Point your MCP client at the Ephorate proxy instead of the upstream server; it
enforces policy on every `tools/call` and ships audit events to the control
plane.

```bash
pip install ephorate-mcp
ephorate-mcp --config ephorate-mcp.example.yaml
```

The full Quickstart, DSL reference, audit-log spec, and framework mapping
guide live in `docs/`.

## Development

Python workspace via [uv](https://docs.astral.sh/uv/):

```bash
uv sync --all-packages --all-extras
uv run pytest engine sdk-python control-plane mcp-proxy
```

TS workspace via pnpm:

```bash
pnpm install
pnpm --filter @ephorate/sdk test
pnpm --filter ephorate-web build
pnpm --filter ephorate-docs build
```

## Testing

- **engine**: pytest + Hypothesis property tests + p99 evaluation budget gate
- **sdk-python**: pytest, including cross-language chain interop with the TS SDK
- **control-plane**: pytest with FastAPI TestClient against in-memory SQLite
- **mcp-proxy**: pytest against the policy gate + transport plumbing
- **sdk-typescript**: Vitest

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security disclosures go via
[SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
