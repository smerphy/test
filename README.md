# Praetor

Enterprise Claude monitoring + alerting + runtime policy enforcement
for AI agents.

Two complementary subsystems share one control plane:

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
   (OWASP LLM01/LLM02/LLM06).

Both layers feed the same audit + reports surface so security, SRE,
and compliance teams work off one source of truth. Apache 2.0.

## Layout

```
engine/          policy engine (Python): types, predicate AST, evaluator,
                 parser, CLI, JSON-schema export, starter compliance bundles
sdk-python/      praetor: Anthropic/OpenAI middleware, audit log, approval flow,
                 control-plane shipping
sdk-typescript/  @praetor/sdk: TS port with feature parity for the runtime path
control-plane/   FastAPI + SQLAlchemy + Alembic + Celery: ingestion, search,
                 approvals, compliance reports (with PDF), OAuth
web/             Next.js 15 control plane UI
docs/            Nextra docs site
examples/        end-to-end demo agents
```

## Quickstart (Python SDK gating an Anthropic agent)

```bash
pip install praetor anthropic
```

```python
from praetor import PraetorClient, load_bundle  # noqa
from praetor.middleware.anthropic import gate_response

client = PraetorClient(
    bundle_path="policy.yaml",
    audit_log_path="audit.jsonl",
    control_plane_url="https://praetor.example.com",  # optional
    api_key="cp-xxx",
    org_slug="acme",
    default_agent_id="research-bot",
)

# In your agent loop:
gated_response = gate_response(
    anthropic_response, client=client, session_id=session_id
)
```

The full Quickstart, DSL reference, audit-log spec, and framework mapping
guide live in `docs/`.

## Development

Python workspace via [uv](https://docs.astral.sh/uv/):

```bash
uv sync --all-packages --all-extras
uv run pytest engine sdk-python control-plane
```

TS workspace via pnpm:

```bash
pnpm install
pnpm --filter @praetor/sdk test
pnpm --filter praetor-web build
pnpm --filter praetor-docs build
```

## Testing

- **engine**: pytest + Hypothesis property tests + p99 evaluation budget gate
- **sdk-python**: pytest, including cross-language chain interop with the TS SDK
- **control-plane**: pytest with FastAPI TestClient against in-memory SQLite
- **sdk-typescript**: Vitest

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security disclosures go via
[SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
