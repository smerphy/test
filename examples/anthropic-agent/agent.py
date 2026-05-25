"""End-to-end demo: an Anthropic-style agent gated by Praetor.

Runs without the real `anthropic` SDK installed by mocking the
`messages.create` response. Demonstrates:

  - Loading a YAML policy bundle
  - Wrapping a response through `gate_response` middleware
  - Writing each decision to a tamper-evident JSONL audit log

Run from the repo root with:

    uv run python examples/anthropic-agent/agent.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from praetor import JsonlAuditSink, PraetorClient, verify_chain
from praetor.middleware.anthropic import gate_response

POLICY_BUNDLE = """\
policies:
  - id: allow-public-https
    effect: allow
    when:
      op: and
      clauses:
        - op: eq
          path: tool.name
          value: http.get
        - op: matches
          path: tool.arguments.url
          pattern: '^https://'
    reason: outbound https requests are on the allowlist

  - id: redact-tokens
    effect: transform
    when:
      op: matches
      path: tool.arguments.url
      pattern: 'token='
    reason: redact tokens before the call
    transform:
      url: '<redacted>'

  - id: deny-internal
    effect: deny
    when:
      op: matches
      path: tool.arguments.url
      pattern: '\\.internal($|/)'
    reason: agents must not reach internal hostnames
"""

# Simulated Anthropic Messages-API response. In a real agent this comes
# from `client.messages.create(...)` after the model decides to use tools.
SIMULATED_RESPONSE = {
    "id": "msg_demo_1",
    "role": "assistant",
    "content": [
        {"type": "text", "text": "Let me fetch all three URLs in parallel."},
        {
            "type": "tool_use",
            "id": "toolu_01",
            "name": "http.get",
            "input": {"url": "https://example.com/articles/123"},
        },
        {
            "type": "tool_use",
            "id": "toolu_02",
            "name": "http.get",
            "input": {"url": "https://api.example.com/?token=secret"},
        },
        {
            "type": "tool_use",
            "id": "toolu_03",
            "name": "http.get",
            "input": {"url": "https://billing.acme.internal/charge"},
        },
    ],
}


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        bundle_path = Path(tmpdir) / "policy.yaml"
        bundle_path.write_text(POLICY_BUNDLE)

        audit_path = Path(tmpdir) / "audit.jsonl"
        client = PraetorClient(
            bundle_path=bundle_path,
            audit_sink=JsonlAuditSink(audit_path),
            default_agent_id="research-bot",
        )

        gated = gate_response(
            SIMULATED_RESPONSE, client=client, session_id="demo-session"
        )

        print("== gated tool_use blocks ==")
        for block in gated["content"]:
            if block.get("type") == "tool_use":
                print(f"  {block['name']} -> {block['input']}")

        print(f"\n== audit log ({audit_path}) ==")
        for line in audit_path.read_text().splitlines():
            print(" ", line)

        verified = verify_chain(audit_path)
        print(f"\n== verified {verified} chained audit events ==")


if __name__ == "__main__":
    main()
