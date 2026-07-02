"""Verify the audit chain is cross-language compatible.

Writes events with the TypeScript SDK (compiled `dist/`), then verifies
them with the Python SDK's `verify_chain`. This exercises the canonical
wire-bytes hashing contract.

Skipped when Node or the TS SDK build is unavailable so the suite
remains runnable from a Python-only environment.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from praetor import AuditError, verify_chain

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TS_DIST_INDEX = REPO_ROOT / "sdk-typescript" / "dist" / "index.js"


def _node_and_ts_available() -> bool:
    return shutil.which("node") is not None and TS_DIST_INDEX.exists()


pytestmark = pytest.mark.skipif(
    not _node_and_ts_available(),
    reason="node + sdk-typescript build required for cross-language interop",
)


def _write_events_via_ts(out_path: Path, count: int) -> None:
    script = f"""
      import {{ JsonlAuditSink }} from "{TS_DIST_INDEX}";
      const sink = new JsonlAuditSink({out_path.as_posix()!r});
      for (let i = 0; i < {count}; i++) {{
        sink.record(
          {{
            agent: {{ id: "agent-1" }},
            tool: {{ name: "http.get", arguments: {{ url: `https://x/${{i}}` }} }},
            session: {{ id: "sess-1" }},
          }},
          {{ decision: "allow", reason: "ok", matched_policy_id: "p1" }},
        );
      }}
    """
    subprocess.run(
        ["node", "--input-type=module", "-e", script],
        check=True,
        capture_output=True,
    )


def test_python_verifies_ts_written_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_events_via_ts(path, count=5)
    assert verify_chain(path) == 5


def test_python_detects_ts_chain_tamper(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _write_events_via_ts(path, count=3)
    # Tamper with the second event's reason; hash should no longer match.
    import json

    lines = path.read_text().splitlines()
    e1 = json.loads(lines[1])
    e1["reason"] = "tampered"
    lines[1] = json.dumps(e1)
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(AuditError, match="hash mismatch"):
        verify_chain(path)
