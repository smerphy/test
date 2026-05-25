"""JSON Schema export for Praetor engine public types.

Used to generate language-neutral schemas for SDKs, docs, and the policy
editor's input dry-run feature.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from praetor_engine.types import DecisionResult, PolicyInput

PUBLIC_SCHEMAS: dict[str, type[PolicyInput] | type[DecisionResult]] = {
    "PolicyInput": PolicyInput,
    "DecisionResult": DecisionResult,
}


def export_schemas() -> dict[str, dict[str, Any]]:
    """Return JSON Schema (draft 2020-12) for every public type, keyed by name."""
    return {name: model.model_json_schema() for name, model in PUBLIC_SCHEMAS.items()}


def write_schemas(out_dir: Path) -> list[Path]:
    """Write one `<TypeName>.schema.json` per public type. Returns paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, schema in export_schemas().items():
        path = out_dir / f"{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
        written.append(path)
    return written
