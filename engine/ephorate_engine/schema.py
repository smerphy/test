"""JSON Schema export for Ephorate engine public types.

Used to generate language-neutral schemas for SDKs, docs, and the policy
editor's input dry-run feature.

Schemas are emitted in **serialization** mode so consumers see what the
wire shape looks like (what producers send), not the looser input shape
Pydantic accepts. Drift between code and the on-disk schemas in
`engine/schemas/` is caught by `tests/test_schema_freshness.py`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel

from ephorate_engine.evaluator import Policy
from ephorate_engine.types import DecisionResult, PolicyInput

JSON_SCHEMA_DIALECT: Final[str] = "https://json-schema.org/draft/2020-12/schema"

PUBLIC_SCHEMAS: dict[str, type[BaseModel]] = {
    "PolicyInput": PolicyInput,
    "DecisionResult": DecisionResult,
    "Policy": Policy,
}

# Path to the on-disk canonical schemas, relative to the engine package root.
SCHEMA_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "schemas"


def _schema_for(model: type[BaseModel]) -> dict[str, Any]:
    schema = model.model_json_schema(mode="serialization")
    schema["$schema"] = JSON_SCHEMA_DIALECT
    return schema


def export_schemas() -> dict[str, dict[str, Any]]:
    """Return JSON Schema (draft 2020-12) for every public type, keyed by name."""
    return {name: _schema_for(model) for name, model in PUBLIC_SCHEMAS.items()}


def _serialize(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def write_schemas(out_dir: Path) -> list[Path]:
    """Write one `<TypeName>.schema.json` per public type. Returns paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, schema in export_schemas().items():
        path = out_dir / f"{name}.schema.json"
        path.write_text(_serialize(schema))
        written.append(path)
    return written


def _main() -> int:  # pragma: no cover - thin CLI wrapper
    parser = argparse.ArgumentParser(
        description="Emit JSON Schema files for ephorate-engine public types.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=SCHEMA_DIR,
        help=f"Output directory (default: {SCHEMA_DIR})",
    )
    args = parser.parse_args()
    written = write_schemas(args.out)
    for path in written:
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
