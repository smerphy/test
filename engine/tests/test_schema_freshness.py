"""Verify on-disk JSON Schemas in `engine/schemas/` match what the code emits.

If this test fails, regenerate the schemas:

    uv run python -m praetor_engine.schema --out engine/schemas/
"""

from __future__ import annotations

import json

from praetor_engine.schema import SCHEMA_DIR, export_schemas


def test_on_disk_schemas_match_code() -> None:
    generated = export_schemas()
    assert SCHEMA_DIR.is_dir(), (
        f"missing schema directory {SCHEMA_DIR} — "
        "run: uv run python -m praetor_engine.schema --out engine/schemas/"
    )

    expected_files = {f"{name}.schema.json" for name in generated}
    on_disk_files = {p.name for p in SCHEMA_DIR.glob("*.schema.json")}
    assert on_disk_files == expected_files, (
        f"schema files on disk ({on_disk_files}) "
        f"do not match exported types ({expected_files})"
    )

    for name, schema in generated.items():
        path = SCHEMA_DIR / f"{name}.schema.json"
        on_disk = json.loads(path.read_text())
        assert on_disk == schema, (
            f"{path.name} is out of date — "
            "run: uv run python -m praetor_engine.schema --out engine/schemas/"
        )
