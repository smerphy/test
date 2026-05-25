# Contributing to Praetor

Thanks for your interest in Praetor. The engine and SDKs are Apache 2.0
licensed; contributions of any size are welcome.

## Repo layout

This is a monorepo. Python packages are managed with [uv]
workspaces; TypeScript / web packages with pnpm workspaces.

```
engine/          # praetor-engine — policy engine (Python)
sdk-python/      # Python SDK (not yet started)
sdk-typescript/  # TypeScript SDK (not yet started)
control-plane/   # FastAPI control plane (not yet started)
web/             # Next.js UI (not yet started)
```

## Local setup

You will need `uv` (Python) and `pnpm` (Node) on your `PATH`.

```bash
uv sync --package praetor-engine --extra dev
```

This creates `.venv/` at the repo root and installs the engine in
editable mode with its dev dependencies.

## Running the engine checks

All commands below assume your working directory is `engine/`.

```bash
# Tests + coverage gate (matches CI: must be >= 85%)
uv run pytest --cov=praetor_engine --cov-fail-under=85

# Local profiling with pytest-benchmark
uv run pytest --benchmark-enable --benchmark-only

# Lint
uv run ruff check praetor_engine tests

# Type-check (strict)
uv run mypy praetor_engine

# CLI smoke test
uv run praetor eval \
  --policy examples/policy.yaml \
  --input  examples/input.json
```

## Schemas

Public Pydantic models export canonical JSON Schemas to
`engine/schemas/`. When you change a public type, regenerate them:

```bash
uv run praetor-engine-schemas --out engine/schemas/
```

`tests/test_schema_freshness.py` will fail in CI if you forget.

## Coding standards

- Pydantic v2 models, frozen + `extra="forbid"`, types everywhere.
- mypy strict for `praetor_engine`.
- ruff (`select = ["E", "F", "I", "B", "UP", "RUF", "SIM"]`) clean.
- No `print` outside CLI output paths. Structured logging via
  `structlog` once introduced.
- Test coverage ≥85% on the engine. Property tests (Hypothesis) for any
  evaluator behavior that has a stateable invariant.

## Commit style

- Small, reviewable commits. Tests in the same commit as the code.
- Imperative subject line ≤72 chars (e.g. "Add transform field to Policy").
- Reference issues / discussions in the body, not the subject.

## Reporting security issues

Do not file public issues for security vulnerabilities. Email
`security@praetor.dev` (pending), or open a private security advisory
on the repo.

[uv]: https://docs.astral.sh/uv/
