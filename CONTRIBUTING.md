# Contributing to Ephorate

Thanks for your interest. Ephorate is intentionally a small, boring
stack — most contributions are policy bundles, framework mappings,
new SDK middlewares, and bug fixes. Larger architectural changes need
a design discussion in an issue first.

## Scope

In scope:
- **Engine**: new predicate operators, evaluator perf, type definitions
- **SDKs** (Python / TypeScript): new provider middlewares, audit-log
  features, approval-flow improvements
- **Control plane**: new endpoints, search filters, additional
  compliance frameworks
- **Web UI**: missing pages, accessibility fixes
- **Docs**: clarifications, missing reference material
- **Compliance bundles**: new starter rules for additional frameworks
- **Agent-abuse-patterns bundle**: new attack-shape coverage

Not in scope yet (per [the project spec](README.md)):
- Rust port of the engine
- Multi-region control plane
- SSO/SAML (OAuth-only for v0.x)
- ML-based policy suggestions
- Hosted-product billing

## Repo layout

Monorepo. Python packages via [`uv`](https://docs.astral.sh/uv/)
workspaces, TS / web via pnpm workspaces.

```
engine/          ephorate-engine — policy engine + CLI + bundles
sdk-python/      ephorate — Anthropic/OpenAI middleware, audit, approvals
sdk-typescript/  @ephorate/sdk — TS port of the runtime path
control-plane/   FastAPI service: ingestion, search, approvals, reports
web/             Next.js 15 control-plane UI
docs/            Nextra docs site
examples/        end-to-end demo agents
```

## Local setup

You need Python 3.11+, Node 22+, `uv`, and `pnpm` on `PATH`.

```bash
# Python workspace
uv sync --all-packages --all-extras

# TypeScript workspace
pnpm install
```

## Running the test matrix

```bash
# Python: engine, SDK, control plane
uv run pytest engine sdk-python control-plane

# TypeScript: SDK
pnpm --filter @ephorate/sdk test

# Builds
pnpm --filter ephorate-web build
pnpm --filter ephorate-docs build
```

Each Python package has its own `pyproject.toml` with strict mypy +
ruff. CI runs the matrix on every PR.

## Pull-request checklist

- [ ] One logical change per PR. Mixed refactors + features get split
      on review.
- [ ] Tests for new behavior. The engine has a Hypothesis property-test
      pattern; the TS SDK uses Vitest.
- [ ] `uv run ruff check <pkg>` and `uv run mypy <pkg>` clean.
- [ ] If you changed the audit-event shape or the predicate AST,
      regenerate the JSON schemas
      (`uv run python -m ephorate_engine.schema --out engine/schemas/`)
      and commit the result.
- [ ] If you added a public symbol, export it from the package's
      `__init__.py` and document it in `docs/`.
- [ ] Commit messages explain **why**. We don't squash; readable
      history matters.

## Adding a policy to a compliance bundle

1. Edit the appropriate `.ephorate` file under
   `engine/ephorate_engine/bundles/`.
2. Tag the rule with the framework control in `metadata` (e.g.
   `nist_ai_rmf: GOVERN-1.1`) so compliance reports surface it.
3. Add a red-team test case to `engine/tests/test_red_team.py` (for
   `agent_abuse_patterns`) or `engine/tests/test_bundles.py`.
4. Run `ephorate validate --policy engine/ephorate_engine/bundles/<file>`
   to confirm it parses.

## Reporting bugs

Use GitHub Issues. Include:

- Ephorate version (`pip show ephorate-engine`)
- A minimal reproducing input (`PolicyInput` JSON + bundle YAML)
- Expected vs. actual decision

For *security* bugs do **not** open a public issue — see
[SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
By participating you agree to abide by it.

## Licensing & DCO

By submitting a contribution you agree to license it under the
[Apache License 2.0](LICENSE), the same terms as the rest of the
project. We use DCO-style sign-off: please add
`Signed-off-by: Your Name <you@example.com>` to your commit
(`git commit -s`).
