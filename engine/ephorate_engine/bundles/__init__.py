"""Starter compliance bundles shipped with the engine.

These are deliberately minimal — enough to demonstrate the
framework-mapping pattern in `metadata`, not a turnkey audit. Customize
in your own bundle and merge with these via the parser:

    from ephorate_engine.bundles import load_bundle
    from ephorate_engine.parser import parse_bundle_file
    policies = load_bundle("nist_ai_rmf") + parse_bundle_file(Path("my_bundle.yaml"))
"""

from __future__ import annotations

from pathlib import Path

from ephorate_engine.evaluator import Policy
from ephorate_engine.parser import parse_bundle_file

_BUNDLE_DIR = Path(__file__).resolve().parent

# Registered starter bundles. Add new ones by dropping a .ephorate file
# alongside and listing it here.
BUNDLES: dict[str, str] = {
    "nist_ai_rmf": "nist_ai_rmf.ephorate",
    "iso_42001": "iso_42001.ephorate",
    "eu_ai_act": "eu_ai_act.ephorate",
    "agent_abuse_patterns": "agent_abuse_patterns.ephorate",
    "prompt_injection": "prompt_injection.ephorate",
}


def list_bundles() -> list[str]:
    """Return the names of every starter bundle that ships with the engine."""
    return sorted(BUNDLES)


def bundle_path(name: str) -> Path:
    """Path to a shipped bundle YAML. Raises `KeyError` for unknown names."""
    try:
        filename = BUNDLES[name]
    except KeyError as exc:
        raise KeyError(
            f"unknown bundle {name!r}; known: {', '.join(list_bundles())}"
        ) from exc
    return _BUNDLE_DIR / filename


def load_bundle(name: str) -> list[Policy]:
    """Parse a shipped bundle into a list of `Policy`."""
    return parse_bundle_file(bundle_path(name))


__all__ = ["BUNDLES", "bundle_path", "list_bundles", "load_bundle"]
