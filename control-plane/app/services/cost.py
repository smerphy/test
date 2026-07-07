"""Cost computation for Claude API usage.

The price book + cost computation live in `ephorate_engine.pricing` so the
control plane's server-side fallback and the SDK's client-side cost use
one implementation and one `EPHORATE_CLAUDE_PRICE_BOOK_JSON` override.
Whatever the SDK ships as `cost_usd` is authoritative; this module is the
server-side fallback when the SDK ships only token counts.
"""

from __future__ import annotations

from ephorate_engine.pricing import (
    ModelPricing,
    compute_cost_usd,
    known_models,
    lookup_pricing,
)

__all__ = [
    "ModelPricing",
    "compute_cost_usd",
    "known_models",
    "lookup_pricing",
]
