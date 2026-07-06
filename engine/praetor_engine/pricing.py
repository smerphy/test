"""Claude price book + cost computation.

Single source of truth shared by the control plane (server-side cost
fallback at ingestion) and the SDK monitor (client-side cost on each
call). Prices are per-million-tokens in USD.

The defaults are illustrative; override with contract pricing via
`PRAETOR_CLAUDE_PRICE_BOOK_JSON`, e.g.

    PRAETOR_CLAUDE_PRICE_BOOK_JSON='{"claude-opus-4-8": {"input": 12, "output": 60}}'

The override is read here once, so both the SDK and the control plane
honor the same env var (previously the SDK ignored it).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class ModelPricing:
    """Per-million-token pricing in USD."""

    input: float
    output: float
    cache_read: float = 0.0
    cache_write: float = 0.0


_DEFAULT_PRICE_BOOK: dict[str, ModelPricing] = {
    "claude-opus-4-8": ModelPricing(15.0, 75.0, 1.5, 18.75),
    "claude-opus-4-7": ModelPricing(15.0, 75.0, 1.5, 18.75),
    "claude-opus-4-6": ModelPricing(15.0, 75.0, 1.5, 18.75),
    "claude-sonnet-4-6": ModelPricing(3.0, 15.0, 0.3, 3.75),
    "claude-sonnet-4-5": ModelPricing(3.0, 15.0, 0.3, 3.75),
    "claude-haiku-4-5-20251001": ModelPricing(0.8, 4.0, 0.08, 1.0),
    "claude-haiku-4-5": ModelPricing(0.8, 4.0, 0.08, 1.0),
}


@lru_cache(maxsize=1)
def _price_book() -> dict[str, ModelPricing]:
    override = os.environ.get("PRAETOR_CLAUDE_PRICE_BOOK_JSON")
    if not override:
        return _DEFAULT_PRICE_BOOK
    try:
        raw = json.loads(override)
    except json.JSONDecodeError:
        return _DEFAULT_PRICE_BOOK
    book = dict(_DEFAULT_PRICE_BOOK)
    for model, prices in raw.items():
        if not isinstance(prices, dict):
            continue
        book[model] = ModelPricing(
            input=float(prices.get("input", 0)),
            output=float(prices.get("output", 0)),
            cache_read=float(prices.get("cache_read", 0)),
            cache_write=float(prices.get("cache_write", 0)),
        )
    return book


def lookup_pricing(model: str) -> ModelPricing | None:
    book = _price_book()
    if model in book:
        return book[model]
    # Fuzzy: strip a trailing date suffix (e.g. claude-x-20251001 -> claude-x).
    parts = model.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit() and parts[0] in book:
        return book[parts[0]]
    return None


def compute_cost_usd(
    *,
    model: str,
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    """Compute cost in USD for one Claude API call.

    Returns 0.0 for unknown models (caller can decide whether to log a
    warning); never raises.
    """
    pricing = lookup_pricing(model)
    if pricing is None:
        return 0.0
    return (
        input_tokens * pricing.input
        + output_tokens * pricing.output
        + cache_read_tokens * pricing.cache_read
        + cache_write_tokens * pricing.cache_write
    ) / 1_000_000


def known_models() -> list[str]:
    return sorted(_price_book())


__all__ = [
    "ModelPricing",
    "compute_cost_usd",
    "known_models",
    "lookup_pricing",
]
