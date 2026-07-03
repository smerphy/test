from __future__ import annotations

import pytest

from praetor_engine.pricing import (
    _price_book,
    compute_cost_usd,
    lookup_pricing,
)


def test_known_model_cost() -> None:
    # opus-4-8: input 15/Mtok, output 75/Mtok.
    cost = compute_cost_usd(
        model="claude-opus-4-8", input_tokens=1_000_000, output_tokens=1_000_000
    )
    assert cost == pytest.approx(90.0)


def test_fuzzy_date_suffix_match() -> None:
    p = lookup_pricing("claude-sonnet-4-5-20260101")
    assert p is not None and p.input == 3.0


def test_unknown_model_is_zero() -> None:
    assert compute_cost_usd(model="gpt-4", input_tokens=1000) == 0.0


def test_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    _price_book.cache_clear()
    monkeypatch.setenv(
        "PRAETOR_CLAUDE_PRICE_BOOK_JSON",
        '{"claude-opus-4-8": {"input": 1.0, "output": 2.0}}',
    )
    try:
        cost = compute_cost_usd(
            model="claude-opus-4-8", input_tokens=1_000_000, output_tokens=1_000_000
        )
        assert cost == pytest.approx(3.0)
    finally:
        _price_book.cache_clear()
