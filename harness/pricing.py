"""Per-model token pricing + cost estimation for sweep dry-run projections.

Owned by agent:harness. Pricing is used only for the operator-facing cost
projection; it never feeds trial generation, scoring, or aggregation. Rows with
``confirmed=False`` must be verified before their projections are trusted.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelPrice:
    input_per_m: float
    output_per_m: float
    confirmed: bool
    note: str = ""


#: USD per 1,000,000 tokens, keyed by the exact model ids used in configs.
PRICES: dict[str, ModelPrice] = {
    "claude-opus-4-8": ModelPrice(
        5.0, 25.0, True, "Anthropic pricing 2026-07",
    ),
    "gpt-5.5": ModelPrice(
        5.0, 30.0, True, "OpenAI GPT-5.5 API pricing 2026-07",
    ),
    "gpt-5.4-nano": ModelPrice(
        0.05,
        0.40,
        False,
        "TODO(confirm): placeholder gpt-5.4-nano input/output rate",
    ),
    "deepseek-v4-flash": ModelPrice(
        0.28,
        0.42,
        False,
        "TODO(confirm): placeholder deepseek-v4-flash rate and pricing tiers",
    ),
    "claude-sonnet-5": ModelPrice(
        3.0, 15.0, True, "Anthropic pricing 2026-07",
    ),
    "claude-haiku-4-5": ModelPrice(
        1.0, 5.0, True, "Anthropic pricing 2026-07",
    ),
    "claude-haiku-4-5-20251001": ModelPrice(
        1.0, 5.0, True, "Anthropic pricing 2026-07",
    ),
    "gpt-4o-mini": ModelPrice(
        0.15, 0.60, False, "PLACEHOLDER — historical rate, verify",
    ),
    "deepseek-chat": ModelPrice(
        0.27, 1.10, False, "PLACEHOLDER — legacy rate, verify",
    ),
}


def price_for(model: str) -> ModelPrice | None:
    """Return the exact-id price row, or ``None`` rather than guessing."""
    return PRICES.get(model)


def estimate_cost(model: str, in_tokens: int, out_tokens: int) -> float | None:
    """Estimate USD cost, returning ``None`` when no price row exists."""
    price = price_for(model)
    if price is None:
        return None
    return (
        (in_tokens / 1_000_000.0) * price.input_per_m
        + (out_tokens / 1_000_000.0) * price.output_per_m
    )


def is_confirmed(model: str) -> bool:
    """Whether ``model`` has a price row explicitly marked confirmed."""
    price = price_for(model)
    return bool(price and price.confirmed)
