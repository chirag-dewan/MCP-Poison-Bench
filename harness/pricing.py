"""Per-model token pricing + cost estimation for the sweep's dry-run projection.

Owned by agent:harness. This module exists ONLY to turn recorded token usage into a
dollar figure for the dry-run cost projection (harness/sweep.py --dry-run). It does
NOT touch trial generation, scoring, or the matrix — cost is a side report, never an
input to ASR/utility.

Prices are USD per 1,000,000 tokens, (input, output). `confirmed=False` marks a rate
the maintainer must verify against the vendor's live pricing page before trusting the
projection — the dry-run report prints a loud warning listing every unconfirmed model
it priced, so a guessed rate can never be mistaken for a measured one.

Sources for the confirmed rows (as of 2026-07): Anthropic pricing (Opus 4.8 $5/$25,
Sonnet 5 $3/$15, Haiku 4.5 $1/$5) and OpenAI GPT-5.5 ($5/$30). The two 2026-07 budget
models added for the refresh — gpt-5.4-nano and deepseek-v4-flash — are PLACEHOLDERS:
their exact per-token rates were not confirmable at authoring time and MUST be filled
in before the cost projection is used to size the full run.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelPrice:
    input_per_m: float   # USD per 1M input (prompt) tokens
    output_per_m: float  # USD per 1M output (completion, incl. reasoning) tokens
    confirmed: bool      # False => verify against the vendor page before trusting
    note: str = ""


#: Exact-id price table. Keys are the model strings used in the sweep configs.
PRICES: dict[str, ModelPrice] = {
    # --- 2026-07 refresh roster ---
    "claude-opus-4-8": ModelPrice(5.0, 25.0, True, "Anthropic pricing 2026-07"),
    "gpt-5.5": ModelPrice(5.0, 30.0, True, "OpenAI GPT-5.5 API pricing 2026-07"),
    "gpt-5.4-nano": ModelPrice(
        0.05, 0.40, False,
        "PLACEHOLDER — confirm gpt-5.4-nano input/output rate on the OpenAI pricing page",
    ),
    "deepseek-v4-flash": ModelPrice(
        0.28, 0.42, False,
        "PLACEHOLDER — confirm deepseek-v4-flash rate (and cache/off-peak tiers) on the DeepSeek pricing page",
    ),
    # --- other current models (not in the refresh roster; kept for convenience) ---
    "claude-sonnet-5": ModelPrice(3.0, 15.0, True, "Anthropic pricing 2026-07"),
    "claude-haiku-4-5": ModelPrice(1.0, 5.0, True, "Anthropic pricing 2026-07"),
    "claude-haiku-4-5-20251001": ModelPrice(1.0, 5.0, True, "Anthropic pricing 2026-07"),
    # --- original-run models (for back-of-envelope comparison only) ---
    "gpt-4o-mini": ModelPrice(0.15, 0.60, False, "PLACEHOLDER — historical gpt-4o-mini rate, verify"),
    "deepseek-chat": ModelPrice(0.27, 1.10, False, "PLACEHOLDER — legacy deepseek-chat, retires 2026-07-24"),
}


def price_for(model: str) -> ModelPrice | None:
    """Exact-id lookup. Returns None if the model has no price row (never guesses)."""
    return PRICES.get(model)


def estimate_cost(model: str, in_tokens: int, out_tokens: int) -> float | None:
    """USD cost for `in_tokens` input + `out_tokens` output on `model`.

    Returns None if the model is not in the table — the caller must surface that
    rather than silently price it at zero.
    """
    p = PRICES.get(model)
    if p is None:
        return None
    return (in_tokens / 1_000_000.0) * p.input_per_m + (out_tokens / 1_000_000.0) * p.output_per_m


def is_confirmed(model: str) -> bool:
    """True only if the model has a price row AND it is marked confirmed."""
    p = PRICES.get(model)
    return bool(p and p.confirmed)
