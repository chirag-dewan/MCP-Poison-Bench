"""Lightweight provenance tracking for capability-policy decisions.

The tracker deliberately uses literal substring matching rather than attempting
semantic data-flow analysis.  A string leaf is considered derived from a prior
tool result when the two strings share at least 24 consecutive characters.  This
catches copied or quoted result text while limiting collisions on short, common
fragments, but it remains an approximation: paraphrases are not detected and
unrelated long boilerplate can produce a false positive.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Callable


_MIN_RESULT_SUBSTRING = 24


def _string_leaves(value: Any) -> Iterator[str]:
    """Yield string values recursively from JSON-like mappings and sequences."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for child in value.values():
            yield from _string_leaves(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _string_leaves(child)


def _shares_long_substring(left: str, right: str) -> bool:
    """Return whether two strings share a 24-or-more-character substring."""
    if len(left) < _MIN_RESULT_SUBSTRING or len(right) < _MIN_RESULT_SUBSTRING:
        return False
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    last_start = len(shorter) - _MIN_RESULT_SUBSTRING
    return any(
        shorter[start:start + _MIN_RESULT_SUBSTRING] in longer
        for start in range(last_start + 1)
    )


@dataclass
class TaintStore:
    """Per-trial confidential values and raw tool-result provenance.

    Result provenance is the documented substring approximation described in
    this module's docstring, not a complete information-flow guarantee.
    """

    secrets: set[str]
    tool_outputs: dict[str, str] = field(default_factory=dict)
    server_of: dict[str, str] = field(default_factory=dict)

    def taints_in(self, value: Any) -> set[str]:
        """Return taint labels found in any recursively nested string leaf."""
        leaves = tuple(_string_leaves(value))
        labels: set[str] = set()

        if any(
            secret and secret in leaf
            for secret in self.secrets
            for leaf in leaves
        ):
            labels.add("secret")

        for tool_use_id, result_text in self.tool_outputs.items():
            server_path = self.server_of.get(tool_use_id)
            if server_path is None:
                continue
            if any(_shares_long_substring(leaf, result_text) for leaf in leaves):
                labels.add(f"result:{server_path}")

        return labels


def recording_transform(
    store: TaintStore,
) -> Callable[[str, str, dict[str, Any]], str]:
    """Build an identity result transform that records raw per-trial results."""

    def record(
        _tool_name: str,
        result_text: str,
        ctx: dict[str, Any],
    ) -> str:
        tool_use_id = ctx.get("tool_use_id")
        server_path = ctx.get("server_path")
        if not isinstance(tool_use_id, str) or not isinstance(server_path, str):
            raise ValueError(
                "recording_transform requires string tool_use_id and server_path"
            )
        # Some adapters synthesize IDs and can reuse one on a later model turn.
        # Preserve every result under a deterministic collision suffix so older
        # provenance cannot disappear and make a later policy check fail open.
        record_key = tool_use_id
        suffix = 2
        while record_key in store.tool_outputs:
            record_key = f"{tool_use_id}#{suffix}"
            suffix += 1
        store.tool_outputs[record_key] = result_text
        store.server_of[record_key] = server_path
        return result_text

    return record
