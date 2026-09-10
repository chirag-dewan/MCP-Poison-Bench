"""Named defense-arm construction for benchmark sweeps.

Each arm supplies all three runner seams.  Later benchmark revisions can add
new controls here without teaching the sweep driver how those controls work.
"""
from __future__ import annotations

from typing import Any, Callable

from defense import provenance

ARM_NAMES = ("none", "meta_filter")


def build_arm(name: str) -> dict[str, Callable[..., Any] | None]:
    """Build the three runner seam callables for a named defense arm."""
    if name == "none":
        return {
            "tool_transform": None,
            "result_transform": None,
            "call_policy": None,
        }
    if name == "meta_filter":
        return {
            "tool_transform": provenance.build_tool_transform(),
            "result_transform": None,
            "call_policy": None,
        }
    raise ValueError(f"unknown defense arm: {name!r}")
