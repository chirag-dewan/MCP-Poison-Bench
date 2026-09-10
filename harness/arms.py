"""Named defense-arm construction for benchmark sweeps.

Each arm supplies all three runner seams.  Later benchmark revisions can add
new controls here without teaching the sweep driver how those controls work.
"""
from __future__ import annotations

from typing import Any, Callable

from defense import policy, provenance, taint

ARM_NAMES = ("none", "meta_filter", "policy", "policy_full")


def build_arm(
    name: str, task: dict[str, Any],
) -> dict[str, Callable[..., Any] | None]:
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
    if name in {"policy", "policy_full"}:
        task_policy = task.get("policy")
        if not isinstance(task_policy, dict):
            raise ValueError(f"{name} arm requires task.policy")
        secrets = task_policy.get("secrets", [])
        if not isinstance(secrets, list) or not all(
            isinstance(secret, str) for secret in secrets
        ):
            raise ValueError("task.policy.secrets must be a list of strings")
        store = taint.TaintStore(secrets=set(secrets))
        # TODO(prompt 03): compose result-side injection filtering with this
        # provenance-recording transform for the policy_full arm.
        return {
            "tool_transform": (
                provenance.build_tool_transform()
                if name == "policy_full"
                else None
            ),
            "result_transform": taint.recording_transform(store),
            "call_policy": policy.build_call_policy(task_policy, store),
        }
    raise ValueError(f"unknown defense arm: {name!r}")
