"""Named defense-arm construction for benchmark sweeps.

Each arm supplies all three runner seams.  Later benchmark revisions can add
new controls here without teaching the sweep driver how those controls work.
"""
from __future__ import annotations

from typing import Any, Callable

from defense import policy, provenance, result_filter, taint

ARM_NAMES = (
    "none",
    "meta_filter",
    "result_filter",
    "meta_and_result_filter",
    "policy",
    "policy_full",
)


def _compose_result_transforms(
    *transforms: Callable[[str, str, dict[str, Any]], str],
) -> Callable[[str, str, dict[str, Any]], str]:
    """Apply result transforms left-to-right, preserving the raw-first order."""

    def composed(tool_name: str, text: str, ctx: dict[str, Any]) -> str:
        for transform in transforms:
            text = transform(tool_name, text, ctx)
        return text

    return composed


def _result_filter_parts() -> tuple[Callable[..., Any], list[Any]]:
    """Build a filter and its per-result findings collector for trace output."""
    findings: list[Any] = []
    transform = result_filter.build_result_transform(on_findings=findings.extend)
    return transform, findings


def build_arm(
    name: str, task: dict[str, Any],
) -> dict[str, Any]:
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
    if name in {"result_filter", "meta_and_result_filter"}:
        transform, findings = _result_filter_parts()
        return {
            "tool_transform": (
                provenance.build_tool_transform()
                if name == "meta_and_result_filter"
                else None
            ),
            "result_transform": transform,
            "call_policy": None,
            "result_findings": findings,
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
        recording = taint.recording_transform(store)
        findings: list[Any] | None = None
        result_transform: Callable[..., Any] = recording
        if name == "policy_full":
            filtering, findings = _result_filter_parts()
            # Taint must see the raw server text before content filtering changes
            # what the model reads.
            result_transform = _compose_result_transforms(recording, filtering)
        return {
            "tool_transform": (
                provenance.build_tool_transform()
                if name == "policy_full"
                else None
            ),
            "result_transform": result_transform,
            "call_policy": policy.build_call_policy(task_policy, store),
            **({"result_findings": findings} if findings is not None else {}),
        }
    raise ValueError(f"unknown defense arm: {name!r}")
