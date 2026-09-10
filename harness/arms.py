"""Named defense-arm construction for benchmark sweeps.

Each arm supplies all three runner seams.  Later benchmark revisions can add
new controls here without teaching the sweep driver how those controls work.
"""
from __future__ import annotations

from typing import Any, Callable

from defense import confirm, hardening, pinning, policy, provenance, result_filter, taint

ARM_NAMES = (
    "none",
    "meta_filter",
    "result_filter",
    "meta_and_result_filter",
    "pinning",
    "policy",
    "policy_full",
    "confirm",
    "confirm_ux",
    "model_hardening",
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


def _compose_tool_transforms(
    *transforms: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
) -> Callable[[list[dict[str, Any]]], list[dict[str, Any]]]:
    """Apply metadata transforms left-to-right."""

    def composed(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for transform in transforms:
            tools = transform(tools)
        return tools

    return composed


def _result_filter_parts() -> tuple[Callable[..., Any], list[Any]]:
    """Build a filter and its per-result findings collector for trace output."""
    findings: list[Any] = []
    transform = result_filter.build_result_transform(on_findings=findings.extend)
    return transform, findings


def _pinning_parts() -> tuple[Callable[..., Any], list[Any]]:
    """Build a fresh per-trial pin store, transform, and findings collector."""
    findings: list[Any] = []
    transform = pinning.build_pinning_transform(
        pinning.PinStore(), on_findings=findings.extend,
    )
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
    if name == "pinning":
        transform, findings = _pinning_parts()
        return {
            "tool_transform": transform,
            "result_transform": None,
            "call_policy": None,
            "pinning_findings": findings,
            "relist_each_step": True,
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
        tool_transform: Callable[..., Any] | None = None
        pinning_findings: list[Any] | None = None
        if name == "policy_full":
            filtering, findings = _result_filter_parts()
            # Taint must see the raw server text before content filtering changes
            # what the model reads.
            result_transform = _compose_result_transforms(recording, filtering)
            pinning_transform, pinning_findings = _pinning_parts()
            # Pin the raw server metadata before the v1 filter rewrites it.
            tool_transform = _compose_tool_transforms(
                pinning_transform, provenance.build_tool_transform(),
            )
        return {
            "tool_transform": tool_transform,
            "result_transform": result_transform,
            "call_policy": policy.build_call_policy(task_policy, store),
            **({"result_findings": findings} if findings is not None else {}),
            **(
                {
                    "pinning_findings": pinning_findings,
                    "relist_each_step": True,
                }
                if pinning_findings is not None
                else {}
            ),
        }
    if name in {"confirm", "confirm_ux"}:
        task_policy = task.get("policy")
        if not isinstance(task_policy, dict):
            raise ValueError(f"{name} arm requires task.policy")
        secrets = task_policy.get("secrets", [])
        if not isinstance(secrets, list) or not all(
            isinstance(secret, str) for secret in secrets
        ):
            raise ValueError("task.policy.secrets must be a list of strings")
        store = taint.TaintStore(secrets=set(secrets))
        oracle = confirm.ConfirmOracle(
            "deny_tainted_egress" if name == "confirm" else "allow_all"
        )
        return {
            "tool_transform": None,
            "result_transform": taint.recording_transform(store),
            "call_policy": confirm.build_confirm_policy(
                task_policy, store, oracle,
            ),
            "confirm_prompts": oracle.prompts,
        }
    if name == "model_hardening":
        return {
            "tool_transform": hardening.build_marker_only_tool_transform(),
            "result_transform": result_filter.build_marker_only_transform(),
            "call_policy": None,
            "context_transform": hardening.build_context_transform(),
            "hardening_version": hardening.HARDENING_VERSION,
        }
    raise ValueError(f"unknown defense arm: {name!r}")
