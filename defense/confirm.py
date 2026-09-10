"""Deterministic confirmation gate for tainted egress calls."""
from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from defense.taint import TaintStore
from harness.runner import CallPolicy, PolicyDecision

ConfirmMode = Literal[
    "deny_all_egress",
    "deny_tainted_egress",
    "allow_all",
]

_VALID_MODES = frozenset(
    {"deny_all_egress", "deny_tainted_egress", "allow_all"}
)
_VALID_TOOL_CLASSES = frozenset({"read", "write", "egress"})


@dataclass
class ConfirmOracle:
    """Deterministic simulated human and the prompts shown during one trial."""

    mode: ConfirmMode
    prompts: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in _VALID_MODES:
            raise ValueError(f"unsupported confirmation mode: {self.mode!r}")


def build_confirm_policy(
    task_policy: dict[str, Any],
    store: TaintStore,
    oracle: ConfirmOracle,
) -> CallPolicy:
    """Build a gate that prompts only when tainted data would reach egress.

    Unknown tools fail closed into the ``egress`` class.  Calls outside the
    prompt condition are allowed directly; prompted calls are allowed only by
    the ``allow_all`` oracle.
    """
    raw_tool_classes = task_policy.get("tool_classes", {})
    if not isinstance(raw_tool_classes, Mapping) or not all(
        isinstance(name, str) and isinstance(tool_class, str)
        for name, tool_class in raw_tool_classes.items()
    ):
        raise ValueError("policy tool_classes must map tool names to classes")
    invalid_classes = sorted(set(raw_tool_classes.values()) - _VALID_TOOL_CLASSES)
    if invalid_classes:
        raise ValueError(
            "policy tool_classes contains unsupported classes: "
            + ", ".join(invalid_classes)
        )
    tool_classes = dict(raw_tool_classes)

    def decide(
        tool_name: str,
        tool_input: dict[str, Any],
        ctx: dict[str, Any],
    ) -> PolicyDecision:
        taints = sorted(store.taints_in(tool_input))
        tool_class = tool_classes.get(tool_name, "egress")
        if tool_class != "egress" or not taints:
            return PolicyDecision(True, "Confirmation not required.")

        allow = oracle.mode == "allow_all"
        decision = "allow" if allow else "deny"
        oracle.prompts.append(
            {
                "step": ctx.get("step"),
                "tool_name": tool_name,
                "tool_input": copy.deepcopy(tool_input),
                "taints": taints,
                "decision": decision,
            }
        )
        labels = ", ".join(taints)
        disposition = "allowed" if allow else "denied"
        return PolicyDecision(
            allow,
            f"Confirmation oracle '{oracle.mode}' {disposition} egress tool "
            f"'{tool_name}' carrying taints: {labels}.",
            f"confirm:{oracle.mode}",
        )

    return decide
