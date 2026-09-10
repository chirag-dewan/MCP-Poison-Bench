"""Capability and provenance policy for pre-dispatch tool calls."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from defense.taint import TaintStore
from harness.runner import CallPolicy, PolicyDecision

_VALID_TOOL_CLASSES = frozenset({"read", "write", "egress"})
_RESULT_LABEL_PREFIX = "result:"


def build_call_policy(
    task_policy: dict[str, Any],
    store: TaintStore,
) -> CallPolicy:
    """Build a fail-closed call policy for one task and one trial."""
    raw_allowed_tools = task_policy.get("allowed_tools", [])
    if not isinstance(raw_allowed_tools, list) or not all(
        isinstance(name, str) for name in raw_allowed_tools
    ):
        raise ValueError("policy allowed_tools must be a list of tool names")
    allowed_tools = frozenset(raw_allowed_tools)

    raw_tool_classes = task_policy.get("tool_classes", {})
    if not isinstance(raw_tool_classes, Mapping) or not all(
        isinstance(name, str) and isinstance(tool_class, str)
        for name, tool_class in raw_tool_classes.items()
    ):
        raise ValueError("policy tool_classes must map tool names to classes")
    invalid_classes = sorted(
        set(raw_tool_classes.values()) - _VALID_TOOL_CLASSES
    )
    if invalid_classes:
        raise ValueError(
            "policy tool_classes contains unsupported classes: "
            + ", ".join(invalid_classes)
        )
    tool_classes = dict(raw_tool_classes)

    egress_requires = task_policy.get("egress_requires", "no_tainted_args")
    if egress_requires != "no_tainted_args":
        raise ValueError(
            "policy egress_requires must be 'no_tainted_args'"
        )

    allow_cross_server = task_policy.get("allow_cross_server", False)
    if not isinstance(allow_cross_server, bool):
        raise ValueError("policy allow_cross_server must be a boolean")

    def decide(
        tool_name: str,
        tool_input: dict[str, Any],
        ctx: dict[str, Any],
    ) -> PolicyDecision:
        if tool_name not in allowed_tools:
            return PolicyDecision(
                False,
                f"Tool '{tool_name}' is not in the task allowlist.",
                "not_in_allowlist",
            )

        taints = store.taints_in(tool_input)
        tool_class = tool_classes.get(tool_name, "egress")
        if tool_class == "egress" and taints:
            labels = ", ".join(sorted(taints))
            return PolicyDecision(
                False,
                f"Egress tool '{tool_name}' received tainted arguments: {labels}.",
                "tainted_egress",
            )

        if not allow_cross_server:
            destination_server = ctx.get("server_path")
            cross_server_taints = {
                label
                for label in taints
                if label.startswith(_RESULT_LABEL_PREFIX)
                and label[len(_RESULT_LABEL_PREFIX):] != destination_server
            }
            if cross_server_taints:
                labels = ", ".join(sorted(cross_server_taints))
                return PolicyDecision(
                    False,
                    f"Tool '{tool_name}' received cross-server data: {labels}.",
                    "cross_server_flow",
                )

        return PolicyDecision(True, "Allowed by task policy.")

    return decide
