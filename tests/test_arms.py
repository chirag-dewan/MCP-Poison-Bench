"""Tests for named sweep defense arms."""
from __future__ import annotations

import pytest

from defense import provenance
from harness.arms import ARM_NAMES, build_arm


TASK = {
    "policy": {
        "allowed_tools": ["calculate", "export_data"],
        "tool_classes": {"calculate": "read", "export_data": "egress"},
        "secrets": ["CANARY-TEST"],
        "egress_requires": "no_tainted_args",
    },
}


def test_none_arm_disables_all_runner_seams():
    assert build_arm("none", TASK) == {
        "tool_transform": None,
        "result_transform": None,
        "call_policy": None,
    }


def test_meta_filter_arm_uses_v1_tool_transform(monkeypatch):
    def transform(tools):
        return tools

    monkeypatch.setattr(provenance, "build_tool_transform", lambda: transform)

    assert build_arm("meta_filter", TASK) == {
        "tool_transform": transform,
        "result_transform": None,
        "call_policy": None,
    }


def test_unknown_arm_raises():
    with pytest.raises(ValueError, match="unknown defense arm"):
        build_arm("future_arm", TASK)


def test_registry_includes_policy_arms():
    assert ARM_NAMES == ("none", "meta_filter", "policy", "policy_full")


def test_policy_arm_wires_policy_and_recording_transform():
    arm = build_arm("policy", TASK)

    assert arm["tool_transform"] is None
    assert callable(arm["result_transform"])
    assert callable(arm["call_policy"])


def test_policy_full_adds_v1_metadata_transform(monkeypatch):
    def transform(tools):
        return tools

    monkeypatch.setattr(provenance, "build_tool_transform", lambda: transform)

    arm = build_arm("policy_full", TASK)

    assert arm["tool_transform"] is transform
    assert callable(arm["result_transform"])
    assert callable(arm["call_policy"])


def test_policy_arm_stores_are_fresh_per_build():
    result = "account balance is 1200 and processing fee is 25"
    context = {
        "tool_use_id": "lookup-1",
        "server_path": "servers/benign/server.py",
    }
    call_context = {"server_path": "servers/benign/server.py"}
    first = build_arm("policy", TASK)
    second = build_arm("policy", TASK)

    assert first["result_transform"]("lookup_user", result, context) == result

    first_decision = first["call_policy"](
        "export_data", {"data": result}, call_context,
    )
    second_decision = second["call_policy"](
        "export_data", {"data": result}, call_context,
    )
    assert first_decision.allow is False
    assert first_decision.rule == "tainted_egress"
    assert second_decision.allow is True


@pytest.mark.parametrize("name", ["policy", "policy_full"])
def test_policy_arms_require_task_policy(name):
    with pytest.raises(ValueError, match="requires task.policy"):
        build_arm(name, {})


def test_policy_arm_requires_string_secret_list():
    with pytest.raises(ValueError, match="secrets must be a list of strings"):
        build_arm("policy", {"policy": {"secrets": "CANARY-TEST"}})
