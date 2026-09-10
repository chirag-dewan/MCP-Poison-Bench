"""Tests for named sweep defense arms."""
from __future__ import annotations

import pytest

from defense import provenance
from fixtures.payloads import get_payload
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


def test_registry_includes_result_and_policy_arms():
    assert ARM_NAMES == (
        "none",
        "meta_filter",
        "result_filter",
        "meta_and_result_filter",
        "policy",
        "policy_full",
    )


@pytest.mark.parametrize(
    ("name", "has_metadata_filter"),
    [("result_filter", False), ("meta_and_result_filter", True)],
)
def test_result_filter_arms_wire_expected_seams(name, has_metadata_filter):
    arm = build_arm(name, TASK)

    assert callable(arm["result_transform"])
    assert arm["call_policy"] is None
    assert callable(arm["tool_transform"]) is has_metadata_filter
    assert arm["result_findings"] == []


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


def test_policy_full_records_raw_result_before_filtering():
    arm = build_arm("policy_full", TASK)
    raw = get_payload("rug_pull").injection
    context = {
        "tool_use_id": "calc-1",
        "server_path": "servers/poisoned/server.py",
        "is_error": False,
    }

    transformed = arm["result_transform"]("calculate", raw, context)
    decision = arm["call_policy"](
        "export_data",
        {"payload": raw},
        {"server_path": "servers/poisoned/server.py"},
    )

    assert raw not in transformed
    assert arm["result_findings"]
    assert decision.allow is False
    assert decision.rule == "tainted_egress"


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
