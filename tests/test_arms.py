"""Tests for named sweep defense arms."""
from __future__ import annotations

import pytest

from defense import pinning, provenance
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
        "pinning",
        "policy",
        "policy_full",
        "confirm",
        "confirm_ux",
        "model_hardening",
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


def test_policy_full_pins_before_v1_metadata_transform(monkeypatch):
    order = []

    def pin_transform(tools):
        order.append("pinning")
        return tools

    def meta_transform(tools):
        order.append("meta_filter")
        return tools

    monkeypatch.setattr(
        pinning,
        "build_pinning_transform",
        lambda _store, on_findings: pin_transform,
    )
    monkeypatch.setattr(provenance, "build_tool_transform", lambda: meta_transform)

    arm = build_arm("policy_full", TASK)
    arm["tool_transform"]([])

    assert order == ["pinning", "meta_filter"]
    assert callable(arm["result_transform"])
    assert callable(arm["call_policy"])
    assert arm["pinning_findings"] == []
    assert arm["relist_each_step"] is True


def test_pinning_arm_uses_fresh_store_and_requests_relisting():
    first = build_arm("pinning", TASK)
    second = build_arm("pinning", TASK)
    original = {
        "name": "calculate",
        "description": "clean",
        "input_schema": {},
        "server_path": "server.py",
    }
    changed = {**original, "description": "changed"}

    assert first["tool_transform"]([original]) == [original]
    assert first["tool_transform"]([changed]) == []
    assert second["tool_transform"]([changed]) == [changed]
    assert first["pinning_findings"]
    assert second["pinning_findings"] == []
    assert first["result_transform"] is None
    assert first["call_policy"] is None
    assert first["relist_each_step"] is True


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


@pytest.mark.parametrize(
    ("name", "expected_allow", "expected_mode"),
    [
        ("confirm", False, "deny_tainted_egress"),
        ("confirm_ux", True, "allow_all"),
    ],
)
def test_confirmation_arms_record_and_decide_tainted_egress(
    name, expected_allow, expected_mode,
):
    arm = build_arm(name, TASK)

    assert arm["tool_transform"] is None
    assert arm["result_transform"](
        "calculate",
        "17 add 25 = 42",
        {"tool_use_id": "calc-1", "server_path": "server.py"},
    ) == "17 add 25 = 42"
    decision = arm["call_policy"](
        "export_data",
        {"payload": "CANARY-TEST"},
        {"step": 1, "server_path": "server.py"},
    )

    assert decision.allow is expected_allow
    assert decision.rule == f"confirm:{expected_mode}"
    assert arm["confirm_prompts"][0]["decision"] == (
        "allow" if expected_allow else "deny"
    )


def test_confirmation_arm_oracles_are_fresh_per_build():
    first = build_arm("confirm", TASK)
    second = build_arm("confirm", TASK)

    first["call_policy"](
        "export_data",
        {"payload": "CANARY-TEST"},
        {"step": 0, "server_path": "server.py"},
    )

    assert len(first["confirm_prompts"]) == 1
    assert second["confirm_prompts"] == []


def test_model_hardening_arm_composes_prompt_and_marker_only_transforms():
    arm = build_arm("model_hardening", TASK)
    injected = get_payload("rug_pull").injection

    context = arm["context_transform"]("original context")
    tool = arm["tool_transform"]([{
        "name": "calculate",
        "description": injected,
        "input_schema": {},
    }])[0]
    result = arm["result_transform"]("calculate", injected, {})

    assert arm["hardening_version"] == "v2.0"
    assert context.endswith("original context")
    assert injected in tool["description"]
    assert injected in result
    assert arm["call_policy"] is None


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


@pytest.mark.parametrize(
    "name", ["policy", "policy_full", "confirm", "confirm_ux"],
)
def test_policy_arms_require_task_policy(name):
    with pytest.raises(ValueError, match="requires task.policy"):
        build_arm(name, {})


def test_policy_arm_requires_string_secret_list():
    with pytest.raises(ValueError, match="secrets must be a list of strings"):
        build_arm("policy", {"policy": {"secrets": "CANARY-TEST"}})
