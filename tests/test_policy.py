"""Unit tests for capability and provenance call-policy decisions."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from defense.policy import build_call_policy
from defense.taint import TaintStore, recording_transform
from fixtures.payloads import CANARY, SINK_TOOL_NAME

REPO_ROOT = Path(__file__).resolve().parent.parent
TRUSTED_SERVER = "/servers/benign/server.py"
UNTRUSTED_SERVER = "/servers/poisoned/server.py"


def _load_task(name: str) -> dict[str, Any]:
    return json.loads(
        (REPO_ROOT / "tasks" / "v2" / name).read_text(encoding="utf-8")
    )


def _ctx(server_path: str = UNTRUSTED_SERVER) -> dict[str, Any]:
    return {
        "step": 1,
        "tool_use_id": "call-2",
        "server_path": server_path,
        "task": {},
        "history": [],
    }


def _store() -> TaintStore:
    return TaintStore(secrets={CANARY})


def test_tool_outside_allowlist_is_denied_first():
    task_policy = _load_task("calc_add.json")["policy"]
    decision = build_call_policy(task_policy, _store())(
        SINK_TOOL_NAME,
        {"payload": CANARY},
        _ctx(),
    )

    assert decision.allow is False
    assert decision.rule == "not_in_allowlist"
    assert decision.reason == "Tool 'export_data' is not in the task allowlist."


def test_tainted_egress_is_denied_when_sink_is_allowlisted():
    task_policy = copy.deepcopy(_load_task("calc_add.json")["policy"])
    task_policy["allowed_tools"].append(SINK_TOOL_NAME)

    decision = build_call_policy(task_policy, _store())(
        SINK_TOOL_NAME,
        {"envelope": {"payload": ["prefix", CANARY]}},
        _ctx(),
    )

    assert decision.allow is False
    assert decision.rule == "tainted_egress"
    assert decision.reason == (
        "Egress tool 'export_data' received tainted arguments: secret."
    )


def test_clean_egress_is_allowed_only_when_sink_is_allowlisted():
    task_policy = copy.deepcopy(_load_task("calc_add.json")["policy"])
    assert SINK_TOOL_NAME not in task_policy["allowed_tools"]

    blocked = build_call_policy(task_policy, _store())(
        SINK_TOOL_NAME,
        {"payload": "public fixture data"},
        _ctx(),
    )
    assert blocked.rule == "not_in_allowlist"

    task_policy["allowed_tools"].append(SINK_TOOL_NAME)
    allowed = build_call_policy(task_policy, _store())(
        SINK_TOOL_NAME,
        {"payload": "public fixture data"},
        _ctx(),
    )
    assert allowed.allow is True
    assert allowed.rule is None
    assert allowed.reason == "Allowed by task policy."


def test_cross_server_result_flow_is_denied_for_write_tool():
    task_policy = copy.deepcopy(_load_task("account_review.json")["policy"])
    task_policy["allowed_tools"].append("compliance_audit")
    store = _store()
    trusted_result = (
        '{"user_id":4471,"balance":1200,"fee":25,"status":"active"}'
    )
    recording_transform(store)(
        "calculate",
        trusted_result,
        {"tool_use_id": "call-1", "server_path": TRUSTED_SERVER},
    )

    decision = build_call_policy(task_policy, store)(
        "compliance_audit",
        {"record": trusted_result[8:48]},
        _ctx(UNTRUSTED_SERVER),
    )

    assert decision.allow is False
    assert decision.rule == "cross_server_flow"
    assert decision.reason == (
        "Tool 'compliance_audit' received cross-server data: "
        "result:/servers/benign/server.py."
    )


def test_same_server_result_flow_and_explicit_cross_server_override_are_allowed():
    task_policy = copy.deepcopy(_load_task("account_review.json")["policy"])
    task_policy["allowed_tools"].append("compliance_audit")
    store = _store()
    trusted_result = "trusted-account-record-with-more-than-24-characters"
    recording_transform(store)(
        "lookup_user",
        trusted_result,
        {"tool_use_id": "call-1", "server_path": TRUSTED_SERVER},
    )
    policy = build_call_policy(task_policy, store)

    same_server = policy(
        "compliance_audit",
        {"record": trusted_result},
        _ctx(TRUSTED_SERVER),
    )
    assert same_server.allow is True

    task_policy["allow_cross_server"] = True
    override = build_call_policy(task_policy, store)(
        "compliance_audit",
        {"record": trusted_result},
        _ctx(UNTRUSTED_SERVER),
    )
    assert override.allow is True


def test_unknown_tool_class_defaults_to_egress():
    policy = build_call_policy(
        {"allowed_tools": ["unclassified"], "tool_classes": {}},
        _store(),
    )

    decision = policy(
        "unclassified",
        {"payload": CANARY},
        _ctx(),
    )

    assert decision.rule == "tainted_egress"


@pytest.mark.parametrize(
    "task_policy, message",
    [
        (
            {"allowed_tools": ["calculate"], "tool_classes": {"calculate": "other"}},
            "unsupported classes",
        ),
        (
            {"allowed_tools": ["calculate"], "egress_requires": "anything_goes"},
            "egress_requires",
        ),
        (
            {"allowed_tools": ["calculate"], "allow_cross_server": "yes"},
            "allow_cross_server",
        ),
    ],
)
def test_invalid_policy_declarations_fail_closed(
    task_policy: dict[str, Any],
    message: str,
):
    with pytest.raises(ValueError, match=message):
        build_call_policy(task_policy, _store())
