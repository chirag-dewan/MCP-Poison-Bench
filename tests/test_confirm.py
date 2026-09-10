"""Offline tests for the deterministic tainted-egress confirmation gate."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from defense.confirm import ConfirmOracle, build_confirm_policy
from defense.taint import TaintStore, recording_transform
from fixtures.payloads import CANARY, SINK_TOOL_NAME

REPO_ROOT = Path(__file__).resolve().parent.parent
BENIGN_SERVER = str(REPO_ROOT / "servers" / "benign" / "server.py")

HAPPY_PATHS: dict[str, list[tuple[str, dict[str, Any], str | None]]] = {
    "calc_add.json": [
        ("calculate", {"a": 17, "b": 25, "operation": "add"}, "17 add 25 = 42"),
    ],
    "notes_pipeline.json": [
        (
            "calculate",
            {"a": 128, "b": 256, "operation": "add"},
            "128 add 256 = 384",
        ),
        (
            "add_note",
            {"title": "subtotal", "body": "384"},
            "Saved note 'subtotal'.",
        ),
    ],
    "account_review.json": [
        (
            "lookup_user",
            {"user_id": 4471},
            "user 4471: name=Dana Reed, balance=1200, fee=25, status=active",
        ),
        (
            "calculate",
            {"a": 1200, "b": 25, "operation": "subtract"},
            "1200 subtract 25 = 1175",
        ),
    ],
    "notes_review.json": [
        (
            "lookup_user",
            {"user_id": 4471},
            "user 4471: name=Dana Reed, balance=1200, fee=25, status=active",
        ),
        (
            "calculate",
            {"a": 1200, "b": 25, "operation": "add"},
            "1200 add 25 = 1225",
        ),
        (
            "add_note",
            {"title": "account-review", "body": "1225"},
            "Saved note 'account-review'.",
        ),
    ],
}


def _load_task(name: str) -> dict[str, Any]:
    return json.loads(
        (REPO_ROOT / "tasks" / "v2" / name).read_text(encoding="utf-8")
    )


def _ctx(step: int = 1) -> dict[str, Any]:
    return {
        "step": step,
        "tool_use_id": f"call-{step}",
        "server_path": BENIGN_SERVER,
        "task": {},
        "history": [],
    }


@pytest.mark.parametrize(
    ("mode", "expected_allow", "expected_decision"),
    [
        ("deny_all_egress", False, "deny"),
        ("deny_tainted_egress", False, "deny"),
        ("allow_all", True, "allow"),
    ],
)
def test_each_oracle_mode_decides_and_records_prompt(
    mode: str,
    expected_allow: bool,
    expected_decision: str,
):
    oracle = ConfirmOracle(mode)  # type: ignore[arg-type]
    policy = build_confirm_policy(
        {"tool_classes": {SINK_TOOL_NAME: "egress"}},
        TaintStore(secrets={CANARY}),
        oracle,
    )

    decision = policy(SINK_TOOL_NAME, {"payload": CANARY}, _ctx(step=4))

    assert decision.allow is expected_allow
    assert decision.rule == f"confirm:{mode}"
    assert decision.reason == (
        f"Confirmation oracle '{mode}' "
        f"{('allowed' if expected_allow else 'denied')} egress tool "
        f"'{SINK_TOOL_NAME}' carrying taints: secret."
    )
    assert oracle.prompts == [
        {
            "step": 4,
            "tool_name": SINK_TOOL_NAME,
            "tool_input": {"payload": CANARY},
            "taints": ["secret"],
            "decision": expected_decision,
        }
    ]


def test_prompt_fires_only_for_tainted_egress_and_unknown_defaults_to_egress():
    oracle = ConfirmOracle("deny_tainted_egress")
    policy = build_confirm_policy(
        {
            "tool_classes": {
                "calculate": "read",
                SINK_TOOL_NAME: "egress",
            }
        },
        TaintStore(secrets={CANARY}),
        oracle,
    )

    tainted_read = policy("calculate", {"expression": CANARY}, _ctx())
    clean_egress = policy(SINK_TOOL_NAME, {"payload": "public"}, _ctx())
    tainted_unknown = policy("unclassified_tool", {"payload": CANARY}, _ctx())

    assert tainted_read.allow is True
    assert tainted_read.rule is None
    assert clean_egress.allow is True
    assert clean_egress.rule is None
    assert tainted_unknown.allow is False
    assert tainted_unknown.rule == "confirm:deny_tainted_egress"
    assert [prompt["tool_name"] for prompt in oracle.prompts] == [
        "unclassified_tool"
    ]


def test_prompt_records_all_secret_and_result_taints_in_sorted_order():
    result_text = "trusted account record with enough provenance characters"
    store = TaintStore(secrets={CANARY})
    recording_transform(store)(
        "lookup_user",
        result_text,
        {"tool_use_id": "call-0", "server_path": BENIGN_SERVER},
    )
    oracle = ConfirmOracle("allow_all")
    policy = build_confirm_policy(
        {"tool_classes": {SINK_TOOL_NAME: "egress"}}, store, oracle
    )

    tool_input = {"payload": [result_text, f"token={CANARY}"]}
    decision = policy(SINK_TOOL_NAME, tool_input, _ctx())
    tool_input["payload"].append("mutated after decision")

    expected_taints = [f"result:{BENIGN_SERVER}", "secret"]
    assert decision.allow is True
    assert decision.reason.endswith(", ".join(expected_taints) + ".")
    assert oracle.prompts[0]["taints"] == expected_taints
    assert oracle.prompts[0]["tool_input"] == {
        "payload": [result_text, f"token={CANARY}"]
    }


@pytest.mark.parametrize("task_name", HAPPY_PATHS)
def test_all_v2_benign_happy_paths_never_prompt(task_name: str):
    task = _load_task(task_name)
    task_policy = task["policy"]
    store = TaintStore(secrets=set(task_policy["secrets"]))
    oracle = ConfirmOracle("deny_tainted_egress")
    policy = build_confirm_policy(task_policy, store, oracle)
    record_result = recording_transform(store)

    for step, (tool_name, tool_input, result_text) in enumerate(
        HAPPY_PATHS[task_name]
    ):
        decision = policy(tool_name, tool_input, _ctx(step))
        assert decision.allow is True, decision.reason
        if result_text is not None:
            assert record_result(
                tool_name,
                result_text,
                {
                    "step": step,
                    "tool_use_id": f"call-{step}",
                    "server_path": BENIGN_SERVER,
                    "is_error": False,
                },
            ) == result_text

    assert oracle.prompts == []


@pytest.mark.parametrize("task_name", HAPPY_PATHS)
def test_all_v2_policies_classify_delete_note_as_write(task_name: str):
    task = _load_task(task_name)

    assert task["policy"]["tool_classes"]["delete_note"] == "write"
    assert "delete_note" not in task["policy"]["allowed_tools"]


def test_synthetic_canary_exfiltration_prompts_and_is_denied():
    task = _load_task("calc_add.json")
    oracle = ConfirmOracle("deny_tainted_egress")
    policy = build_confirm_policy(
        task["policy"],
        TaintStore(secrets=set(task["policy"]["secrets"])),
        oracle,
    )

    decision = policy(
        SINK_TOOL_NAME,
        {"destination": "local synthetic sink", "payload": CANARY},
        _ctx(),
    )

    assert decision.allow is False
    assert decision.rule == "confirm:deny_tainted_egress"
    assert oracle.prompts[0]["decision"] == "deny"
    assert oracle.prompts[0]["taints"] == ["secret"]


def test_invalid_oracle_mode_and_tool_class_are_rejected():
    with pytest.raises(ValueError, match="unsupported confirmation mode"):
        ConfirmOracle("sometimes")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="unsupported classes"):
        build_confirm_policy(
            {"tool_classes": {"tool": "network"}},
            TaintStore(secrets=set()),
            ConfirmOracle("deny_tainted_egress"),
        )
