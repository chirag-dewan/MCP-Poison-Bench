"""Offline tests for metadata pinning and shadowing detection."""
from __future__ import annotations

import copy

import pytest

from defense.pinning import PinStore, build_pinning_transform, fingerprint


FIRST_SERVER = "/servers/first.py"
SECOND_SERVER = "/servers/second.py"


def _tool(
    *,
    description: str = "Add two numbers.",
    server_path: str = FIRST_SERVER,
) -> dict:
    return {
        "name": "calculate",
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": {
                "b": {"type": "number"},
                "a": {"description": "First operand.", "type": "number"},
            },
            "required": ["a", "b"],
        },
        "server_path": server_path,
    }


def test_fingerprint_is_stable_under_recursive_key_order():
    first = _tool()
    reordered = {
        "server_path": FIRST_SERVER,
        "input_schema": {
            "required": ["a", "b"],
            "properties": {
                "a": {"type": "number", "description": "First operand."},
                "b": {"type": "number"},
            },
            "type": "object",
        },
        "description": "Add two numbers.",
        "name": "calculate",
    }

    assert fingerprint(first) == fingerprint(reordered)


def test_fingerprint_uses_only_name_description_and_input_schema():
    first = _tool(server_path=FIRST_SERVER)
    second = _tool(server_path=SECOND_SERVER)
    second["runner_only"] = {"ignored": True}

    assert fingerprint(first) == fingerprint(second)


@pytest.mark.parametrize(
    ("mode", "survives", "action"),
    [("block", False, "dropped"), ("alert", True, "alerted")],
)
def test_metadata_drift_is_dropped_or_alerted(mode, survives, action):
    store = PinStore()
    observed = []
    transform = build_pinning_transform(
        store,
        on_drift=mode,
        on_findings=lambda findings: observed.append(findings),
    )
    original = _tool()
    original_snapshot = copy.deepcopy(original)

    assert transform([original]) == [original]
    changed = _tool(description="Changed after approval.")
    result = transform([changed])

    assert bool(result) is survives
    assert original == original_snapshot
    assert store.approved == {
        "calculate": (FIRST_SERVER, fingerprint(original)),
    }
    finding = observed[-1][0]
    assert finding.tool_name == "calculate"
    assert finding.server_path == FIRST_SERVER
    assert finding.kind == "drift"
    assert finding.action == action


def test_shadowing_always_drops_the_later_server_registration():
    findings = []
    transform = build_pinning_transform(
        PinStore(), on_findings=lambda current: findings.extend(current)
    )
    first = _tool(server_path=FIRST_SERVER)
    shadow = _tool(server_path=SECOND_SERVER)

    result = transform([first, shadow])

    assert result == [first]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool_name == "calculate"
    assert finding.server_path == SECOND_SERVER
    assert finding.kind == "shadowing"
    assert finding.action == "dropped"


def test_callback_receives_a_fresh_finding_list_for_each_relist():
    batches = []
    transform = build_pinning_transform(
        PinStore(), on_findings=lambda current: batches.append(current)
    )

    transform([_tool()])
    transform([_tool(description="Changed after approval.")])
    transform([_tool()])

    assert batches[0] == []
    assert [finding.kind for finding in batches[1]] == ["drift"]
    assert batches[2] == []
    assert batches[0] is not batches[2]


def test_invalid_drift_mode_is_rejected_when_building_transform():
    with pytest.raises(ValueError, match="on_drift"):
        build_pinning_transform(PinStore(), on_drift="ignore")  # type: ignore[arg-type]
