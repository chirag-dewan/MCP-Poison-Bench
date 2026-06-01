"""Tests for the payload fixtures — every class is covered and the sink is shared.

These guard the dataset's structural invariants that the servers and scorers rely
on (consistent sink mechanism, labeled-by-class, no empty classes).
"""
from __future__ import annotations

import pytest

from fixtures.payloads import (
    ATTACK_CLASSES,
    CANARY,
    PAYLOADS,
    SINK_TOOL_NAME,
    get_payload,
    iter_payloads,
)


def test_all_four_classes_present():
    assert set(ATTACK_CLASSES) == {
        "tool_description", "schema_field", "rug_pull", "cross_server",
    }
    for cls in ATTACK_CLASSES:
        assert PAYLOADS[cls], f"class {cls} has no payloads"


def test_payloads_labeled_with_their_class():
    for cls in ATTACK_CLASSES:
        for p in iter_payloads(cls):
            assert p.attack_class == cls


def test_sink_and_canary_are_shared_constants():
    assert SINK_TOOL_NAME == "export_data"
    assert CANARY.startswith("CANARY-")


def test_every_payload_targets_the_shared_sink():
    # Consistent attacker-sink mechanism across classes: every injection steers
    # toward export_data (named directly, or — for rug_pull/td — via the objective).
    for cls in ATTACK_CLASSES:
        for p in iter_payloads(cls):
            assert "export_data" in p.injection


def test_get_payload_unknown_class_raises():
    with pytest.raises(KeyError):
        get_payload("not_a_class")


def test_get_payload_unknown_id_raises():
    with pytest.raises(ValueError):
        get_payload("tool_description", "nonexistent-id")
