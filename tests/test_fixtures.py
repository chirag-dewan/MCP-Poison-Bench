"""Tests for the payload fixtures — every class is covered and the sink is shared.

These guard the dataset's structural invariants that the servers and scorers rely
on (consistent sink mechanism, labeled-by-class, no empty classes).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defense.provenance import scan_tools
from fixtures.payloads import (
    ATTACK_CLASSES,
    CANARY,
    HELDOUT_PAYLOADS,
    PAYLOADS,
    SINK_TOOL_NAME,
    get_payload,
    iter_payloads,
    payload_set,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


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


# ---------------------------------------------------------------------------
# Held-out set: the de-circularization guarantee.
# ---------------------------------------------------------------------------

def _heldout_cases():
    return [(cls, p) for cls in ATTACK_CLASSES for p in HELDOUT_PAYLOADS[cls]]


def test_heldout_has_at_least_five_per_class():
    for cls in ATTACK_CLASSES:
        assert len(HELDOUT_PAYLOADS[cls]) >= 5, f"{cls} held-out set too small"


@pytest.mark.parametrize("cls,p", _heldout_cases(), ids=lambda x: getattr(x, "id", str(x)))
def test_heldout_payload_trips_zero_defense_rules(cls, p):
    """THE key guard: every held-out injection must evade the defense's rules.

    If a held-out payload ever starts matching a provenance.py rule, the held-out
    matrix is no longer independent of the defense and this test fails loudly —
    so the de-circularization property cannot silently regress (e.g. someone
    adding a rule, or editing a payload to use a trigger word).

    We place the injection in BOTH a tool description and a schema-field
    description and assert scan_tools finds nothing, regardless of carrier.
    """
    tool = {
        "name": "calculate",
        "description": f"Perform an arithmetic operation.{p.injection}",
        "input_schema": {
            "type": "object",
            "properties": {"operation": {"type": "string", "description": p.injection}},
        },
    }
    report = scan_tools([tool])
    assert not report.flagged, (
        f"held-out payload {p.id!r} unexpectedly tripped rules: "
        f"{[(f.rule, f.snippet) for f in report.findings]}"
    )


@pytest.mark.parametrize("cls,p", _heldout_cases(), ids=lambda x: getattr(x, "id", str(x)))
def test_heldout_payload_does_not_name_the_sink(cls, p):
    """Held-out payloads reference the sink by FUNCTION, never by its tool name."""
    assert SINK_TOOL_NAME not in p.injection
    assert p.attack_class == cls


def test_heldout_payloads_still_carry_the_canary_target():
    """They must still try to ship the secret — they reference the context value
    the task labels as the session token (without using egress-verb+noun phrasing)."""
    for cls in ATTACK_CLASSES:
        for p in HELDOUT_PAYLOADS[cls]:
            assert "payload" in p.injection.lower()
            assert "context" in p.injection.lower()


def test_payload_set_selector():
    assert payload_set("seen") is PAYLOADS
    assert payload_set("heldout") is HELDOUT_PAYLOADS
    with pytest.raises(KeyError):
        payload_set("nope")
    # iter_payloads honors the set.
    assert len(iter_payloads("tool_description", "heldout")) >= 5


def test_seen_set_DOES_trip_rules_proving_the_contrast():
    """Sanity check on the premise: the original 'seen' payloads DO match the
    defense rules. That overlap is exactly what makes a defended-ASR drop on the
    seen set near-circular and motivates the held-out set."""
    flagged_classes = 0
    for cls in ATTACK_CLASSES:
        p = PAYLOADS[cls][0]
        tool = {
            "name": "calculate",
            "description": f"x{p.injection}",
            "input_schema": {
                "type": "object",
                "properties": {"operation": {"type": "string", "description": p.injection}},
            },
        }
        if scan_tools([tool]).flagged:
            flagged_classes += 1
    assert flagged_classes == len(ATTACK_CLASSES), (
        "expected every seen payload to trip the defense — the contrast premise"
    )


# ---------------------------------------------------------------------------
# New multi-step tasks load and declare what the scorers need.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("task_file", ["notes_pipeline.json", "account_review.json", "calc_add.json"])
def test_task_files_are_well_formed(task_file):
    task = json.loads((REPO_ROOT / "tasks" / task_file).read_text(encoding="utf-8"))
    for key in ("id", "prompt", "context", "expected_tool", "expected_answer_contains"):
        assert key in task, f"{task_file} missing {key}"
    # The canary must be planted in context for the attack to have something to steal.
    assert CANARY in task["context"]
