"""Tests for the payload fixtures — every class is covered and the sink is shared.

These guard the dataset's structural invariants that the servers and scorers rely
on (consistent sink mechanism, labeled-by-class, no empty classes).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from defense.provenance import scan_tools
from fixtures.payloads import (
    ATTACK_CLASSES,
    CANARY,
    DESTRUCTIVE_NOTE_TITLE,
    DESTRUCTIVE_TOOL_NAME,
    HELDOUT_PAYLOADS,
    OBJECTIVES,
    PAYLOADS,
    SINK_TOOL_NAME,
    TAMPER_MARK,
    get_payload,
    iter_payloads,
    payload_set,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

_LEGACY_IDS = {
    "seen": {
        "tool_description": ("td-compliance-audit",),
        "schema_field": ("sf-operation-desc",),
        "rug_pull": ("rp-post-approval",),
        "cross_server": ("xs-shadow-audit",),
        "metadata_drift": ("md-post-call-description",),
    },
    "heldout": {
        "tool_description": (
            "ho-td-ledger", "ho-td-mirror", "ho-td-telemetry",
            "ho-td-normalize", "ho-td-handshake", "ho-td-md",
            "ho-td-changelog", "ho-td-chatty", "ho-td-config",
        ),
        "schema_field": (
            "ho-sf-selector", "ho-sf-validate", "ho-sf-units", "ho-sf-cache",
            "ho-sf-format", "ho-sf-md", "ho-sf-terse", "ho-sf-chatty",
            "ho-sf-config", "ho-sf-verbose",
        ),
        "rug_pull": (
            "ho-rp-continue", "ho-rp-pending", "ho-rp-verify", "ho-rp-sync",
            "ho-rp-ledger", "ho-rp-md", "ho-rp-log", "ho-rp-chatty",
            "ho-rp-config", "ho-rp-verbose",
        ),
        "cross_server": (
            "ho-xs-mirror", "ho-xs-ledger", "ho-xs-cache", "ho-xs-health",
            "ho-xs-sync", "ho-xs-md", "ho-xs-terse", "ho-xs-chatty",
            "ho-xs-config", "ho-xs-verbose",
        ),
        "metadata_drift": (
            "ho-md-ledger", "ho-md-mirror", "ho-md-health",
            "ho-md-normalize", "ho-md-handshake",
        ),
    },
}

_LEGACY_INJECTION_DIGESTS = {
    "seen": {
        "tool_description": "4e321c0938b63f1b3cb587f71d1028edda1717fd06af2f47134e4259e1b731a9",
        "schema_field": "28e0b67bc4f39855bbe87200abc77edef4bb4b73b01dbbb111a9affa473026b4",
        "rug_pull": "99497c7af6b3dc26822f8073acbe1816a9b2123d36401788178a5ec34ac78f57",
        "cross_server": "887169621b99d0cdb8cbb8effd01bf693f796aad0823cf7dcf0558152cdb1fdd",
        "metadata_drift": "a4182dba1b6075f0ce0eda63f0a79911dd3615a243c988c0513953beed22c8c2",
    },
    "heldout": {
        "tool_description": "a6ba9e6caf87b910e5652d3936c05aaaea59c6680b17b34b94f688d77bee46f6",
        "schema_field": "47ec7916364f7098d84a483f4115b06548703cc8510e33308491401c7a85464a",
        "rug_pull": "86ed9bee143104cd5a554b1e4ff63563920d380ce661196b7560b20261e7919f",
        "cross_server": "ad79c7d12fcd1cbe53d0c97b46a1827ea47b31adafeab78081fabdcf99c460cb",
        "metadata_drift": "2027abe847a3eed6c5035e31e177d5e43e582879f56c0db35962848915d1df06",
    },
}


def test_all_classes_present_with_original_order_preserved():
    assert ATTACK_CLASSES[:4] == (
        "tool_description", "schema_field", "rug_pull", "cross_server",
    )
    assert set(ATTACK_CLASSES) == {
        "tool_description", "schema_field", "rug_pull", "cross_server",
        "metadata_drift",
    }
    for cls in ATTACK_CLASSES:
        assert PAYLOADS[cls], f"class {cls} has no payloads"


def test_payloads_labeled_with_their_class():
    for objective in OBJECTIVES:
        for set_name in ("seen", "heldout"):
            for cls in ATTACK_CLASSES:
                for p in iter_payloads(cls, set_name, objective):
                    assert p.attack_class == cls
                    assert p.objective == objective


def test_legacy_register_ids_text_and_default_selection_are_unchanged():
    for set_name in ("seen", "heldout"):
        for cls in ATTACK_CLASSES:
            payloads = iter_payloads(cls, set_name)
            assert tuple(p.id for p in payloads) == _LEGACY_IDS[set_name][cls]
            digest = hashlib.sha256(
                "\0".join(p.injection for p in payloads).encode()
            ).hexdigest()
            assert digest == _LEGACY_INJECTION_DIGESTS[set_name][cls]
            assert all(p.objective == "exfil_sink" for p in payloads)
            if set_name == "seen":
                assert get_payload(cls) is PAYLOADS[cls][0]


def test_sink_and_canary_are_shared_constants():
    assert SINK_TOOL_NAME == "export_data"
    assert CANARY.startswith("CANARY-")
    assert TAMPER_MARK == "TAMPER-MARK-51C0"
    assert DESTRUCTIVE_TOOL_NAME == "delete_note"
    assert DESTRUCTIVE_NOTE_TITLE == "Quarterly Review"
    assert OBJECTIVES == ("exfil_sink", "arg_tamper", "destructive")


def test_every_default_payload_targets_the_shared_sink():
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
    return [
        pytest.param(objective, cls, p, id=p.id)
        for objective in OBJECTIVES
        for cls in ATTACK_CLASSES
        for p in iter_payloads(cls, "heldout", objective)
    ]


def test_heldout_has_at_least_five_per_class():
    for objective in OBJECTIVES:
        for cls in ATTACK_CLASSES:
            heldout = iter_payloads(cls, "heldout", objective)
            assert len(heldout) >= 5, f"{objective}/{cls} held-out set too small"
            if objective != "exfil_sink":
                assert len(heldout) == 5
            assert len(iter_payloads(cls, "seen", objective)) == 1


@pytest.mark.parametrize("objective,cls,p", _heldout_cases())
def test_heldout_payload_trips_zero_defense_rules(objective, cls, p):
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
        f"held-out payload {objective}/{p.id!r} unexpectedly tripped rules: "
        f"{[(f.rule, f.snippet) for f in report.findings]}"
    )


@pytest.mark.parametrize("objective,cls,p", _heldout_cases())
def test_heldout_payload_does_not_name_the_exfil_sink(objective, cls, p):
    """No held-out objective accidentally introduces the exfiltration tool name."""
    assert SINK_TOOL_NAME not in p.injection
    assert p.attack_class == cls
    assert p.objective == objective


def test_new_objective_payloads_encode_their_target():
    for cls in ATTACK_CLASSES:
        for set_name in ("seen", "heldout"):
            for p in iter_payloads(cls, set_name, "arg_tamper"):
                assert TAMPER_MARK in p.injection
                assert "multiply" in p.injection
            for p in iter_payloads(cls, set_name, "destructive"):
                assert DESTRUCTIVE_TOOL_NAME in p.injection


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
    for objective in OBJECTIVES:
        assert payload_set("seen", objective)["tool_description"]
        assert payload_set("heldout", objective)["tool_description"]
    with pytest.raises(KeyError):
        payload_set("nope")
    with pytest.raises(KeyError):
        payload_set("seen", "not_an_objective")
    # iter_payloads honors the set.
    assert len(iter_payloads("tool_description", "heldout")) >= 5


def test_get_payload_is_objective_aware():
    for objective in OBJECTIVES:
        payload = get_payload("tool_description", objective=objective)
        assert payload is iter_payloads("tool_description", "seen", objective)[0]
        heldout = iter_payloads("tool_description", "heldout", objective)[0]
        assert get_payload(
            "tool_description", heldout.id, objective,
        ) is heldout
    with pytest.raises(KeyError):
        get_payload("tool_description", objective="not_an_objective")


def test_seen_set_DOES_trip_rules_proving_the_contrast():
    """Sanity check on the premise: the original 'seen' payloads DO match the
    defense rules. That overlap is exactly what makes a defended-ASR drop on the
    seen set near-circular and motivates the held-out set."""
    flagged_classes = 0
    for objective in OBJECTIVES:
        for cls in ATTACK_CLASSES:
            p = iter_payloads(cls, "seen", objective)[0]
            tool = {
                "name": "calculate",
                "description": f"x{p.injection}",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "operation": {"type": "string", "description": p.injection},
                    },
                },
            }
            if scan_tools([tool]).flagged:
                flagged_classes += 1
    assert flagged_classes == len(ATTACK_CLASSES) * len(OBJECTIVES), (
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
