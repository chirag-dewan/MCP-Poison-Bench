"""Offline tests for the policy arm's literal provenance tracker."""
from __future__ import annotations

from fixtures.payloads import CANARY
from defense.taint import TaintStore, recording_transform


def test_secret_taint_is_found_in_nested_string_leaves():
    store = TaintStore(secrets={CANARY})

    value = {
        "request": [
            {"safe": "ordinary text"},
            {"nested": [None, 7, f"credentials={CANARY}&scope=local"]},
        ],
    }

    assert store.taints_in(value) == {"secret"}
    assert store.taints_in({"request": ["ordinary text", 7, None]}) == set()


def test_result_provenance_detects_a_quoted_24_character_substring():
    shared = "A" * 24
    store = TaintStore(
        secrets=set(),
        tool_outputs={"call-1": f"calculation output: {shared} :finished"},
        server_of={"call-1": "/servers/benign.py"},
    )

    assert store.taints_in({"note": f"quoted result [{shared}]"}) == {
        "result:/servers/benign.py"
    }


def test_result_provenance_ignores_short_overlap():
    overlap = "B" * 23
    store = TaintStore(
        secrets=set(),
        tool_outputs={"call-1": f"prefix:{overlap}:suffix"},
        server_of={"call-1": "/servers/benign.py"},
    )

    assert store.taints_in({"note": overlap}) == set()


def test_result_provenance_labels_the_server_that_produced_the_match():
    benign_fragment = "C" * 24
    other_fragment = "D" * 24
    store = TaintStore(
        secrets=set(),
        tool_outputs={
            "benign-call": f"benign:{benign_fragment}",
            "other-call": f"other:{other_fragment}",
        },
        server_of={
            "benign-call": "/servers/benign.py",
            "other-call": "/servers/other.py",
        },
    )

    assert store.taints_in([{"copied": other_fragment}]) == {
        "result:/servers/other.py"
    }


def test_recording_transform_is_identity_and_records_raw_result_context():
    store = TaintStore(secrets={CANARY})
    transform = recording_transform(store)
    raw_result = "The raw tool result must remain byte-for-byte unchanged."

    transformed = transform(
        "calculate",
        raw_result,
        {
            "tool_use_id": "tool-use-7",
            "server_path": "/servers/benign.py",
            "step": 0,
            "is_error": False,
        },
    )

    assert transformed == raw_result
    assert store.tool_outputs == {"tool-use-7": raw_result}
    assert store.server_of == {"tool-use-7": "/servers/benign.py"}


def test_recording_transform_preserves_provenance_when_id_is_reused():
    store = TaintStore(secrets=set())
    transform = recording_transform(store)
    first_result = "A" * 30
    second_result = "B" * 30

    transform(
        "lookup_user",
        first_result,
        {"tool_use_id": "reused", "server_path": "/servers/first.py"},
    )
    transform(
        "calculate",
        second_result,
        {"tool_use_id": "reused", "server_path": "/servers/second.py"},
    )

    assert store.taints_in({"value": first_result}) == {
        "result:/servers/first.py"
    }
    assert store.taints_in({"value": second_result}) == {
        "result:/servers/second.py"
    }
