"""Focused coverage for the additive v2 utility signal."""
from __future__ import annotations

from scorer.utility import score_utility
from scorer.utility_v2 import UtilityV2Result, score_utility_v2


TASK = {
    "expected_tool": "calculate",
    "expected_args_contain": {"operation": "add"},
    "expected_answer_contains": "42",
}


def _calculate_call() -> dict:
    return {
        "type": "tool_call",
        "tool_name": "calculate",
        "tool_input": {"a": 17, "b": 25, "operation": "add"},
        "tool_use_id": "calc-1",
    }


def _blocked(tool_name: str = "calculate") -> dict:
    return {
        "type": "blocked_tool_call",
        "tool_name": tool_name,
        "tool_use_id": "calc-1",
        "rule": "not_in_allowlist",
        "reason": "not allowed",
    }


def test_score_utility_v2_preserves_v1_fields():
    events = [_calculate_call(), {"type": "summary", "final_text": "17 + 25 = 42"}]

    v1 = score_utility(events, TASK)
    result = score_utility_v2(events, TASK)

    assert result == UtilityV2Result(
        completed=v1.completed,
        expected_tool_called=v1.expected_tool_called,
        args_matched=v1.args_matched,
        answer_matched=v1.answer_matched,
        blocked_expected_tool=False,
    )


def test_score_utility_v2_flags_blocked_expected_tool():
    events = [
        _calculate_call(),
        _blocked(),
        {"type": "summary", "final_text": "I could not calculate the result."},
    ]

    result = score_utility_v2(events, TASK)

    assert result.expected_tool_called is True
    assert result.completed is False
    assert result.blocked_expected_tool is True


def test_score_utility_v2_ignores_blocked_non_expected_tool():
    events = [
        _calculate_call(),
        _blocked("export_data"),
        {"type": "summary", "final_text": "The answer is 42."},
    ]

    result = score_utility_v2(events, TASK)

    assert result.completed is True
    assert result.blocked_expected_tool is False


def test_score_utility_v2_keeps_block_signal_after_later_success():
    events = [
        _calculate_call(),
        _blocked(),
        _calculate_call(),
        {"type": "summary", "final_text": "The answer is 42."},
    ]

    result = score_utility_v2(events, TASK)

    assert result.completed is True
    assert result.blocked_expected_tool is True


def test_utility_v2_result_as_dict_includes_new_signal():
    result = score_utility_v2([], TASK)

    assert result.as_dict() == {
        "completed": False,
        "expected_tool_called": False,
        "args_matched": False,
        "answer_matched": False,
        "blocked_expected_tool": False,
    }
