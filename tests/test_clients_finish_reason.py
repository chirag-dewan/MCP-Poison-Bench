"""Offline tests for OpenAI-compatible finish-reason normalization."""
from __future__ import annotations

from types import SimpleNamespace

import openai
import pytest

from harness import clients


@pytest.mark.parametrize(
    ("finish_reason", "tool_calls", "expected_stop_reason"),
    [
        ("length", None, "max_tokens"),
        ("tool_calls", [], "tool_use"),
        (
            "stop",
            [SimpleNamespace(
                id="call-1",
                function=SimpleNamespace(name="lookup", arguments="{}"),
            )],
            "tool_use",
        ),
        ("stop", None, "end_turn"),
    ],
)
def test_openai_finish_reason_is_normalized(
    monkeypatch, finish_reason, tool_calls, expected_stop_reason,
):
    response = SimpleNamespace(
        choices=[SimpleNamespace(
            finish_reason=finish_reason,
            message=SimpleNamespace(content=None, tool_calls=tool_calls),
        )],
        usage=None,
    )
    def create(**_kwargs):
        return response

    fake_client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(openai, "OpenAI", lambda **_kwargs: fake_client)

    result = clients._complete_openai_compatible(
        model="gpt-4o",
        system=None,
        tools=[],
        messages=[],
        temperature=0.0,
        max_tokens=64,
    )

    assert result.stop_reason == expected_stop_reason
    assert result.usage["finish_reason"] == finish_reason
