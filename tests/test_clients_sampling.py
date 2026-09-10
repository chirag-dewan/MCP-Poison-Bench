"""Offline tests for Anthropic sampling-parameter compatibility."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from harness import clients


@pytest.mark.parametrize(
    "model",
    [
        "claude-opus-4-7",
        "claude-opus-4-8-20260901",
        "claude-sonnet-5",
        "claude-fable-5-latest",
        "claude-mythos-5-20260901",
    ],
)
def test_sampling_params_are_not_supported_for_frontier_models(model):
    assert clients.supports_sampling_params(model) is False


@pytest.mark.parametrize("model", ["claude-sonnet-4-5", "claude-haiku-5"])
def test_sampling_params_are_supported_for_other_models(model):
    assert clients.supports_sampling_params(model) is True


@pytest.mark.parametrize(
    ("model", "temperature_sent"),
    [
        ("claude-opus-4-8-20260901", False),
        ("claude-sonnet-4-5", True),
    ],
)
def test_anthropic_temperature_is_gated_and_recorded(
    monkeypatch, model, temperature_sent,
):
    captured = {}

    def create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            stop_reason="max_tokens",
            content=[],
            usage=SimpleNamespace(model_dump=lambda: {"input_tokens": 1}),
        )

    fake_client = SimpleNamespace(messages=SimpleNamespace(create=create))
    monkeypatch.setattr(clients, "get_anthropic_client", lambda: fake_client)

    result = clients._complete_anthropic(
        model=model,
        system=None,
        tools=[],
        messages=[],
        temperature=0.25,
        max_tokens=64,
    )

    assert ("temperature" in captured) is temperature_sent
    if temperature_sent:
        assert captured["temperature"] == 0.25
    assert result.stop_reason == "max_tokens"
    assert result.usage["sampling"] == {
        "temperature": 0.25 if temperature_sent else None,
        "sent": temperature_sent,
    }
