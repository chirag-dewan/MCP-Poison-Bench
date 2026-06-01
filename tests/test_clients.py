"""Tests for the provider-agnostic ModelClient routing + canonical serialization.

These exercise the pure functions — prefix routing, key mapping, and the
canonical <-> provider translations — without any API keys or live SDK calls. The
live `_complete_*` calls can only be smoke-tested with real keys.
"""
from __future__ import annotations

import pytest

from harness import clients

# Anthropic-shaped canonical history: text, a tool_use, then its tool_result.
CANONICAL = [
    {"role": "user", "content": "compute 17 + 25"},
    {"role": "assistant", "content": [
        {"type": "text", "text": "ok"},
        {"type": "tool_use", "id": "t1", "name": "calculate", "input": {"a": 17, "b": 25, "operation": "add"}},
    ]},
    {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": "42"},
    ]},
]


def test_provider_routing_by_prefix():
    assert clients.provider_for("claude-opus-4-8") == "anthropic"
    assert clients.provider_for("gpt-4o") == "openai"
    assert clients.provider_for("o3-mini") == "openai"
    assert clients.provider_for("deepseek-v4-pro") == "deepseek"
    assert clients.provider_for("gemini-2.5-pro") == "google"
    with pytest.raises(ValueError):
        clients.provider_for("llama-3-70b")


def test_key_env_mapping():
    assert clients.key_env_for("claude-x") == "ANTHROPIC_API_KEY"
    assert clients.key_env_for("gpt-x") == "OPENAI_API_KEY"
    assert clients.key_env_for("deepseek-x") == "DEEPSEEK_API_KEY"
    assert clients.key_env_for("gemini-x") == "GEMINI_API_KEY"


def test_has_api_key_reads_env(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    assert clients.has_api_key("deepseek-v4-pro") is False
    monkeypatch.setenv("DEEPSEEK_API_KEY", "x")
    assert clients.has_api_key("deepseek-v4-pro") is True


def test_openai_translation_shape():
    out = clients._anthropic_to_openai_messages("be careful", CANONICAL)
    assert out[0] == {"role": "system", "content": "be careful"}
    assert out[1] == {"role": "user", "content": "compute 17 + 25"}
    asst = out[2]
    assert asst["role"] == "assistant"
    assert asst["tool_calls"][0]["id"] == "t1"
    assert asst["tool_calls"][0]["function"]["name"] == "calculate"
    tool = out[3]
    assert tool == {"role": "tool", "tool_call_id": "t1", "content": "42"}


def test_gemini_translation_pairs_result_by_name():
    # Gemini has no call id — the tool_result must be re-keyed to the function NAME.
    contents = clients._anthropic_to_gemini_contents(CANONICAL)
    assert contents[0] == {"role": "user", "parts": [{"text": "compute 17 + 25"}]}
    model_turn = contents[1]
    assert model_turn["role"] == "model"
    assert model_turn["parts"][-1]["function_call"]["name"] == "calculate"
    fr = contents[2]["parts"][0]["function_response"]
    assert fr["name"] == "calculate"            # matched by name, not id
    assert fr["response"] == {"result": "42"}


def test_gemini_schema_sanitizer_drops_unsupported_keys():
    schema = {
        "type": "object", "title": "calculateArguments", "additionalProperties": False,
        "properties": {"operation": {"type": "string", "title": "Operation"}},
        "required": ["operation"],
    }
    out = clients._sanitize_schema_for_gemini(schema)
    assert "title" not in out and "additionalProperties" not in out
    assert "title" not in out["properties"]["operation"]
    assert out["properties"]["operation"]["type"] == "string"
    assert out["required"] == ["operation"]
