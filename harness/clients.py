"""MCP-to-model tool conversion + model-API routing.

Owned by agent:harness. Pure wiring — no scoring logic, no defense logic, no
server-side state. The defense layer plugs in by passing a `tool_transform`
callable into the runner that rewrites the tool list before it reaches the model.

ModelClient
-----------
`complete(model, system, messages, tools, ...)` is the single provider-agnostic
interface. It dispatches on the model-id PREFIX and always returns the canonical
form — `ModelResponse` with Anthropic-shaped content blocks (text + tool_use):

    claude-*    -> Anthropic Messages API              (ANTHROPIC_API_KEY)
    gpt-* / o*  -> OpenAI Chat Completions             (OPENAI_API_KEY)
    deepseek-*  -> OpenAI-compatible Chat Completions  (DEEPSEEK_API_KEY)
    gemini-*    -> google-genai generate_content       (GEMINI_API_KEY)

The exact model id is supplied by the caller/config and never guessed here. The
canonical tool spec and attack payloads are identical across providers — only
serialization differs (each `_complete_*` adapter translates out and back). Keys
are read from env; if a provider's key is unset the sweep skips its models with a
log (harness/sweep.py) and nothing is mocked. Gemini's two unavoidable
serialization differences (no per-call id; restricted schema) are handled and
documented on `_complete_gemini`. DeepSeek requires `pip install openai`; Gemini
requires `pip install google-genai`.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from anthropic import Anthropic
from mcp.types import Tool as MCPTool


def mcp_tools_to_anthropic(tools: list[MCPTool]) -> list[dict[str, Any]]:
    """Convert MCP Tool objects to the Anthropic Messages API tool spec.

    Anthropic expects {name, description, input_schema}. MCP exposes
    {name, description, inputSchema}.
    """
    return [
        {
            "name": t.name,
            "description": t.description or "",
            "input_schema": t.inputSchema,
        }
        for t in tools
    ]


def get_anthropic_client() -> Anthropic:
    """Return an Anthropic SDK client. Reads ANTHROPIC_API_KEY from env.

    `max_retries` is well above the SDK default (2): sweeps fan many trials at a
    low req/min org limit, so 429s are expected and transient. The SDK does
    exponential backoff honoring the `retry-after` header, so a high retry count
    turns rate-limit pressure into slower (not failed, not silently-zeroed) runs.
    """
    return Anthropic(max_retries=8)


def provider_for(model: str) -> str:
    """Map a model id to its provider by prefix. Raises on unknown families.

    The exact model id is supplied by the caller/config and never guessed here.
    """
    if model.startswith("claude"):
        return "anthropic"
    if model.startswith("gpt") or model.startswith(("o1", "o3", "o4")):
        return "openai"
    if model.startswith("deepseek"):
        return "deepseek"          # OpenAI-compatible API
    if model.startswith("gemini"):
        return "google"
    raise ValueError(f"no provider mapping for model {model!r}")


#: API-key env var per provider. Routing stays prefix-based; keys come from env.
PROVIDER_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "google": "GEMINI_API_KEY",
}


class MissingKeyError(RuntimeError):
    """Raised when a model is requested but its provider's API key is unset."""


def key_env_for(model: str) -> str:
    """Env var name holding the API key for `model`'s provider."""
    return PROVIDER_KEY_ENV[provider_for(model)]


def has_api_key(model: str) -> bool:
    """True if the API key for `model`'s provider is present in the environment."""
    return bool(os.environ.get(key_env_for(model)))


@dataclass
class ModelResponse:
    """Provider-neutral response, normalized to Anthropic content blocks.

    content blocks are dicts: {"type": "text", "text": ...} or
    {"type": "tool_use", "id": ..., "name": ..., "input": {...}}.
    """

    stop_reason: str          # "tool_use" | "end_turn"
    content: list[dict[str, Any]]
    usage: dict[str, Any]


def complete(
    *,
    model: str,
    system: str | None,
    tools: list[dict[str, Any]],
    messages: list[dict[str, Any]],
    temperature: float,
    max_tokens: int,
) -> ModelResponse:
    """Single model turn, normalized across providers to Anthropic block shape.

    `messages` are Anthropic-shaped (the runner's native format). For OpenAI we
    translate in and out so the runner never branches on provider.
    """
    provider = provider_for(model)
    if provider == "anthropic":
        return _complete_anthropic(
            model=model, system=system, tools=tools, messages=messages,
            temperature=temperature, max_tokens=max_tokens,
        )
    if provider == "google":
        return _complete_gemini(
            model=model, system=system, tools=tools, messages=messages,
            temperature=temperature, max_tokens=max_tokens,
        )
    # openai + deepseek share the OpenAI-compatible Chat Completions path.
    base_url = "https://api.deepseek.com" if provider == "deepseek" else None
    return _complete_openai_compatible(
        model=model, system=system, tools=tools, messages=messages,
        temperature=temperature, max_tokens=max_tokens,
        base_url=base_url, api_key_env=PROVIDER_KEY_ENV[provider],
    )


def _complete_anthropic(
    *, model, system, tools, messages, temperature, max_tokens,
) -> ModelResponse:
    client = get_anthropic_client()
    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "tools": tools,
        "messages": messages,
    }
    if system:
        kwargs["system"] = system
    resp = client.messages.create(**kwargs)
    return ModelResponse(
        stop_reason=resp.stop_reason,
        content=[b.model_dump() for b in resp.content],
        usage=resp.usage.model_dump() if hasattr(resp.usage, "model_dump") else {},
    )


def _complete_openai_compatible(
    *, model, system, tools, messages, temperature, max_tokens,
    base_url: str | None = None, api_key_env: str = "OPENAI_API_KEY",
) -> ModelResponse:
    """OpenAI-compatible Chat Completions path (OpenAI + DeepSeek), adapted to the
    canonical Anthropic block shape. `base_url` selects the endpoint (DeepSeek);
    `api_key_env` selects the key. Raises MissingKeyError if the key is unset."""
    key = os.environ.get(api_key_env)
    if not key:
        raise MissingKeyError(f"model {model!r} needs {api_key_env}")
    from openai import OpenAI

    client = OpenAI(api_key=key, base_url=base_url)
    oai_tools = [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]
    oai_messages = _anthropic_to_openai_messages(system, messages)
    # GPT-5 / o-series reject the legacy `max_tokens` and require
    # `max_completion_tokens`; gpt-4o* and DeepSeek still take `max_tokens`.
    token_param = (
        "max_completion_tokens"
        if model.startswith(("gpt-5", "o1", "o3", "o4"))
        else "max_tokens"
    )
    resp = client.chat.completions.create(
        model=model,
        temperature=temperature,
        tools=oai_tools,
        messages=oai_messages,
        **{token_param: max_tokens},
    )
    choice = resp.choices[0]
    blocks: list[dict[str, Any]] = []
    if choice.message.content:
        blocks.append({"type": "text", "text": choice.message.content})
    for tc in choice.message.tool_calls or []:
        blocks.append({
            "type": "tool_use",
            "id": tc.id,
            "name": tc.function.name,
            "input": json.loads(tc.function.arguments or "{}"),
        })
    stop = "tool_use" if (choice.message.tool_calls) else "end_turn"
    usage = resp.usage.model_dump() if resp.usage else {}
    return ModelResponse(stop_reason=stop, content=blocks, usage=usage)


def _anthropic_to_openai_messages(
    system: str | None, messages: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Translate the runner's Anthropic-shaped history into OpenAI chat messages."""
    out: list[dict[str, Any]] = []
    if system:
        out.append({"role": "system", "content": system})
    for m in messages:
        role, content = m["role"], m["content"]
        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue
        if role == "assistant":
            text_parts, tool_calls = [], []
            for b in content:
                if b.get("type") == "text":
                    text_parts.append(b["text"])
                elif b.get("type") == "tool_use":
                    tool_calls.append({
                        "id": b["id"],
                        "type": "function",
                        "function": {
                            "name": b["name"],
                            "arguments": json.dumps(b.get("input", {})),
                        },
                    })
            msg: dict[str, Any] = {"role": "assistant", "content": "".join(text_parts) or None}
            if tool_calls:
                msg["tool_calls"] = tool_calls
            out.append(msg)
        else:  # user turn carrying tool_result blocks
            for b in content:
                if b.get("type") == "tool_result":
                    out.append({
                        "role": "tool",
                        "tool_call_id": b["tool_use_id"],
                        "content": b["content"],
                    })
                else:
                    out.append({"role": "user", "content": b.get("text", str(b))})
    return out


def _sanitize_schema_for_gemini(schema: dict[str, Any]) -> dict[str, Any]:
    """Drop JSON-Schema keys Gemini's FunctionDeclaration rejects (e.g. `title`,
    `additionalProperties`, `$schema`). Recurses into properties/items. The
    canonical schema is untouched — this is purely a serialization difference."""
    keep = {"type", "description", "enum", "properties", "required", "items", "nullable"}
    out: dict[str, Any] = {}
    for k, v in (schema or {}).items():
        if k not in keep:
            continue
        if k == "properties" and isinstance(v, dict):
            out[k] = {pk: _sanitize_schema_for_gemini(pv) for pk, pv in v.items()}
        elif k == "items" and isinstance(v, dict):
            out[k] = _sanitize_schema_for_gemini(v)
        else:
            out[k] = v
    return out


def _anthropic_to_gemini_contents(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Translate canonical Anthropic-shaped history into Gemini `contents`.

    Gemini has no per-call tool id; a function response is paired to its call by
    NAME. We track id->name from assistant tool_use blocks so each tool_result can
    be emitted under the right function name. Unambiguous here (sequential, distinct
    tools per turn)."""
    id_to_name: dict[str, str] = {}
    contents: list[dict[str, Any]] = []
    for m in messages:
        role, content = m["role"], m["content"]
        if isinstance(content, str):
            contents.append({"role": "model" if role == "assistant" else "user",
                             "parts": [{"text": content}]})
            continue
        if role == "assistant":
            parts: list[dict[str, Any]] = []
            for b in content:
                if b.get("type") == "text" and b.get("text"):
                    parts.append({"text": b["text"]})
                elif b.get("type") == "tool_use":
                    id_to_name[b["id"]] = b["name"]
                    parts.append({"function_call": {"name": b["name"],
                                                    "args": b.get("input", {})}})
            contents.append({"role": "model", "parts": parts})
        else:  # user turn carrying tool_result blocks
            parts = []
            for b in content:
                if b.get("type") == "tool_result":
                    name = id_to_name.get(b.get("tool_use_id"), "unknown")
                    parts.append({"function_response": {
                        "name": name, "response": {"result": b.get("content", "")}}})
                else:
                    parts.append({"text": b.get("text", str(b))})
            contents.append({"role": "user", "parts": parts})
    return contents


def _complete_gemini(
    *, model, system, tools, messages, temperature, max_tokens,
) -> ModelResponse:
    """Gemini path via the `google-genai` SDK, adapted to the canonical block shape.

    Two serialization differences are handled here, not papered over (see
    `_anthropic_to_gemini_contents` for the id->name pairing and
    `_sanitize_schema_for_gemini` for the schema subset). Requires
    `pip install google-genai` and GEMINI_API_KEY.

    Note: this adapter is implemented against the documented google-genai API but is
    not exercised in this repo (no Gemini key here); the pure translation helpers
    above are unit-tested. Smoke-test once a GEMINI_API_KEY is provisioned.
    """
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise MissingKeyError(f"model {model!r} needs GEMINI_API_KEY")
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=key)
    decls = [
        types.FunctionDeclaration(
            name=t["name"], description=t["description"],
            parameters=_sanitize_schema_for_gemini(t["input_schema"]),
        )
        for t in tools
    ]
    config = types.GenerateContentConfig(
        temperature=temperature,
        max_output_tokens=max_tokens,
        system_instruction=system or None,
        tools=[types.Tool(function_declarations=decls)] if decls else None,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )
    resp = client.models.generate_content(
        model=model, contents=_anthropic_to_gemini_contents(messages), config=config,
    )

    blocks: list[dict[str, Any]] = []
    parts = (resp.candidates[0].content.parts if resp.candidates else None) or []
    n_calls = 0
    for part in parts:
        if getattr(part, "text", None):
            blocks.append({"type": "text", "text": part.text})
        fc = getattr(part, "function_call", None)
        if fc is not None:
            blocks.append({
                "type": "tool_use",
                "id": f"gemini-{fc.name}-{n_calls}",   # synthesized; Gemini has none
                "name": fc.name,
                "input": dict(fc.args or {}),
            })
            n_calls += 1
    stop = "tool_use" if n_calls else "end_turn"
    um = getattr(resp, "usage_metadata", None)
    usage = um.model_dump() if (um is not None and hasattr(um, "model_dump")) else {}
    return ModelResponse(stop_reason=stop, content=blocks, usage=usage)
