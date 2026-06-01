"""MCP-to-model tool conversion + model-API routing.

Owned by agent:harness. Pure wiring — no scoring logic, no defense logic, no
server-side state. The defense layer plugs in by passing a `tool_transform`
callable into the runner that rewrites the tool list before it reaches the model.

Model routing
-------------
`complete()` dispatches on the model id so the runner stays provider-agnostic and
always sees Anthropic-shaped content blocks (list of {type, ...} dicts):

    claude-*  -> Anthropic Messages API           (requires ANTHROPIC_API_KEY)
    gpt-*     -> OpenAI Chat Completions, adapted  (requires OPENAI_API_KEY)

Only the Anthropic key is provisioned in this repo, so the benchmark's three
models are all Anthropic (Opus / Sonnet / Haiku). The OpenAI path is implemented
and adapted to the same block shape so a second provider can be added by dropping
in a key — no runner changes required.
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
    """Return an Anthropic SDK client. Reads ANTHROPIC_API_KEY from env."""
    return Anthropic()


def provider_for(model: str) -> str:
    """Map a model id to its provider. Raises on unknown families."""
    if model.startswith("claude"):
        return "anthropic"
    if model.startswith("gpt") or model.startswith("o1") or model.startswith("o3"):
        return "openai"
    raise ValueError(f"no provider mapping for model {model!r}")


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
    return _complete_openai(
        model=model, system=system, tools=tools, messages=messages,
        temperature=temperature, max_tokens=max_tokens,
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


def _complete_openai(
    *, model, system, tools, messages, temperature, max_tokens,
) -> ModelResponse:
    """OpenAI path, adapted to Anthropic block shape. Inert until OPENAI_API_KEY set."""
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError(
            f"model {model!r} needs OPENAI_API_KEY; only Anthropic is provisioned"
        )
    from openai import OpenAI

    client = OpenAI()
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
    resp = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        temperature=temperature,
        tools=oai_tools,
        messages=oai_messages,
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
