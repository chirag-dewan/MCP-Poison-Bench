"""MCP-to-model tool conversion + Anthropic client wrapper.

Owned by agent:harness. Pure wiring — no scoring logic, no defense logic, no
server-side state. The defense layer plugs in by wrapping `mcp_tools_to_anthropic`
or by post-processing the tool list before it reaches the model.
"""
from __future__ import annotations

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
