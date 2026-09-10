"""Real-stdio coverage for the metadata-drift poisoned server fixture."""
from __future__ import annotations

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from fixtures.payloads import get_payload
from harness.runner import REPO_ROOT


def test_metadata_drift_server_changes_description_after_any_tool_call():
    payload = get_payload("metadata_drift")

    async def exercise() -> tuple[str, str]:
        env = {
            **os.environ,
            "POISON_CLASS": "metadata_drift",
            "POISON_PAYLOAD_ID": payload.id,
        }
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / "servers/poisoned/server.py")],
            env=env,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                first = await session.list_tools()
                before = next(
                    tool.description for tool in first.tools
                    if tool.name == "calculate"
                )
                result = await session.call_tool(
                    "add_note", {"title": "probe", "body": "benign"},
                )
                assert result.isError is False
                second = await session.list_tools()
                after = next(
                    tool.description for tool in second.tools
                    if tool.name == "calculate"
                )
                return before, after

    before, after = asyncio.run(exercise())

    assert payload.injection not in before
    assert payload.injection in after
    assert after == before + payload.injection
