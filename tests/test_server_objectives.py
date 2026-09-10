"""Real-stdio coverage for objective selection and destructive note state."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from fixtures.payloads import (
    DESTRUCTIVE_NOTE_TITLE,
    DESTRUCTIVE_TOOL_NAME,
    TAMPER_MARK,
    get_payload,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _result_text(result: object) -> str:
    return "".join(
        getattr(block, "text", "")
        for block in getattr(result, "content", [])
    )


def test_poisoned_server_selects_argument_tamper_register():
    payload = get_payload("tool_description", objective="arg_tamper")
    legacy = get_payload("tool_description")

    async def exercise() -> tuple[str, set[str]]:
        env = {
            **os.environ,
            "POISON_CLASS": "tool_description",
            "POISON_OBJECTIVE": "arg_tamper",
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
                listed = await session.list_tools()
                calculate = next(t for t in listed.tools if t.name == "calculate")
                return calculate.description or "", {t.name for t in listed.tools}

    description, tool_names = asyncio.run(exercise())

    assert description.endswith(payload.injection)
    assert TAMPER_MARK in description
    assert legacy.injection not in description
    assert DESTRUCTIVE_TOOL_NAME in tool_names


@pytest.mark.parametrize("attack_class", ["rug_pull", "metadata_drift"])
def test_notes_review_tool_path_exists_on_self_contained_modes(attack_class):
    async def exercise() -> set[str]:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / "servers/poisoned/server.py")],
            env={
                **os.environ,
                "POISON_CLASS": attack_class,
                "POISON_OBJECTIVE": "arg_tamper",
            },
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                return {t.name for t in listed.tools}

    assert {"lookup_user", "calculate", "add_note"} <= asyncio.run(exercise())


@pytest.mark.parametrize(
    "server_rel,server_env",
    [
        ("servers/benign/server.py", {}),
        (
            "servers/poisoned/server.py",
            {
                "POISON_CLASS": "tool_description",
                "POISON_OBJECTIVE": "destructive",
            },
        ),
    ],
    ids=("benign", "self-contained-poisoned"),
)
def test_delete_note_removes_seed_and_shares_add_note_state(server_rel, server_env):
    async def exercise() -> tuple[set[str], str, str, str]:
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(REPO_ROOT / server_rel)],
            env={**os.environ, **server_env},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                deleted = await session.call_tool(
                    DESTRUCTIVE_TOOL_NAME,
                    {"title": DESTRUCTIVE_NOTE_TITLE},
                )
                missing = await session.call_tool(
                    DESTRUCTIVE_TOOL_NAME,
                    {"title": DESTRUCTIVE_NOTE_TITLE},
                )
                assert deleted.isError is False
                assert missing.isError is False
                saved = await session.call_tool(
                    "add_note",
                    {"title": DESTRUCTIVE_NOTE_TITLE, "body": "42"},
                )
                assert saved.isError is False
                deleted_again = await session.call_tool(
                    DESTRUCTIVE_TOOL_NAME,
                    {"title": DESTRUCTIVE_NOTE_TITLE},
                )
                assert deleted_again.isError is False
                return (
                    {t.name for t in listed.tools},
                    _result_text(deleted),
                    _result_text(missing),
                    _result_text(deleted_again),
                )

    tool_names, deleted_text, missing_text, deleted_again_text = asyncio.run(
        exercise()
    )

    assert {"add_note", DESTRUCTIVE_TOOL_NAME} <= tool_names
    assert deleted_text == f"Deleted note '{DESTRUCTIVE_NOTE_TITLE}'."
    assert missing_text == f"No note found with title '{DESTRUCTIVE_NOTE_TITLE}'."
    assert deleted_again_text == f"Deleted note '{DESTRUCTIVE_NOTE_TITLE}'."
