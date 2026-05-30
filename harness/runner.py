"""Runner: loads an MCP server, runs a benign task against a model, logs traces.

Owned by agent:harness. See CLAUDE.md for scope rules.

Usage (from repo root):
    python -m harness.runner \\
        --server servers/benign/server.py \\
        --task tasks/calc_add.json \\
        --model claude-sonnet-4-6 \\
        --seed 42

Writes JSONL to results/<utc>-<task_id>-seed<N>.jsonl. One event per line:
run_config, mcp_initialize, mcp_list_tools, user_prompt, assistant_message,
tool_call, tool_result, summary.

Determinism note: --seed seeds Python RNG and is logged into every trace. Model
sampling uses temperature=0; residual model-side non-determinism is not
controllable from the harness, so traces are stored verbatim for re-analysis.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from harness.clients import get_anthropic_client, mcp_tools_to_anthropic

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
MAX_STEPS = 8
MAX_TOKENS = 1024


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            stderr=subprocess.DEVNULL,
        ).decode().strip()
    except Exception:
        return "unknown"


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _serialize(obj: Any) -> Any:
    """Best-effort JSON-safe serialization for MCP/Anthropic SDK objects."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, list):
        return [_serialize(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    try:
        json.dumps(obj)
        return obj
    except TypeError:
        return repr(obj)


class TraceWriter:
    """Append-only JSONL writer for run traces."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh = path.open("w", encoding="utf-8")

    def write(self, event: dict[str, Any]) -> None:
        self._fh.write(json.dumps(_serialize(event), ensure_ascii=False) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


async def run(
    server_path: Path,
    task: dict[str, Any],
    model: str,
    seed: int,
    trace: TraceWriter,
) -> dict[str, Any]:
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_path)],
        env={**os.environ},
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init_result = await session.initialize()
            trace.write({"type": "mcp_initialize", "server": _serialize(init_result)})

            tools_result = await session.list_tools()
            anthropic_tools = mcp_tools_to_anthropic(tools_result.tools)
            trace.write({
                "type": "mcp_list_tools",
                "tools": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.inputSchema,
                    }
                    for t in tools_result.tools
                ],
            })

            client = get_anthropic_client()
            messages: list[dict[str, Any]] = [
                {"role": "user", "content": task["prompt"]}
            ]
            trace.write({"type": "user_prompt", "content": task["prompt"]})

            final_text: str | None = None
            step = 0
            for step in range(MAX_STEPS):
                resp = client.messages.create(
                    model=model,
                    max_tokens=MAX_TOKENS,
                    temperature=0,
                    tools=anthropic_tools,
                    messages=messages,
                )
                content_blocks = [b.model_dump() for b in resp.content]
                trace.write({
                    "type": "assistant_message",
                    "step": step,
                    "stop_reason": resp.stop_reason,
                    "usage": _serialize(resp.usage),
                    "content": content_blocks,
                })
                messages.append({"role": "assistant", "content": content_blocks})

                if resp.stop_reason != "tool_use":
                    final_text = "".join(
                        b.get("text", "") for b in content_blocks if b.get("type") == "text"
                    )
                    break

                tool_results_payload: list[dict[str, Any]] = []
                for block in resp.content:
                    if block.type != "tool_use":
                        continue
                    trace.write({
                        "type": "tool_call",
                        "step": step,
                        "tool_name": block.name,
                        "tool_input": block.input,
                        "tool_use_id": block.id,
                    })
                    mcp_result = await session.call_tool(block.name, block.input)
                    is_error = bool(getattr(mcp_result, "isError", False))
                    result_text = "\n".join(
                        getattr(c, "text", str(c)) for c in mcp_result.content
                    )
                    trace.write({
                        "type": "tool_result",
                        "step": step,
                        "tool_use_id": block.id,
                        "is_error": is_error,
                        "content": [_serialize(c) for c in mcp_result.content],
                    })
                    tool_results_payload.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_text,
                        "is_error": is_error,
                    })
                messages.append({"role": "user", "content": tool_results_payload})
            else:
                trace.write({"type": "warning", "message": f"hit MAX_STEPS={MAX_STEPS}"})

            summary = {
                "type": "summary",
                "task_id": task["id"],
                "model": model,
                "seed": seed,
                "final_text": final_text,
                "steps": step + 1,
            }
            trace.write(summary)
            return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP-Poison-Bench runner (M1).")
    parser.add_argument("--server", required=True, type=Path)
    parser.add_argument("--task", required=True, type=Path)
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    random.seed(args.seed)
    task = json.loads(args.task.read_text(encoding="utf-8"))

    RESULTS_DIR.mkdir(exist_ok=True)
    trace_path = RESULTS_DIR / f"{_utc_stamp()}-{task['id']}-seed{args.seed}.jsonl"
    trace = TraceWriter(trace_path)

    trace.write({
        "type": "run_config",
        "task_id": task["id"],
        "task_path": str(args.task),
        "server_path": str(args.server),
        "model": args.model,
        "seed": args.seed,
        "git_sha": _git_sha(),
        "started_at": datetime.now(timezone.utc).isoformat(),
    })

    try:
        summary = asyncio.run(run(args.server, task, args.model, args.seed, trace))
    finally:
        trace.close()

    print(f"\n=== summary ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\nFull trace: {trace_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
