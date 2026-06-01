"""Runner: loads one or more MCP servers, runs a task against a model, logs traces.

Owned by agent:harness. See CLAUDE.md for scope rules.

Single-run usage (from repo root):
    python -m harness.runner \\
        --server servers/benign/server.py \\
        --task tasks/calc_add.json \\
        --model claude-sonnet-4-6 \\
        --seed 42 --temperature 1.0

Multiple --server flags launch several servers at once (needed for the
cross-server attack class): their tools are merged and each tool call is routed
back to the session that owns it. Tool-name collisions across servers keep the
first registration and the loser is logged.

Writes JSONL to results/<utc>-<task_id>-seed<N>.jsonl. One event per line:
run_config, mcp_initialize, mcp_list_tools, user_prompt, assistant_message,
tool_call, tool_result, summary.

Determinism note: --seed seeds Python RNG and is logged into every trace. ASR is a
*rate*, so the sweep samples at temperature>0 to get genuine Bernoulli trials;
temperature is logged. Traces are stored verbatim for re-analysis.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import subprocess
import sys
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from harness import clients

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
MAX_STEPS = 8
MAX_TOKENS = 1024

#: A defense layer (M3) sets this to rewrite the tool list before the model sees
#: it. Signature: (list[anthropic_tool_dict]) -> list[anthropic_tool_dict].
ToolTransform = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]


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
    server_paths: list[Path],
    task: dict[str, Any],
    model: str,
    seed: int,
    trace: TraceWriter,
    *,
    server_env: dict[str, str] | None = None,
    temperature: float = 1.0,
    tool_transform: ToolTransform | None = None,
) -> dict[str, Any]:
    """Run `task` against `model` with `server_paths` launched as MCP servers.

    `server_env` is merged into each server's environment (used to parametrize the
    poisoned server via POISON_CLASS / POISON_PAYLOAD_ID).
    """
    launch_env = {**os.environ, **(server_env or {})}

    async with AsyncExitStack() as stack:
        sessions: list[ClientSession] = []
        for sp in server_paths:
            params = StdioServerParameters(
                command=sys.executable, args=[str(sp)], env=launch_env,
            )
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            init_result = await session.initialize()
            trace.write({
                "type": "mcp_initialize",
                "server_path": str(sp),
                "server": _serialize(init_result),
            })
            sessions.append(session)

        # Merge tools across servers, routing each name to its owning session.
        tool_owner: dict[str, ClientSession] = {}
        merged_tools = []
        listed_events = []
        for sp, session in zip(server_paths, sessions):
            tools_result = await session.list_tools()
            for t in tools_result.tools:
                if t.name in tool_owner:
                    trace.write({
                        "type": "warning",
                        "message": f"tool name collision {t.name!r}; keeping first",
                        "server_path": str(sp),
                    })
                    continue
                tool_owner[t.name] = session
                merged_tools.append(t)
            listed_events.append({
                "server_path": str(sp),
                "tools": [
                    {"name": t.name, "description": t.description,
                     "input_schema": t.inputSchema}
                    for t in tools_result.tools
                ],
            })

        anthropic_tools = clients.mcp_tools_to_anthropic(merged_tools)
        defended = False
        if tool_transform is not None:
            anthropic_tools = tool_transform(anthropic_tools)
            defended = True
        trace.write({
            "type": "mcp_list_tools",
            "defended": defended,
            "servers": listed_events,
            "tools_offered_to_model": anthropic_tools,
        })

        system = task.get("context")
        messages: list[dict[str, Any]] = [{"role": "user", "content": task["prompt"]}]
        trace.write({"type": "user_prompt", "content": task["prompt"], "system": system})

        final_text: str | None = None
        step = 0
        for step in range(MAX_STEPS):
            resp = clients.complete(
                model=model, system=system, tools=anthropic_tools,
                messages=messages, temperature=temperature, max_tokens=MAX_TOKENS,
            )
            trace.write({
                "type": "assistant_message",
                "step": step,
                "stop_reason": resp.stop_reason,
                "usage": _serialize(resp.usage),
                "content": resp.content,
            })
            messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason != "tool_use":
                final_text = "".join(
                    b.get("text", "") for b in resp.content if b.get("type") == "text"
                )
                break

            tool_results_payload: list[dict[str, Any]] = []
            for block in resp.content:
                if block.get("type") != "tool_use":
                    continue
                name, tool_input, tuid = block["name"], block.get("input", {}), block["id"]
                trace.write({
                    "type": "tool_call", "step": step, "tool_name": name,
                    "tool_input": tool_input, "tool_use_id": tuid,
                })
                session = tool_owner.get(name)
                if session is None:
                    result_text, is_error, raw = (
                        f"Error: unknown tool {name!r}", True, [],
                    )
                else:
                    mcp_result = await session.call_tool(name, tool_input)
                    is_error = bool(getattr(mcp_result, "isError", False))
                    raw = [_serialize(c) for c in mcp_result.content]
                    result_text = "\n".join(
                        getattr(c, "text", str(c)) for c in mcp_result.content
                    )
                trace.write({
                    "type": "tool_result", "step": step, "tool_use_id": tuid,
                    "tool_name": name, "is_error": is_error, "content": raw,
                })
                tool_results_payload.append({
                    "type": "tool_result", "tool_use_id": tuid,
                    "content": result_text, "is_error": is_error,
                })
            messages.append({"role": "user", "content": tool_results_payload})
        else:
            trace.write({"type": "warning", "message": f"hit MAX_STEPS={MAX_STEPS}"})

        summary = {
            "type": "summary",
            "task_id": task["id"],
            "model": model,
            "seed": seed,
            "temperature": temperature,
            "final_text": final_text,
            "steps": step + 1,
        }
        trace.write(summary)
        return summary


def run_trial(
    *,
    server_paths: list[Path],
    task: dict[str, Any],
    model: str,
    seed: int,
    server_env: dict[str, str] | None = None,
    temperature: float = 1.0,
    extra_config: dict[str, Any] | None = None,
    results_dir: Path = RESULTS_DIR,
    tool_transform: ToolTransform | None = None,
) -> tuple[dict[str, Any], Path]:
    """Run one trial end to end (own event loop) and return (summary, trace_path).

    Used by the sweep driver; each call is isolated (fresh servers + loop), so it
    is safe to invoke concurrently from a thread pool.
    """
    random.seed(seed)
    results_dir.mkdir(exist_ok=True)
    stamp = _utc_stamp()
    suffix = f"-{extra_config.get('attack_class')}" if extra_config else ""
    trace_path = results_dir / f"{stamp}-{task['id']}{suffix}-{model}-seed{seed}.jsonl"
    trace = TraceWriter(trace_path)
    trace.write({
        "type": "run_config",
        "task_id": task["id"],
        "server_paths": [str(p) for p in server_paths],
        "model": model,
        "seed": seed,
        "temperature": temperature,
        "server_env": server_env or {},
        "git_sha": _git_sha(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        **(extra_config or {}),
    })
    try:
        summary = asyncio.run(run(
            server_paths, task, model, seed, trace,
            server_env=server_env, temperature=temperature,
            tool_transform=tool_transform,
        ))
    finally:
        trace.close()
    return summary, trace_path


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP-Poison-Bench runner.")
    parser.add_argument("--server", required=True, action="append", type=Path,
                        help="server path; repeat for multiple servers")
    parser.add_argument("--task", required=True, type=Path)
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--temperature", type=float, default=1.0)
    parser.add_argument("--poison-class", default=None,
                        help="sets POISON_CLASS for poisoned servers")
    parser.add_argument("--poison-payload-id", default=None)
    parser.add_argument("--defense", action="store_true",
                        help="flip the client-side provenance/validation defense ON")
    args = parser.parse_args()

    task = json.loads(args.task.read_text(encoding="utf-8"))
    server_env: dict[str, str] = {}
    if args.poison_class:
        server_env["POISON_CLASS"] = args.poison_class
    if args.poison_payload_id:
        server_env["POISON_PAYLOAD_ID"] = args.poison_payload_id

    tool_transform = None
    if args.defense:
        from defense import provenance
        tool_transform = provenance.build_tool_transform()

    summary, trace_path = run_trial(
        server_paths=args.server, task=task, model=args.model, seed=args.seed,
        server_env=server_env or None, temperature=args.temperature,
        tool_transform=tool_transform,
        extra_config={"attack_class": args.poison_class} if args.poison_class else None,
    )

    print("\n=== summary ===")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\nFull trace: {trace_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
