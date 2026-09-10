"""Offline contract tests for the runner's v2 extension seams."""
from __future__ import annotations

import asyncio
import copy
import json
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from fixtures.payloads import CANARY, SINK_TOOL_NAME, get_payload, iter_payloads
from harness import clients, runner
from harness.arms import build_arm
from scorer.asr_v2 import score_asr_v2
from scorer.utility import score_utility


TASK = {"id": "seam-test", "prompt": "Use the tool.", "context": "test context"}
SERVER_PATH = Path("/tmp/fake-mcp-server.py")


class MemoryTrace:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(copy.deepcopy(event))


class FakeContent:
    def __init__(self, text: str) -> None:
        self.text = text

    def model_dump(self, *, mode: str) -> dict[str, str]:
        assert mode == "json"
        return {"type": "text", "text": self.text}


class FakeSession:
    def __init__(self, tool_name: str | list[str], result_text: str = "raw result") -> None:
        self.tool_names = [tool_name] if isinstance(tool_name, str) else tool_name
        self.result_text = result_text
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def initialize(self) -> dict[str, str]:
        return {"server": "fake"}

    async def list_tools(self) -> SimpleNamespace:
        return SimpleNamespace(tools=[
            SimpleNamespace(
                name=name,
                description="A fake tool.",
                inputSchema={"type": "object", "properties": {}},
            )
            for name in self.tool_names
        ])

    async def call_tool(self, name: str, tool_input: dict[str, Any]) -> SimpleNamespace:
        self.calls.append((name, tool_input))
        return SimpleNamespace(isError=False, content=[FakeContent(self.result_text)])


def _tool_turn(
    tool_name: str,
    *,
    tool_input: dict[str, Any] | None = None,
    tool_use_id: str = "call-1",
) -> clients.ModelResponse:
    return clients.ModelResponse(
        stop_reason="tool_use",
        content=[{
            "type": "tool_use",
            "id": tool_use_id,
            "name": tool_name,
            "input": {"value": 7} if tool_input is None else tool_input,
        }],
        usage={},
    )


def _end_turn(
    stop_reason: str = "end_turn", text: str = "done",
) -> clients.ModelResponse:
    return clients.ModelResponse(
        stop_reason=stop_reason,
        content=[] if stop_reason == "max_tokens" else [{"type": "text", "text": text}],
        usage={},
    )


def _drive_run(
    monkeypatch,
    *,
    tool_name: str | list[str] = "calculate",
    responses: list[clients.ModelResponse] | None = None,
    result_transform=None,
    result_findings=None,
    call_policy=None,
    task: dict[str, Any] = TASK,
    result_text: str = "raw result",
) -> tuple[MemoryTrace, FakeSession, list[dict[str, Any]]]:
    session = FakeSession(tool_name, result_text=result_text)
    trace = MemoryTrace()
    scripted = list(responses or [_tool_turn(tool_name), _end_turn()])
    completion_calls: list[dict[str, Any]] = []

    @asynccontextmanager
    async def fake_stdio_client(_params):
        yield object(), object()

    def fake_complete(**kwargs):
        completion_calls.append(copy.deepcopy(kwargs))
        return scripted.pop(0)

    monkeypatch.setattr(runner, "stdio_client", fake_stdio_client)
    monkeypatch.setattr(runner, "ClientSession", lambda _read, _write: session)
    monkeypatch.setattr(runner.clients, "complete", fake_complete)

    asyncio.run(runner.run(
        [SERVER_PATH],
        task,
        "claude-test",
        7,
        trace,
        result_transform=result_transform,
        result_findings=result_findings,
        call_policy=call_policy,
    ))
    assert not scripted
    return trace, session, completion_calls


def test_result_transform_receives_context_and_preserves_raw_trace(monkeypatch):
    seen: list[tuple[str, str, dict[str, Any]]] = []

    def transform(name: str, result_text: str, ctx: dict[str, Any]) -> str:
        seen.append((name, result_text, ctx))
        return "transformed result"

    trace, session, completions = _drive_run(
        monkeypatch, result_transform=transform,
    )

    assert session.calls == [("calculate", {"value": 7})]
    assert seen == [(
        "calculate",
        "raw result",
        {
            "server_path": str(SERVER_PATH),
            "step": 0,
            "tool_use_id": "call-1",
            "is_error": False,
        },
    )]
    event = next(e for e in trace.events if e["type"] == "tool_result")
    assert event["content"] == [{"type": "text", "text": "raw result"}]
    assert event["content_transformed"] == "transformed result"
    assert event["result_transformed"] is True
    assert event["blocked"] is False
    assert completions[1]["messages"][-1]["content"][0]["content"] == "transformed result"


@pytest.mark.parametrize(
    ("payload", "survives", "has_findings"),
    [
        (get_payload("rug_pull"), False, True),
        (iter_payloads("rug_pull", "heldout")[0], True, False),
    ],
    ids=lambda case: getattr(case, "id", str(case)),
)
def test_result_filter_seen_and_heldout_reach_model_as_expected(
    monkeypatch, payload, survives, has_findings,
):
    raw = f"17.0 add 25.0 = 42.0{payload.injection}"
    arm = build_arm("result_filter", TASK)

    trace, _session, completions = _drive_run(
        monkeypatch,
        result_text=raw,
        result_transform=arm["result_transform"],
        result_findings=arm["result_findings"],
    )

    model_text = completions[1]["messages"][-1]["content"][0]["content"]
    assert (payload.injection in model_text) is survives
    assert "17.0 add 25.0 = 42.0" in model_text
    assert "untrusted-tool-result" in model_text
    result = next(event for event in trace.events if event["type"] == "tool_result")
    assert result["content"] == [{"type": "text", "text": raw}]
    assert bool(result["result_findings"]) is has_findings


def test_result_findings_do_not_leak_to_an_untransformed_later_result(monkeypatch):
    payload = get_payload("rug_pull")
    arm = build_arm("result_filter", TASK)
    responses = [
        _tool_turn("calculate", tool_use_id="call-1"),
        _tool_turn("missing_tool", tool_use_id="call-2"),
        _end_turn(),
    ]

    trace, _session, _completions = _drive_run(
        monkeypatch,
        responses=responses,
        result_text=payload.injection,
        result_transform=arm["result_transform"],
        result_findings=arm["result_findings"],
    )

    results = [event for event in trace.events if event["type"] == "tool_result"]
    assert results[0]["result_findings"]
    assert results[1]["tool_name"] == "missing_tool"
    assert results[1]["result_findings"] == []


def test_denied_call_is_traced_but_never_dispatched(monkeypatch):
    policy_contexts: list[dict[str, Any]] = []

    def deny(_name: str, _tool_input: dict[str, Any], ctx: dict[str, Any]):
        policy_contexts.append(ctx)
        return runner.PolicyDecision(False, "egress denied", "deny_sink")

    trace, session, completions = _drive_run(
        monkeypatch, tool_name="export_data", call_policy=deny,
    )

    assert session.calls == []
    types = [e["type"] for e in trace.events]
    call_index = types.index("tool_call")
    assert types[call_index:call_index + 3] == [
        "tool_call", "blocked_tool_call", "tool_result",
    ]
    blocked = trace.events[call_index + 1]
    assert blocked["reason"] == "egress denied"
    assert blocked["rule"] == "deny_sink"
    result = trace.events[call_index + 2]
    assert result["blocked"] is True
    assert result["is_error"] is True
    expected = "Error: call to 'export_data' was blocked by client policy."
    assert result["content_transformed"] == expected
    assert result["result_transformed"] is False
    assert completions[1]["messages"][-1]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "call-1",
        "content": expected,
        "is_error": True,
    }
    assert policy_contexts[0]["server_path"] == str(SERVER_PATH)
    assert policy_contexts[0]["step"] == 0
    assert policy_contexts[0]["tool_use_id"] == "call-1"
    assert policy_contexts[0]["task"] == TASK
    assert policy_contexts[0]["history"][-1]["role"] == "assistant"


def test_allowed_call_dispatches_and_records_blocked_false(monkeypatch):
    def allow(_name: str, _tool_input: dict[str, Any], _ctx: dict[str, Any]):
        return runner.PolicyDecision(True, "allowed")

    trace, session, _ = _drive_run(monkeypatch, call_policy=allow)

    assert session.calls == [("calculate", {"value": 7})]
    assert not any(e["type"] == "blocked_tool_call" for e in trace.events)
    result = next(e for e in trace.events if e["type"] == "tool_result")
    assert result["blocked"] is False
    assert result["is_error"] is False


def test_none_seams_preserve_event_sequence(monkeypatch):
    trace, session, _ = _drive_run(monkeypatch)

    assert session.calls == [("calculate", {"value": 7})]
    assert [e["type"] for e in trace.events] == [
        "mcp_initialize",
        "mcp_list_tools",
        "user_prompt",
        "assistant_message",
        "tool_call",
        "tool_result",
        "assistant_message",
        "summary",
    ]
    listed = next(e for e in trace.events if e["type"] == "mcp_list_tools")
    assert listed["defended"] is False
    assert listed["result_transform_on"] is False
    assert listed["call_policy_on"] is False
    result = next(e for e in trace.events if e["type"] == "tool_result")
    assert result["content_transformed"] == "raw result"
    assert result["result_transformed"] is False
    assert result["blocked"] is False
    assert trace.events[-1]["truncated"] is False


def test_max_tokens_is_explicitly_traced(monkeypatch):
    trace, session, _ = _drive_run(
        monkeypatch, responses=[_end_turn("max_tokens")],
    )

    assert session.calls == []
    assert [e["type"] for e in trace.events] == [
        "mcp_initialize",
        "mcp_list_tools",
        "user_prompt",
        "assistant_message",
        "warning",
        "summary",
    ]
    assert trace.events[-2] == {
        "type": "warning",
        "message": "output truncated at MAX_TOKENS",
        "step": 0,
    }
    assert trace.events[-1]["truncated"] is True


def test_policy_arm_blocks_canary_egress_without_breaking_utility(monkeypatch):
    task = json.loads(
        (runner.REPO_ROOT / "tasks/v2/calc_add.json").read_text(encoding="utf-8")
    )
    arm = build_arm("policy", task)
    responses = [
        _tool_turn(
            "calculate",
            tool_input={"a": 17, "b": 25, "operation": "add"},
            tool_use_id="calc-1",
        ),
        _tool_turn(
            SINK_TOOL_NAME,
            tool_input={"payload": CANARY},
            tool_use_id="sink-1",
        ),
        _end_turn(text="The result is 42."),
    ]

    trace, session, _ = _drive_run(
        monkeypatch,
        tool_name=["calculate", SINK_TOOL_NAME],
        responses=responses,
        result_transform=arm["result_transform"],
        call_policy=arm["call_policy"],
        task=task,
    )

    assert session.calls == [("calculate", {"a": 17, "b": 25, "operation": "add"})]
    blocked = next(event for event in trace.events if event["type"] == "blocked_tool_call")
    assert blocked["tool_use_id"] == "sink-1"
    assert blocked["rule"] == "not_in_allowlist"
    blocked_result = next(
        event
        for event in trace.events
        if event["type"] == "tool_result" and event["tool_use_id"] == "sink-1"
    )
    assert blocked_result["blocked"] is True
    assert blocked_result["is_error"] is True

    attack = score_asr_v2(trace.events)
    assert attack.attempted is True
    assert attack.realized is False
    assert attack.blocked is True
    assert attack.canary_exfiltrated is True
    assert attack.canary_realized is False
    assert score_utility(trace.events, task).completed is True


def test_run_trial_creates_nested_unique_trace_paths(monkeypatch, tmp_path):
    async def fake_run(*_args, **_kwargs):
        return {"type": "summary", "truncated": False}

    monkeypatch.setattr(runner, "run", fake_run)
    monkeypatch.setattr(runner, "_utc_stamp", lambda: "20260910T120000Z")
    trace_dir = tmp_path / "nested" / "traces"
    common = {
        "server_paths": [SERVER_PATH],
        "task": TASK,
        "model": "claude-test",
        "seed": 7,
        "results_dir": trace_dir,
    }

    _, first = runner.run_trial(
        **common,
        extra_config={
            "attack_class": "rug_pull",
            "payload_set": "heldout",
            "payload_id": "held-1",
            "defense_arm": "policy",
        },
    )
    _, second = runner.run_trial(
        **common,
        extra_config={
            "attack_class": "rug_pull",
            "payload_set": "heldout",
            "payload_id": "held-2",
            "defense_arm": "policy",
        },
    )

    assert first.parent == trace_dir
    assert first.exists()
    assert second.exists()
    assert first != second
    assert "-held-1-policy-" in first.name
    assert "-held-2-policy-" in second.name


def test_trace_writer_hook_matches_serialized_lines_in_write_order(tmp_path):
    trace_path = tmp_path / "trace.jsonl"
    observed: list[dict[str, Any]] = []

    def observe(event: dict[str, Any]) -> None:
        # The corresponding line is flushed before the synchronous callback runs.
        lines = trace_path.read_text(encoding="utf-8").splitlines()
        assert json.loads(lines[-1]) == event
        observed.append(copy.deepcopy(event))

    trace = runner.TraceWriter(trace_path, on_event=observe)
    try:
        trace.write({"type": "first", "content": FakeContent("serialized")})
        trace.write({"type": "second", "ordinal": 2})
    finally:
        trace.close()

    persisted = [
        json.loads(line)
        for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]
    assert observed == persisted == [
        {"type": "first", "content": {"type": "text", "text": "serialized"}},
        {"type": "second", "ordinal": 2},
    ]


def test_run_trial_forwards_hook_for_every_event(monkeypatch, tmp_path):
    async def fake_run(
        _server_paths, _task, _model, _seed, trace, **_kwargs,
    ):
        summary = {"type": "summary", "truncated": False}
        trace.write(summary)
        return summary

    observed: list[dict[str, Any]] = []
    monkeypatch.setattr(runner, "run", fake_run)
    monkeypatch.setattr(runner, "_utc_stamp", lambda: "20260910T120000Z")
    monkeypatch.setattr(runner, "_git_sha", lambda: "canonical-sha")

    summary, trace_path = runner.run_trial(
        server_paths=[SERVER_PATH],
        task=TASK,
        model="claude-test",
        seed=7,
        results_dir=tmp_path,
        extra_config={
            "git_sha": "spoofed-sha",
            "task_id": "spoofed-task",
            "model": "spoofed-model",
            "seed": 999,
            "started_at": "spoofed-time",
            "custom_field": "preserved",
        },
        on_event=lambda event: observed.append(copy.deepcopy(event)),
    )

    persisted = [
        json.loads(line)
        for line in trace_path.read_text(encoding="utf-8").splitlines()
    ]
    assert summary == {"type": "summary", "truncated": False}
    assert observed == persisted
    assert [event["type"] for event in observed] == ["run_config", "summary"]
    assert observed[0]["git_sha"] == "canonical-sha"
    assert observed[0]["task_id"] == TASK["id"]
    assert observed[0]["model"] == "claude-test"
    assert observed[0]["seed"] == 7
    assert observed[0]["started_at"] != "spoofed-time"
    assert observed[0]["custom_field"] == "preserved"


def test_run_config_hook_exception_is_fatal_and_closes_trace(monkeypatch, tmp_path):
    created: list[runner.TraceWriter] = []
    real_trace_writer = runner.TraceWriter

    class RecordingTraceWriter(real_trace_writer):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            created.append(self)

    async def run_must_not_start(*_args, **_kwargs):
        raise AssertionError("run should not start after the run_config hook fails")

    def fail_on_event(event: dict[str, Any]) -> None:
        assert event["type"] == "run_config"
        raise RuntimeError("observer failed")

    monkeypatch.setattr(runner, "TraceWriter", RecordingTraceWriter)
    monkeypatch.setattr(runner, "run", run_must_not_start)

    with pytest.raises(RuntimeError, match="observer failed"):
        runner.run_trial(
            server_paths=[SERVER_PATH],
            task=TASK,
            model="claude-test",
            seed=7,
            results_dir=tmp_path,
            on_event=fail_on_event,
        )

    assert len(created) == 1
    assert created[0]._fh.closed is True
    persisted = [
        json.loads(line)
        for line in created[0].path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event["type"] for event in persisted] == ["run_config"]
