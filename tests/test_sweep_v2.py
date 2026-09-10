"""v2 sweep integration tests."""
from __future__ import annotations

import json
from pathlib import Path

from harness import sweep


def _spec(task: dict) -> dict:
    return {
        "model": "test-model",
        "attack_class": "tool_description",
        "payload_id": "td_seen_01",
        "payload_set": "seen",
        "task": task,
        "task_id": task["id"],
        "seed": 7,
        "servers": [Path("server.py")],
        "server_env": {},
    }


def test_build_trial_specs_replaces_leading_tasks_root(tmp_path, monkeypatch):
    task_root = tmp_path / "tasks-v2"
    nested = task_root / "nested"
    nested.mkdir(parents=True)
    task = {"id": "replacement-task", "prompt": "test"}
    (nested / "task.json").write_text(json.dumps(task), encoding="utf-8")
    cfg = {
        "models": ["test-model"],
        "attack_classes": ["tool_description"],
        "task": "tasks/nested/task.json",
        "benign_server": "benign.py",
        "poisoned_server": "poisoned.py",
        "seeds": [1],
    }
    monkeypatch.setattr(sweep.clients, "has_api_key", lambda _model: True)

    specs = sweep._build_trial_specs(cfg, task_dir=task_root)

    assert specs[0]["task"] == task
    assert specs[0]["task_id"] == "replacement-task"


def test_run_one_passes_task_to_arm_and_records_v2_utility(tmp_path, monkeypatch):
    task = {
        "id": "expected-blocked",
        "prompt": "test",
        "expected_tool": "export_data",
    }
    trace_path = tmp_path / "trace.jsonl"
    events = [
        {
            "type": "tool_call",
            "step": 0,
            "tool_use_id": "sink-1",
            "tool_name": "export_data",
            "tool_input": {"data": "test"},
        },
        {
            "type": "blocked_tool_call",
            "step": 0,
            "tool_use_id": "sink-1",
            "tool_name": "export_data",
            "tool_input": {"data": "test"},
            "rule": "not_in_allowlist",
        },
        {
            "type": "tool_result",
            "tool_use_id": "sink-1",
            "tool_name": "export_data",
            "is_error": True,
            "blocked": True,
        },
        {"type": "summary", "final_text": "", "truncated": False},
    ]
    trace_path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    seen: dict[str, object] = {}

    def fake_build_arm(name, arm_task):
        seen["name"] = name
        seen["task"] = arm_task
        return {
            "tool_transform": None,
            "result_transform": None,
            "call_policy": None,
        }

    def fake_run_trial(**_kwargs):
        return {"git_sha": "abc123"}, trace_path

    monkeypatch.setattr(sweep.arms, "build_arm", fake_build_arm)
    monkeypatch.setattr(sweep, "run_trial", fake_run_trial)

    record = sweep._run_one(_spec(task), 1.0, "policy", tmp_path)

    assert seen == {"name": "policy", "task": task}
    assert record["blocked_expected_tool"] is True


def test_run_sweep_threads_task_dir_and_defaults_error_signal_false(
    tmp_path, monkeypatch,
):
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"temperature": 0, "max_concurrency": 1}),
        encoding="utf-8",
    )
    task = {"id": "error-task", "prompt": "test"}
    seen: dict[str, object] = {}

    def fake_build_specs(_cfg, task_dir):
        seen["task_dir"] = task_dir
        return [_spec(task)]

    def fail_run(*_args, **_kwargs):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(sweep, "_build_trial_specs", fake_build_specs)
    monkeypatch.setattr(sweep, "_run_one", fail_run)
    out_path = tmp_path / "trials.jsonl"

    sweep.run_sweep(
        config_path,
        out_path=out_path,
        trace_dir=tmp_path,
        task_dir="tasks/v2",
    )

    record = json.loads(out_path.read_text(encoding="utf-8"))
    assert seen["task_dir"] == "tasks/v2"
    assert record["blocked_expected_tool"] is False
