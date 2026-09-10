"""v2 sweep integration tests."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from harness import sweep


def _spec(task: dict) -> dict:
    return {
        "model": "test-model",
        "attack_class": "tool_description",
        "payload_id": "td_seen_01",
        "payload_set": "seen",
        "objective": "exfil_sink",
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
        "relist_each_step": True,
    }
    monkeypatch.setattr(sweep.clients, "has_api_key", lambda _model: True)

    specs = sweep._build_trial_specs(cfg, task_dir=task_root)

    assert specs[0]["task"] == task
    assert specs[0]["task_id"] == "replacement-task"
    assert specs[0]["relist_each_step"] is True
    assert specs[0]["objective"] == "exfil_sink"
    assert specs[0]["server_env"]["POISON_OBJECTIVE"] == "exfil_sink"


def test_build_trial_specs_threads_explicit_objective(tmp_path, monkeypatch):
    task_path = tmp_path / "task.json"
    task_path.write_text(
        json.dumps({"id": "objective-task", "prompt": "test"}),
        encoding="utf-8",
    )
    cfg = {
        "models": ["test-model"],
        "class_tasks": {"rug_pull": ["task.json"]},
        "objective": "arg_tamper",
        "payload_set": "heldout",
        "benign_server": "benign.py",
        "poisoned_server": "poisoned.py",
        "seeds": [1],
    }
    seen: dict[str, str] = {}

    def fake_iter_payloads(attack_class, set_name, *, objective):
        seen.update(
            attack_class=attack_class,
            set_name=set_name,
            objective=objective,
        )
        return [SimpleNamespace(id="tamper-payload")]

    monkeypatch.setattr(sweep.clients, "has_api_key", lambda _model: True)
    monkeypatch.setattr(sweep, "iter_payloads", fake_iter_payloads)

    specs = sweep._build_trial_specs(cfg, task_dir=tmp_path)

    assert seen == {
        "attack_class": "rug_pull",
        "set_name": "heldout",
        "objective": "arg_tamper",
    }
    assert specs[0]["objective"] == "arg_tamper"
    assert specs[0]["server_env"] == {
        "POISON_CLASS": "rug_pull",
        "POISON_PAYLOAD_ID": "tamper-payload",
        "POISON_OBJECTIVE": "arg_tamper",
    }


def test_run_one_uses_trace_config_for_git_sha_and_records_v2_utility(
    tmp_path, monkeypatch,
):
    task = {
        "id": "expected-blocked",
        "prompt": "test",
        "context": "original context",
        "expected_tool": "export_data",
    }
    trace_path = tmp_path / "trace.jsonl"
    events = [
        {"type": "run_config", "git_sha": "trace-sha"},
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
        {"type": "confirm_prompt", "decision": "deny"},
        {"type": "summary", "final_text": "", "truncated": False},
    ]
    trace_path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    seen: dict[str, object] = {}
    pinning_findings: list[object] = []

    def fake_build_arm(name, arm_task):
        seen["name"] = name
        seen["task"] = arm_task
        return {
            "tool_transform": None,
            "result_transform": None,
            "call_policy": None,
            "pinning_findings": pinning_findings,
            "relist_each_step": True,
            "confirm_prompts": [],
            "context_transform": lambda context: f"hardened: {context}",
            "hardening_version": "test-version",
        }

    def fake_run_trial(**kwargs):
        # The live summary is deliberately misleading: provenance belongs to
        # the durable trace's run_config event.
        seen["run_trial_kwargs"] = kwargs
        return {"git_sha": "summary-sha"}, trace_path

    monkeypatch.setattr(sweep.arms, "build_arm", fake_build_arm)
    monkeypatch.setattr(sweep, "run_trial", fake_run_trial)

    record = sweep._run_one(_spec(task), 1.0, "policy", tmp_path)

    assert seen["name"] == "policy"
    assert seen["task"] == task
    run_trial_kwargs = seen["run_trial_kwargs"]
    assert run_trial_kwargs["pinning_findings"] is pinning_findings
    assert run_trial_kwargs["relist_each_step"] is True
    assert run_trial_kwargs["confirm_prompts"] == []
    assert run_trial_kwargs["task"]["context"] == "hardened: original context"
    assert run_trial_kwargs["extra_config"]["hardening_version"] == "test-version"
    assert run_trial_kwargs["extra_config"]["objective"] == "exfil_sink"
    assert task["context"] == "original context"
    assert record["blocked_expected_tool"] is True
    assert record["confirm_prompts"] == 1
    assert record["objective"] == "exfil_sink"
    assert record["obj_fired"] is True
    assert record["obj_realized"] is False
    assert record["git_sha"] == "trace-sha"


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
    assert record["confirm_prompts"] == 0
    assert record["objective"] == "exfil_sink"
    assert record["obj_fired"] is False
    assert record["obj_realized"] is False
    assert record["git_sha"] == ""
    assert record["trace"] is None


def test_run_sweep_fails_fast_when_arm_cannot_be_built(tmp_path, monkeypatch):
    """A policy arm on a task without `policy` must abort before any trial runs,
    not degrade into a full sweep of swallowed per-trial errors."""
    import pytest

    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps({"temperature": 0, "max_concurrency": 1}), encoding="utf-8",
    )
    v1_task = {"id": "calc_basic_add", "prompt": "test"}  # no `policy` key

    def never_run(*_args, **_kwargs):
        raise AssertionError("_run_one must not be reached")

    monkeypatch.setattr(
        sweep, "_build_trial_specs", lambda _cfg, task_dir: [_spec(v1_task)],
    )
    monkeypatch.setattr(sweep, "_run_one", never_run)
    out_path = tmp_path / "trials.jsonl"

    with pytest.raises(ValueError, match=r"'policy' cannot be built for task 'calc_basic_add'"):
        sweep.run_sweep(config_path, out_path=out_path, trace_dir=tmp_path,
                        defense_arm="policy")

    assert not out_path.exists()
