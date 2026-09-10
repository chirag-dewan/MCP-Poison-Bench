"""The single-trial CLI must select defenses through the same named arms as the
sweep, so any arm is runnable from `python -m harness.runner` and the runner never
grows its own defense wiring. `trial_kwargs_from_arm` is the one translation from
an arm dict to `run_trial` kwargs; the sweep and the CLI both go through it."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from harness import arms, runner

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_ARGS = ["--server", "servers/poisoned/server.py", "--task", "tasks/calc_add.json"]


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ([], "none"),
        (["--defense"], "meta_filter"),
        (["--defense-arm", "policy"], "policy"),
        (["--defense-arm", "pinning"], "pinning"),
    ],
)
def test_cli_resolves_defense_arm(extra: list[str], expected: str):
    args = runner.build_arg_parser().parse_args(BASE_ARGS + extra)
    assert args.defense_arm == expected


def test_cli_offers_every_registered_arm():
    help_text = runner.build_arg_parser().format_help()
    for name in arms.ARM_NAMES:
        assert name in help_text


def test_cli_rejects_unknown_arm(capsys):
    with pytest.raises(SystemExit):
        runner.build_arg_parser().parse_args(BASE_ARGS + ["--defense-arm", "bogus"])
    assert "invalid choice" in capsys.readouterr().err


@pytest.mark.parametrize("name", arms.ARM_NAMES)
def test_trial_kwargs_cover_every_arm_option(name: str):
    """Every key an arm can emit must reach run_trial; a new arm option that this
    helper does not forward would otherwise be dropped silently."""
    task = json.loads(
        (REPO_ROOT / "tasks" / "v2" / "notes_pipeline.json").read_text(encoding="utf-8")
    )
    arm = arms.build_arm(name, task)
    kwargs = runner.trial_kwargs_from_arm(arm, task)

    forwarded = {"tool_transform", "result_transform", "result_findings", "call_policy",
                 "pinning_findings", "confirm_prompts", "relist_each_step"}
    handled_elsewhere = {"context_transform", "hardening_version"}
    unknown = set(arm) - forwarded - handled_elsewhere
    assert not unknown, f"arm {name!r} emits options the CLI does not forward: {unknown}"

    for key in forwarded - {"relist_each_step"}:
        assert kwargs[key] is arm.get(key)
    assert kwargs["relist_each_step"] is bool(arm.get("relist_each_step", False))
    if arm.get("context_transform") is None:
        assert kwargs["task"] is task
    else:
        assert kwargs["task"] is not task and kwargs["task"]["id"] == task["id"]


def test_main_threads_the_policy_arm_into_run_trial(monkeypatch, tmp_path):
    captured: dict[str, Any] = {}

    def fake_run_trial(**kwargs):
        captured.update(kwargs)
        trace = tmp_path / "trace.jsonl"
        trace.write_text("")
        return {"task_id": kwargs["task"]["id"]}, trace

    monkeypatch.setattr(runner, "run_trial", fake_run_trial)
    monkeypatch.setattr(runner, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", [
        "runner", "--server", "servers/poisoned/server.py",
        "--task", str(REPO_ROOT / "tasks" / "v2" / "notes_pipeline.json"),
        "--poison-class", "rug_pull", "--defense-arm", "policy",
    ])

    runner.main()

    assert captured["tool_transform"] is None          # policy alone: no metadata filter
    assert callable(captured["result_transform"])       # taint recording pass-through
    assert callable(captured["call_policy"])            # capability policy
    assert captured["relist_each_step"] is False
    assert captured["extra_config"] == {
        "defended": True, "defense_arm": "policy", "attack_class": "rug_pull",
    }


def test_runner_module_does_not_import_defense_package():
    """`harness.runner` is meant to be importable as a library on its own; the
    defense package must only be pulled in lazily by the CLI / arms."""
    import subprocess

    code = (
        "import sys, harness.runner; "
        "print(sorted(m for m in sys.modules if m.startswith('defense')))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True,
        check=True,
    ).stdout.strip()
    assert out == "[]", out
