"""The single-trial CLI must select defenses through the same named arms as the
sweep, so a `policy` run is possible from `python -m harness.runner` and the runner
never grows its own defense wiring."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from harness import runner

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_ARGS = ["--server", "servers/poisoned/server.py", "--task", "tasks/calc_add.json"]


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ([], "none"),
        (["--defense"], "meta_filter"),
        (["--defense-arm", "policy"], "policy"),
        (["--defense-arm", "policy_full"], "policy_full"),
    ],
)
def test_cli_resolves_defense_arm(extra: list[str], expected: str):
    args = runner.build_arg_parser().parse_args(BASE_ARGS + extra)
    assert args.defense_arm == expected


def test_cli_rejects_unknown_arm(capsys):
    with pytest.raises(SystemExit):
        runner.build_arg_parser().parse_args(BASE_ARGS + ["--defense-arm", "bogus"])
    assert "invalid choice" in capsys.readouterr().err


def test_main_threads_all_three_seams_from_the_arm(monkeypatch, tmp_path):
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

    assert captured["tool_transform"] is None            # policy arm: no metadata filter
    assert callable(captured["result_transform"])         # taint recording pass-through
    assert callable(captured["call_policy"])              # capability policy
    assert captured["extra_config"] == {"defense_arm": "policy", "attack_class": "rug_pull"}
    assert captured["task"] == json.loads(
        (REPO_ROOT / "tasks" / "v2" / "notes_pipeline.json").read_text(encoding="utf-8")
    )


def test_runner_module_does_not_import_defense_package():
    """`harness.runner` is meant to be importable as a library on its own; the
    defense package must only be pulled in lazily by the CLI / arms."""
    import importlib
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
    importlib.import_module("harness.runner")  # and it is importable here too
