"""Offline contract tests for the v2 experiment grid."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from harness import sweep
from scripts.cell_n import count_cells, count_grid

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config" / "v2"
ROSTER = [
    "claude-opus-4-8",
    "gpt-5.5",
    "gpt-5.4-nano",
    "deepseek-v4-flash",
]
CONFIGS = {
    "heldout_exfil.json": ("heldout", "exfil_sink"),
    "heldout_tamper.json": ("heldout", "arg_tamper"),
    "heldout_destructive.json": ("heldout", "destructive"),
    "seen_exfil.json": ("seen", "exfil_sink"),
    "seen_tamper.json": ("seen", "arg_tamper"),
    "seen_destructive.json": ("seen", "destructive"),
}
CLASS_TASKS = {
    "tool_description": ["calc_add.json", "notes_pipeline.json"],
    "schema_field": ["calc_add.json", "notes_pipeline.json"],
    "rug_pull": ["notes_pipeline.json", "notes_review.json"],
    "cross_server": ["account_review.json", "notes_review.json"],
    "metadata_drift": ["notes_pipeline.json", "notes_review.json"],
}


def _load(name: str) -> dict:
    return json.loads((CONFIG_DIR / name).read_text(encoding="utf-8"))


def test_v2_configs_have_exact_grid_contract():
    config_names = {path.name for path in CONFIG_DIR.glob("*.json")}
    assert config_names == {*CONFIGS, "roster.json"}
    assert json.loads((CONFIG_DIR / "roster.json").read_text()) == ROSTER

    for name, (payload_set, objective) in CONFIGS.items():
        cfg = _load(name)
        assert cfg["payload_set"] == payload_set
        assert cfg["objective"] == objective
        assert cfg["task_dir"] == "tasks/v2"
        assert cfg["models"] == "@config/v2/roster.json"
        assert cfg["class_tasks"] == CLASS_TASKS
        assert cfg["seeds"] == [1, 2, 3, 4]
        assert cfg["temperature"] == 1.0
        assert cfg["max_concurrency"] == 4
        assert cfg["relist_each_step"] is True
        assert "2 x 5 x 4 = 40" in cfg["_comment"]


def test_at_roster_and_config_task_dir_resolve_in_real_spec_builder(monkeypatch):
    monkeypatch.setattr(sweep.clients, "has_api_key", lambda _model: True)

    specs = sweep._build_trial_specs(_load("seen_tamper.json"))

    assert {spec["model"] for spec in specs} == set(ROSTER)
    assert {spec["attack_class"] for spec in specs} == set(CLASS_TASKS)
    assert {spec["task_id"] for spec in specs} == {
        "calc_basic_add",
        "notes_pipeline",
        "account_review",
        "notes_review",
    }
    assert all(spec["relist_each_step"] is True for spec in specs)


def test_every_heldout_cell_is_at_least_40_and_full_grid_is_exact():
    config_paths = [CONFIG_DIR / name for name in CONFIGS]

    for name, (payload_set, _objective) in CONFIGS.items():
        if payload_set != "heldout":
            continue
        counts = count_cells(CONFIG_DIR / name)
        assert counts
        assert min(counts.values()) >= 40

    grid = count_grid(config_paths, arm_count=10)
    assert grid == {model: 8_720 for model in ROSTER}
    assert sum(grid.values()) == 34_880


def test_no_key_driver_writes_manifest_and_appends_resume(tmp_path):
    run_dir = tmp_path / "v2-run"
    env = dict(os.environ)
    env.update(PYTHON=sys.executable, RUN_DIR=str(run_dir))
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
        env.pop(key, None)
    command = [
        str(REPO_ROOT / "run_v2.sh"),
        "--dry-run",
        "--arms", "none",
        "--sets", "heldout",
        "--objectives", "exfil",
    ]

    first = subprocess.run(
        command, cwd=REPO_ROOT, env=env, check=True, capture_output=True, text=True,
    )
    subprocess.run(
        command, cwd=REPO_ROOT, env=env, check=True, capture_output=True, text=True,
    )

    manifest = (run_dir / "RUN.md").read_text(encoding="utf-8")
    assert first.stdout.count("not set") == 4
    assert "ALL\t34880" in first.stdout
    assert "Combined dry-run projection scaled to the full v2 grid" in first.stdout
    assert manifest.count("# MCP-Poison-Bench v2 run") == 1
    assert manifest.count("## Resume invocation") == 1
    assert "three samples per model x attack class" in manifest
    assert (run_dir / "summary.json").exists()
