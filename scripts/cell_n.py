#!/usr/bin/env python3
"""Print generated trial counts per (model, class, objective) cell."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness import sweep  # noqa: E402

Cell = tuple[str, str, str]


def _build_specs(
    config_path: str | Path,
    task_dir: str | Path | None = None,
) -> tuple[dict, list[dict]]:
    """Build the real sweep specs while bypassing only API-key availability."""
    path = Path(config_path)
    cfg = json.loads(path.read_text(encoding="utf-8"))
    resolved_task_dir = task_dir if task_dir is not None else cfg.get(
        "task_dir", "tasks"
    )
    with patch.object(sweep.clients, "has_api_key", return_value=True):
        specs = sweep._build_trial_specs(cfg, task_dir=resolved_task_dir)
    return cfg, specs


def count_cells(
    config_path: str | Path,
    task_dir: str | Path | None = None,
) -> Counter[Cell]:
    """Build specs without provider keys and count each objective cell."""
    _cfg, specs = _build_specs(config_path, task_dir)
    return Counter(
        (
            spec["model"],
            spec["attack_class"],
            spec.get("objective", "exfil_sink"),
        )
        for spec in specs
    )


def count_first_payloads_per_class(
    config_path: str | Path,
    task_dir: str | Path | None = None,
    payload_limit: int = 5,
) -> Counter[Cell]:
    """Count a stable first-N-payload core from an expanded config.

    This exposes the historical five-payload v1 core without changing either the
    live fixture register or the sweep's actual expansion.
    """
    if payload_limit < 1:
        raise ValueError("payload_limit must be positive")
    _cfg, specs = _build_specs(config_path, task_dir)
    selected: dict[tuple[str, str], list[str]] = {}
    for spec in specs:
        key = (spec["attack_class"], spec.get("objective", "exfil_sink"))
        ids = selected.setdefault(key, [])
        payload_id = spec["payload_id"]
        if payload_id not in ids and len(ids) < payload_limit:
            ids.append(payload_id)
    return Counter(
        (
            spec["model"],
            spec["attack_class"],
            spec.get("objective", "exfil_sink"),
        )
        for spec in specs
        if spec["payload_id"] in selected[
            (spec["attack_class"], spec.get("objective", "exfil_sink"))
        ]
    )


def format_report(counts: Counter[Cell]) -> str:
    """Render deterministic per-cell counts plus per-model totals."""
    lines = ["model\tattack_class\tobjective\tn"]
    for (model, attack_class, objective), n in sorted(counts.items()):
        lines.append(f"{model}\t{attack_class}\t{objective}\t{n}")

    totals: Counter[tuple[str, str]] = Counter()
    for (model, _attack_class, objective), n in counts.items():
        totals[(model, objective)] += n
    lines.append("")
    lines.append("model\tobjective\ttotal_n")
    for (model, objective), n in sorted(totals.items()):
        lines.append(f"{model}\t{objective}\t{n}")
    return "\n".join(lines)


def format_config_report(
    config_path: str | Path,
    task_dir: str | Path | None = None,
) -> str:
    """Report actual cells and, for unpinned v1 grids, the historical core."""
    cfg, _specs = _build_specs(config_path, task_dir)
    counts = count_cells(config_path, task_dir)
    report = format_report(counts)
    is_unpinned_v1_heldout = (
        cfg.get("payload_set") == "heldout"
        and "objective" not in cfg
        and not cfg.get("payload_ids")
        and "metadata_drift" not in cfg.get("class_tasks", {})
    )
    if is_unpinned_v1_heldout:
        core = count_first_payloads_per_class(config_path, task_dir)
        if core != counts:
            report += (
                "\n\nHISTORICAL FIVE-PAYLOAD CORE (published v1)\n"
                + format_report(core)
            )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Count generated trials per model/class/objective cell."
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument(
        "--task-dir",
        type=Path,
        default=None,
        help="override the config task_dir (default: config value or tasks)",
    )
    args = parser.parse_args()
    print(format_config_report(args.config, args.task_dir))


if __name__ == "__main__":
    main()
