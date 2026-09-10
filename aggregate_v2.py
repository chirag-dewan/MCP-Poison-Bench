"""Aggregate a v2 benchmark run into long, wide, delta, and JSON artifacts.

The input directory contains one JSONL file per payload-set/objective/defense-arm
combination, named ``trials_<set>_<objective>_<arm>.jsonl``.  This module is a
pure post-processing step: it never imports a model client or makes network calls.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from harness.arms import ARM_NAMES
from scorer.aggregate import wilson_ci


REPO_ROOT = Path(__file__).resolve().parent

OBJECTIVE_ALIASES = {
    "exfil": "exfil_sink",
    "exfil_sink": "exfil_sink",
    "tamper": "arg_tamper",
    "arg_tamper": "arg_tamper",
    "destructive": "destructive",
}
OBJECTIVE_LABELS = {
    "exfil_sink": "exfil",
    "arg_tamper": "tamper",
    "destructive": "destructive",
}
OBJECTIVE_ORDER = {"exfil_sink": 0, "arg_tamper": 1, "destructive": 2}

RATE_FIELDS = {
    "attempted": "asr_attempted",
    "realized": "asr_realized",
    "canary_exfil": "canary_exfiltrated",
    "canary_realized": "canary_realized",
    "obj_fired": "obj_fired",
    "obj_realized": "obj_realized",
    "utility": "utility_ok",
    "truncated": "truncated",
    "blocked": "asr_blocked",
}
METRIC_ORDER = (*RATE_FIELDS, "confirm_prompts")


def _canonical_objective(value: str) -> str:
    return OBJECTIVE_ALIASES.get(value, value)


def _objective_label(objective: str) -> str:
    return OBJECTIVE_LABELS.get(objective, objective)


def _arm_order(arm: str) -> tuple[int, str]:
    try:
        return (ARM_NAMES.index(arm), arm)
    except ValueError:
        return (len(ARM_NAMES), arm)


def ci_overlap(
    first: tuple[float, float], second: tuple[float, float],
) -> bool:
    """Return whether two closed confidence intervals overlap.

    Endpoint contact counts as overlap.  This is deliberately the only
    inferential comparison emitted by the v2 aggregator.
    """
    return first[0] <= second[1] and second[0] <= first[1]


def _rate_metric(successes: int, n: int) -> dict[str, Any]:
    lo, hi = wilson_ci(successes, n)
    return {
        "successes": successes,
        "n": n,
        "mean": successes / n if n else 0.0,
        "lo": lo,
        "hi": hi,
    }


@dataclass
class V2Cell:
    model: str
    attack_class: str
    arm: str
    n: int = 0
    errors: int = 0
    successes: dict[str, int] = field(
        default_factory=lambda: {metric: 0 for metric in RATE_FIELDS}
    )
    confirm_prompts_total: int = 0

    def add(self, record: dict[str, Any]) -> None:
        if record.get("error"):
            self.errors += 1
            return

        fired = bool(record["asr_fired"])
        attempted = bool(record.get("asr_attempted", fired))
        assert attempted == fired, (
            "corrupted v2 trial: asr_attempted must equal asr_fired "
            f"for {self.model}/{self.attack_class}/{self.arm}"
        )

        self.n += 1
        for metric, source_field in RATE_FIELDS.items():
            value = attempted if metric == "attempted" else bool(
                record.get(source_field, False)
            )
            self.successes[metric] += int(value)
        self.confirm_prompts_total += int(record.get("confirm_prompts", 0) or 0)

    def metrics(self) -> dict[str, dict[str, Any]]:
        result = {
            metric: _rate_metric(self.successes[metric], self.n)
            for metric in RATE_FIELDS
        }
        result["confirm_prompts"] = {
            "total": self.confirm_prompts_total,
            "n": self.n,
            "mean": self.confirm_prompts_total / self.n if self.n else 0.0,
            "lo": None,
            "hi": None,
        }
        return result

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "attack_class": self.attack_class,
            "arm": self.arm,
            "n": self.n,
            "errors": self.errors,
            "metrics": self.metrics(),
        }


def build_cells(records: Iterable[dict[str, Any]]) -> list[V2Cell]:
    """Group records by model, attack class, and defense arm.

    Errored records create/count their cell but do not contribute to ``n`` or
    any metric.  Non-error records must preserve the v1/v2 attempted invariant.
    """
    buckets: dict[tuple[str, str, str], V2Cell] = {}
    for record in records:
        key = (
            str(record["model"]),
            str(record["attack_class"]),
            str(record.get("defense_arm", "none")),
        )
        if key not in buckets:
            buckets[key] = V2Cell(*key)
        buckets[key].add(record)
    return sorted(
        buckets.values(),
        key=lambda cell: (cell.model, cell.attack_class, _arm_order(cell.arm)),
    )


def _parse_trial_filename(path: Path) -> tuple[str, str, str] | None:
    stem = path.stem
    if not stem.startswith("trials_"):
        return None
    body = stem.removeprefix("trials_")
    try:
        payload_set, remainder = body.split("_", 1)
    except ValueError:
        return None
    if payload_set not in {"heldout", "seen"}:
        return None
    for arm in sorted(ARM_NAMES, key=len, reverse=True):
        suffix = f"_{arm}"
        if remainder.endswith(suffix):
            objective_label = remainder[: -len(suffix)]
            if objective_label:
                return payload_set, _canonical_objective(objective_label), arm
    return None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON in {path}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"trial record in {path}:{line_number} is not an object")
            records.append(value)
    return records


def load_trial_groups(
    run_dir: str | Path,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Load and group run files by ``(payload_set, objective, arm)``.

    Known filenames preserve an empty group when a no-key sweep wrote an empty
    JSONL file.  For an unconventional filename, record metadata is used instead.
    """
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}

    def group_for(payload_set: str, objective: str, arm: str) -> dict[str, Any]:
        key = payload_set, objective, arm
        return groups.setdefault(key, {"records": [], "trial_files": set()})

    for path in sorted(Path(run_dir).glob("trials_*.jsonl")):
        records = _load_jsonl(path)
        parsed = _parse_trial_filename(path)
        if parsed is not None:
            payload_set, objective, arm = parsed
            group = group_for(payload_set, objective, arm)
            group["trial_files"].add(path.name)
            for record in records:
                record_set = record.get("payload_set")
                record_objective = _canonical_objective(
                    str(record.get("objective", objective))
                )
                record_arm = str(record.get("defense_arm", arm))
                if record_set is not None and record_set != payload_set:
                    raise ValueError(
                        f"{path.name} contains payload_set={record_set!r}; "
                        f"expected {payload_set!r}"
                    )
                if record_objective != objective:
                    raise ValueError(
                        f"{path.name} contains objective={record_objective!r}; "
                        f"expected {objective!r}"
                    )
                if record_arm != arm:
                    raise ValueError(
                        f"{path.name} contains defense_arm={record_arm!r}; "
                        f"expected {arm!r}"
                    )
                normalized = dict(record)
                normalized.setdefault("payload_set", payload_set)
                normalized["objective"] = objective
                normalized.setdefault("defense_arm", arm)
                group["records"].append(normalized)
            continue

        for record in records:
            payload_set = str(record["payload_set"])
            objective = _canonical_objective(str(record["objective"]))
            arm = str(record.get("defense_arm", "none"))
            group = group_for(payload_set, objective, arm)
            group["trial_files"].add(path.name)
            normalized = dict(record)
            normalized["objective"] = objective
            group["records"].append(normalized)
    return groups


def _fmt_rate(metric: dict[str, Any]) -> str:
    return f"{metric['mean']:.2f} [{metric['lo']:.2f},{metric['hi']:.2f}]"


def write_long_csv(
    cells: list[V2Cell], path: str | Path, payload_set: str, objective: str,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "payload_set", "objective", "model", "attack_class", "arm", "metric",
        "successes", "mean", "lo", "hi", "n", "errors",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for cell in cells:
            for metric_name in METRIC_ORDER:
                metric = cell.metrics()[metric_name]
                writer.writerow({
                    "payload_set": payload_set,
                    "objective": objective,
                    "model": cell.model,
                    "attack_class": cell.attack_class,
                    "arm": cell.arm,
                    "metric": metric_name,
                    "successes": metric.get("successes", ""),
                    "mean": f"{metric['mean']:.6f}",
                    "lo": "" if metric["lo"] is None else f"{metric['lo']:.6f}",
                    "hi": "" if metric["hi"] is None else f"{metric['hi']:.6f}",
                    "n": metric["n"],
                    "errors": cell.errors,
                })
    return path


def _all_arms(cells: Iterable[V2Cell]) -> list[str]:
    extras = sorted({cell.arm for cell in cells} - set(ARM_NAMES))
    return [*ARM_NAMES, *extras]


def _headline_metrics(objective: str) -> tuple[str, str]:
    if objective == "exfil_sink":
        return "attempted", "realized"
    return "obj_fired", "obj_realized"


def write_ablation_md(
    cells: list[V2Cell], path: str | Path, payload_set: str, objective: str,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    arms = _all_arms(cells)
    attempted_name, realized_name = _headline_metrics(objective)
    by_key = {(cell.model, cell.attack_class, cell.arm): cell for cell in cells}
    rows = sorted({(cell.model, cell.attack_class) for cell in cells})
    lines = [
        f"# Ablation: {payload_set} / {objective}",
        "",
        "| model | attack_class | " + " | ".join(arms) + " |",
        "|---|---|" + "---|" * len(arms),
    ]
    for model, attack_class in rows:
        values = []
        for arm in arms:
            cell = by_key.get((model, attack_class, arm))
            if cell is None or cell.n == 0:
                values.append("—")
                continue
            metrics = cell.metrics()
            values.append(
                f"real={_fmt_rate(metrics[realized_name])} · "
                f"att={_fmt_rate(metrics[attempted_name])} · "
                f"util={metrics['utility']['mean']:.2f}"
            )
        lines.append(
            f"| {model} | {attack_class} | " + " | ".join(values) + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def build_deltas(cells: list[V2Cell], objective: str) -> list[dict[str, Any]]:
    """Compare every measured arm with the matching ``none`` cell."""
    by_key = {(cell.model, cell.attack_class, cell.arm): cell for cell in cells}
    realized_name = _headline_metrics(objective)[1]
    deltas: list[dict[str, Any]] = []
    for cell in cells:
        if cell.arm == "none":
            continue
        baseline = by_key.get((cell.model, cell.attack_class, "none"))
        if baseline is None or baseline.n == 0 or cell.n == 0:
            continue
        baseline_metrics = baseline.metrics()
        arm_metrics = cell.metrics()
        baseline_realized = baseline_metrics[realized_name]
        arm_realized = arm_metrics[realized_name]
        baseline_utility = baseline_metrics["utility"]
        arm_utility = arm_metrics["utility"]
        deltas.append({
            "model": cell.model,
            "attack_class": cell.attack_class,
            "arm": cell.arm,
            "baseline_arm": "none",
            "realized_metric": realized_name,
            "realized_baseline": baseline_realized,
            "realized_arm": arm_realized,
            "delta_realized": arm_realized["mean"] - baseline_realized["mean"],
            "realized_cis_overlap": ci_overlap(
                (baseline_realized["lo"], baseline_realized["hi"]),
                (arm_realized["lo"], arm_realized["hi"]),
            ),
            "utility_baseline": baseline_utility,
            "utility_arm": arm_utility,
            "delta_utility": arm_utility["mean"] - baseline_utility["mean"],
            "utility_cis_overlap": ci_overlap(
                (baseline_utility["lo"], baseline_utility["hi"]),
                (arm_utility["lo"], arm_utility["hi"]),
            ),
        })
    return sorted(
        deltas,
        key=lambda row: (
            row["model"], row["attack_class"], _arm_order(row["arm"]),
        ),
    )


def write_deltas_md(
    deltas: list[dict[str, Any]], path: str | Path,
    payload_set: str, objective: str,
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Deltas vs `none`: {payload_set} / {objective}",
        "",
        "| model | attack_class | arm | Δrealized | realized CIs overlap | "
        "Δutility | utility CIs overlap |",
        "|---|---|---|---:|---|---:|---|",
    ]
    for row in deltas:
        lines.append(
            f"| {row['model']} | {row['attack_class']} | {row['arm']} | "
            f"{row['delta_realized']:+.2f} | "
            f"{'yes' if row['realized_cis_overlap'] else 'no'} | "
            f"{row['delta_utility']:+.2f} | "
            f"{'yes' if row['utility_cis_overlap'] else 'no'} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _read_config_roster() -> list[str]:
    path = REPO_ROOT / "config" / "v2" / "roster.json"
    if not path.exists():
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value = value.get("models", [])
    return [str(model) for model in value] if isinstance(value, list) else []


def _read_config_seeds() -> list[int]:
    seeds: set[int] = set()
    config_dir = REPO_ROOT / "config" / "v2"
    for path in config_dir.glob("*.json"):
        if path.name == "roster.json":
            continue
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            seeds.update(int(seed) for seed in value.get("seeds", []))
    return sorted(seeds)


def _metadata(records: list[dict[str, Any]]) -> dict[str, Any]:
    observed_models = {
        str(record["model"]) for record in records if record.get("model")
    }
    # Keep skipped models in partial-run metadata. Narrowing to providers that
    # happened to have keys would let an unconfirmed-price roster member vanish
    # from the report generator's publication gate.
    roster = _read_config_roster()
    roster.extend(sorted(observed_models - set(roster)))
    seeds = sorted({int(record["seed"]) for record in records if "seed" in record})
    if not seeds:
        seeds = _read_config_seeds()
    git_shas = sorted({
        str(record["git_sha"])
        for record in records
        if record.get("git_sha")
    })
    observed_arms = {str(record.get("defense_arm", "none")) for record in records}
    extra_arms = sorted(observed_arms - set(ARM_NAMES))
    return {
        "roster": roster,
        "arms": [*ARM_NAMES, *extra_arms],
        "seeds": seeds,
        "git_sha": git_shas[0] if len(git_shas) == 1 else None,
        "git_shas": git_shas,
    }


def _model_health(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_model: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_model[str(record["model"])].append(record)
    result = []
    for model, model_records in sorted(by_model.items()):
        valid = [record for record in model_records if not record.get("error")]
        errors = len(model_records) - len(valid)
        truncated = sum(bool(record.get("truncated")) for record in valid)
        error_lo, error_hi = wilson_ci(errors, len(model_records))
        trunc_lo, trunc_hi = wilson_ci(truncated, len(valid))
        result.append({
            "model": model,
            "records": len(model_records),
            "n": len(valid),
            "errors": errors,
            "error_rate": errors / len(model_records) if model_records else 0.0,
            "error_ci": {"lo": error_lo, "hi": error_hi},
            "truncated": truncated,
            "truncated_rate": truncated / len(valid) if valid else 0.0,
            "truncated_ci": {"lo": trunc_lo, "hi": trunc_hi},
        })
    return result


def aggregate_run(run_dir: str | Path) -> dict[str, Any]:
    """Aggregate all v2 trial files under ``run_dir`` and write artifacts."""
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    loaded_by_arm = load_trial_groups(run_path)
    loaded: dict[tuple[str, str], dict[str, Any]] = {}
    for (payload_set, objective, _arm), arm_group in loaded_by_arm.items():
        group = loaded.setdefault(
            (payload_set, objective), {"records": [], "trial_files": set()}
        )
        group["records"].extend(arm_group["records"])
        group["trial_files"].update(arm_group["trial_files"])
    all_records = [
        record
        for group in loaded.values()
        for record in group["records"]
    ]
    summary: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_path.name,
        "run_dir": str(run_path.resolve()),
        "metadata": _metadata(all_records),
        "groups": [],
        "model_health": _model_health(all_records),
    }

    ordered_groups = sorted(
        loaded.items(),
        key=lambda item: (
            0 if item[0][0] == "heldout" else 1,
            OBJECTIVE_ORDER.get(item[0][1], len(OBJECTIVE_ORDER)),
            item[0][1],
        ),
    )
    for (payload_set, objective), loaded_group in ordered_groups:
        records = loaded_group["records"]
        cells = build_cells(records)
        label = _objective_label(objective)
        matrix_name = f"matrix_{payload_set}_{label}.csv"
        ablation_name = f"ablation_{payload_set}_{label}.md"
        deltas_name = f"deltas_{payload_set}_{label}.md"
        write_long_csv(cells, run_path / matrix_name, payload_set, objective)
        write_ablation_md(cells, run_path / ablation_name, payload_set, objective)
        deltas = build_deltas(cells, objective)
        write_deltas_md(
            deltas, run_path / deltas_name, payload_set, objective,
        )
        attempted_name, realized_name = _headline_metrics(objective)
        group_errors = sum(cell.errors for cell in cells)
        group_n = sum(cell.n for cell in cells)
        summary["groups"].append({
            "payload_set": payload_set,
            "objective": objective,
            "objective_label": label,
            "headline_attempted_metric": attempted_name,
            "headline_realized_metric": realized_name,
            "trial_files": sorted(loaded_group["trial_files"]),
            "records": group_n + group_errors,
            "n": group_n,
            "errors": group_errors,
            "outputs": {
                "matrix_csv": matrix_name,
                "ablation_md": ablation_name,
                "deltas_md": deltas_name,
            },
            "cells": [cell.as_dict() for cell in cells],
            "deltas": deltas,
        })

    summary_path = run_path / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate a v2 benchmark run.")
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    summary = aggregate_run(args.run_dir)
    print(
        f"aggregated {len(summary['groups'])} group(s) into "
        f"{Path(args.run_dir) / 'summary.json'}"
    )


if __name__ == "__main__":
    main()
