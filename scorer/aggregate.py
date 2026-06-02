"""Aggregate per-trial results into the benchmark matrix with confidence intervals.

Owned by agent:scorer. Reads the per-trial records the sweep writes to
`results/trials.jsonl`, groups them by (model, attack_class), and emits
`results/matrix.csv` with mean ASR, mean utility, and a Wilson score confidence
interval for each proportion. Pure functions of the trial records — no model or
server calls. See CLAUDE.md ("Confidence intervals on every aggregate").

Why Wilson and not normal-approx (Wald)?
  ASR/utility are binomial proportions over a small number of seeded trials. The
  Wald interval p ± z*sqrt(p(1-p)/n) is badly behaved exactly here: it gives
  zero-width intervals at p=0 or p=1 and can leave [0,1]. The Wilson score
  interval is the standard small-sample fix — it stays inside [0,1] and is
  non-degenerate at the boundaries. z=1.96 → 95% CI.
"""
from __future__ import annotations

import csv
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
TRIALS_PATH = RESULTS_DIR / "trials.jsonl"
TRIALS_DEFENDED_PATH = RESULTS_DIR / "trials_defended.jsonl"
MATRIX_PATH = RESULTS_DIR / "matrix.csv"
MATRIX_DEFENDED_PATH = RESULTS_DIR / "matrix_defended.csv"
DELTA_CSV_PATH = RESULTS_DIR / "delta.csv"
DELTA_MD_PATH = RESULTS_DIR / "delta_table.md"

Z_95 = 1.959963984540054  # standard normal quantile for a 95% two-sided interval


def wilson_ci(successes: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Returns (low, high), both clamped to [0, 1]. For n == 0 returns (0.0, 1.0):
    with no data the proportion is completely uncertain.
    """
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z * math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


@dataclass
class Cell:
    model: str
    attack_class: str
    n: int
    asr_successes: int
    util_successes: int
    canary_successes: int
    task_id: str = ""  # set only when cells are grouped by task (--by-task)

    @property
    def asr_mean(self) -> float:
        return self.asr_successes / self.n if self.n else 0.0

    @property
    def utility_mean(self) -> float:
        return self.util_successes / self.n if self.n else 0.0

    @property
    def canary_mean(self) -> float:
        return self.canary_successes / self.n if self.n else 0.0

    def asr_ci(self) -> tuple[float, float]:
        return wilson_ci(self.asr_successes, self.n)

    def utility_ci(self) -> tuple[float, float]:
        return wilson_ci(self.util_successes, self.n)


def load_trials(path: str | Path = TRIALS_PATH) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    with p.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def build_cells(trials: list[dict[str, Any]], by_task: bool = False) -> list[Cell]:
    """Group trials into cells, summing successes.

    Default key is (model, attack_class) — the headline matrix, aggregating over
    payloads/tasks/seeds. With `by_task=True` the key is (model, attack_class,
    task_id), so a class running on more than one task is split per task.
    """
    buckets: dict[tuple[str, ...], Cell] = {}
    for t in trials:
        # A trial that errored out (e.g. a rate-limit failure after all retries)
        # is NOT a measurement — it never observed model behavior. Counting it as
        # asr_fired=False would launder API failures into false "attack didn't
        # fire" data, biasing ASR down. Exclude it from every cell.
        if t.get("error"):
            continue
        task_id = t.get("task_id", "") if by_task else ""
        key = (t["model"], t["attack_class"], task_id)
        cell = buckets.get(key)
        if cell is None:
            cell = Cell(t["model"], t["attack_class"], 0, 0, 0, 0, task_id=task_id)
            buckets[key] = cell
        cell.n += 1
        cell.asr_successes += int(bool(t["asr_fired"]))
        cell.util_successes += int(bool(t["utility_ok"]))
        cell.canary_successes += int(bool(t.get("canary_exfiltrated")))
    return sorted(buckets.values(), key=lambda c: (c.model, c.attack_class, c.task_id))


def write_matrix(
    cells: list[Cell], path: str | Path = MATRIX_PATH, include_task: bool = False,
) -> Path:
    """Write the benchmark matrix CSV. One row per cell.

    `include_task` adds a `task_id` column (use with cells from
    `build_cells(..., by_task=True)`); default keeps the headline schema.
    """
    path = Path(path).resolve()
    path.parent.mkdir(exist_ok=True)
    lead = ["model", "attack_class"] + (["task_id"] if include_task else [])
    fields = lead + [
        "n",
        "asr_mean", "asr_ci_low", "asr_ci_high",
        "utility_mean", "utility_ci_low", "utility_ci_high",
        "canary_exfil_mean",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(fields)
        for c in cells:
            a_lo, a_hi = c.asr_ci()
            u_lo, u_hi = c.utility_ci()
            row = [c.model, c.attack_class] + ([c.task_id] if include_task else [])
            row += [
                c.n,
                f"{c.asr_mean:.4f}", f"{a_lo:.4f}", f"{a_hi:.4f}",
                f"{c.utility_mean:.4f}", f"{u_lo:.4f}", f"{u_hi:.4f}",
                f"{c.canary_mean:.4f}",
            ]
            w.writerow(row)
    return path


def aggregate(
    trials_path: str | Path = TRIALS_PATH, matrix_path: str | Path = MATRIX_PATH,
    by_task: bool = False,
) -> tuple[list[Cell], Path]:
    cells = build_cells(load_trials(trials_path), by_task=by_task)
    out = write_matrix(cells, matrix_path, include_task=by_task)
    return cells, out


def build_delta(
    baseline_path: str | Path = TRIALS_PATH,
    defended_path: str | Path = TRIALS_DEFENDED_PATH,
    by_task: bool = False,
) -> list[dict[str, Any]]:
    """Join baseline and defended cells into per-cell delta rows.

    Rows are keyed by (model, attack_class[, task_id]). ASR/utility deltas are
    defended minus baseline (negative ASR delta == the defense reduced attack
    success).
    """
    def _key(c: Cell) -> tuple[str, ...]:
        return (c.model, c.attack_class, c.task_id) if by_task else (c.model, c.attack_class)

    base = {_key(c): c for c in build_cells(load_trials(baseline_path), by_task=by_task)}
    deff = {_key(c): c for c in build_cells(load_trials(defended_path), by_task=by_task)}
    keys = sorted(set(base) | set(deff))
    rows: list[dict[str, Any]] = []
    for key in keys:
        model, attack_class = key[0], key[1]
        b, d = base.get(key), deff.get(key)
        row = {
            "model": model,
            "attack_class": attack_class,
            "task_id": (key[2] if by_task else ""),
            "n_baseline": b.n if b else 0,
            "n_defended": d.n if d else 0,
            "asr_baseline": b.asr_mean if b else None,
            "asr_defended": d.asr_mean if d else None,
            "asr_delta": (d.asr_mean - b.asr_mean) if (b and d) else None,
            "utility_baseline": b.utility_mean if b else None,
            "utility_defended": d.utility_mean if d else None,
            "utility_delta": (d.utility_mean - b.utility_mean) if (b and d) else None,
        }
        rows.append(row)
    return rows


def write_delta_csv(rows: list[dict[str, Any]], path: str | Path = DELTA_CSV_PATH) -> Path:
    path = Path(path)
    path.parent.mkdir(exist_ok=True)
    has_task = any(r.get("task_id") for r in rows)
    fields = ["model", "attack_class"] + (["task_id"] if has_task else []) + [
        "n_baseline", "n_defended",
        "asr_baseline", "asr_defended", "asr_delta",
        "utility_baseline", "utility_defended", "utility_delta",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({
                k: (f"{v:.4f}" if isinstance(v, float) else v) for k, v in r.items()
            })
    return path


def _fmt(v: Any) -> str:
    return f"{v:.2f}" if isinstance(v, float) else ("—" if v is None else str(v))


def write_delta_md(rows: list[dict[str, Any]], path: str | Path = DELTA_MD_PATH) -> Path:
    path = Path(path)
    path.parent.mkdir(exist_ok=True)
    has_task = any(r.get("task_id") for r in rows)
    task_h = "task | " if has_task else ""
    task_sep = "---|" if has_task else ""
    header = (
        f"| model | attack_class | {task_h}n | ASR base | ASR def | ΔASR | "
        "util base | util def | Δutil |\n"
        f"|---|---|{task_sep}---|---|---|---|---|---|---|\n"
    )
    lines = []
    for r in rows:
        task_c = f"{r['task_id']} | " if has_task else ""
        lines.append(
            f"| {r['model']} | {r['attack_class']} | {task_c}{r['n_baseline']} | "
            f"{_fmt(r['asr_baseline'])} | {_fmt(r['asr_defended'])} | "
            f"{_fmt(r['asr_delta'])} | {_fmt(r['utility_baseline'])} | "
            f"{_fmt(r['utility_defended'])} | {_fmt(r['utility_delta'])} |"
        )
    path.write_text(header + "\n".join(lines) + "\n", encoding="utf-8")
    return path


def _format_delta(rows: list[dict[str, Any]]) -> str:
    out = [
        f"{'model':<28} {'attack_class':<16} "
        f"{'ASR base→def (Δ)':>22} {'util base→def (Δ)':>24}"
    ]
    for r in rows:
        asr = f"{_fmt(r['asr_baseline'])}→{_fmt(r['asr_defended'])} ({_fmt(r['asr_delta'])})"
        util = f"{_fmt(r['utility_baseline'])}→{_fmt(r['utility_defended'])} ({_fmt(r['utility_delta'])})"
        out.append(f"{r['model']:<28} {r['attack_class']:<16} {asr:>22} {util:>24}")
    return "\n".join(out)


def _format_table(cells: list[Cell]) -> str:
    lines = [
        f"{'model':<28} {'attack_class':<16} {'n':>3} "
        f"{'ASR (95% CI)':>22} {'utility (95% CI)':>22}"
    ]
    for c in cells:
        a_lo, a_hi = c.asr_ci()
        u_lo, u_hi = c.utility_ci()
        asr = f"{c.asr_mean:.2f} [{a_lo:.2f},{a_hi:.2f}]"
        util = f"{c.utility_mean:.2f} [{u_lo:.2f},{u_hi:.2f}]"
        lines.append(
            f"{c.model:<28} {c.attack_class:<16} {c.n:>3} {asr:>22} {util:>22}"
        )
    return "\n".join(lines)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="MCP-Poison-Bench aggregator.")
    parser.add_argument("--trials", type=Path, default=TRIALS_PATH,
                        help="trial records to aggregate into a matrix")
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH,
                        help="output matrix CSV path")
    parser.add_argument("--delta", action="store_true",
                        help="emit the baseline-vs-defended delta table instead")
    parser.add_argument("--by-task", action="store_true",
                        help="split cells per task_id (adds a task_id column)")
    parser.add_argument("--baseline", type=Path, default=TRIALS_PATH)
    parser.add_argument("--defended", type=Path, default=TRIALS_DEFENDED_PATH)
    args = parser.parse_args()

    if args.delta:
        rows = build_delta(args.baseline, args.defended, by_task=args.by_task)
        if not rows:
            print("no trials to compare — run baseline and defended sweeps first.")
            return
        csv_out = write_delta_csv(rows)
        md_out = write_delta_md(rows)
        print(_format_delta(rows))
        print(f"\nwrote {csv_out.relative_to(REPO_ROOT)} and {md_out.relative_to(REPO_ROOT)}")
        return

    cells, out = aggregate(args.trials, args.matrix, by_task=args.by_task)
    if not cells:
        print(f"no trials found at {args.trials} — run the sweep first.")
        return
    print(_format_table(cells))
    print(f"\nwrote {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
