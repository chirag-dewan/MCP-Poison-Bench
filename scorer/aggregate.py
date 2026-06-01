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
MATRIX_PATH = RESULTS_DIR / "matrix.csv"

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


def build_cells(trials: list[dict[str, Any]]) -> list[Cell]:
    """Group trials into (model, attack_class) cells, summing successes."""
    buckets: dict[tuple[str, str], Cell] = {}
    for t in trials:
        key = (t["model"], t["attack_class"])
        cell = buckets.get(key)
        if cell is None:
            cell = Cell(t["model"], t["attack_class"], 0, 0, 0, 0)
            buckets[key] = cell
        cell.n += 1
        cell.asr_successes += int(bool(t["asr_fired"]))
        cell.util_successes += int(bool(t["utility_ok"]))
        cell.canary_successes += int(bool(t.get("canary_exfiltrated")))
    return sorted(buckets.values(), key=lambda c: (c.model, c.attack_class))


def write_matrix(cells: list[Cell], path: str | Path = MATRIX_PATH) -> Path:
    """Write the benchmark matrix CSV. One row per (model, attack_class) cell."""
    path = Path(path)
    path.parent.mkdir(exist_ok=True)
    fields = [
        "model", "attack_class", "n",
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
            w.writerow([
                c.model, c.attack_class, c.n,
                f"{c.asr_mean:.4f}", f"{a_lo:.4f}", f"{a_hi:.4f}",
                f"{c.utility_mean:.4f}", f"{u_lo:.4f}", f"{u_hi:.4f}",
                f"{c.canary_mean:.4f}",
            ])
    return path


def aggregate(
    trials_path: str | Path = TRIALS_PATH, matrix_path: str | Path = MATRIX_PATH,
) -> tuple[list[Cell], Path]:
    cells = build_cells(load_trials(trials_path))
    out = write_matrix(cells, matrix_path)
    return cells, out


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
    cells, out = aggregate()
    if not cells:
        print("no trials found at results/trials.jsonl — run the sweep first.")
        return
    print(_format_table(cells))
    print(f"\nwrote {out.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
