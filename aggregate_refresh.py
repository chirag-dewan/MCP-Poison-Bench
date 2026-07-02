"""Aggregate the 2026-07 refresh into labeled matrices + deltas, mirroring
aggregate_all.py exactly — held-out core pools with held-out ext (as core pooled
with ext in the original run), seen is reported separately, errored trials are
excluded and counted, and the confidence intervals are the same Wilson-score code
in scorer/aggregate.py (untouched). Reads and writes ONLY under
results/2026-07-refresh/, so the original run's artifacts are never involved.

    .venv/bin/python aggregate_refresh.py
"""
from __future__ import annotations

import json
from pathlib import Path

from scorer.aggregate import (
    build_cells, write_matrix, build_delta, write_delta_csv, write_delta_md, load_trials,
)

R = Path(__file__).resolve().parent / "results" / "2026-07-refresh"

# Held-out = core (register-1) + ext (register-2), exactly as the published run merged them.
GROUPS = {
    "heldout":          ["trials_heldout.jsonl", "trials_heldout_ext.jsonl"],
    "heldout_defended": ["trials_heldout_defended.jsonl", "trials_heldout_defended_ext.jsonl"],
    "seen":             ["trials_seen.jsonl"],
    "seen_defended":    ["trials_seen_defended.jsonl"],
}


def _load(group: str) -> list[dict]:
    rows: list[dict] = []
    for fn in GROUPS[group]:
        rows.extend(load_trials(R / fn))
    return rows


def _report(tag: str, rows: list[dict]) -> None:
    err = sum(1 for r in rows if r.get("error"))
    models = sorted({r["model"] for r in rows})
    print(f"  [{tag}] {len(rows)} trials, {err} excluded (errored), models={models}")


def main() -> None:
    R.mkdir(parents=True, exist_ok=True)
    for set_name in ("heldout", "seen"):
        base = _load(set_name)
        deff = _load(f"{set_name}_defended")
        if not base:
            print(f"[{set_name}] no trials yet — skipped"); continue
        _report(f"{set_name} baseline", base)
        _report(f"{set_name} defended", deff)
        write_matrix(build_cells(base), R / f"matrix_{set_name}.csv")
        if deff:
            write_matrix(build_cells(deff), R / f"matrix_{set_name}_defended.csv")
        # build_delta reads files off disk; write merged temporaries and point it at them.
        bt, dt = R / f"_merged_{set_name}.jsonl", R / f"_merged_{set_name}_def.jsonl"
        bt.write_text("\n".join(json.dumps(r) for r in base) + "\n")
        dt.write_text("\n".join(json.dumps(r) for r in deff) + "\n")
        for by_task, suffix in ((False, ""), (True, "_bytask")):
            rows = build_delta(bt, dt, by_task=by_task)
            write_delta_md(rows, R / f"delta_{set_name}{suffix}_table.md")
            if not suffix:
                write_delta_csv(rows, R / f"delta_{set_name}.csv")
        bt.unlink(); dt.unlink()
        print(f"  -> wrote matrix_{set_name}[_defended].csv, delta_{set_name}[_bytask]_table.md")
    print("done.")


if __name__ == "__main__":
    main()
