#!/usr/bin/env bash
# De-circularization run: held-out vs seen payloads, baseline vs defended, on the
# 3 Anthropic models, over the multi-step tasks. Produces separate, labeled
# matrices. See GAPS/the held-out payload set for why this exists.
#
# Reproduce:  ./run_decirc.sh
set -euo pipefail
cd "$(dirname "$0")"
PYTHON="${PYTHON:-.venv/bin/python}"

if [[ -f .env ]]; then set -a; source .env; set +a; fi

R=results
mkdir -p "$R"

echo "==> [1/4] HELD-OUT baseline"
"$PYTHON" -m harness.sweep --config config/bench_heldout.json --out "$R/trials_heldout.jsonl"
echo "==> [2/4] HELD-OUT defended"
"$PYTHON" -m harness.sweep --config config/bench_heldout.json --defense --out "$R/trials_heldout_defended.jsonl"
echo "==> [3/4] SEEN baseline"
"$PYTHON" -m harness.sweep --config config/bench_seen.json --out "$R/trials_seen.jsonl"
echo "==> [4/4] SEEN defended"
"$PYTHON" -m harness.sweep --config config/bench_seen.json --defense --out "$R/trials_seen_defended.jsonl"

echo "==> aggregating labeled matrices + deltas"
"$PYTHON" - <<'PY'
from pathlib import Path
from scorer.aggregate import (
    build_cells, write_matrix, build_delta, write_delta_csv, write_delta_md, load_trials,
)
R = Path("results")

def do(tag, base, deff):
    bt = load_trials(R / base)
    dt = load_trials(R / deff)
    if not bt:
        print(f"  [{tag}] no baseline trials at {base} — skipped"); return
    # Report excluded (errored) trials explicitly — no silent caps.
    eb = sum(1 for t in bt if t.get("error"))
    ed = sum(1 for t in dt if t.get("error"))
    if eb or ed:
        print(f"  [{tag}] EXCLUDED errored trials: baseline {eb}/{len(bt)}, defended {ed}/{len(dt)}")
    # headline matrices (by model x class)
    write_matrix(build_cells(bt), R / f"matrix_{tag}.csv")
    if dt:
        write_matrix(build_cells(dt), R / f"matrix_{tag}_defended.csv")
    # deltas, by class and by (class,task)
    rows = build_delta(R / base, R / deff)
    write_delta_csv(rows, R / f"delta_{tag}.csv")
    write_delta_md(rows, R / f"delta_{tag}_table.md")
    rows_bt = build_delta(R / base, R / deff, by_task=True)
    write_delta_md(rows_bt, R / f"delta_{tag}_bytask_table.md")
    fired = sum(1 for r in rows if (r['asr_baseline'] or 0) > 0)
    print(f"  [{tag}] {len(bt)} base / {len(dt)} def trials; cells with ASR>0 at baseline: {fired}/{len(rows)}")

do("heldout", "trials_heldout.jsonl", "trials_heldout_defended.jsonl")
do("seen",    "trials_seen.jsonl",    "trials_seen_defended.jsonl")
print("done.")
PY
echo "==> run_decirc complete"
