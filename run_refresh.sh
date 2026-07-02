#!/usr/bin/env bash
# 2026-07 ROSTER REFRESH driver. Re-runs the de-circularized benchmark on the
# refreshed frontier+budget lineup (claude-opus-4-8, gpt-5.5 / gpt-5.4-nano,
# deepseek-v4-flash) with EVERYTHING else held fixed — same attack taxonomy,
# prompts, scoring, defense, held-out split, seeds, and Wilson CIs. All output
# lands under results/2026-07-refresh/ (trials + per-trial traces), so the
# original run is never touched: the comparison between the two runs is a finding.
#
#   ./run_refresh.sh              # full refresh (held-out core+ext + seen, base+def)
#   ./run_refresh.sh --dry-run    # ~10 trials/model, parse-validation + cost projection
#
# Resumable: a sweep whose output file already exists is skipped (delete to force).
set -euo pipefail
cd "$(dirname "$0")"
PYTHON="${PYTHON:-.venv/bin/python}"

if [[ -f .env ]]; then set -a; source .env; set +a; fi

R=results/2026-07-refresh
mkdir -p "$R"

CORE=config/refresh/bench_heldout_refresh.json
EXT=config/refresh/bench_heldout_ext_refresh.json
SEEN=config/refresh/bench_seen_refresh.json

# ---- dry-run: one small baseline sweep over all 4 models, then exit ----
if [[ "${1:-}" == "--dry-run" ]]; then
  echo "==> DRY-RUN: ~10 trials/model over the held-out core config (all classes)"
  "$PYTHON" -m harness.sweep --config "$CORE" \
    --out "$R/dryrun/trials_dryrun.jsonl" --trace-dir "$R/dryrun" --dry-run
  echo "==> dry-run complete. Inspect the report above before launching the full run."
  exit 0
fi

run_sweep () {  # $1=label  $2=outfile  $3=config  $4(optional)=--defense
  local label="$1" out="$2" config="$3" defense="${4:-}"
  if [[ -s "$out" ]]; then echo "==> $label  SKIP (exists: $out, $(wc -l < "$out") lines)"; return; fi
  echo "==> $label"
  "$PYTHON" -m harness.sweep --config "$config" --out "$out" --trace-dir "$R" $defense
}

run_sweep "[1/6] HELD-OUT core baseline"  "$R/trials_heldout.jsonl"              "$CORE"
run_sweep "[2/6] HELD-OUT core defended"  "$R/trials_heldout_defended.jsonl"     "$CORE" --defense
run_sweep "[3/6] HELD-OUT ext  baseline"  "$R/trials_heldout_ext.jsonl"          "$EXT"
run_sweep "[4/6] HELD-OUT ext  defended"  "$R/trials_heldout_defended_ext.jsonl" "$EXT"  --defense
run_sweep "[5/6] SEEN baseline"           "$R/trials_seen.jsonl"                 "$SEEN"
run_sweep "[6/6] SEEN defended"           "$R/trials_seen_defended.jsonl"        "$SEEN"  --defense

echo "==> aggregating refresh matrices + deltas (Wilson CIs)"
"$PYTHON" aggregate_refresh.py
echo "==> run_refresh complete. Matrices + deltas under $R/"
