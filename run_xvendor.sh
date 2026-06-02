#!/usr/bin/env bash
# Cross-vendor extension: run the held-out + seen grids on non-Anthropic models
# (gpt-4o-mini, deepseek-chat) into separate *_xvendor trial files, so the
# resumable Anthropic run is untouched. aggregate_all.py merges everything.
set -euo pipefail
cd "$(dirname "$0")"
PYTHON="${PYTHON:-.venv/bin/python}"
if [[ -f .env ]]; then set -a; source .env; set +a; fi
R=results; mkdir -p "$R"

run_sweep () {  # $1=label $2=outfile $3...=args
  local label="$1" out="$2"; shift 2
  if [[ -s "$out" ]]; then echo "==> $label  SKIP (exists: $out, $(wc -l < "$out") lines)"; return; fi
  echo "==> $label"; "$PYTHON" -m harness.sweep "$@" --out "$out"
}

run_sweep "[1/4] XVENDOR HELD-OUT baseline"  "$R/trials_heldout_xvendor.jsonl"          --config config/bench_heldout_xvendor.json
run_sweep "[2/4] XVENDOR HELD-OUT defended"  "$R/trials_heldout_defended_xvendor.jsonl" --config config/bench_heldout_xvendor.json --defense
run_sweep "[3/4] XVENDOR SEEN baseline"      "$R/trials_seen_xvendor.jsonl"             --config config/bench_seen_xvendor.json
run_sweep "[4/4] XVENDOR SEEN defended"      "$R/trials_seen_defended_xvendor.jsonl"    --config config/bench_seen_xvendor.json --defense
echo "==> run_xvendor complete"
