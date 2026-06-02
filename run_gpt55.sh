#!/usr/bin/env bash
set -euo pipefail; cd "$(dirname "$0")"
PYTHON="${PYTHON:-.venv/bin/python}"
if [[ -f .env ]]; then set -a; source .env; set +a; fi
R=results; mkdir -p "$R"
run_sweep () { local label="$1" out="$2"; shift 2
  if [[ -s "$out" ]]; then echo "==> $label SKIP ($out)"; return; fi
  echo "==> $label"; "$PYTHON" -m harness.sweep "$@" --out "$out"; }
run_sweep "[1/4] gpt55 HELD-OUT baseline" "$R/trials_heldout_gpt55.jsonl"          --config config/bench_heldout_gpt55.json
run_sweep "[2/4] gpt55 HELD-OUT defended" "$R/trials_heldout_defended_gpt55.jsonl" --config config/bench_heldout_gpt55.json --defense
run_sweep "[3/4] gpt55 SEEN baseline"     "$R/trials_seen_gpt55.jsonl"             --config config/bench_seen_gpt55.json
run_sweep "[4/4] gpt55 SEEN defended"     "$R/trials_seen_defended_gpt55.jsonl"    --config config/bench_seen_gpt55.json --defense
echo "==> run_gpt55 complete"
