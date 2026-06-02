#!/usr/bin/env bash
set -euo pipefail; cd "$(dirname "$0")"
PYTHON="${PYTHON:-.venv/bin/python}"
if [[ -f .env ]]; then set -a; source .env; set +a; fi
R=results; mkdir -p "$R"
run_sweep () { local label="$1" out="$2"; shift 2
  if [[ -s "$out" ]]; then echo "==> $label SKIP ($out)"; return; fi
  echo "==> $label"; "$PYTHON" -m harness.sweep "$@" --out "$out"; }
run_sweep "[1/2] EXT HELD-OUT baseline" "$R/trials_heldout_ext.jsonl"          --config config/bench_heldout_ext.json
run_sweep "[2/2] EXT HELD-OUT defended" "$R/trials_heldout_defended_ext.jsonl" --config config/bench_heldout_ext.json --defense
echo "==> run_ext complete"
