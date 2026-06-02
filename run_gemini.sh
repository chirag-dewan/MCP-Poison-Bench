#!/usr/bin/env bash
set -euo pipefail; cd "$(dirname "$0")"
PYTHON="${PYTHON:-.venv/bin/python}"
if [[ -f .env ]]; then set -a; source .env; set +a; fi
R=results; mkdir -p "$R"
run_sweep () { local label="$1" out="$2"; shift 2
  if [[ -s "$out" ]]; then echo "==> $label SKIP ($out)"; return; fi
  echo "==> $label"; "$PYTHON" -m harness.sweep "$@" --out "$out"; }
run_sweep "[1/4] gemini HELD-OUT baseline" "$R/trials_heldout_gemini.jsonl"          --config config/bench_heldout_gemini.json
run_sweep "[2/4] gemini HELD-OUT defended" "$R/trials_heldout_defended_gemini.jsonl" --config config/bench_heldout_gemini.json --defense
run_sweep "[3/4] gemini SEEN baseline"     "$R/trials_seen_gemini.jsonl"             --config config/bench_seen_gemini.json
run_sweep "[4/4] gemini SEEN defended"     "$R/trials_seen_defended_gemini.jsonl"    --config config/bench_seen_gemini.json --defense
echo "==> run_gemini complete"
