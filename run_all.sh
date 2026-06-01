#!/usr/bin/env bash
# One-command reproduction of the full benchmark.
# Owned by agent:harness. See CLAUDE.md for scope rules.
#
#   1. unit tests (scorers + Wilson CI math)        — fast, no API calls
#   2. full sweep  {model} x {attack class} x {seed} — writes results/trials.jsonl
#   3. aggregate                                     — writes results/matrix.csv
#   4. real-client spot-check                        — writes results/spotcheck/
#
# Requires ANTHROPIC_API_KEY (loaded from .env if present).
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-.venv/bin/python}"
CONFIG="${CONFIG:-config/bench.json}"

if [[ -f .env ]]; then
  set -a; source .env; set +a
fi

echo "==> [1/4] unit tests"
"$PYTHON" -m pytest -q

echo "==> [2/7] baseline sweep ($CONFIG)"
"$PYTHON" -m harness.sweep --config "$CONFIG"

echo "==> [3/7] defended sweep (defense ON)"
"$PYTHON" -m harness.sweep --config "$CONFIG" --defense

echo "==> [4/7] aggregate baseline + defended matrices"
"$PYTHON" -m scorer.aggregate
"$PYTHON" -m scorer.aggregate --trials results/trials_defended.jsonl --matrix results/matrix_defended.csv

echo "==> [5/7] delta table -> results/delta.csv + delta_table.md"
"$PYTHON" -m scorer.aggregate --delta

echo "==> [6/7] adversarial self-review -> results/defense_limits.md"
"$PYTHON" -m defense.adversarial_tests --live

echo "==> [7/7] real-client spot-check"
"$PYTHON" -m harness.spotcheck --config "$CONFIG"

echo "==> done. matrices: results/matrix.csv, results/matrix_defended.csv; delta: results/delta_table.md"
