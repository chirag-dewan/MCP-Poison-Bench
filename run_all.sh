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

echo "==> [2/4] sweep ($CONFIG)"
"$PYTHON" -m harness.sweep --config "$CONFIG"

echo "==> [3/4] aggregate -> results/matrix.csv"
"$PYTHON" -m scorer.aggregate

echo "==> [4/4] real-client spot-check"
"$PYTHON" -m harness.spotcheck --config "$CONFIG"

echo "==> done. matrix: results/matrix.csv"
