#!/usr/bin/env bash
# v2 ablation driver. Full runs are budget-gated; use --dry-run first.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-.venv/bin/python}"
RUN="${RUN_DIR:-results/v2-$(date +%Y-%m-%d)}"
DRY_RUN=false
ARMS_FILTER=""
SETS_FILTER="heldout,seen"
OBJECTIVES_FILTER="exfil,tamper,destructive"

ALL_ARMS=(
  none meta_filter result_filter meta_and_result_filter pinning
  policy policy_full confirm confirm_ux model_hardening
)
ALL_CONFIGS=(
  "heldout:exfil:config/v2/heldout_exfil.json"
  "heldout:tamper:config/v2/heldout_tamper.json"
  "heldout:destructive:config/v2/heldout_destructive.json"
  "seen:exfil:config/v2/seen_exfil.json"
  "seen:tamper:config/v2/seen_tamper.json"
  "seen:destructive:config/v2/seen_destructive.json"
)

usage () {
  echo "usage: ./run_v2.sh [--dry-run] [--arms a,b] [--sets heldout,seen] [--objectives exfil,tamper,destructive]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --arms|--sets|--objectives)
      if [[ $# -lt 2 ]]; then usage >&2; exit 2; fi
      case "$1" in
        --arms) ARMS_FILTER="$2" ;;
        --sets) SETS_FILTER="$2" ;;
        --objectives) OBJECTIVES_FILTER="$2" ;;
      esac
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

csv_contains () {
  case ",$1," in
    *",$2,"*) return 0 ;;
    *) return 1 ;;
  esac
}

validate_csv () {
  local label="$1" csv="$2"
  shift 2
  local value allowed found
  local old_ifs="$IFS"
  IFS=','
  for value in $csv; do
    found=false
    for allowed in "$@"; do
      if [[ "$value" == "$allowed" ]]; then found=true; break; fi
    done
    if [[ "$found" != true ]]; then
      echo "unknown $label: $value" >&2
      exit 2
    fi
  done
  IFS="$old_ifs"
}

if [[ -z "$ARMS_FILTER" ]]; then
  ARMS_FILTER="$(IFS=,; echo "${ALL_ARMS[*]}")"
fi
validate_csv "arm" "$ARMS_FILTER" "${ALL_ARMS[@]}"
validate_csv "set" "$SETS_FILTER" heldout seen
validate_csv "objective" "$OBJECTIVES_FILTER" \
  exfil exfil_sink tamper arg_tamper destructive

objective_selected () {
  local slug="$1"
  if csv_contains "$OBJECTIVES_FILTER" "$slug"; then return 0; fi
  case "$slug" in
    exfil) csv_contains "$OBJECTIVES_FILTER" exfil_sink ;;
    tamper) csv_contains "$OBJECTIVES_FILTER" arg_tamper ;;
    *) return 1 ;;
  esac
}

mkdir -p "$RUN/traces"
GIT_SHA="$(git rev-parse HEAD)"
RUN_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ROSTER="$("$PYTHON" - <<'PY'
import json
from pathlib import Path
print(", ".join(json.loads(Path("config/v2/roster.json").read_text())))
PY
)"
UNCONFIRMED_PRICES="$("$PYTHON" - <<'PY'
import json
from pathlib import Path
from harness import pricing
models = json.loads(Path("config/v2/roster.json").read_text())
print(", ".join(model for model in models if not pricing.is_confirmed(model)))
PY
)"

if [[ -s "$RUN/RUN.md" ]]; then
  {
    echo
    echo "## Resume invocation — $RUN_DATE"
    echo
    echo "- Current Git SHA: \`$GIT_SHA\`"
    echo "- Current roster: $ROSTER"
    echo "- Requested arms: $ARMS_FILTER"
    echo "- Requested sets: $SETS_FILTER"
    echo "- Requested objectives: $OBJECTIVES_FILTER"
  } >> "$RUN/RUN.md"
else
  {
    echo "# MCP-Poison-Bench v2 run"
    echo
    echo "- Started: $RUN_DATE"
    echo "- Git SHA: \`$GIT_SHA\`"
    echo "- Roster: $ROSTER"
    echo "- Arms: $ARMS_FILTER"
    echo "- Configs: config/v2/{heldout,seen}_{exfil,tamper,destructive}.json"
    echo "- Seeds: 1, 2, 3, 4"
    echo "- Payload registers: seen and heldout, grouped by objective and attack class"
    echo "- Selected sets: $SETS_FILTER"
    echo "- Selected objectives: $OBJECTIVES_FILTER"
  } > "$RUN/RUN.md"
fi

COUNT_ARGS=()
for entry in "${ALL_CONFIGS[@]}"; do
  config="${entry##*:}"
  COUNT_ARGS+=(--config "$config")
done
GRID_REPORT="$("$PYTHON" scripts/cell_n.py "${COUNT_ARGS[@]}" \
  --arm-count "${#ALL_ARMS[@]}" --grid-totals)"
FULL_TRIALS="$(printf '%s\n' "$GRID_REPORT" | awk -F '\t' '$1 == "ALL" {print $2}')"
PER_MODEL_COUNTS="$(printf '%s\n' "$GRID_REPORT" | awk -F '\t' \
  '$1 != "model" && $1 != "ALL" {printf "%s%s=%s", separator, $1, $2; separator=", "}')"
if [[ -z "$PER_MODEL_COUNTS" || -z "$FULL_TRIALS" ]]; then
  echo "failed to compute the v2 grid size" >&2
  exit 1
fi

echo "==> full-grid arithmetic (computed by scripts/cell_n.py)"
printf '%s\n' "$GRID_REPORT"
print_cost_formula () {
  echo
  "$PYTHON" - "$RUN/dryrun" <<'PY'
import json
import sys
from collections import defaultdict
from pathlib import Path

from harness.arms import ARM_NAMES
from harness import pricing
from scripts.cell_n import count_grid

roster = json.loads(Path("config/v2/roster.json").read_text(encoding="utf-8"))
configs = sorted(
    path for path in Path("config/v2").glob("*.json") if path.name != "roster.json"
)
totals = count_grid(configs, arm_count=len(ARM_NAMES))
records_by_model = defaultdict(list)
dryrun_dir = Path(sys.argv[1])
paths = sorted(dryrun_dir.glob("trials_*.jsonl")) if dryrun_dir.exists() else []
for path in paths:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            record = json.loads(line)
            records_by_model[record.get("model")].append(record)

print("Combined dry-run projection scaled to the full v2 grid:")
trusted_total = 0.0
trusted = True
for model in roster:
    n = totals[model]
    price = pricing.price_for(model)
    if price is None:
        print(f"  {model}: NO PRICE ROW ({n:,} full-run trials)")
        trusted = False
        continue
    status = "confirmed" if price.confirmed else "UNCONFIRMED"
    scored = [record for record in records_by_model[model] if not record.get("error")]
    formula = (
        f"{n:,} x ((avg input tokens / 1M x ${price.input_per_m}/M) "
        f"+ (avg output tokens / 1M x ${price.output_per_m}/M))"
    )
    if not scored:
        print(f"  {model}: {formula} [{status}; no measured samples]")
        trusted = False
        continue
    in_tokens = sum(int(record.get("in_tokens", 0) or 0) for record in scored)
    out_tokens = sum(int(record.get("out_tokens", 0) or 0) for record in scored)
    measured = pricing.estimate_cost(model, in_tokens, out_tokens)
    projected = (measured / len(scored)) * n if measured is not None else None
    print(
        f"  {model}: {formula} = ${projected:,.2f} "
        f"from {len(scored)} samples [{status}]"
    )
    trusted_total += projected
    trusted = trusted and price.confirmed
if trusted:
    print(f"TRUSTED PROJECTED FULL-RUN TOTAL: ${trusted_total:,.2f}")
else:
    print("No trusted aggregate dollar total until every roster price is confirmed.")
PY
}

run_sweep () {
  local label="$1" out="$2" config="$3" arm="$4"
  shift 4
  if [[ -s "$out" ]]; then
    echo "==> $label SKIP (exists: $out, $(wc -l < "$out") lines)"
    return
  fi
  echo "==> $label"
  "$PYTHON" -m harness.sweep \
    --config "$config" \
    --defense-arm "$arm" \
    --out "$out" \
    --trace-dir "$RUN/traces" \
    "$@"
}

if [[ "$DRY_RUN" == true ]]; then
  if ! csv_contains "$SETS_FILTER" heldout || ! objective_selected exfil; then
    echo "--dry-run requires filters that include heldout/exfil" >&2
    exit 2
  fi
  mkdir -p "$RUN/dryrun"
  for arm in "${ALL_ARMS[@]}"; do
    if ! csv_contains "$ARMS_FILTER" "$arm"; then continue; fi
    run_sweep "DRY-RUN heldout/exfil arm=$arm" \
      "$RUN/dryrun/trials_heldout_exfil_${arm}.jsonl" \
      config/v2/heldout_exfil.json "$arm" \
      --dry-run --limit 3 --limit-per-class --no-dry-run-report
  done
  print_cost_formula
else
  # A full invocation displays the formula before any potentially paid trial.
  print_cost_formula
  for entry in "${ALL_CONFIGS[@]}"; do
    set_name="${entry%%:*}"
    remainder="${entry#*:}"
    objective_slug="${remainder%%:*}"
    config="${remainder#*:}"
    if ! csv_contains "$SETS_FILTER" "$set_name"; then continue; fi
    if ! objective_selected "$objective_slug"; then continue; fi
    for arm in "${ALL_ARMS[@]}"; do
      if ! csv_contains "$ARMS_FILTER" "$arm"; then continue; fi
      out="$RUN/trials_${set_name}_${objective_slug}_${arm}.jsonl"
      run_sweep "$set_name/$objective_slug arm=$arm" "$out" "$config" "$arm"
    done
  done
fi

{
  echo
  echo "## Invocation completion — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  if [[ "$DRY_RUN" == true ]]; then
    echo "- Dry-run only; no full v2 run was launched."
    echo "- Used \`--limit 3 --limit-per-class\`: three samples per model x attack class, so every roster model and all five classes are exercised in every arm when keys are available."
    echo "- The token-cost projection extrapolates the combined heldout/exfil dry-run mean to each model's full-grid count; it is an estimate, not a measured full-run cost."
  else
    echo "- Selection filters, if any, are recorded above; each nonempty config-arm output was treated as complete for restart purposes."
  fi
  if [[ -n "$UNCONFIRMED_PRICES" ]]; then
    echo "- Unconfirmed prices in \`harness/pricing.py\`: $UNCONFIRMED_PRICES; no trusted aggregate dollar total is reported."
  else
    echo "- All roster prices are marked confirmed in \`harness/pricing.py\`."
  fi
  echo "- Computed full grid: $FULL_TRIALS trials ($PER_MODEL_COUNTS)."
} >> "$RUN/RUN.md"

echo "==> aggregating v2 artifacts"
"$PYTHON" aggregate_v2.py "$RUN"
if [[ "$DRY_RUN" == true ]]; then
  echo "==> v2 dry-run complete: $RUN"
else
  echo "==> v2 run complete: $RUN"
fi
