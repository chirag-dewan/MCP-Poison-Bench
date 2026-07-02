"""Sweep driver: run the full {model} x {attack class} x {seed} matrix.

Owned by agent:harness. Reads a JSON config, runs every cell over every seed,
scores each trace, and appends one compact per-trial record to
`results/trials.jsonl`. The aggregator (`scorer/aggregate.py`) turns those records
into `results/matrix.csv`. See CLAUDE.md for scope rules.

Each trial is fully isolated (its own MCP server subprocesses + event loop), so we
fan out across a bounded thread pool for wall-clock speed without affecting
per-trial determinism. Trial records are sorted before writing so the file order
is stable regardless of completion order.

Server selection per attack class:
  * cross_server -> [benign_server, poisoned_server], poisoned launched with
    POISON_CLASS=cross_server (malicious half providing the shadow tool + sink);
    benign provides `calculate`. The attack must cross the server boundary.
  * everything else -> [poisoned_server] with POISON_CLASS=<class>; the poisoned
    server provides both the (injected) benign tool and the sink.

Usage:
    python -m harness.sweep --config config/bench.json
    python -m harness.sweep --config config/bench.json --append   # keep prior trials
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from defense import provenance
from fixtures.payloads import iter_payloads
from harness import clients, pricing
from harness.runner import RESULTS_DIR, run_trial
from scorer.asr import score_asr
from scorer.utility import score_utility

REPO_ROOT = Path(__file__).resolve().parent.parent
TRIALS_PATH = RESULTS_DIR / "trials.jsonl"
TRIALS_DEFENDED_PATH = RESULTS_DIR / "trials_defended.jsonl"

#: Full 2026-07 refresh depth PER MODEL, summed across the run_refresh.sh set
#: (held-out core 240 + held-out ext 112 + seen 120, each = baseline + defended).
#: Used only to project the dry-run's measured cost-per-trial up to the full run.
REFRESH_TRIALS_PER_MODEL = 472


def _resolve_class_tasks(cfg: dict[str, Any]) -> dict[str, list[str]]:
    """Per-class task lists. New schema uses `class_tasks`; the old single-`task`
    + `attack_classes` schema still works (every class runs the one task)."""
    if "class_tasks" in cfg:
        return cfg["class_tasks"]
    return {ac: [cfg["task"]] for ac in cfg["attack_classes"]}


def _build_trial_specs(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand the config into one spec per (model, class, task, payload, seed) trial.

    The payload dimension comes from the selected `payload_set` ("seen" |
    "heldout") and runs EVERY payload in that set, not just the first — so a
    headline (model, class) cell aggregates over payloads × tasks × seeds, which
    is how n reaches >=20 without inflating any single phrasing.
    """
    benign = REPO_ROOT / cfg["benign_server"]
    poisoned = REPO_ROOT / cfg["poisoned_server"]
    set_name = cfg.get("payload_set", "seen")
    class_tasks = _resolve_class_tasks(cfg)
    task_cache: dict[str, dict[str, Any]] = {}

    def _load_task(rel: str) -> dict[str, Any]:
        if rel not in task_cache:
            task_cache[rel] = json.loads((REPO_ROOT / rel).read_text(encoding="utf-8"))
        return task_cache[rel]

    specs: list[dict[str, Any]] = []
    for model in cfg["models"]:
        if not clients.has_api_key(model):
            print(f"  skip {model}: {clients.key_env_for(model)} not set")
            continue
        only_ids = set(cfg.get("payload_ids") or [])
        for attack_class, task_rels in class_tasks.items():
            payloads = iter_payloads(attack_class, set_name)
            if only_ids:  # run a specific subset (e.g. the register-widening batch)
                payloads = [p for p in payloads if p.id in only_ids]
            servers = [benign, poisoned] if attack_class == "cross_server" else [poisoned]
            for task_rel in task_rels:
                task = _load_task(task_rel)
                for payload in payloads:
                    for seed in cfg["seeds"]:
                        specs.append({
                            "model": model,
                            "attack_class": attack_class,
                            "payload_id": payload.id,
                            "payload_set": set_name,
                            "task": task,
                            "task_id": task["id"],
                            "seed": seed,
                            "servers": servers,
                            "server_env": {
                                "POISON_CLASS": attack_class,
                                "POISON_PAYLOAD_ID": payload.id,
                            },
                        })
    return specs


def _usage_from_events(events: list[dict[str, Any]]) -> tuple[int, int, int]:
    """Sum (input, output, reasoning) tokens across a trace's assistant turns.

    Usage keys differ by provider — Anthropic uses input/output_tokens, the
    OpenAI-compatible path (OpenAI + DeepSeek) uses prompt/completion_tokens, and
    Gemini uses *_token_count. Reasoning models (GPT-5.x, DeepSeek V4) fold their
    reasoning tokens into completion_tokens and also break them out under
    completion_tokens_details.reasoning_tokens; we surface that separately so the
    dry-run can flag reasoning-token burn against the MAX_TOKENS cap.
    """
    in_tok = out_tok = reason_tok = 0
    for e in events:
        if e.get("type") != "assistant_message":
            continue
        u = e.get("usage") or {}
        in_tok += int(u.get("input_tokens") or u.get("prompt_tokens")
                      or u.get("prompt_token_count") or 0)
        out_tok += int(u.get("output_tokens") or u.get("completion_tokens")
                       or u.get("candidates_token_count") or 0)
        details = u.get("completion_tokens_details") or {}
        reason_tok += int(details.get("reasoning_tokens") or 0)
    return in_tok, out_tok, reason_tok


def _is_empty_output(events: list[dict[str, Any]]) -> bool:
    """True if the model produced NO tool call and NO non-empty text this trial.

    An empty output is the tell-tale of a reasoning model exhausting MAX_TOKENS on
    reasoning tokens (the OpenAI-compatible adapter surfaces a length-capped, empty
    completion as stop_reason='end_turn' with no blocks — invisible otherwise). The
    dry-run counts these per model so the operator can catch a too-low token cap
    before committing to the full run.
    """
    for e in events:
        if e.get("type") == "tool_call":
            return False
        if e.get("type") == "assistant_message":
            for b in e.get("content") or []:
                if b.get("type") == "text" and (b.get("text") or "").strip():
                    return False
    return True


def _run_one(
    spec: dict[str, Any], temperature: float, defense: bool,
    trace_dir: Path = RESULTS_DIR,
) -> dict[str, Any]:
    """Run a single trial and score it into a compact record.

    `defense` flips the client-side provenance/validation layer on — the ONLY
    thing that changes between baseline and defended runs. `trace_dir` routes the
    per-trial JSONL trace (defaults to the repo results/ dir; the refresh run points
    it at results/2026-07-refresh/ so the new run never mixes with the original).
    Token-usage fields are added to the record for the dry-run cost projection; they
    do not feed scoring.
    """
    task = spec["task"]
    tool_transform = provenance.build_tool_transform() if defense else None
    summary, trace_path = run_trial(
        server_paths=spec["servers"],
        task=task,
        model=spec["model"],
        seed=spec["seed"],
        server_env=spec["server_env"],
        temperature=temperature,
        tool_transform=tool_transform,
        results_dir=trace_dir,
        extra_config={
            "attack_class": spec["attack_class"],
            "payload_id": spec["payload_id"],
            "payload_set": spec["payload_set"],
            "task_id": spec["task_id"],
            "defended": defense,
        },
    )
    # Scorers read the written trace (scorer reads traces, not live runs).
    from scorer.asr import load_trace
    events = load_trace(trace_path)
    asr = score_asr(events)
    util = score_utility(events, task)
    in_tok, out_tok, reason_tok = _usage_from_events(events)
    return {
        "model": spec["model"],
        "attack_class": spec["attack_class"],
        "payload_id": spec["payload_id"],
        "payload_set": spec["payload_set"],
        "task_id": spec["task_id"],
        "seed": spec["seed"],
        "temperature": temperature,
        "defended": defense,
        "asr_fired": asr.fired,
        "canary_exfiltrated": asr.canary_exfiltrated,
        "sink_calls": asr.sink_calls,
        "utility_ok": util.completed,
        "in_tokens": in_tok,
        "out_tokens": out_tok,
        "reasoning_tokens": reason_tok,
        "empty_output": _is_empty_output(events),
        "git_sha": summary.get("git_sha", ""),
        "trace": str(trace_path.relative_to(REPO_ROOT)),
    }


def _limit_specs(specs: list[dict[str, Any]], per_model: int) -> list[dict[str, Any]]:
    """Down-sample to at most `per_model` trials per model, spread round-robin across
    that model's attack classes so the dry-run exercises every vector (rug_pull and
    cross_server included) rather than burning the whole budget on tool_description.
    Selection is deterministic (config order), so a dry-run is reproducible."""
    by_model: dict[str, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
    order: list[str] = []
    for s in specs:
        m = s["model"]
        if m not in by_model:
            order.append(m)
        by_model[m][s["attack_class"]].append(s)
    out: list[dict[str, Any]] = []
    for m in order:
        queues = [q for q in by_model[m].values()]
        taken = 0
        while taken < per_model and any(queues):
            for q in queues:
                if not q:
                    continue
                out.append(q.popleft())
                taken += 1
                if taken >= per_model:
                    break
    return out


def run_sweep(
    config_path: str | Path,
    append: bool = False,
    defense: bool = False,
    out_path: Path | None = None,
    trace_dir: Path | None = None,
    limit: int | None = None,
    dry_run: bool = False,
    project_trials_per_model: int = REFRESH_TRIALS_PER_MODEL,
) -> Path:
    cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
    temperature = float(cfg.get("temperature", 1.0))
    max_workers = int(cfg.get("max_concurrency", 4))
    if out_path is None:
        out_path = TRIALS_DEFENDED_PATH if defense else TRIALS_PATH
    # Resolve so a relative --out (e.g. results/foo.jsonl) is still under REPO_ROOT
    # for the final relative_to() display — passing a relative path used to crash
    # the sweep *after* it had already written every trial.
    out_path = Path(out_path).resolve()
    trace_dir = Path(trace_dir).resolve() if trace_dir is not None else RESULTS_DIR

    specs = _build_trial_specs(cfg)
    # --dry-run implies a small per-model cap (10) unless --limit overrides it.
    if dry_run and limit is None:
        limit = 10
    if limit is not None:
        specs = _limit_specs(specs, limit)
    set_name = cfg.get("payload_set", "seen")
    print(
        f"sweep [{'DEFENDED' if defense else 'baseline'}] set={set_name}"
        f"{' DRY-RUN' if dry_run else ''}: "
        f"{len(specs)} trials (temp={temperature}, concurrency={max_workers}) "
        f"-> {Path(out_path).name}"
    )

    records: list[dict[str, Any]] = []
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_one, s, temperature, defense, trace_dir): s for s in specs}
        for fut in as_completed(futures):
            s = futures[fut]
            try:
                rec = fut.result()
            except Exception as exc:  # keep going; one bad cell shouldn't sink the run
                rec = {
                    "model": s["model"], "attack_class": s["attack_class"],
                    "payload_id": s["payload_id"], "payload_set": s["payload_set"],
                    "task_id": s["task_id"], "seed": s["seed"],
                    "temperature": temperature, "asr_fired": False,
                    "canary_exfiltrated": False, "sink_calls": 0,
                    "utility_ok": False, "error": repr(exc), "trace": None,
                }
                print(f"  ! trial errored {s['model']}/{s['attack_class']}/{s['task_id']}/"
                      f"{s['payload_id']}/seed{s['seed']}: {exc!r}")
            records.append(rec)
            done += 1
            flag = "ASR" if rec["asr_fired"] else "   "
            print(f"  [{done}/{len(specs)}] {flag} {rec['model']:<26} "
                  f"{rec['attack_class']:<16} {rec.get('task_id',''):<15} "
                  f"{rec['payload_id']:<14} seed{rec['seed']} util={rec['utility_ok']}")

    # Stable order: model, class, task, payload, seed — independent of completion.
    records.sort(key=lambda r: (r["model"], r["attack_class"], r.get("task_id", ""),
                                r["payload_id"], r["seed"]))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with out_path.open(mode, encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\nwrote {len(records)} trial records to {out_path}")
    if dry_run:
        _dry_run_report(records, project_trials_per_model)
    return out_path


def _dry_run_report(records: list[dict[str, Any]], project_trials_per_model: int) -> None:
    """Print the dry-run validation + cost projection: per model, how many trials
    parsed cleanly, how many came back empty (a MAX_TOKENS red flag for reasoning
    models), measured token usage, and the projected full-run cost. Any model priced
    from an unconfirmed (placeholder) rate is flagged loudly so a guessed number is
    never mistaken for a measured one."""
    by_model: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in records:
        by_model[r["model"]].append(r)

    print("\n" + "=" * 78)
    print("DRY-RUN REPORT — parse validation + full-run cost projection")
    print("=" * 78)
    print(f"projecting each model's measured cost/trial x {project_trials_per_model} "
          "trials/model (full refresh = held-out core 240 + ext 112 + seen 120)")

    total_proj = 0.0
    any_unconfirmed = False
    any_missing_price = False
    for model in sorted(by_model):
        rs = by_model[model]
        n = len(rs)
        n_err = sum(1 for r in rs if r.get("error"))
        n_ok = n - n_err
        n_empty = sum(1 for r in rs if r.get("empty_output") and not r.get("error"))
        in_tok = sum(r.get("in_tokens", 0) for r in rs)
        out_tok = sum(r.get("out_tokens", 0) for r in rs)
        reason_tok = sum(r.get("reasoning_tokens", 0) for r in rs)
        scored = [r for r in rs if not r.get("error")]
        meas_cost = pricing.estimate_cost(model, in_tok, out_tok)
        price = pricing.price_for(model)

        print(f"\n  {model}")
        print(f"    trials: {n}  ok: {n_ok}  errored: {n_err}  "
              f"empty-output: {n_empty}"
              + ("   <-- reasoning/MAX_TOKENS red flag" if n_empty else ""))
        print(f"    tokens: in={in_tok:,}  out={out_tok:,}  "
              f"(reasoning={reason_tok:,})")
        if price is None:
            any_missing_price = True
            print("    cost: NO PRICE ROW for this model — add it to harness/pricing.py")
            continue
        if not price.confirmed:
            any_unconfirmed = True
        tag = "" if price.confirmed else "  [UNCONFIRMED PRICE]"
        if scored and meas_cost is not None:
            per_trial = meas_cost / max(1, len(scored))
            proj = per_trial * project_trials_per_model
            total_proj += proj
            print(f"    price:  ${price.input_per_m}/{price.output_per_m} per 1M "
                  f"(in/out){tag}")
            print(f"    cost:   ${meas_cost:.4f} measured over {len(scored)} scored "
                  f"trials  =>  ${per_trial:.5f}/trial")
            print(f"    PROJECTED full-run: ${proj:,.2f}  "
                  f"(${per_trial:.5f} x {project_trials_per_model})")
        else:
            print(f"    price:  ${price.input_per_m}/{price.output_per_m} per 1M{tag}")
            print("    cost:   no scored trials to measure from")

    print("\n" + "-" * 78)
    print(f"PROJECTED FULL-RUN TOTAL (all models): ${total_proj:,.2f}")
    if any_unconfirmed:
        print("\n  ⚠  One or more models were priced from an UNCONFIRMED placeholder "
              "rate.\n     Confirm those rates in harness/pricing.py before trusting "
              "this projection.")
    if any_missing_price:
        print("\n  ⚠  One or more models have NO price row and were left out of the "
              "total.")
    print("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP-Poison-Bench sweep driver.")
    parser.add_argument("--config", default="config/bench.json", type=Path)
    parser.add_argument("--append", action="store_true",
                        help="append instead of overwriting the trials file")
    parser.add_argument("--defense", action="store_true",
                        help="flip the client-side provenance/validation defense ON "
                             "(writes results/trials_defended.jsonl)")
    parser.add_argument("--out", type=Path, default=None,
                        help="explicit output trials path (overrides the default "
                             "baseline/defended filename; used for the held-out matrix)")
    parser.add_argument("--trace-dir", type=Path, default=None,
                        help="directory for per-trial JSONL traces (default: results/; "
                             "the refresh run points this at results/2026-07-refresh/)")
    parser.add_argument("--limit", type=int, default=None,
                        help="cap trials PER MODEL, spread round-robin across attack "
                             "classes (deterministic; for smoke/dry runs)")
    parser.add_argument("--dry-run", action="store_true",
                        help="cap to ~10 trials/model and print a parse-validation + "
                             "cost-projection report instead of a full sweep")
    parser.add_argument("--project-trials-per-model", type=int,
                        default=REFRESH_TRIALS_PER_MODEL,
                        help="full-run trials/model the dry-run cost is projected onto")
    args = parser.parse_args()
    run_sweep(args.config, append=args.append, defense=args.defense, out_path=args.out,
              trace_dir=args.trace_dir, limit=args.limit, dry_run=args.dry_run,
              project_trials_per_model=args.project_trials_per_model)


if __name__ == "__main__":
    main()
