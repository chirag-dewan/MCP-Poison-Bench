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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from defense import provenance
from fixtures.payloads import iter_payloads
from harness import clients
from harness.runner import RESULTS_DIR, run_trial
from scorer.asr import score_asr
from scorer.utility import score_utility

REPO_ROOT = Path(__file__).resolve().parent.parent
TRIALS_PATH = RESULTS_DIR / "trials.jsonl"
TRIALS_DEFENDED_PATH = RESULTS_DIR / "trials_defended.jsonl"


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


def _run_one(
    spec: dict[str, Any], temperature: float, defense: bool,
) -> dict[str, Any]:
    """Run a single trial and score it into a compact record.

    `defense` flips the client-side provenance/validation layer on — the ONLY
    thing that changes between baseline and defended runs.
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
        "git_sha": summary.get("git_sha", ""),
        "trace": str(trace_path.relative_to(REPO_ROOT)),
    }


def run_sweep(
    config_path: str | Path,
    append: bool = False,
    defense: bool = False,
    out_path: Path | None = None,
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

    specs = _build_trial_specs(cfg)
    set_name = cfg.get("payload_set", "seen")
    print(
        f"sweep [{'DEFENDED' if defense else 'baseline'}] set={set_name}: "
        f"{len(specs)} trials (temp={temperature}, concurrency={max_workers}) "
        f"-> {Path(out_path).name}"
    )

    records: list[dict[str, Any]] = []
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_one, s, temperature, defense): s for s in specs}
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
    RESULTS_DIR.mkdir(exist_ok=True)
    mode = "a" if append else "w"
    with out_path.open(mode, encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\nwrote {len(records)} trial records to {out_path.relative_to(REPO_ROOT)}")
    return out_path


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
    args = parser.parse_args()
    run_sweep(args.config, append=args.append, defense=args.defense, out_path=args.out)


if __name__ == "__main__":
    main()
