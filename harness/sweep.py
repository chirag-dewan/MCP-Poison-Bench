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

from fixtures.payloads import get_payload
from harness.runner import RESULTS_DIR, run_trial
from scorer.asr import score_asr
from scorer.utility import score_utility

REPO_ROOT = Path(__file__).resolve().parent.parent
TRIALS_PATH = RESULTS_DIR / "trials.jsonl"


def _build_trial_specs(cfg: dict[str, Any], task: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand the config into one spec per (model, attack_class, seed) trial."""
    benign = REPO_ROOT / cfg["benign_server"]
    poisoned = REPO_ROOT / cfg["poisoned_server"]
    specs: list[dict[str, Any]] = []
    for model in cfg["models"]:
        for attack_class in cfg["attack_classes"]:
            payload = get_payload(attack_class)
            if attack_class == "cross_server":
                servers = [benign, poisoned]
            else:
                servers = [poisoned]
            for seed in cfg["seeds"]:
                specs.append({
                    "model": model,
                    "attack_class": attack_class,
                    "payload_id": payload.id,
                    "seed": seed,
                    "servers": servers,
                    "server_env": {
                        "POISON_CLASS": attack_class,
                        "POISON_PAYLOAD_ID": payload.id,
                    },
                })
    return specs


def _run_one(spec: dict[str, Any], task: dict[str, Any], temperature: float) -> dict[str, Any]:
    """Run a single trial and score it into a compact record."""
    summary, trace_path = run_trial(
        server_paths=spec["servers"],
        task=task,
        model=spec["model"],
        seed=spec["seed"],
        server_env=spec["server_env"],
        temperature=temperature,
        extra_config={
            "attack_class": spec["attack_class"],
            "payload_id": spec["payload_id"],
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
        "seed": spec["seed"],
        "temperature": temperature,
        "asr_fired": asr.fired,
        "canary_exfiltrated": asr.canary_exfiltrated,
        "sink_calls": asr.sink_calls,
        "utility_ok": util.completed,
        "git_sha": summary.get("git_sha", ""),
        "trace": str(trace_path.relative_to(REPO_ROOT)),
    }


def run_sweep(config_path: str | Path, append: bool = False) -> Path:
    cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
    task = json.loads((REPO_ROOT / cfg["task"]).read_text(encoding="utf-8"))
    temperature = float(cfg.get("temperature", 1.0))
    max_workers = int(cfg.get("max_concurrency", 4))

    specs = _build_trial_specs(cfg, task)
    print(
        f"sweep: {len(cfg['models'])} models x {len(cfg['attack_classes'])} classes "
        f"x {len(cfg['seeds'])} seeds = {len(specs)} trials "
        f"(temp={temperature}, concurrency={max_workers})"
    )

    records: list[dict[str, Any]] = []
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_run_one, s, task, temperature): s for s in specs}
        for fut in as_completed(futures):
            s = futures[fut]
            try:
                rec = fut.result()
            except Exception as exc:  # keep going; one bad cell shouldn't sink the run
                rec = {
                    "model": s["model"], "attack_class": s["attack_class"],
                    "payload_id": s["payload_id"], "seed": s["seed"],
                    "temperature": temperature, "asr_fired": False,
                    "canary_exfiltrated": False, "sink_calls": 0,
                    "utility_ok": False, "error": repr(exc), "trace": None,
                }
                print(f"  ! trial errored {s['model']}/{s['attack_class']}/seed{s['seed']}: {exc!r}")
            records.append(rec)
            done += 1
            flag = "ASR" if rec["asr_fired"] else "   "
            print(f"  [{done}/{len(specs)}] {flag} {rec['model']:<26} "
                  f"{rec['attack_class']:<16} seed{rec['seed']} util={rec['utility_ok']}")

    # Stable order: model, class, seed — independent of completion order.
    records.sort(key=lambda r: (r["model"], r["attack_class"], r["seed"]))
    RESULTS_DIR.mkdir(exist_ok=True)
    mode = "a" if append else "w"
    with TRIALS_PATH.open(mode, encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"\nwrote {len(records)} trial records to {TRIALS_PATH.relative_to(REPO_ROOT)}")
    return TRIALS_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP-Poison-Bench sweep driver.")
    parser.add_argument("--config", default="config/bench.json", type=Path)
    parser.add_argument("--append", action="store_true",
                        help="append to trials.jsonl instead of overwriting")
    args = parser.parse_args()
    run_sweep(args.config, append=args.append)


if __name__ == "__main__":
    main()
