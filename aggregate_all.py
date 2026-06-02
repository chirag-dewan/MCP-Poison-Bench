"""Combined aggregator: merge Anthropic + cross-vendor trial files into the final
labeled matrices (held-out vs seen, baseline vs defended) across ALL models.

Held-out and seen are reported SEPARATELY and labeled — the held-out matrix is the
de-circularized headline (payloads that trip zero defense rules); the seen matrix
is the near-circular contrast. Errored trials are excluded (never scored as
asr_fired=False) and the count is reported. Run after run_decirc.sh and
run_xvendor.sh finish:  .venv/bin/python aggregate_all.py
"""
from __future__ import annotations

from pathlib import Path

from scorer.aggregate import (
    build_cells, write_matrix, build_delta, write_delta_csv, write_delta_md, load_trials,
)

R = Path(__file__).resolve().parent / "results"

# Each logical group = Anthropic file + cross-vendor file (either may be absent).
GROUPS = {
    "heldout":          ["trials_heldout.jsonl", "trials_heldout_xvendor.jsonl"],
    "heldout_defended": ["trials_heldout_defended.jsonl", "trials_heldout_defended_xvendor.jsonl"],
    "seen":             ["trials_seen.jsonl", "trials_seen_xvendor.jsonl"],
    "seen_defended":    ["trials_seen_defended.jsonl", "trials_seen_defended_xvendor.jsonl"],
}


def _load(group: str) -> list[dict]:
    rows: list[dict] = []
    for fn in GROUPS[group]:
        rows.extend(load_trials(R / fn))
    return rows


def _report(tag: str, rows: list[dict]) -> None:
    err = sum(1 for r in rows if r.get("error"))
    models = sorted({r["model"] for r in rows})
    print(f"  [{tag}] {len(rows)} trials, {err} excluded (errored), models={models}")


def main() -> None:
    for set_name in ("heldout", "seen"):
        base = _load(set_name)
        deff = _load(f"{set_name}_defended")
        if not base:
            print(f"[{set_name}] no trials yet — skipped"); continue
        _report(f"{set_name} baseline", base)
        _report(f"{set_name} defended", deff)
        write_matrix(build_cells(base), R / f"matrix_{set_name}.csv")
        if deff:
            write_matrix(build_cells(deff), R / f"matrix_{set_name}_defended.csv")
        # deltas need both files written to the same place build_delta reads, so
        # write merged temporaries and point build_delta at them.
        bt, dt = R / f"_merged_{set_name}.jsonl", R / f"_merged_{set_name}_def.jsonl"
        bt.write_text("\n".join(__import__("json").dumps(r) for r in base) + "\n")
        dt.write_text("\n".join(__import__("json").dumps(r) for r in deff) + "\n")
        for by_task, suffix in ((False, ""), (True, "_bytask")):
            rows = build_delta(bt, dt, by_task=by_task)
            write_delta_md(rows, R / f"delta_{set_name}{suffix}_table.md")
            if not suffix:
                write_delta_csv(rows, R / f"delta_{set_name}.csv")
        bt.unlink(); dt.unlink()
        print(f"  -> wrote matrix_{set_name}[_defended].csv, delta_{set_name}[_bytask]_table.md")
    print("done.")


if __name__ == "__main__":
    main()
