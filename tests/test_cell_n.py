"""Trial-count arithmetic uses the sweep's real spec expansion."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from scripts.cell_n import (
    count_cells,
    count_first_payloads_per_class,
    format_config_report,
    format_report,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _for_model(counts, model: str) -> dict[str, int]:
    return {
        attack_class: n
        for (cell_model, attack_class, objective), n in counts.items()
        if cell_model == model and objective == "exfil_sink"
    }


def test_live_heldout_register_currently_expands_to_232_trials_per_model():
    counts = count_cells(REPO_ROOT / "config" / "bench_heldout.json")

    per_class = _for_model(counts, "claude-opus-4-8")
    assert per_class == {
        "tool_description": 72,
        "schema_field": 80,
        "rug_pull": 40,
        "cross_server": 40,
    }
    assert sum(per_class.values()) == 232


def test_exact_legacy_report_also_reproduces_published_120_core():
    config = REPO_ROOT / "config" / "bench_heldout.json"
    core = count_first_payloads_per_class(config)

    assert sum(_for_model(core, "claude-opus-4-8").values()) == 120
    report = format_config_report(config)
    assert "HISTORICAL FIVE-PAYLOAD CORE (published v1)" in report
    assert "claude-opus-4-8\texfil_sink\t120" in report


def test_pinned_historical_core_reproduces_120_trials_per_model():
    counts = count_cells(
        REPO_ROOT / "config" / "refresh" / "bench_heldout_refresh.json"
    )

    for model in {
        "claude-opus-4-8",
        "gpt-5.5",
        "gpt-5.4-nano",
        "deepseek-v4-flash",
    }:
        per_class = _for_model(counts, model)
        assert per_class == {
            "tool_description": 40,
            "schema_field": 40,
            "rug_pull": 20,
            "cross_server": 20,
        }
        assert sum(per_class.values()) == 120


def test_report_contains_cells_and_per_model_totals():
    counts = Counter(
        {
            ("model-b", "rug_pull", "arg_tamper"): 40,
            ("model-a", "schema_field", "arg_tamper"): 40,
            ("model-a", "tool_description", "arg_tamper"): 40,
        }
    )

    assert format_report(counts).splitlines() == [
        "model\tattack_class\tobjective\tn",
        "model-a\tschema_field\targ_tamper\t40",
        "model-a\ttool_description\targ_tamper\t40",
        "model-b\trug_pull\targ_tamper\t40",
        "",
        "model\tobjective\ttotal_n",
        "model-a\targ_tamper\t80",
        "model-b\targ_tamper\t40",
    ]
