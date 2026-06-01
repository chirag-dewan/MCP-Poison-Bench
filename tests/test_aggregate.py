"""Tests for the aggregator — Wilson CIs and cell grouping.

Wilson interval reference values are checked against known closed-form results so a
regression in the CI math is caught without a live run.
"""
from __future__ import annotations

import math

import pytest

from scorer.aggregate import Cell, build_cells, wilson_ci, write_matrix


def test_wilson_zero_successes_is_nondegenerate():
    lo, hi = wilson_ci(0, 5)
    assert lo == pytest.approx(0.0, abs=1e-9)
    assert hi > 0.0  # Wald would give hi == 0 here; Wilson must not
    assert hi < 1.0


def test_wilson_all_successes_is_nondegenerate():
    lo, hi = wilson_ci(5, 5)
    assert hi == pytest.approx(1.0, abs=1e-9)
    assert lo < 1.0  # Wald would give lo == 1 here; Wilson must not
    assert lo > 0.0


def test_wilson_known_value_half():
    # n=10, x=5, z=1.96 -> Wilson center 0.5, half-width ~0.2365 (textbook value).
    lo, hi = wilson_ci(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-3)
    assert hi == pytest.approx(0.7634, abs=1e-3)


def test_wilson_known_value_skewed():
    # n=10, x=9 -> Wilson interval ~[0.5958, 0.9821] (textbook value).
    lo, hi = wilson_ci(9, 10)
    assert lo == pytest.approx(0.5958, abs=1e-3)
    assert hi == pytest.approx(0.9821, abs=1e-3)


def test_wilson_stays_in_unit_interval():
    for x in range(0, 8):
        lo, hi = wilson_ci(x, 7)
        assert 0.0 <= lo <= hi <= 1.0


def test_wilson_empty_cell_is_fully_uncertain():
    assert wilson_ci(0, 0) == (0.0, 1.0)


def test_build_cells_groups_and_counts():
    trials = [
        {"model": "m1", "attack_class": "c1", "asr_fired": True, "utility_ok": True},
        {"model": "m1", "attack_class": "c1", "asr_fired": False, "utility_ok": True},
        {"model": "m1", "attack_class": "c2", "asr_fired": True, "utility_ok": False,
         "canary_exfiltrated": True},
    ]
    cells = {(c.model, c.attack_class): c for c in build_cells(trials)}
    c1 = cells[("m1", "c1")]
    assert c1.n == 2 and c1.asr_successes == 1 and c1.util_successes == 2
    assert c1.asr_mean == pytest.approx(0.5)
    c2 = cells[("m1", "c2")]
    assert c2.n == 1 and c2.asr_successes == 1 and c2.canary_successes == 1


def test_write_matrix_roundtrip(tmp_path):
    cells = build_cells([
        {"model": "m1", "attack_class": "c1", "asr_fired": True, "utility_ok": True},
        {"model": "m1", "attack_class": "c1", "asr_fired": False, "utility_ok": False},
    ])
    out = write_matrix(cells, tmp_path / "matrix.csv")
    text = out.read_text(encoding="utf-8")
    lines = text.strip().splitlines()
    assert lines[0].startswith("model,attack_class,n,asr_mean")
    assert "m1,c1,2,0.5000" in lines[1]
