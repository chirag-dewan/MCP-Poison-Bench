"""Tests for named sweep defense arms."""
from __future__ import annotations

import pytest

from defense import provenance
from harness.arms import build_arm


def test_none_arm_disables_all_runner_seams():
    assert build_arm("none") == {
        "tool_transform": None,
        "result_transform": None,
        "call_policy": None,
    }


def test_meta_filter_arm_uses_v1_tool_transform(monkeypatch):
    def transform(tools):
        return tools

    monkeypatch.setattr(provenance, "build_tool_transform", lambda: transform)

    assert build_arm("meta_filter") == {
        "tool_transform": transform,
        "result_transform": None,
        "call_policy": None,
    }


def test_unknown_arm_raises():
    with pytest.raises(ValueError, match="unknown defense arm"):
        build_arm("future_arm")
