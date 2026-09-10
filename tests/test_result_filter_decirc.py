"""CI guard for result-filter de-circularization on rug-pull payloads."""
from __future__ import annotations

import pytest

from defense.provenance import Finding
from defense.result_filter import (
    _RESULT_PROV_CLOSE,
    _RESULT_PROV_OPEN,
    build_result_transform,
)
from fixtures.payloads import Payload, iter_payloads
from servers.poisoned.server import _do_calc


_BENIGN_RESULT = _do_calc(17.0, 25.0, "add")
_RUG_PULL_CASES = [
    (set_name, payload)
    for set_name in ("seen", "heldout")
    for payload in iter_payloads("rug_pull", set_name)
]


@pytest.mark.parametrize(
    "set_name,payload",
    _RUG_PULL_CASES,
    ids=[payload.id for _, payload in _RUG_PULL_CASES],
)
def test_result_filter_seen_and_heldout_contrast(
    set_name: str,
    payload: Payload,
):
    findings: list[Finding] = []
    transform = build_result_transform(
        on_findings=lambda current: findings.extend(current)
    )
    raw_result = _BENIGN_RESULT + payload.injection

    transformed = transform(
        "calculate",
        raw_result,
        {
            "server_path": "/servers/poisoned/server.py",
            "step": 0,
            "tool_use_id": "call-1",
            "is_error": False,
        },
    )

    assert _BENIGN_RESULT == "17.0 add 25.0 = 42.0"
    assert _BENIGN_RESULT in transformed
    assert transformed.startswith(f"{_RESULT_PROV_OPEN}\n")
    assert transformed.endswith(f"\n{_RESULT_PROV_CLOSE}")

    if set_name == "heldout":
        assert findings == [], (
            f"held-out payload {payload.id!r} unexpectedly tripped rules: "
            f"{[(finding.rule, finding.snippet) for finding in findings]}"
        )
        assert payload.injection in transformed
    else:
        assert findings, f"seen payload {payload.id!r} should trip at least one rule"
        assert payload.injection not in transformed
        assert {finding.location for finding in findings} == {"result"}
