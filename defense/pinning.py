"""Per-trial metadata pinning and cross-server shadowing detection."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

from harness.runner import ToolTransform


FindingKind = Literal["drift", "shadowing"]
FindingAction = Literal["dropped", "alerted"]


@dataclass(frozen=True)
class PinningFinding:
    """One metadata change or cross-server name collision."""

    tool_name: str
    server_path: str
    kind: FindingKind
    action: FindingAction


@dataclass
class PinStore:
    """Metadata approved on first sight during one trial."""

    approved: dict[str, tuple[str, str]] = field(default_factory=dict)


def fingerprint(tool: dict[str, Any]) -> str:
    """Return a SHA-256 digest of the tool's canonical model-facing metadata."""
    pinned = {
        "name": tool.get("name"),
        "description": tool.get("description"),
        "input_schema": tool.get("input_schema"),
    }
    canonical = json.dumps(
        pinned,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_pinning_transform(
    store: PinStore,
    *,
    on_drift: Literal["block", "alert"] = "block",
    on_findings: Callable[[list[PinningFinding]], None] | None = None,
) -> ToolTransform:
    """Pin first-seen metadata and reject drift or later server registrations.

    The runner adds ``server_path`` to each ordered registration before invoking
    this transform, then removes it before the surviving tools reach a model.
    The approved digest is never advanced after a change, including in alert
    mode: approval remains anchored to the first metadata observed in the trial.
    """
    if on_drift not in {"block", "alert"}:
        raise ValueError("on_drift must be 'block' or 'alert'")

    def transform(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings: list[PinningFinding] = []
        surviving: list[dict[str, Any]] = []

        for tool in tools:
            name = tool.get("name")
            server_path = tool.get("server_path")
            if not isinstance(name, str) or not isinstance(server_path, str):
                raise ValueError(
                    "pinning transform requires string name and server_path"
                )

            observed = fingerprint(tool)
            approved = store.approved.get(name)
            if approved is None:
                store.approved[name] = (server_path, observed)
                surviving.append(tool)
                continue

            approved_server, approved_fingerprint = approved
            if server_path != approved_server:
                findings.append(PinningFinding(
                    tool_name=name,
                    server_path=server_path,
                    kind="shadowing",
                    action="dropped",
                ))
                continue

            if observed != approved_fingerprint:
                action: FindingAction = (
                    "dropped" if on_drift == "block" else "alerted"
                )
                findings.append(PinningFinding(
                    tool_name=name,
                    server_path=server_path,
                    kind="drift",
                    action=action,
                ))
                if on_drift == "block":
                    continue

            surviving.append(tool)

        if on_findings is not None:
            on_findings(findings)
        return surviving

    return transform
