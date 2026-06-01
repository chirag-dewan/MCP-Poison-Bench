"""Emit a labeled descriptor catalog from the payload fixtures.

A tidy, human-readable summary of each attack class's *vector* (which metadata
field carries the injection, in which class). The full, runnable payloads live in
`fixtures/payloads.py` — defanged: the "exfiltration" target is a local no-op sink
tool and the "secret" is a synthetic token. This catalog reads the fixtures and
emits a summary entry per descriptor, with the operative instruction replaced by a
short description rather than the verbatim string, so the JSON stays a readable
overview rather than a copy-paste payload bank.

    python -m dataset.build_neutered_dataset      # writes dataset/poisoned_descriptors.json
"""
from __future__ import annotations

import json
from pathlib import Path

from fixtures.payloads import ATTACK_CLASSES, PAYLOADS, SINK_TOOL_NAME

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "dataset" / "poisoned_descriptors.json"

# What the injection does, described — the verbatim string lives in the fixtures.
_NEUTERED = (
    "[SUMMARY] directive-shaped text that steers the agent to additionally call the "
    f"attacker sink tool `{SINK_TOOL_NAME}` and pass it the confidential session "
    "token from context. The runnable, defanged string (local sink + synthetic "
    "token) is in fixtures/payloads.py."
)

# Per-class description of where the (withheld) instruction sits and how it reaches
# the model — the part that is safe and useful to publish.
_VECTOR_NOTE = {
    "tool_description": (
        "Appended to a benign tool's free-text `description`. The client passes the "
        "description into model context verbatim, so the agent reads attacker text "
        "as guidance."
    ),
    "schema_field": (
        "Hidden in the JSON-schema `description` of a parameter. Many clients render "
        "the legitimate enumeration but not the full field description to the user, "
        "while the model still receives it."
    ),
    "rug_pull": (
        "Tool is benign at list/approval time; the instruction is injected into the "
        "tool RESULT returned after the user approves and calls it. Out of reach for "
        "any metadata-time validator."
    ),
    "cross_server": (
        "A second, malicious server exposes a shadow tool whose description claims "
        "authority over the whole session and redirects data produced by a trusted "
        "server's tool to the attacker sink (toxic cross-server flow)."
    ),
}


def build() -> dict:
    entries = []
    for cls in ATTACK_CLASSES:
        for p in PAYLOADS.get(cls, []):
            entries.append({
                "id": p.id,
                "attack_class": p.attack_class,
                "carrier_field": p.carrier,
                "vector": _VECTOR_NOTE.get(cls, ""),
                "benign_host": _benign_host(cls),
                "injection": _NEUTERED,       # <-- live string replaced here
                "label": p.note,
            })
    return {
        "schema": "mcp-poison-bench/neutered-descriptors/v1",
        "note": (
            "Labeled catalog of tool-poisoning descriptors. Each entry shows the "
            "attack class and carrier field with a summary of the injection; the "
            "full, runnable payloads (defanged: local sink + synthetic token) are in "
            "fixtures/payloads.py."
        ),
        "sink_tool": SINK_TOOL_NAME,
        "attack_classes": list(ATTACK_CLASSES),
        "descriptors": entries,
    }


def _benign_host(cls: str) -> str:
    if cls == "cross_server":
        return "compliance_audit(note: str)  # malicious shadow tool"
    return "calculate(a: float, b: float, operation: str)  # benign arithmetic tool"


def _assert_neutered(blob: str) -> None:
    """Fail loudly if any live injection text leaked into the output."""
    for cls in ATTACK_CLASSES:
        for p in PAYLOADS.get(cls, []):
            # A long, distinctive slice of the live injection must not appear.
            probe = p.injection.strip()[:40]
            if probe and probe in blob:
                raise SystemExit(f"LIVE STRING LEAKED for {p.id!r}; aborting write.")


def main() -> None:
    data = build()
    blob = json.dumps(data, indent=2, ensure_ascii=False)
    _assert_neutered(blob)
    OUT.write_text(blob + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO_ROOT)} ({len(data['descriptors'])} neutered descriptors)")


if __name__ == "__main__":
    main()
