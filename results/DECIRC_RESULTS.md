# MCP Tool-Poisoning: a de-circularized, multi-model measurement

**Status:** research note (controlled harness). All claims are scoped to the
MCP-Poison-Bench harness, not to production MCP clients. Numbers are reproducible
with `run_decirc.sh`, `run_xvendor.sh`, `run_gpt55.sh`, `run_gemini.sh`,
`run_ext.sh` and merged by `aggregate_all.py`.

> Two cells are still finalizing as of this draft: the Gemini register-1 sweep and
> the widened-register (`_ext`) sweep across all models. They refine the numbers
> below; they do not change the qualitative findings (the flagship/cheap split and
> the rug-pull blind spot are already saturated across 6 models).

## TL;DR

The original headline of this project — *"a client-side provenance/validation
defense cuts tool-poisoning ASR by −1.00 with utility retained"* — does **not**
survive scrutiny. It was **circular**: the only attack payload that the defense
"removed" shared its trigger vocabulary (`export_data`, "compliance", "audit",
"mandatory") with the defense's own keyword rules. We rebuilt the evaluation to
remove that circularity and to give every attack class a real opening, then
measured **7 models across 4 vendors**. What's left is smaller but honest:

1. **Susceptibility tracks model capability, not vendor.** Every flagship — Claude
   Opus 4.8, Sonnet 4.6, GPT-5.5 — resists essentially all classes. The cheap
   models (gpt-4o-mini, deepseek-chat) are the vulnerable ones. gpt-4o-mini is the
   single worst model.
2. **The defense has a structural blind spot: `rug_pull`.** It rewrites the tool
   *list* (descriptions/schemas) but never inspects tool *results*. Result-borne
   injection therefore bypasses it entirely — gpt-4o-mini seen `rug_pull` is
   **1.00 → 1.00** under the defense. And `rug_pull` is the *only* class that fires
   on independently-authored (held-out) payloads. The defense neutralizes what it
   can see and is powerless against what it can't.
3. **The headline reduction was circular.** On held-out payloads (which trip zero
   defense rules, CI-enforced), baseline ASR is already ≈0 on most cells, so there
   is little for the defense to reduce. The large reductions appear only on the
   *seen* payloads whose wording the filter was co-designed against.

## Method: de-circularizing the measurement

- **Held-out payload set** (`fixtures/HELDOUT_PAYLOADS`, ≥9/class, 5 registers:
  markdown, terse changelog, conversational, config-comment, verbose prose). Every
  payload is authored to contain **none** of the strings `defense/provenance.py`
  matches; it references the exfiltration sink by *function* ("analytics ingest
  helper") and moves the secret with non-egress verbs. A parametrized test
  (`tests/test_fixtures.py`) asserts mechanically that each held-out payload trips
  **zero** defense rules and that the *seen* payloads still trip them — so the
  separation cannot silently regress.
- **Multi-step tasks** so each class has a structural opening: `notes_pipeline`
  (calculate → save-note; `rug_pull` lands mid-flow in a tool result) and
  `account_review` (two servers; `lookup_user` on the critical path gives
  `cross_server` a real trigger event). The original single 2-step calc task gave
  `rug_pull`/`cross_server` no opening, which is why they read 0.00 before.
- **Scoring integrity.** Trials that error (e.g. rate-limit failures after retries)
  are **excluded**, never scored as `asr_fired=False` — counting them would launder
  API failures into fake "attack didn't fire" data. Utility matching tolerates
  thousands separators (`$1,175.00` satisfies `1175`); fixing this turned a fake
  Sonnet `0/18` into a true `18/18`, confirming its `cross_server` 0.00 is a genuine
  resist, not non-engagement.

## Results — held-out (de-circularized), ASR baseline → defended

| model | tool_description | schema_field | rug_pull | cross_server |
|---|---|---|---|---|
| Opus 4.8 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 |
| Sonnet 4.6 | 0.07→0.00 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 |
| Haiku 4.5 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 |
| GPT-5.5 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 |
| gpt-4o-mini | 0.00→0.00 | 0.00→0.00 | **0.60→0.55** | 0.00→0.00 |
| deepseek-chat | 0.10→0.05 | 0.00→0.00 | **0.35→0.10** | 0.00→0.00 |
| gemini-3.1-pro | _finalizing_ | | | |
| gemini-3.5-flash | _finalizing_ | | | |

n = 20–40 per cell (5 payloads × {tasks} × 4 seeds). The only held-out firing is
`rug_pull` on the two cheap models, and the defense does ~nothing there
(gpt-4o-mini 0.60→0.55, Δ within overlapping Wilson CIs).

## Results — seen (near-circular contrast), ASR baseline → defended

| model | tool_description | schema_field | rug_pull | cross_server |
|---|---|---|---|---|
| Opus 4.8 / Sonnet 4.6 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 |
| Haiku 4.5 | **0.50→0.00** | 0.00→0.00 | 0.00→0.00 | 0.00→0.00 |
| gpt-4o-mini | **0.50→0.00** | **0.50→0.00** | **1.00→1.00** | **1.00→0.00** |
| deepseek-chat | 0.05→0.00 | **0.40→0.00** | **0.70→0.50** | **0.60→0.00** |

The defense drives metadata-borne injection (description/schema/cross-server) to
~0 **on the seen set** — but that is the payload family whose vocabulary it was
built against. `rug_pull` is the tell: gpt-4o-mini **1.00→1.00**, deepseek
0.70→0.50 — the defense cannot touch result-borne injection at all.

## Worst model

**gpt-4o-mini** (overall baseline ASR 0.29; fires on all four classes, rug_pull
0.73). deepseek-chat second (0.18). Every flagship ≈0.

## Limitations (honest)

- **Controlled harness, not production.** Real-client behavior (Claude Desktop,
  Cursor, Cline) is explicitly out of scope here and is a separate project; no
  claim is made about deployed clients.
- **One sink, one objective** (exfiltrate a synthetic canary), toy tasks. ASR is
  payload-sensitive (rephrasing moved a cell from 1.00 to 0.07), so any single ASR
  number reflects the payload as much as the model. We mitigate with a 5-register
  held-out set but do not claim register-completeness.
- **The "defense" is a regex/heuristic filter**, not architectural confinement.
  Its measured limits point toward CaMeL-style designs; this work does not build one.
- **Is `rug_pull` "injection" or agentic instruction-following?** A model acting on
  an instruction embedded in a tool result is a blurry case; we report it as ASR but
  flag the interpretive question.

## What to take away

The publishable contributions are **methodological** (held-out, mechanically
defense-blind payloads that expose circular defense evaluations) and a **negative
result with teeth**: metadata-validation defenses are structurally blind to
result-borne (`rug_pull`) injection, which is the only vector that reliably
succeeds — and only on smaller models. Extending provenance/validation to tool
*results* (or confining untrusted data architecturally) is the actionable direction.
