# Prompt 08 (optional) — LLM-judge detector arm

Branch: `v2/08-judge` (off `master` after 07 merged). Depends on: 07.

## Read first

1. `goals.md` §1 (arm `judge`), §2 items 2–3.
2. `defense/provenance.py`, `defense/result_filter.py`, `harness/arms.py`,
   `harness/clients.py::complete`.
3. The de-circularization tests from prompts 03 and 06.

## Why this arm exists

The audience will ask: "a regex is a strawman — would a *model-based* classifier
escape the circularity?" This arm answers with data, and it is only honest if the
judge is de-circularized the same way: it must never be shown the rule set or the
held-out payloads, and it must be evaluated on the same held-out register.

## Deliverables

### A. `defense/judge.py`

- `build_judge_transforms(judge_model: str, *, cache_dir: Path) -> (ToolTransform, ResultTransform)`.
- Both call `clients.complete` on `judge_model` with a **fixed, versioned** system
  prompt (`JUDGE_PROMPT_VERSION`) asking for a strict JSON verdict per segment:
  `{"instruction_shaped": bool, "confidence": float, "why": str}`. Use the same
  `_SEGMENT_SPLIT` as `provenance` (import it; do not copy). Redact segments the
  judge flags at confidence ≥ 0.5 (constant), wrap survivors in the same provenance
  markers as the corresponding v1/result arms.
- The judge prompt must **not** contain: the sink name, the canary, any payload
  text, any rule name, or any vocabulary lifted from `_RULES`. Add a test that
  asserts none of those strings appear in the prompt.
- Deterministic caching: key = sha256(judge_model, prompt_version, segment) →
  verdict JSON under `cache_dir`, so re-runs and aggregation are reproducible and
  cheap. Judge temperature omitted (let the model default); record the judge model
  and version in `run_config`.
- Findings emitted like every other arm (`rule = "judge"`), so the existing trace
  and scorer plumbing works unchanged.

### B. Arms

- `judge` → judge tool transform + judge result transform, no policy.
- `judge_policy` → judge transforms + prompt-02 policy (upper bound on "smart
  filter plus structural control").

### C. Cost & rate limits

The judge doubles model calls. Add the judge model to `harness/pricing.py` (it will
be one of the roster models — default `claude-haiku-4-5`, confirmed price) and make
the dry-run report include judge-call tokens as a separate line per arm.

### D. De-circularization for a learned detector

You cannot assert "zero rules tripped" for a judge. Instead add
`tests/test_judge_offline.py` that uses a **recorded** verdict cache (commit a small
fixture cache produced once with real keys — mark it clearly as a fixture and note
the judge model/version) and asserts the arm behaves deterministically from cache
with no network. Then add `scripts/judge_leakage_check.py` that greps the judge
prompt and the judge module for every string in `fixtures.payloads` (all registers,
all objectives) and every rule pattern literal, failing on any hit. Wire that script
into CI.

## Acceptance

- Offline tests green with no keys (cache fixture present).
- Leakage check passes.
- Arm appears in `run_v2.sh --arms judge,judge_policy` and in the ablation columns.

## Finish

Commit and push. Report the judge prompt verbatim, the confidence threshold, the
cache key, and the leakage-check scope. STOP.
