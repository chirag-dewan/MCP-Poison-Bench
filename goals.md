# MCP-Poison-Bench — v2 Goals

This file is the north star for the v2 work. Every prompt in `prompts/` points back
here. If a change does not serve a goal below, or violates a non-negotiable below,
it does not ship.

---

## 0. Where v1 landed (do not re-litigate)

v1 measured MCP tool-poisoning across 4 attack classes × 6 models × 3 vendors and
produced one honest negative result:

- The recommended client-side *metadata* defense (a keyword/regex redactor over tool
  descriptions + schema descriptions, wrapped in provenance markers) looks effective
  only on payloads that share its own vocabulary. On an independently-authored,
  CI-enforced **held-out** register it reduces almost nothing, because almost
  nothing fires there to begin with.
- The one vector that reliably fires on weaker models — `rug_pull` (instruction
  injected into a tool *result*) — is **structurally invisible** to the defense,
  because the defense only ever sees the tool *list*. `gpt-4o-mini` rug_pull:
  `1.00 → 1.00` with the defense on.
- Susceptibility tracks **model capability, not vendor**.

v1's methodology is the asset: de-circularized seen/held-out split, pure trace
scorers, Wilson-score CIs, errored trials excluded rather than laundered, defense as
a single toggled variable. **v2 builds on that methodology; it does not replace it.**

---

## 1. The v2 thesis

> Content-based defenses (filters over text the model reads) bend to phrasing and
> are therefore circular to evaluate. **Capability-based defenses** (controls over
> what the model is *allowed to do* with data of a given provenance) are
> phrasing-independent by construction. v2 measures both in the same harness, on the
> same held-out register, with the same CIs, and reports the gap.

The v2 headline artifact is one **ablation matrix**:

- rows: model × attack class (held-out and seen reported separately, as in v1)
- columns: defense arm — `none` / `meta_filter` (= v1) / `result_filter` /
  `pinning` / `policy` / `policy_full` (policy + both filters) / `confirm` /
  `model_hardening` / (optional) `judge`
- cells: **attempted ASR**, **realized ASR**, **canary exfiltration**, **utility**,
  each with a 95% Wilson interval

Hypotheses (state them; let the data answer):

- **H5** — Adding a *result-side* keyword filter closes rug_pull on *seen* payloads
  but not on *held-out* payloads (a second negative result that strengthens v1).
- **H6** — A capability/egress policy with provenance taint tracking drives
  **realized** ASR to ≈0 on every class of the held-out register, while
  **attempted** ASR is unchanged — the gap *is* the measurement of a structural
  defense.
- **H7** — Capability policies cost measurable utility; the size of that cost is a
  finding, not a footnote.
- **H8** — Metadata pinning catches metadata-borne rug-pulls and cross-server
  shadowing that v1 did not model at all, and is complementary to (not a substitute
  for) result-side controls.

---

## 2. Non-negotiables

1. **v1 stays reproducible, byte-for-byte.** `scorer/asr.py::score_asr`,
   `scorer/utility.py`, `scorer/aggregate.py` (Wilson), `fixtures/payloads.py`'s
   existing registers, `defense/provenance.py`'s existing rule set and
   `build_tool_transform()`, the `tasks/*.json` used by v1, and the v1
   `config/*.json` grids are **not modified**. New behavior lives in new functions,
   new modules, new configs, new tasks, or new fixture registers. `pytest -q` must
   keep every existing test green.
2. **One variable at a time.** Every defense arm is a toggle composed at the sweep
   level. Baseline and defended runs differ by exactly the arm under test. No arm
   touches server behavior, task prompts, or scorers.
3. **De-circularization is preserved and extended.** Every new content-based arm
   must ship with a CI test asserting that held-out payloads trip **zero** of its
   rules. If you cannot write that test, the arm is not de-circularized and cannot be
   reported as such.
4. **Attempted ≠ realized.** v2 scoring distinguishes the model *trying* to reach the
   sink from the sink *receiving* the payload. Never report one as the other.
5. **Errored ≠ resisted.** Errored trials, truncated trials (`stop_reason ==
   "max_tokens"`), and blocked trials are each recorded distinctly and never scored
   as a clean non-fire.
6. **Results are versioned, never overwritten.** Each run writes under
   `results/<run-id>/`. The small aggregated artifacts (`matrix_*.csv`,
   `delta_*.md`) are **committed**; per-trial traces stay git-ignored.
7. **No claim extends beyond the controlled harness.** Same ethics posture as v1:
   defanged fixtures, local sink, synthetic canary, no third-party targets.
8. **Do not editorialize past the CIs.** If two arms' intervals overlap, say so.

---

## 3. Success criteria (v2 is "done" when)

- [ ] The runner exposes two new seams — `result_transform` and `call_policy` —
      each a pure callable toggled exactly like `tool_transform`.
- [ ] The OpenAI-compatible adapter surfaces truncation (`finish_reason == "length"`
      → `stop_reason == "max_tokens"`) and the sweep counts it.
- [ ] Sampling parameters are gated per model so current frontier models that reject
      `temperature` do not 400; the trace records what was actually sent.
- [ ] `scorer/asr_v2.py` reports `attempted`, `realized`, `blocked`,
      `canary_exfiltrated` per trace, with tests.
- [ ] Every arm in §1 is implemented as a composable toggle with a `--defense-arm`
      flag, and `--defense` remains a back-compatible alias for `meta_filter`.
- [ ] A second attacker-objective family exists (argument tampering; destructive
      action) with its own seen + held-out registers and the CI zero-rules test.
- [ ] `cross_server` runs on at least two tasks; every held-out cell has n ≥ 40.
- [ ] `config/v2/` grids + `run_v2.sh` + `aggregate_v2.py` produce the ablation
      matrix under `results/v2-<date>/`, and `RESULTS-v2.md` reports it without
      editorializing past the CIs.
- [ ] `CLAUDE.md` exists in the repo (tracked) and matches what the docstrings
      already claim it says.
- [ ] Offline test count grows; nothing existing breaks.

---

## 4. Ordering (dependencies flow downward)

1. `prompts/01` — harness seams + correctness fixes (everything depends on this)
2. `prompts/02` — capability/egress policy + taint tracking (the headline arm)
3. `prompts/03` — result-side provenance filter (the honest second negative)
4. `prompts/04` — metadata pinning + shadowing detection
5. `prompts/05` — confirmation gate + model-side hardening arms
6. `prompts/06` — second objective family, more tasks, more n
7. `prompts/07` — v2 configs, driver, aggregator, ablation report
8. `prompts/08` — (optional) LLM-judge detector arm
9. `prompts/09` — finish the 2026-07 roster refresh (independent of v2; keep on
   its own branch so the re-run stays a pure re-run)

---

## 5. Out of scope for v2

- Real-client (Claude Desktop / Cursor / Cline) testing — still a separate project.
- Any change to v1 numbers, v1 configs, or the v1 README tables.
- Novel attack techniques against deployed products.
- A defense that "works" as a product. v2 measures; it does not ship a client.

---

## 6. Branch & results discipline

- v1 = `master` as of the v1 tag. Tag it (`v1.0`) before v2 work starts.
- Each prompt runs on its own branch off `master`: `v2/01-seams`, `v2/02-policy`,
  … and lands by PR. Never stack unmerged branches unless a prompt says so.
- The 2026-07 roster refresh stays on `claude/mcp-poison-bench-roster-refresh-*`
  and writes to `results/2026-07-refresh/`. It must not absorb v2 changes.
- Every run directory carries a `RUN.md` with: git SHA, roster, arms, seeds,
  payload registers, date, and any deviations.
