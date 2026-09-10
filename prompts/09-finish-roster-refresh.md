# Prompt 09 — Finish the 2026-07 roster refresh (independent of v2)

Branch: a fresh branch off `master` (the refresh tooling is already merged there).
Depends on: nothing in v2 beyond what `master` already has. The run uses only the
`none` / `meta_filter` arms, which are snapshot-tested to reproduce v1's exact trace
shape, so it remains a pure re-run of v1's protocol on new models. Requires API keys
in a `.env` (never commit it).

## Read first

1. `README.md` (v1 numbers are the comparison target), `goals.md §6`.
2. On the branch: `config/refresh/*.json`, `run_refresh.sh`, `aggregate_refresh.py`,
   `harness/pricing.py`, and the `--dry-run` report code in `harness/sweep.py`.
3. `harness/clients.py::supports_sampling_params` — the harness already omits
   `temperature` for current Anthropic frontier models (they reject sampling
   params) and records `usage.sampling.{temperature, sent}` in every trace. Two
   deviations from the v1 harness therefore apply to this run and **must be
   written into `RUN.md`**: Opus 4.8 samples at its default, and length-capped
   responses surface as `stop_reason == "max_tokens"` (v1 recorded them as
   `end_turn`). Neither changes trial generation.

## Steps

1. Confirm the two placeholder rows in `harness/pricing.py` (`gpt-5.4-nano`,
   `deepseek-v4-flash`) against the vendors' pricing pages; set `confirmed=True`
   with the source in `note`. Also verify `gpt-5.4-nano` is the exact API id (it
   was chosen from a product name; the dry-run will 404 if wrong).
2. `./run_refresh.sh --dry-run`. Read the report. For each model check:
   - errored = 0 (or explain each),
   - empty-output count — if non-zero for a reasoning model, that is
     `MAX_TOKENS=1024` truncation. **Do not raise `MAX_TOKENS`** (v1 ran GPT-5.5 at
     1024; changing it breaks comparability). Record the rate in `RUN.md` and flag
     it as a confound for the budget reasoning models vs their non-reasoning v1
     predecessors.
   - the projected cost, now computed from measured tokens and confirmed prices.
3. Report the dry-run numbers and the projection and **STOP for a go/no-go**.
4. On go: `./run_refresh.sh` (resumable). On completion, `aggregate_refresh.py` has
   written matrices/deltas under `results/2026-07-refresh/`. Commit the small
   artifacts (`matrix_*.csv`, `delta_*.md`) and a `results/2026-07-refresh/RUN.md`.
5. Write `RESULTS-REFRESH.md` at repo root:
   - the held-out and seen tables in the README's exact format for the four models,
     with Wilson CIs in every cell,
   - a comparison table per attack family per **tier** (frontier: Opus 4.8 & GPT-5.5
     vs v1 Opus 4.8 & GPT-5.5; budget: gpt-5.4-nano & deepseek-v4-flash vs v1
     gpt-4o-mini & deepseek-chat) with both runs' CIs side by side and a
     "CIs overlap: yes/no" column,
   - one paragraph per hypothesis: did "susceptibility tracks capability, not
     vendor" hold, strengthen, or shift — decided only by CI overlap,
   - the truncation/empty-output rates per model,
   - the deviations from v1 (DeepSeek string migration, any sampling-param change).
   No editorializing beyond what the CIs support.
6. Push. Open a PR only if asked.

## Finish

Report the dry-run table, the final matrices, and the hypothesis verdicts. STOP.
