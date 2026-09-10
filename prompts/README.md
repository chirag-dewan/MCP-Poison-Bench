# v2 prompts — how to use these

Each file in this directory is a complete, self-contained prompt for one Claude
Code session. Paste the whole file as the opening message of a fresh session on a
fresh branch. The prompts assume **no prior conversation context** — everything the
session needs is inside the prompt or in `goals.md`.

Run them in numeric order unless a prompt's "Depends on" line says otherwise.

| # | File | Branch | Depends on |
|---|---|---|---|
| 01 | `01-harness-seams-and-correctness.md` | `v2/01-seams` | — |
| 02 | `02-capability-policy-and-taint.md` | `v2/02-policy` | 01 merged |
| 03 | `03-result-side-provenance-filter.md` | `v2/03-result-filter` | 01 merged |
| 04 | `04-metadata-pinning-and-shadowing.md` | `v2/04-pinning` | 01 merged |
| 05 | `05-confirmation-gate-and-model-hardening.md` | `v2/05-confirm-hardening` | 02 merged |
| 06 | `06-second-objective-tasks-and-n.md` | `v2/06-objectives` | 01 merged |
| 07 | `07-v2-configs-driver-and-ablation-report.md` | `v2/07-ablation` | 02–06 merged |
| 08 | `08-llm-judge-detector-arm.md` (optional) | `v2/08-judge` | 07 merged |
| 09 | `09-finish-roster-refresh.md` | existing refresh branch | — (independent) |

Ground rules that apply to every prompt (repeated inside each one on purpose):

- Read `goals.md` first. Its §2 non-negotiables override anything ambiguous.
- Never modify v1 scoring, v1 fixtures registers, v1 defense rules, v1 tasks, or
  v1 configs. Add alongside.
- `pytest -q` must stay green; add tests for everything new. Most work needs no
  API key — design it that way.
- Stop and report at the end of each prompt. Do not start the next prompt's work.
