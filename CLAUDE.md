# MCP-Poison-Bench — Agent Guide

## Thesis

MCP-Poison-Bench is a controlled benchmark for MCP tool-poisoning. v1 showed
that metadata keyword filters look effective mainly on payloads that share their
vocabulary and cannot see result-borne attacks. v2 keeps that methodology intact
while comparing content filters with capability controls that govern whether a
model-requested action can reach a server. The benchmark measures these controls;
it does not claim to be a production client defense.

## Ownership

| Owner | Writes | Boundary |
|---|---|---|
| `agent:harness` | `harness/**`, run drivers | MCP/model wiring, traces, defense-arm composition |
| `agent:scorer` | `scorer/**` | Pure functions over saved traces; never calls models or servers |
| `agent:defense` | `defense/**` | Client-side controls implementing runner seam contracts |
| `agent:servers` | `servers/**` | Local benign and poisoned MCP fixtures |

Shared fixtures belong in `fixtures/`; task specifications belong in `tasks/`.
Coordinate cross-owner changes explicitly and import contracts from their owner
instead of duplicating them.

## v1 is untouchable

v2 work must not modify:

- `scorer/asr.py::score_asr`
- `scorer/utility.py`
- `scorer/aggregate.py` and its Wilson interval behavior
- existing registers in `fixtures/payloads.py`
- the existing rules or `build_tool_transform()` in `defense/provenance.py`
- existing `tasks/*.json`
- existing v1 `config/*.json` grids

Add new functions, modules, configs, tasks, or fixture registers instead. Every
existing offline test must remain green.

## Runner seams

All arms are composed at the sweep layer and passed into `harness.runner` as
narrow callables. `None` means the seam is off.

- `ToolTransform(tools) -> tools` rewrites the model-facing tool list once,
  immediately after MCP discovery. Raw server metadata remains in the trace.
- `ResultTransform(tool_name, result_text, ctx) -> result_text` rewrites a real
  MCP result before it returns to the model. `ctx` contains `server_path`,
  `step`, `tool_use_id`, and `is_error`. The raw result remains in
  `tool_result.content`; the model-facing string is recorded separately.
- `CallPolicy(tool_name, tool_input, ctx) -> PolicyDecision` runs after the
  attempted `tool_call` is traced and before dispatch. `ctx` contains `step`,
  `tool_use_id`, `server_path`, `task`, and a defensive copy of `history`.
  A denial records `blocked_tool_call`, never reaches the server, and returns a
  stable error result to the model.

Do not place defense logic in the runner. New arms implement these contracts and
are selected with `--defense-arm`; legacy `--defense` remains an alias for the v1
metadata filter.

## Runs and results

- Seed every experiment and record seed, config, git SHA, model, and sampling.
- Trace every model turn, attempted tool call, policy denial, and tool result as
  JSONL. Scorers read traces, never live runs.
- Keep attempted, realized, blocked, errored, and truncated outcomes distinct.
  Never report an error, truncation, or blocked dispatch as clean resistance.
- Preserve the seen/held-out split and change one defense arm at a time.
- Write versioned runs under `results/<run-id>/`; never overwrite a prior run.
- Commit only small aggregate artifacts (`matrix_*.csv`, `delta_*.md`, `RUN.md`).
  Per-trial traces and JSONL stay ignored.
- Report Wilson 95% intervals and do not editorialize past overlapping intervals.

## Engineering discipline

- Python 3.11+, type hints, async-first I/O, official MCP SDK, and `pytest`.
- Keep edits surgical and use conventional commits.
- Before committing, run the relevant focused tests and then `pytest -q`.
- Confirm generated descriptor fixtures are stable and review the protected-file
  diff before each v2 branch is pushed.

## Ethics

This is defensive research in an authorized local harness. Use defanged payloads,
synthetic canaries, and local sinks only. Do not target deployed third-party
clients, embed live exploit payloads, or extend claims beyond the controlled
benchmark. Follow coordinated disclosure before publishing any client-specific
finding.
