# v2 cell-size arithmetic

The sweep expands every `(model, attack class, objective)` cell as:

```text
n = number of assigned tasks × number of payloads × number of seeds
```

`scripts/cell_n.py` computes this from the same
`harness.sweep._build_trial_specs` path used by a real run while mocking only API-key
availability. It does not call a model or start a server:

```bash
.venv/bin/python scripts/cell_n.py --config config/bench_heldout.json
```

For that unpinned legacy config, the command prints both the live expanded cells
and a clearly labeled first-five-payload historical core. Thus the exact command
reproduces the published 120-trial baseline without concealing the current 232
trials/model that a sweep would actually generate.

## Recommended v2 depth

Use four seeds for every held-out v2 config. Each class is assigned two tasks and
each objective/class register has at least five held-out payloads, so the minimum
cell size is:

| Objective | Attack class | Tasks | Minimum payloads | Seeds | Minimum n |
|---|---|---:|---:|---:|---:|
| `exfil_sink` | `tool_description` | 2 | 5 | 4 | 40 |
| `exfil_sink` | `schema_field` | 2 | 5 | 4 | 40 |
| `exfil_sink` | `rug_pull` | 2 | 5 | 4 | 40 |
| `exfil_sink` | `cross_server` | 2 | 5 | 4 | 40 |
| `exfil_sink` | `metadata_drift` | 2 | 5 | 4 | 40 |
| `arg_tamper` | each class above | 2 | 5 | 4 | 40 |
| `destructive` | each class above | 2 | 5 | 4 | 40 |

The recommended task mapping is:

| Attack class | Tasks |
|---|---|
| `tool_description` | `calc_add`, `notes_pipeline` |
| `schema_field` | `calc_add`, `notes_pipeline` |
| `rug_pull` | `notes_pipeline`, `notes_review` |
| `cross_server` | `account_review`, `notes_review` |
| `metadata_drift` | `notes_pipeline`, `notes_review` |

Four is the smallest integer seed count satisfying the target with the minimum
register: `2 × 5 × 4 = 40`. Registers with more than five payloads produce a
larger cell; the script reports the actual expansion rather than assuming five.

## Why the current v1 config prints 232, not 120

The published v1 core used five held-out payloads per class. Its pinned refresh
config, `config/refresh/bench_heldout_refresh.json`, still selects exactly those
payload ids and reproduces 120 trials per model:

| Attack class | Tasks | Pinned payloads | Seeds | n |
|---|---:|---:|---:|---:|
| `tool_description` | 2 | 5 | 4 | 40 |
| `schema_field` | 2 | 5 | 4 | 40 |
| `rug_pull` | 1 | 5 | 4 | 20 |
| `cross_server` | 1 | 5 | 4 | 20 |
| **Per-model total** |  |  |  | **120** |

Since publication, the live exfiltration held-out registers widened to 9, 10,
10, and 10 payloads respectively. `config/bench_heldout.json` intentionally has
no `payload_ids` pin, so its current expansion is:

| Attack class | Tasks | Live payloads | Seeds | n |
|---|---:|---:|---:|---:|
| `tool_description` | 2 | 9 | 4 | 72 |
| `schema_field` | 2 | 10 | 4 | 80 |
| `rug_pull` | 1 | 10 | 4 | 40 |
| `cross_server` | 1 | 10 | 4 | 40 |
| **Per-model total** |  |  |  | **232** |

This is fixture-register drift, not a change to the v1 configs or scorers. Use the
pinned refresh config to reproduce the historical 120-trial core and the live
config to measure the current 232-trial expansion.
