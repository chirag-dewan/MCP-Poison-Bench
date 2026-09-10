# Contributing

Contributions are welcome — new attack classes, models/providers, defense layers, or
adversarial bypasses.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q          # fully offline; no API key needed
```

## Conventions

- **Python 3.11+, type-hinted, async-first** for I/O. `pytest` only.
- **Conventional commits**: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- **Agent file-scope boundaries** apply (see [`CLAUDE.md`](CLAUDE.md)): servers, harness,
  scorer, and defense each own their directory. Shared attack strings live in
  `fixtures/payloads.py` and are imported, never inlined.
- **Traceability**: every experiment logs a replicate seed identifier, config, and git
  SHA. Provider sampling is stochastic; scorers are deterministic pure functions of trace
  JSONL and never call models or servers.
- **Confidence intervals on every aggregate** (Wilson score).

## Adding an attack class

1. Add new, labeled **defanged** v2 payload IDs/registers (local sink, synthetic token —
   never a working exploit); do not alter the existing v1 registers.
2. Add any server rendering behavior without changing existing class behavior.
3. Add a new grid under `config/v2/`; do not edit the frozen v1 configs or tasks.
4. Provide seen and independently authored held-out coverage. Every content-based defense
   must have a CI test proving the held-out register trips zero of its rules.

## Adding a defense bypass

Add a case to `defense/adversarial_tests.py` and encode the expected outcome as a test in
`tests/test_defense.py`, so a future change that silently "fixes" or breaks it flips a
test rather than going unnoticed.

## Before opening a PR

- `pytest -q` is green.
- `python -m dataset.build_neutered_dataset` followed by
  `git diff --exit-code dataset/poisoned_descriptors.json` confirms the generated
  descriptor catalog is in sync (the same check runs in CI).
- No live secrets or un-defanged payloads in the diff.
- Changes stay within the owning component's directory where possible.
