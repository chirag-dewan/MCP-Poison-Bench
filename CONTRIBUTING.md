# Contributing

Contributions are welcome — new attack classes, models/providers, defense layers, or
adversarial bypasses.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pytest -q          # 37 tests, fully offline (no API key needed)
```

## Conventions

- **Python 3.14+, type-hinted, async-first** for I/O. `pytest` only.
- **Conventional commits**: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- **Agent file-scope boundaries** apply (see [`CLAUDE.md`](CLAUDE.md)): servers, harness,
  scorer, and defense each own their directory. Shared attack strings live in
  `fixtures/payloads.py` and are imported, never inlined.
- **Determinism**: every experiment is seeded and logs seed + config + git SHA. Scorers
  are pure functions of trace JSONL — they never call models or servers.
- **Confidence intervals on every aggregate** (Wilson score).

## Adding an attack class

1. Add a labeled, **defanged** payload to `fixtures/payloads.py` (local sink, synthetic
   token — never a working exploit).
2. Render it in `servers/poisoned/server.py` behind `POISON_CLASS`.
3. Add it to `config/bench.json` and re-run `./run_all.sh`.

## Adding a defense bypass

Add a case to `defense/adversarial_tests.py` and encode the expected outcome as a test in
`tests/test_defense.py`, so a future change that silently "fixes" or breaks it flips a
test rather than going unnoticed.

## Before opening a PR

- `pytest -q` is green.
- No live secrets or un-defanged payloads in the diff.
- Changes stay within the owning component's directory where possible.
