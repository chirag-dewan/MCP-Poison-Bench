# Descriptor catalog

A labeled, human-readable overview of the tool-poisoning descriptors used by the
benchmark. This is a *summary* artifact — handy for skimming the attack surface without
reading code.

## Files

- [`poisoned_descriptors.json`](poisoned_descriptors.json) — one entry per attack class:
  `attack_class`, `carrier_field` (where the injection sits), `vector` (how it reaches
  the model), `benign_host` (the tool it rides on), `label`, and a short summary of the
  `injection` (not the verbatim string).
- [`build_neutered_dataset.py`](build_neutered_dataset.py) — regenerates the catalog from
  the fixtures (`python -m dataset.build_neutered_dataset`). It asserts that no verbatim
  injection slice leaks into the summary, so the JSON stays an overview rather than a
  copy-paste payload bank.

## Where the runnable payloads live

The full, **defanged** payloads are in [`../fixtures/payloads.py`](../fixtures/payloads.py)
— defanged because the "exfiltration" target is a local no-op sink tool
(`export_data`) and the "secret" is a synthetic, fake `CANARY` token. Nothing in this
repository is a working exploit against any real service; the injection *techniques*
(tool-description injection, schema-field injection, rug-pull, cross-server shadowing)
are the publicly-documented MCP tool-poisoning classes.
