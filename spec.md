# MCP-Poison-Bench — Project Spec (v0.1)

A reproducible benchmark measuring how vulnerable MCP clients/models are to
tool-poisoning attacks, plus a client-side defense that reduces that exposure.

This is **defensive security research** intended for publication and coordinated
disclosure. All attack components are controlled test fixtures, not deployed
against third-party products without disclosure. See *Ethics & Disclosure* below.

---

## One-line thesis

MCP clients largely fail to validate server-provided tool metadata, so frontier
models acting through them will follow instructions hidden in tool descriptions
and schemas. This benchmark measures that exposure across attack classes and
models, then shows a client-side provenance/validation layer that cuts it.

## Hypotheses (what "a result" actually tests)

- **H1** — Models acting as MCP clients follow instructions injected into tool
  descriptions / schemas at a measurable, non-trivial rate (Attack Success Rate).
- **H2** — ASR varies meaningfully by attack class and by model.
- **H3** — A client-side defense (provenance tagging + static validation of
  server-supplied metadata) reduces ASR substantially while retaining task utility.

## Scope

**In (v1):** a controlled harness built on the MCP SDK + model APIs; 4 attack
classes; 2–3 models; ASR + utility metrics; one defense prototype; 1–2 real-client
spot-checks for external validity.

**Out (v1):** full end-to-end testing of every real client; novel zero-days fired
at deployed products (that's a separate coordinated-disclosure track); anything
outside the MCP trust-boundary question.

**Key design call:** controlled harness over live-client testing. It's
reproducible, automatable, compute-light, and matches the AgentDojo philosophy.
External validity comes from a couple of real-client spot-checks, not from
automating messy production clients.

## Attack classes (documented vectors, used as test fixtures)

1. **Tool-description injection** — instructions hidden in a tool's `description`.
2. **Schema / metadata-field injection** — instructions in JSON-schema field
   descriptions the model reads as guidance.
3. **Rug-pull** — a tool benign at approval time, mutated by the server afterward.
4. **Cross-server shadowing / toxic flow** — one server's tool overriding or
   redirecting another trusted server's behavior, or chaining to exfiltration.

## Metrics

- **ASR** — fraction of trials where the injected objective fires (wrong tool
  called, data routed to attacker-controlled sink, instruction obeyed).
- **Utility** — fraction of benign tasks still completed correctly.
- **Defense ASR-reduction** — ASR(baseline) − ASR(defended).
- **Utility retention** — utility under the defense vs. without it.

## Definition of a result (the paper's core table)

A table: rows = (model × attack class), columns = ASR-baseline / ASR-defended /
utility / utility-defended, over N seeded trials with confidence intervals. Plus
the defense description and the released harness + labeled poisoned-descriptor
dataset. That table + harness *is* the publishable contribution.

## Repo architecture

```
mcp-poison-bench/
  CLAUDE.md            # scoped-agent scaffold + conventions (like your site repo)
  SPEC.md              # this file
  servers/
    benign/            # baseline well-behaved MCP servers
    poisoned/          # attack-class variants (parametrized payloads)
  harness/
    runner.py          # loads a server, runs tasks against a model, logs traces
    clients.py         # MCP client/model wiring
  tasks/               # benign utility tasks the agent performs
  scorer/
    asr.py             # did the injected objective fire?
    utility.py         # did the benign task complete?
  defense/
    provenance.py      # provenance tagging + static metadata validation
  results/             # seeded run outputs, tables, traces
  run_all.sh           # one-command reproduction
```

## Milestones

- **M1 — walking skeleton (this session):** repo skeleton + CLAUDE.md + one benign
  server + one poisoned server (description injection) + a runner that completes
  one benign task and one attack attempt, and prints ASR for n=1. Prove the loop
  before scaling it.
- **M2 — full attack matrix:** all 4 attack classes, parametrized payloads,
  automated trials over N seeds, 2–3 models, baseline ASR + utility table.
- **M3 — defense:** provenance/validation layer, measure ASR reduction + utility
  retention against the M2 matrix.
- **M4 — ship:** arXiv preprint + cdewan.me writeup + GitHub release; coordinated
  disclosure for any real-client findings; conference/venue submission.

## Ethics & disclosure

- All attack servers are local controlled fixtures. No attacks on third-party
  deployed clients without coordinated disclosure first.
- Withhold live, working payloads in the public writeup; release the methodology,
  the harness, and labeled-but-defanged descriptor examples.
- Coordinate with affected client/vendor before publishing any client-specific
  failure; follow each program's responsible-disclosure terms.
- Note CFAA / legal-risk considerations (cite "Legal Risks of Adversarial ML
  Research," arXiv:2006.16179). Scope everything to authorized, local targets.

## Claude Code usage (disclose in the paper)

Built with Claude Code as the accelerant. Keep CLAUDE.md current; generate seeded,
deterministic experiment scripts; have a subagent draft the results section from
logs; run an adversarial self-review pass on the draft before submission. S&P and
SaTML require an LLM-usage disclosure section — write it as you go.
