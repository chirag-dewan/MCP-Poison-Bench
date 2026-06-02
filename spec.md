# MCP-Poison-Bench — Project Spec (v0.2)

A reproducible benchmark measuring how vulnerable MCP clients/models are to
tool-poisoning attacks, and a **de-circularized** evaluation of the client-side
metadata defense the literature recommends.

This is **defensive security research**. All attack components are controlled test
fixtures; all claims are scoped to the controlled harness, not to production MCP
clients. See *Ethics & Disclosure* below.

> **Note (v0.2).** This spec began (v0.1) as "build a client-side defense and show
> it cuts ASR." The measurement did not support that headline, and the project's
> identity changed to match the evidence — see *Findings* below. The framing here
> now reflects what the benchmark actually shows, not the original plan.

---

## One-line thesis

MCP clients pass server-supplied tool metadata into model context, so a malicious
server can smuggle instructions the model may follow. We measure that exposure
across attack classes, models, and vendors, implement the recommended client-side
provenance/validation defense, and **de-circularize** its evaluation — testing it
on payloads authored independently of its own rules. The defense neutralizes
metadata-borne injection it can read, but is **structurally blind** to result-borne
(rug-pull) injection, which is the vector that still succeeds on weaker models.

## Hypotheses (what "a result" actually tests)

- **H1** — Models acting as MCP clients follow instructions injected into tool
  descriptions / schemas at a measurable rate (ASR). *Result: only on weaker
  models; frontier models resist nearly all classes.*
- **H2** — ASR varies meaningfully by attack class and by model. *Result: yes —
  it tracks model capability, not vendor; gpt-4o-mini is the most susceptible.*
- **H3** — A client-side metadata defense reduces ASR substantially while retaining
  utility. *Result: rejected as stated. The apparent reduction is largely circular
  (the attack payloads shared the defense's keyword vocabulary); on held-out
  payloads it mostly vanishes.*
- **H4** (the de-circularization) — A defense's measured reduction must be tested on
  payloads authored independently of its rules, or the result is an artifact of
  shared vocabulary. *Result: confirmed, and it is the core methodological point.*

## Scope

**In:** a controlled harness built on the MCP SDK + model APIs; 4 attack classes;
**6 models across 3 vendors** (Anthropic: Opus 4.8, Sonnet 4.6, Haiku 4.5; OpenAI:
GPT-5.5, gpt-4o-mini; DeepSeek: deepseek-chat); seen + held-out payload registers;
ASR + utility metrics; the recommended metadata defense and its de-circularized
measurement. (Gemini was attempted but is credit-limited; not in the final matrix.)

**Out:** real-client testing (Claude Desktop, Cursor, Cline, etc.) — a separate,
ongoing project; novel zero-days fired at deployed products; anything outside the
MCP trust-boundary question. **No claim here extends to production clients.**

**Key design call:** controlled harness over live-client testing. It's
reproducible, automatable, and compute-light, matching the AgentDojo philosophy.
Real-client external validity is explicitly deferred rather than asserted.

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

## Definition of a result (the core tables)

**Two** tables, reported side by side: rows = (model × attack class), columns =
ASR-baseline / ASR-defended / utility, over N seeded trials with Wilson CIs — one
for the **held-out** payload register (the de-circularized headline) and one for the
**seen** register (the near-circular contrast). The contribution is that pair plus
the methodology that separates them, the released harness, and the labeled,
CI-gated payload dataset — not a defense that "works."

## Findings (what the measurement showed)

- **Capability, not vendor.** Frontier models (Opus 4.8, GPT-5.5, Sonnet 4.6)
  resist nearly every cell. The cheaper models account for most firing;
  **gpt-4o-mini is the most susceptible** (rug_pull ASR 0.61 held-out, 1.00 seen).
- **The headline reduction was circular.** On seen payloads the defense drives
  metadata-borne injection to ~0, but those payloads share its keyword vocabulary.
  On held-out payloads (which trip zero defense rules, CI-enforced) baseline ASR is
  already ~0, so there is little to reduce — ΔASR ≈ 0.
- **rug_pull is a structural blind spot.** The defense rewrites the tool *list* and
  never inspects tool *results*, so result-borne injection bypasses it by
  construction: gpt-4o-mini rug_pull is **1.00 → 1.00** with the defense on.
- **Open interpretive question.** rug_pull counts as ASR because the result coerces
  disclosure of data the task told the model to keep, with no user in the loop —
  but the line between "injection" and ordinary tool-result-following is genuinely
  blurry and is flagged, not assumed.

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
