# Minority Prophet Gate

**Refuse manufactured consensus.** A drop-in gate for multi-agent systems that
counts *independent, attested evidence roots* instead of voices — so seven
agents repeating one unverified guess can never outvote two agents who
actually checked.

> **Research status:** REPLICA results pending canonical re-runs. The gate is a reference implementation; its library tests do not establish production safety.

```
Nine messages say a deploy is SAFE?             Voices:  SAFE 7 — UNSAFE 2
Seven of them trace to one security scan.       Roots:   SAFE 1 — UNSAFE 2
Two trace to independent failing test runs.     Verdict: BLOCK (flip cost: 1 forged root)
```

## Why

Multi-agent consensus is currently counted by voice, and voices are free:
copies, re-broadcasts, summaries, sybils, and conformity-injection attacks
(e.g. MAD-Spear) all inflate agreement without adding evidence. This gate
implements evidence-root aggregation, whose core properties are
**machine-checked under the stated model**, not tuned:

- **T2 — Copy invariance:** duplicating a claim can never change the verdict.
- **T1 — Immunity:** given side-consistent attestations **and an unchanged set of
  origins**, the verdict is invariant under arbitrary corruption of who-copied-whom
  among the rest. Lineage accuracy between claims is irrelevant; only origins
  matter.
  - The origin-set hypothesis is load-bearing and was previously omitted here.
    Corruption that *creates or destroys an origin* — orphaning a claim so it
    becomes a root, or attaching a root under a parent — is outside T1, and the
    verdict may change. What T1 buys is indifference to who copied whom, not
    indifference to how many independent origins exist. Tolerance to origin-set
    error is a **separate** theorem, T5, with its own bound: a verdict survives if
    its margin exceeds the number of origin-set changes.
  - See `FORMAL.md`. The normative statement of every hypothesis is the theorem
    ledger in the research repository, not this list.
- **T4 — Margin flip condition:** every decision ships with its attack price,
  and there are **two prices**, because there are two attacks. Message volume is
  worthless against both.
  - `flip_budget` — **forgery**: fabricating new *independent attested roots* on
    the losing side. Each moves the margin one unit, so `flip_budget` forgeries
    force abstention and one more reverses.
  - `conversions_to_reverse` — **compromise**: stealing the key of a root that
    already supports the winner and flipping it. That root leaves the winning
    side *and* joins the losing one, so each action moves the margin **two**
    units. This price is roughly **half** `flip_budget`, and it is the relevant
    one when the threat is key compromise. Quoting `flip_budget` alone overstates
    the attacker's cost by ~2× (research counterexample CE-03).
  - `abstention_reachable_by_conversion` — **false at odd `flip_budget`.**
    Conversions move the margin in steps of two and so preserve its parity: from
    an odd margin the attacker can never land on a tie. Abstention — the safe
    outcome — is simply not on the compromise path, and the cheapest attack goes
    straight to a confidently *wrong* verdict. Do not assume a thin margin
    degrades to "don't know"; at odd margins it does not.

Proof texts, an exhaustive machine verifier (all worlds ≤ 6 claims, 121,944
rewirings, 100k randomized instances, zero violations), benchmarks against
Dawid–Skene / truth-discovery baselines, and the research paper draft live in
the [Minority Prophet research repository](https://github.com/Silentpartnercoding/minority-prophet).

## Quickstart

> `TrustAllVerifier` below is an unsafe testing fixture for the bundled example.
> It must be replaced by a fail-closed production verifier before real use.

```python
from minority_prophet import decide, TrustAllVerifier
import json

envelopes = [json.loads(l) for l in open("examples/pr482.jsonl")]
d = decide(envelopes, TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)

print(d.action)        # "block"
print(d.roots_for, d.roots_against)   # 1 2
print(d.flip_budget)              # 1.0 <- FORGED roots needed to change this
print(d.conversions_to_reverse)   # 1   <- COMPROMISED roots needed. Usually the
                                  #        smaller number, and the one to plan against.
print(d.diagnostics["abstention_reachable_by_conversion"])
                                  # False <- odd margin: a compromise attack cannot
                                  #          produce a tie, only a wrong answer.
```

Replace the one line in your orchestrator that says
`if enough_agents_agree: proceed` with a call to `decide()`. Three actions
come back: `proceed`, `block`, or `escalate` (abstention / thin margin /
no verifiable evidence — a reason to ask a human, never a reason to proceed).

For belief formation, analysis, or any use that must not imply execution,
call `assess()` instead. It returns an action-neutral evidence verdict and
flip budget. `decide()` is the separate policy layer that interprets that
assessment as `proceed`, `block`, or `escalate`.

### Evidence-sensitive authorization example

`examples/evidence_sensitive_authorization.py` demonstrates the narrow case
where this assessment adds information that ordinary authorization does not:
seven agents approve a production deployment, but all seven copied one scan;
two independent test runs reject it. The example produces this flow:

```
9 voices -> Minority Prophet assessment (1 SAFE root, 2 UNSAFE roots)
         -> separate authority policy (BLOCK)
         -> exact-action runtime boundary (0 effects)
```

Minority Prophet does not grant authority in this example. It reports the
structure and strength of the evidence. A separate provider-owned policy
interprets that assessment, and the runtime independently enforces the
result. Run it from the repository root with
`python -m examples.evidence_sensitive_authorization`.

The same runnable example includes a harder comparison. Twelve SAFE voices
include six copies, two invalid forgeries, one expired observation, one claim
bound to the wrong action, and two valid independent roots. Three fresh,
bound, independently grounded UNSAFE roots oppose them. Head count, signature
checking alone, and signature-plus-subject-plus-freshness still choose SAFE;
independent-root assessment chooses UNSAFE and the runtime executes zero
effects. This is an illustrative adversarial case, not a population-level
accuracy benchmark.

### Optional Border Mandate seam

`MandateGate` consumes one provider-neutral Border authority-relation receipt
before a consequential runtime action. It is useful when Agent A is allowed to
request one exact action and Agent B independently has permission to execute it;
A's request does not transfer B's permission.

The caller supplies the trusted Border verifier, the Gate's expected audience,
the exact `RuntimeAction` about to be released, a separate resource-policy
decision, and an atomic nonce store. Gate follows this order:

```
Border re-verifies both live authority paths and the exact action
  -> existing resource policy must also say proceed
  -> Gate binds the verified relationship to a runtime-only context
  -> any result cache is scoped to that relationship and exact action
  -> Gate consumes the Mandate nonce once
  -> RuntimeController records intent before effect
  -> runtime executes once or records zero attempts
  -> an execution receipt and neutral lineage record are emitted
```

A receipt cannot choose its own verifier, audience, or policy. A valid Mandate
is only one required green light: it never overrides another block or
escalation. A block does not consume the Mandate; consumption occurs only when
every conjunctive gate is ready to release the effect.
`InMemoryMandateNonceStore` exists only for tests and local demonstrations.
Production deployments need durable atomic reservation shared across every
Gate replica and the existing durable execution ledger. An identical retry may
return the prior receipt from that execution ledger; it must not execute again
through a fresh controller. A crash after nonce consumption but before the
runtime records execution intent can leave a safely consumed Mandate with no
effect. Production must reconcile that state or coordinate both durable records
transactionally; this reference seam proves zero-or-one effect, not distributed
exactly-once delivery.

The seam remains vendor-neutral by design. It does not own agent scheduling,
runtime lifecycle, identity issuance, resource credentials, or a vendor control
plane. `AuthorityRuntimeContext` is not a new credential. It carries only the
already-verified relationship into a provider-blind adapter. Cache entries are
never accepted as authority: every retry repeats live Border verification and
the independent resource-policy check before a cached result can be returned.
The default lineage record marks the authority anchor `verified` and the runtime
outcome `observed`; it does not mint a new evidence root or claim that an
unsigned runtime result is cryptographic proof. Production callers can adapt the
`KnowledgeLedgerSink` protocol to any durable evidence store.

### Optional memory-evidence socket

Gate does not require a memory system. When an action explicitly depends on a
remembered approval, observation, or prior event, callers may pass a neutral
Memory Evidence Interoperability Profile to `selective_decide` together with
the expected proposition, memory-object, request, and action digests.

The consumer is deliberately asymmetric:

- malformed, incomplete, unverifiable, or unknown evidence escalates;
- revoked, expired, replayed, or incorrectly bound evidence blocks;
- accepted memory proceeds only to the ordinary evidence assessment;
- memory never grants authority and never overrides a deterministic denial.

The neutral profile is defined in the Minority Prophet research repository.
Identity, signature, controller, and revocation providers remain external to
Gate. The caller must persist consumed nonces across processes if replay
protection is required; passing an in-memory set is only a local demonstration.

## Security model — read this before trusting anything

`TrustAllVerifier` is for **testing only**. The guarantees above are
conditional on attestation: origins must be unforgeable, which means
signatures checked by a real production verifier implementing
the 3-state `AttestationVerifier` interface (`root` / `derived` / `invalid`).
Wire yours via `CallbackVerifier`. Rules the adapter enforces regardless:

1. **Default-derived:** any claim without a verified fresh-root attestation
   is presumed an echo. Copying is the presumption; independence requires
   proof. Unverifiable claims are quarantined and contribute zero roots.
2. **Zero evidence ⇒ escalate:** no verifiable roots is never a green light.
3. **Side-consistency at signing:** assertion and origin are fused in one
   signed unit, so a claim cannot be re-labeled to the other side later.

4. **Verifier independence:** a verifier is not trusted merely because it is a
   third party. Its rules must be transparent, it must remain independent of
   the evidence producer, it must expose uncertainty, and it must be unable to
   mint, alter, or promote the evidence it verifies.

   The current Gate consumes a verifier's `root` / `derived` / `invalid`
   classification; it does **not** discover shared organizational control by
   itself. Deployments must not return `root` merely because producer and
   verifier use different names, keys, services, or labels. When an upstream
   verifier returns `derived` or `invalid`, the Gate does not count an
   independent root; when evidence is empty, tied, or below policy margin, it
   escalates rather than converting uncertainty into permission. The HVI-1
   research study defines the future control-domain experiment; it is not a
   present implementation claim.

### Subject binding and freshness (R2.5)

For a decision about a specific subject, call `decide(...,
decision_subject="job:123")`. Matching **bound** roots determine
`flip_budget` and the `min_flip_budget` policy threshold. A legacy root without a subject remains
visible during migration at the configurable `unbound_root_weight=0.5`, but
never increases the strength score; this makes migration-mode `flip_budget`
conservative. Set `unbound_root_weight=0.0` for the documented strict end
state.

**Units, when weights are in play.** With any root weight other than `1.0`,
`flip_budget` is a quantity of *root mass*, not a count of roots — it can come
back `1.5`, and half a forged root is not something an attacker can buy. Every
verdict therefore reports which it is:

| field | meaning |
|---|---|
| `flip_budget_unit` | `"independent roots"` or `"weighted root mass"` |
| `flip_budget_is_root_count` | `True` only when the number is a countable number of roots |

`conversions_to_reverse` is always a count of actions, so it stays an integer in
both modes and is the safer number to threshold on.

**On T5, and what a threshold does not inherit from it.** Earlier revisions of
this file called `min_flip_budget` "the T5 safety floor". T5 states that a
verdict with `|margin| > k` survives `k` root-set errors — but only between
worlds that are side-consistent **and carry the same assertions**. That second
hypothesis is necessary, not decorative: the research repository's `CE-02`
falsifies the version without it, and `T5_needs_assert_fixed` compiles a witness
where a single side conversion flips a margin-2 verdict at *zero* root-set
error.

So T5 covers **misattribution** — a root dropped, duplicated, or wrongly
identified, with no assertion changed. It does not cover **compromise**, which
changes assertions by definition. Measured on this aggregator, five supporting
roots against two:

    2 supporting roots removed (assertions preserved) -> verdict survives
    2 supporting roots flipped (assertions changed)   -> verdict REVERSED

Same `k`. Setting `min_flip_budget` from T5 buys protection against the first
column and none against the second. Price compromise with
`conversions_to_reverse`, which is what it is for.

Subject and `observed_at` live in the signed Entry Stamp predicate, not in an
issuer manifest: manifests answer *may this identity testify?*; stamps answer
*is this observation current and about this case?* Derived claims must retain
their root subject or are quarantined. Default freshness is configurable:
probes decay with a five-minute half-life; start events expire after 24 hours;
origins without a policy do not decay; a missing timestamp under a policy is
expired.

What this gate does NOT do: verify signatures itself (bring a verifier),
decide which tool boundaries count as roots (that's your runtime's stamping
policy), or protect root signing keys (that's ops). The attack surface it
leaves is exactly: *compromise of root signing keys* — stated per-decision
by `flip_budget`.

## State Reconciliation

`reconcile()` answers a different operational question: many status views,
one job state. It counts receipt roots rather than board voices and returns
`None` as **unverified** on a tie or a configured thin margin.

```python
from minority_prophet import reconcile
import json

status_claims = [json.loads(line) for line in open("examples/state_reconciliation.jsonl")]
state = reconcile(status_claims, freshness={"half_life_s": 600})
print(state.state, state.flip_budget)  # exited, ~2.0
```

Rule: receipts are roots, everything else is derived, and derived claims
never outrank a root. Freshness applies to roots only; a root without an
observation time under a freshness policy is excluded conservatively.

## Status

## Selective decision ladder

`selective_decide` keeps explicit deterministic policy primary. Clear allows
and denies do not invoke the provenance challenger. Only an action marked
evidence-sensitive (or returned as `review`) enters independent-root
assessment. Contradictory evidence blocks; balanced, missing, or thin evidence
escalates to a separately authorized human. Escalation is not permission, and
evidence cannot override a deterministic deny.

Evidence-sensitive policy may independently require both attack prices:
`min_flip_budget` for newly forged opposing root mass and
`min_conversions_to_reverse` for compromised winning roots. The latter is
optional for backward compatibility. When configured, a missing or sub-threshold
conversion price escalates; it can never inherit the deterministic allow.

This routing contract is an execution-safety policy, not a claim that the
provenance method is globally more accurate than ordinary authorization rules.

Two reference runtime integrations exercise the neutral boundary: an
allowlisted in-process tool adapter and an idempotent HTTP adapter. Both bind
the exact payload digest and idempotency key. The HTTP target and any
in-process handler must persist idempotency outcomes to provide crash-safe
exactly-once effects; the reference controller's in-memory ledger alone does
not provide that production guarantee.

`v0.1.1` — reference implementation. Aggregator core is conformance-tested
against spec-derived vectors and backed by exhaustively machine-checked
theorems; the ACP adapter and gate policy are new and seeking adversarial
review. Not yet battle-tested against hostile inputs in production.
Issues, attack attempts, and counterexamples are actively invited — a
counterexample to T1/T2 within the stated preconditions is a research
result, and we will credit and publish it.

## Repo layout

```
minority_prophet/aggregator.py   # machine-checked core: Claim, EvidenceGraph, aggregate()
minority_prophet/adapter_acp.py  # envelopes -> verified Claims (security model here)
minority_prophet/gate.py         # decide(): proceed / block / escalate + flip_budget
minority_prophet/reconcile.py    # reconcile(): many status sources, one state
minority_prophet/runtime_adapter.py # neutral prepare/execute-once/prevent boundary
minority_prophet/runtime_integrations.py # in-process and idempotent HTTP adapters
examples/pr482.jsonl           # the 9-message scenario from the paper
tests/                         # unit + end-to-end attack tests + conformance vectors
```

## Cite

See `CITATION.cff`. Research: the minority-prophet repository (paper draft,
proofs, benchmarks E1–E8b).

## License

Licensed under Apache License 2.0. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).
