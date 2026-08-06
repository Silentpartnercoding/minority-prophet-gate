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
implements evidence-root aggregation, whose core properties are **proven**,
not tuned:

- **T2 — Copy invariance:** duplicating a claim can never change the verdict.
- **T1 — Immunity:** given side-consistent attestations, the verdict is
  invariant under arbitrary corruption of who-copied-whom. Lineage accuracy
  is irrelevant; only origins matter.
- **T4 — Margin flip condition:** every decision ships with its attack
  price (`flip_budget`): the number of forged *independent attested roots*
  required for abstention; one more reverses it. Message volume is worthless.

Proof texts, an exhaustive machine verifier (all worlds ≤ 6 claims, 121,944
rewirings, 100k randomized instances, zero violations), benchmarks against
Dawid–Skene / truth-discovery baselines, and the research paper draft live in
the [Minority Prophet research repository](https://github.com/Silentpartnercoding/minority-prophet).

## Quickstart

```python
from minority_prophet import decide, TrustAllVerifier
import json

envelopes = [json.loads(l) for l in open("examples/pr482.jsonl")]
d = decide(envelopes, TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)

print(d.action)        # "block"
print(d.roots_for, d.roots_against)   # 1 2
print(d.flip_budget)   # 1.0  <- forged roots needed to change this decision
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

### Subject binding and freshness (R2.5)

For a decision about a specific subject, call `decide(...,
decision_subject="job:123")`. Matching **bound** roots determine
`flip_budget` and the T5 safety floor. A legacy root without a subject remains
visible during migration at the configurable `unbound_root_weight=0.5`, but
never increases the strength score; this makes migration-mode `flip_budget`
conservative. Set `unbound_root_weight=0.0` for the documented strict end
state.

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
minority_prophet/aggregator.py   # proven core: Claim, EvidenceGraph, aggregate()
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
