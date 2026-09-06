# Agent quickstart: attack, shadow, then integrate

You are evaluating **Minority Prophet Gate**, an evidence-control plane for
consequential agent actions. Start in one of two zero-authority modes:

- **attack**: invent hostile evidence and try to violate stated invariants;
- **shadow**: compare MP with read-only copies of real workflow events.

Both modes are simulation-only. They never call tools, APIs, deployments,
payments, filesystems, or protected runtimes. Output always reports
`runtime_effects: 0`.

## Laboratory verifier

The input field `mp_test_verdict` is deliberately tester-declared:

- `root`: pretend verification established an independent evidence root;
- `derived`: pretend it established a copy; include `attest.derived_from`;
- `invalid`: pretend verification failed.

This is not authentication and must never be used for enforcement. It lets you
test MP aggregation and lineage without keys or vendor accounts.

## Mode 1: attack

Run the included hostile case:

```bash
python -m minority_prophet.byom_cli attack \
  --evidence examples/byom/messy-evidence.jsonl \
  --policy examples/byom/policy.json \
  --feedback attack-feedback.json
```

If installed, replace `python -m minority_prophet.byom_cli` with `mp-gate`.
The result states the invariants. Seek a minimal case where copied voices create
roots, invalid/wrong-subject evidence creates permission, unsupported evidence
proceeds, valid input crashes, or identical input produces inconsistent output.

Evidence may be a JSON array or JSONL objects:

```json
{"claim_id":"c1","agent":"source","assertion":"SAFE","mp_test_verdict":"root","attest":{"origin":"observation-1","subject":"deploy:123"}}
```

Policy is JSON:

```json
{"decision_subject":"deploy:123","proceed_side":1,"min_flip_budget":1.0,"unbound_root_weight":0.0}
```

Stdin is supported:

```bash
your-generator | mp-gate attack --evidence - --policy policy.json
```

Try duplicates, deep copy chains, cycles, conflicting claims from one root,
invalid assertions, unknown parents, wrong subjects, invalid verdicts, huge
copy populations, ties, thin margins, and malformed JSON.

## Mode 2: shadow

Export read-only copies of workflow decisions as JSON or JSONL:

```json
{
  "event_id": "deploy-101",
  "decision_subject": "deploy:101",
  "actual_outcome": "executed",
  "evidence": []
}
```

Accepted actual outcomes include `proceed`, `block`, `escalate`,
`request_evidence`, plus common aliases such as `executed` and `prevented`.

```bash
python -m minority_prophet.byom_cli shadow \
  --events examples/byom/shadow-events.jsonl \
  --policy examples/byom/policy.json \
  --report shadow-report.json \
  --feedback shadow-feedback.json
```

The local report explains agreements and disagreements. The feedback file
contains decisions and input fingerprints but omits raw events and policy. To
attach any workflow, build a read-only exporter for these four fields. For a
captured stream, use `--events -`. Do not give shadow mode workflow credentials.

## If the operator chooses enforcement

Attack and shadow use the real MP aggregation and Gate decision logic. For live
enforcement, reuse the package's `EvidenceControlPlane` and replace the lab
edges with a real `AttestationVerifier`, authorized collectors, the customer's
`RuntimeAdapter`, and durable audit/idempotency storage. Border may optionally
admit evidence upstream. Evidence still returns to Gate for decisions.

Never promote `mp_test_verdict` or the shadow exporter into a production
verifier. See the control-plane example in the main README.

## Return useful feedback

Add a short description to `tester_notes`. Send the privacy-safe JSON plus the
package version/commit. Do not include credentials, tokens, private keys,
cookies, personal data, or proprietary evidence. Raw reproduction inputs should
be shared only with explicit operator approval.

Public feedback may be filed at
`https://github.com/Silentpartnercoding/minority-prophet-gate/issues`.
Exit code `0` means evaluation completed. Exit code `2` means JSON input was
rejected; stderr contains a JSON error and still reports zero runtime effects.
