# Evidence routing contract

The Gate identifies an unresolved evidence requirement. It does not ask an
LLM to decide who should investigate. The provider-owned policy selects a
collector route when the requirement is defined.

```text
requesting agent
      |
      v
deterministic Gate -- request_evidence --> evidence router
                                            |       |       |       |
                                            v       v       v       v
                                           agent  epistemic human  program
                                           again  service
                                            |       |       |       |
                                            +-------+-------+-------+
                                                    |
                                             attested evidence
                                                    |
                                                    v
                                           deterministic Gate again
```

An `epistemic_service` route can be implemented by Minority Prophet, but the
contract does not mention or require Minority Prophet. Any adapter with the
configured capability can serve the route.

## Policy mapping

Typical mappings are:

| Missing evidence | Collector kind | Output role | Example capability |
|---|---|---|---|
| Test output, repository artifact, or ordinary receipt | `requesting_agent` | `candidate_evidence` | `test.execution` |
| Source ancestry, copying, or evidence independence | `epistemic_service` | `verification_artifact` | `provenance.analysis` |
| Approval or judgment only a person may provide | `human` | `human_handoff` | `judgment.review` |
| Independent artifact validation | `program` | policy-selected | `artifact.verify` |

The mapping is explicit in `CollectorRoute`; it is not inferred from prose at
runtime. Requirements that must be independent set `requires_independence`.
The router then rejects an adapter in the requester's control domain. Accurate
control-domain labeling remains a caller responsibility.

Output roles stop a provenance service from becoming another vote. Candidate
evidence may carry an assertion into the ordinary verifier. A verification
artifact may qualify, collapse, or reject that original evidence but cannot
carry its own assertion. A human handoff cannot be converted into collected
evidence by the router.

## Authority boundaries

There are three distinct decisions:

1. The Gate may issue an evidence request. This grants no authority.
2. A provider-owned `CollectionAuthorizer` may permit the exact evidence
   dispatch and its least-privilege collection actions. This permits only
   evidence collection, not the protected action.
3. After returned envelopes pass the normal verifier and evidence assessment,
   the Gate may produce a final operational decision.

The router verifies the challenge, route, action digest, subject, policy,
collector kind, capability, control-domain constraint, collection authorization,
result bindings, accepted evidence kinds, requirement coverage, and item cap.
Raw returned evidence never enters the router audit log.

The returned `evidence_kind` wrapper must match `attest.evidence_kind` inside
the envelope. A production verifier must include that field in the signed
predicate; otherwise an adapter could relabel an artifact after it was issued.

## Audit and recovery

`EvidenceAuditLog` records a hash-chained event sequence:

```text
challenge_received
route_planned
dispatch_authorized | dispatch_denied
dispatch_started
collection_returned | collection_failed
gate_reassessed
```

Router operations emit the collection events automatically. After the returned
envelopes are reassessed, the orchestrator calls `record_gate_decision` with the
result so the final Gate handback is appended without copying raw evidence.

Dispatch intent is recorded before invoking a collector. If collection crashes
after that point, the same dispatch fails closed rather than running again. A
new attempt requires reconciliation or a new challenge round.

The optional JSONL backend flushes and fsyncs every event and verifies its hash
chain when reopened. It is suitable as a single-process reference artifact,
not as a multi-process transactional ledger. Event hashes detect drift; without
an external integrity authority they do not prevent an attacker from rewriting
the entire file and recomputing every hash.

`AuthenticatedSqliteEvidenceLedger` is the stronger local implementation. It
uses SQLite transactions for the event chain, derived dispatch state, evidence
artifacts, and pending human-review records. Every event and artifact is bound
with HMAC-SHA256 under a caller-supplied key that is never stored in the
database. It verifies the complete chain and derived state on reopen, stores
returned evidence by digest outside audit-event bodies, and leaves interrupted
dispatches unresolved so they cannot silently run twice.

Concrete neutral adapters are included for:

- `HttpEpistemicCollector`: sends an exact packet and proposal to an
  authenticated read-only receipt service. Loopback is required by default;
  remote endpoints need explicit opt-in.
- `HumanQueueCollector`: durably creates a pending handoff and returns
  `needs_human`; it cannot invent or convert a human decision.
- `ConstrainedSubprocessCollector`: invokes one fixed command without a shell,
  checks every configured executable/script digest, uses JSON stdin/stdout,
  and applies time and response-size limits.

The subprocess adapter pins program identity and invocation. It is not an OS
sandbox: filesystem, network, syscall, and resource isolation must still be
provided by the embedding deployment. Likewise, the SQLite HMAC boundary is
only as strong as external key custody and host integrity. Live URLs, keys,
human identity, control-domain registry protection, and deployment policy are
configuration responsibilities and are deliberately absent from this repo.
