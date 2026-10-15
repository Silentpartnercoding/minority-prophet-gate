# ReleaseWarden Real Crossing v0.1 Design

## Status

Design for review. This document freezes the first externally falsifiable
Mandate → Border → Gate crossing. It does not authorize production enforcement,
publication of credentials, or use on customer systems.

## Outcome

Prove that a real GitHub deployment request can travel through the hosted
ReleaseWarden GitHub App, be evaluated against evidence bound to one exact
commit and one exact environment, and produce a verifiable harmless external
effect.

The crossing is:

```text
owner test instruction
  → exact GitHub commit
  → GitHub Actions + independently operated Semgrep check evidence
  → GitHub deployment request for releasewarden-sandbox
  → GitHub App webhook
  → hosted ReleaseWarden Worker
  → Mandate validation
  → Border continuity checks
  → Gate shadow decision
  → GitHub callback
  → disposable Cloudflare preview effect
  → read-back receipt
```

Success is not “the workflow is green.” Success is an evidence bundle that
lets another person verify which authority, commit, checks, environment,
decision, callback, deployed artifact, and observed effect belonged to the same
run.

## Constraints

- Spend no money and do not enable a paid Cloudflare, GitHub, Semgrep, or model
  feature.
- Keep every existing repository separate. This work changes only
  `Silentpartnercoding/minority-prophet-gate` and uses its existing public
  `releasewarden-sandbox` environment.
- Do not expose GitHub App private keys, webhook secrets, Cloudflare tokens,
  account data, D1 contents, or customer material.
- Do not gate a production environment. ReleaseWarden remains shadow-only for
  this milestone and always releases GitHub after recording its decision.
- Do not claim arbitrary natural-language understanding or automatic discovery
  of evidence independence.
- Bind all evidence and receipts to a full 40-character Git commit SHA.
- Prefer pinned action versions and least-privilege credentials.

## Why this crossing

Three approaches were considered:

1. **Wire the existing public repository and environment (selected).** This
   exercises the real GitHub App and hosted Worker with the least new surface.
   The external effect is harmless and disposable.
2. Create a new sandbox repository. This offers stronger isolation but adds a
   second public project, duplicates configuration, and makes the result harder
   to relate to the product under test.
3. Enforce a real deployment immediately. This would demonstrate blocking, but
   it gives an experimental, candidate-controlled policy authority before its
   trust boundary is ready.

The selected approach is the smallest test that crosses a real protocol and
causes an observable effect without making ReleaseWarden a production control.

## Existing reality

- `releasewarden-experimental` is deployed on Cloudflare Workers with D1.
- The Worker validates GitHub webhook signatures, parses GitHub deployment
  protection requests, reads exact-SHA check runs, evaluates `.releasewarden.json`,
  records delivery state, and calls GitHub back.
- The hosted adapter accepts only `mode: shadow` and deliberately sends an
  approval callback even when the recorded Gate decision is reject/escalate.
- The public repository has a `releasewarden-sandbox` GitHub environment, but
  it currently has no custom protection rule enabled.
- The existing dogfood workflow evaluates live check evidence locally and then
  records a no-effect deployment summary. It does not exercise the GitHub App
  webhook or a real external effect.
- The GitHub App slug observed previously is
  `releasewarden-spc-experimental`, but the unauthenticated public App API does
  not currently resolve it. Ownership, installation, webhook target, and App
  permissions must therefore be verified in the authenticated GitHub settings
  UI before wiring.

## Authority model

### Mandate

For v0.1 the owner mandate is a machine-readable, run-scoped deployment intent
created by the workflow. It contains:

- schema and mandate ID;
- repository numeric ID and `owner/name`;
- full subject SHA;
- source workflow run ID and attempt;
- allowed environment: `releasewarden-sandbox`;
- allowed effect: deploy the immutable crossing fixture;
- allowed destination: the dedicated Cloudflare preview Worker;
- issuance and expiry timestamps;
- unique nonce;
- policy revision digest.

The mandate is not a general credential. It authorizes exactly one bounded test
effect and expires after the run.

### Border

Border verifies that meaning survives each representation change:

- GitHub event repository ID and name match the mandate;
- webhook SHA, workflow SHA, evidence SHA, artifact SHA, and receipt SHA match;
- GitHub environment exactly matches `releasewarden-sandbox`;
- check names are accepted only from configured GitHub App slugs;
- evidence is complete and concluded for the subject SHA;
- the effect target and artifact digest have not changed;
- the mandate is fresh and its nonce has not already completed;
- callback URL is the expected GitHub API endpoint for the same repository and
  workflow run.

Any widening, substitution, stale value, or mismatch becomes a recorded
reject/escalate decision. Shadow mode still returns approval to GitHub.

### Gate

Gate is the final deterministic decision immediately before GitHub releases the
deployment job. Its inputs are the validated mandate, Border continuity result,
policy revision, exact-SHA check observations, and replay state. It produces a
structured decision with `proceed`, `block`, `escalate`, or `review` plus
machine-readable reasons.

Gate does not run Semgrep, infer independence, deploy the Worker, or interpret
free-form intent. It judges the supplied evidence and continuity claims.

## Components and changes

### 1. Frozen crossing fixture

Add a tiny immutable HTTP response fixture whose body contains the full subject
SHA, artifact digest, mandate ID, and schema version. It exposes no secrets and
does not call other services.

### 2. Deployment workflow

Replace the existing no-effect `harmless-deploy` step with a separate manual
crossing workflow. It:

1. checks out the exact SHA;
2. waits for the existing test/package/Semgrep evidence;
3. creates the bounded mandate and fixture artifact;
4. references `environment: releasewarden-sandbox`, causing GitHub to call the
   custom protection rule;
5. deploys only the fixture to a dedicated Cloudflare preview Worker after
   GitHub releases the job;
6. reads the public fixture back over HTTPS;
7. compares the returned SHA and digest to the mandate;
8. uploads a non-secret evidence bundle as a GitHub Actions artifact and writes
   a concise run summary.

The workflow has `workflow_dispatch` only for the first milestone. It uses a
GitHub Environment secret containing a narrowly scoped Cloudflare API token and
the Cloudflare account ID. The secret is never printed or placed in an artifact.

### 3. Hosted Worker decision receipt

Extend the hosted ReleaseWarden journal to retain a non-secret decision receipt
for the delivery: delivery ID digest, repository ID, SHA, environment, policy
digest, selected check-run IDs/providers/conclusions, decision, reason, and
timestamps. The public workflow does not receive D1 contents or signing keys.

For v0.1, GitHub's authenticated callback plus the D1 journal are operational
evidence, not a cryptographic proof of the external effect. A signed
ReleaseWarden receipt remains a later milestone.

### 4. Read-back effect receipt

The workflow records:

- Cloudflare deployment command outcome;
- returned public URL;
- HTTPS response status;
- exact response body;
- SHA-256 of the response body;
- observation timestamp;
- GitHub run ID and attempt.

This proves what the test endpoint returned, not that an arbitrary third-party
service performed a real-world action.

## Trust boundaries

The candidate repository currently supplies `.releasewarden.json`. Therefore a
candidate change could weaken its own policy. That makes enforce mode unsafe.
For this milestone:

- the hosted adapter stays shadow-only;
- the crossing workflow compares the candidate policy digest to a frozen
  expected digest stored in the workflow;
- a mismatch is recorded as a failed continuity test;
- future enforcement must load policy from a protected branch, GitHub App
  configuration, or an external control-plane store.

Semgrep counts as a separate evidence provider only at the service/credential
boundary. ReleaseWarden does not claim that this alone establishes complete
organizational independence.

## Failure behavior

- Invalid webhook signature or malformed event: HTTP rejection; no callback or
  deployment claim.
- Duplicate GitHub delivery: return the previously recorded outcome and do not
  evaluate or callback twice.
- Missing/pending/wrong-provider evidence: record `escalate`; shadow callback
  approves so the sandbox experiment can finish.
- Failed evidence or continuity mismatch: record `block`; shadow callback
  approves.
- GitHub callback failure: retain retryable journal state and do not call the
  event completed.
- Cloudflare deployment failure: workflow fails; no successful effect receipt.
- Read-back mismatch: workflow fails even if deployment command succeeded.
- Secrets unavailable: workflow fails closed before deployment.

## Falsification matrix

Each test records expected and observed outcomes:

| Case | Expected Gate result | Expected external effect |
|---|---|---|
| Correct mandate, SHA, evidence, target | proceed | matching fixture is observable |
| Missing Semgrep check | escalate | shadow-only effect may occur; clearly labeled |
| Pending required check | escalate | workflow waits, then fails on timeout |
| Failed required check | block | shadow-only effect may occur; clearly labeled |
| Evidence from another SHA | block | no successful matching receipt |
| Environment changed | block | no authorized matching receipt |
| Destination or artifact digest changed | block | read-back verification fails |
| Duplicate delivery ID | prior decision reused | callback/evaluation not duplicated |
| Reused mandate nonce | block | no second valid receipt |
| Candidate changes policy digest | block | no valid continuity receipt |
| Copied checks assigned fake domains | review/reject in corpus | no independence claim |
| Valid deployment but returned body mutated | proceed at Gate, receipt failure | effect is not certified |

Because hosted mode is shadow-only, “external effect may occur” is an explicit
experimental limitation, not an enforcement claim. The run summary must show
both the hypothetical Gate decision and GitHub's actual released state.

## Verification and acceptance

The milestone is complete only when:

1. Existing Python and Worker unit tests pass from a clean checkout.
2. New tests cover mandate parsing, exact binding, policy digest, target digest,
   nonce reuse, journal retry state, and receipt construction.
3. Worker dry-run/config validation passes without exposing secrets.
4. The GitHub App identity, installation, permissions, event subscription, and
   webhook URL are recorded in a private operator checklist.
5. The custom protection rule is enabled only on `releasewarden-sandbox`.
6. One live positive run produces a matching read-back receipt.
7. At least the wrong-SHA, policy-mutation, failed-check, replay, and returned-
   body-mutation cases produce their expected failures.
8. The public artifact contains no credentials, tokens, private keys, account
   IDs, D1 rows, or private repository data.
9. The environment is returned to shadow-safe state after the experiment.

## Explicit non-goals

- Production enforcement or a paid pilot.
- A permanent general-purpose deployment host for customers.
- Automated semantic equivalence for arbitrary natural language.
- OpenID/OAuth delegation across A2A → MCP → x402 in this milestone.
- Signed external-service receipts.
- Distributed replay storage across multiple providers.
- Automatic proof that two checks are genuinely independent.
- Publishing the GitHub App for third-party installation.

## Next milestone after this one

Once the crossing is reproduced, move policy out of the candidate revision and
run the same corpus in `enforce` against a disposable environment. Only after
that should the work add OpenID-authenticated delegation and a real MCP or x402
boundary. This keeps the first claim narrow: ReleaseWarden can preserve and
evaluate exact authority continuity across a real GitHub deployment boundary.
