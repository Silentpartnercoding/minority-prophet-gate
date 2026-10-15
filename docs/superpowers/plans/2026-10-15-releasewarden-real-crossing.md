# ReleaseWarden Real Crossing v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove a real, no-cost GitHub deployment-protection crossing from an exact commit and independent check evidence through the hosted shadow ReleaseWarden App to a harmless Cloudflare fixture and verified read-back receipt.

**Architecture:** The existing hosted Worker remains shadow-only and gains explicit run-scoped mandate/continuity validation plus durable non-secret receipts. A manual GitHub Actions workflow builds a deterministic fixture, enters the existing `releasewarden-sandbox` environment, deploys only to a dedicated Cloudflare Worker, reads the effect back, and publishes a sanitized evidence artifact. Live wiring happens only after local tests, dry-run validation, authenticated App inspection, and an owner checkpoint.

**Tech Stack:** JavaScript ES modules, Node.js test runner, Cloudflare Workers/D1/Wrangler, pinned `fflate` ZIP decoding, GitHub Actions artifacts, GitHub App deployment protection rules, Semgrep Cloud Platform, SHA-256 JSON canonicalization.

**Spec:** `docs/superpowers/specs/2026-10-15-releasewarden-real-crossing-design.md`

## Global Constraints

- Spend no money and do not enable a paid Cloudflare, GitHub, Semgrep, or model feature.
- Change only `Silentpartnercoding/minority-prophet-gate`; do not combine or move the other repositories.
- Keep `releasewarden-experimental` shadow-only and never attach it to a production environment.
- Use only the public `releasewarden-sandbox` environment and a dedicated harmless Cloudflare fixture Worker.
- Never print, commit, upload, or return GitHub App keys, webhook secrets, Cloudflare tokens, D1 contents, or private account data.
- Every authority, evidence, artifact, deployment, and receipt record uses the same full 40-character Git commit SHA.
- Candidate-controlled policy may be observed but may not become authoritative for enforcement.
- External mutations require an explicit preflight checkpoint after account, target, permissions, cost, and secret handling are verified.

## Review Focus

- **Canonical JSON ambiguity:** mandates with reordered keys must hash identically, while changed values must not; Task 1 pins both cases.
- **Cross-run substitution:** a mandate from another repository, SHA, environment, run attempt, target, or policy digest must fail continuity; Task 1 tests every binding.
- **Crash/retry races:** a callback failure must remain retryable while a completed delivery must not callback or consume the mandate twice; Task 2 tests both transitions.
- **Untrusted workflow output:** fixture and evidence paths must reject symlinks, unexpected files, and secret-shaped content; Tasks 3 and 4 test and scan artifacts.
- **Shadow ambiguity:** every report must distinguish hypothetical Gate outcome from GitHub's actual approval and external effect; Tasks 2, 4, and 6 assert the labels.

---

## File Map

- `cloudflare/releasewarden-worker/src/crossing.mjs` — pure mandate, canonical digest, continuity, and sanitized receipt contracts.
- `cloudflare/releasewarden-worker/src/github-artifact.mjs` — bounded retrieval and extraction of the run-scoped mandate artifact.
- `cloudflare/releasewarden-worker/src/index.mjs` — webhook orchestration, GitHub evidence collection, D1 lifecycle, and shadow callback.
- `cloudflare/releasewarden-worker/migrations/0002_crossing_receipts.sql` — durable mandate nonce and receipt fields/indexes.
- `cloudflare/releasewarden-worker/test/crossing.test.mjs` — pure contract and attack tests.
- `cloudflare/releasewarden-worker/test/github-artifact.test.mjs` — artifact identity, redirect, ZIP, size, and traversal tests.
- `cloudflare/releasewarden-worker/test/webhook.test.mjs` — D1/callback retry and replay integration tests with fakes.
- `cloudflare/releasewarden-crossing-fixture/src/index.mjs` — inert read-only effect endpoint.
- `cloudflare/releasewarden-crossing-fixture/test/index.test.mjs` — exact response and route tests.
- `cloudflare/releasewarden-crossing-fixture/package.json` — pinned Wrangler and tests.
- `cloudflare/releasewarden-crossing-fixture/wrangler.jsonc` — dedicated fixture Worker configuration with no bindings.
- `scripts/releasewarden-crossing.mjs` — local/workflow CLI for mandate creation, fixture generation, and read-back verification.
- `tests/releasewarden-crossing-cli.test.mjs` — CLI behavior and malicious-path tests.
- `.github/workflows/releasewarden-crossing.yml` — manual evidence/deployment/read-back crossing.
- `examples/releasewarden/crossing/` — non-secret frozen examples and expected adversarial vectors.
- `RELEASEWARDEN.md` — operator procedure, limitations, cleanup, and reproduction instructions.
- `cloudflare/releasewarden-worker/README.md` — migration/deployment procedure and receipt schema.

### Task 1: Freeze the mandate and Border continuity contracts

**Files:**
- Create: `cloudflare/releasewarden-worker/src/crossing.mjs`
- Create: `cloudflare/releasewarden-worker/test/crossing.test.mjs`
- Create: `examples/releasewarden/crossing/mandate.valid.json`
- Create: `examples/releasewarden/crossing/attack-vectors.json`

**Interfaces:**
- Produces: `canonicalJson(value: JsonValue): string`
- Produces: `sha256Digest(value: JsonValue | string | Uint8Array): Promise<string>` returning `sha256:<64 lowercase hex>`.
- Produces: `validateMandate(raw: unknown, now: Date): Mandate`
- Produces: `evaluateContinuity(deployment: Deployment, mandate: Mandate, context: CrossingContext): ContinuityResult`
- `Mandate` contains schema, mandate ID, repository ID/name, SHA, run ID/attempt, environment, effect kind, destination, artifact digest, issued/expiry timestamps, nonce, and policy digest.
- `ContinuityResult` contains `valid`, stable `code`, and sanitized `details`; it never contains credentials.

- [ ] **Step 1: Write failing canonicalization and digest tests**

Assert that reordered object keys produce the same canonical string/digest, array order remains significant, duplicate JSON keys are impossible after parsing, unsupported numbers/values throw, and a one-byte value change changes the digest.

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `cd cloudflare/releasewarden-worker && node --test test/crossing.test.mjs`

Expected: FAIL because `src/crossing.mjs` does not exist.

- [ ] **Step 3: Implement canonical JSON and SHA-256 helpers**

Implement the exact exported signatures above using Web Crypto only; reject non-JSON values, non-finite numbers, and unsafe integers.

- [ ] **Step 4: Write failing mandate validation tests**

Assert acceptance of `mandate.valid.json`; reject unknown fields, wrong schema, non-full SHA/digests, malformed IDs, empty destination, issue time in the future, expiry at/before issue time, expired mandates, expiry more than 30 minutes after issue, and nonce shorter than 128 bits encoded as 32 lowercase hex characters.

- [ ] **Step 5: Implement `validateMandate(raw, now)`**

Return a normalized frozen object and stable validation errors without accepting defaults for authority-bearing fields.

- [ ] **Step 6: Write failing exact-binding tests**

For repository ID/name, SHA, run ID, run attempt, environment, effect kind, destination, artifact digest, policy digest, and time window, mutate one field at a time and assert `evaluateContinuity` returns `valid: false` with the expected stable code.

- [ ] **Step 7: Implement `evaluateContinuity` and frozen attack vectors**

Use equality and freshness checks only; do not add fuzzy or natural-language equivalence. Populate `attack-vectors.json` with the valid case plus one mutation per binding.

- [ ] **Step 8: Verify Task 1**

Run: `cd cloudflare/releasewarden-worker && node --test test/crossing.test.mjs && npm test`

Expected: all tests PASS.

- [ ] **Step 9: Commit Task 1**

```bash
git add cloudflare/releasewarden-worker/src/crossing.mjs cloudflare/releasewarden-worker/test/crossing.test.mjs examples/releasewarden/crossing
git commit -m "feat: freeze ReleaseWarden crossing mandate"
```

### Task 2: Bind the hosted webhook decision and durable journal

**Files:**
- Modify: `cloudflare/releasewarden-worker/src/index.mjs`
- Create: `cloudflare/releasewarden-worker/src/github-artifact.mjs`
- Create: `cloudflare/releasewarden-worker/migrations/0002_crossing_receipts.sql`
- Create: `cloudflare/releasewarden-worker/test/github-artifact.test.mjs`
- Create: `cloudflare/releasewarden-worker/test/webhook.test.mjs`
- Modify: `cloudflare/releasewarden-worker/test/core.test.mjs`
- Modify: `cloudflare/releasewarden-worker/package.json`
- Create: `cloudflare/releasewarden-worker/package-lock.json`

**Interfaces:**
- Consumes: Task 1 `validateMandate`, `sha256Digest`, and `evaluateContinuity`.
- Produces: `buildDecisionReceipt(deployment, mandate, policy, observations, continuity, decision, timestamps): DecisionReceipt`
- Produces: `fetchMandateArtifact(deployment, token, fetchImpl): Promise<{mandate: unknown, artifact: ArtifactIdentity}>`
- Produces: a testable `processWebhook(request, env, dependencies?)` export.
- D1 stores mandate ID, nonce hash, policy digest, receipt JSON, callback status, and timestamps; raw nonce is not stored.

- [ ] **Step 1: Write failing receipt-construction tests**

Assert that receipts contain schema, hashed delivery identifier, repository ID/name, full SHA, environment, mandate ID, nonce hash, policy digest, sorted selected check IDs/providers/conclusions, hypothetical Gate outcome, actual callback state `approved`, and timestamps; assert absence of tokens, keys, raw nonce, callback URL, and request body.

- [ ] **Step 2: Write failing D1 lifecycle tests with an in-memory fake**

Cover new delivery, same-body concurrent delivery, same-ID/different-body replay, callback failure → `failed`, retry of failed delivery, completed replay returning the prior receipt without another callback, and a different delivery attempting to reuse a completed mandate nonce.

- [ ] **Step 3: Add the additive D1 migration**

Add nullable crossing columns to preserve existing rows, a unique partial index for completed nonce hashes, and a callback status constrained to `pending|approved|failed`. Never delete or rewrite `0001_deliveries.sql`.

- [ ] **Step 4: Write failing mandate-artifact transport tests**

Using generated ZIP fixtures, require exactly one unexpired artifact named `releasewarden-mandate-v1` from the webhook workflow run with matching repository ID and head SHA. Reject zero/duplicate artifacts, expired artifacts, archive redirects outside GitHub's documented download host flow, downloads over 64 KiB, ZIPs with more than one entry, any entry not exactly `mandate.json`, absolute/traversal paths, symlinks, encrypted entries, unsupported compression, decompressed content over 32 KiB, and GitHub artifact digest mismatch.

- [ ] **Step 5: Implement bounded artifact retrieval and extraction**

Pin `fflate` to an exact reviewed version and commit the lockfile. Use the GitHub App installation token with Actions read, disable ambient redirects, allow only GitHub's documented short-lived artifact redirect, cap compressed and decompressed bytes, and parse only one JSON object. Do not expose the signed download URL in errors or receipts.

- [ ] **Step 6: Export and refactor `processWebhook` around injected dependencies**

Keep production defaults unchanged. Separate parse/authentication, evidence collection, continuity evaluation, callback, and journal completion so tests can fail each boundary deterministically.

- [ ] **Step 7: Load and bind the mandate without expanding GitHub permissions**

Use `workflow_run.id` from the authenticated deployment-protection webhook to retrieve the single mandate artifact through the Actions API, compute the exact candidate policy digest, compare it to the frozen digest encoded by the trusted main-branch workflow, and evaluate continuity before Gate. On absence or mismatch, record `block` or `escalate` according to the frozen vector while still sending the shadow approval callback.

- [ ] **Step 8: Build and persist the sanitized receipt only after callback outcome is known**

Record failed callbacks as retryable. Mark completed only after GitHub accepts the callback. A completed replay returns the same stored receipt and performs no external call.

- [ ] **Step 9: Verify Task 2**

Run: `cd cloudflare/releasewarden-worker && node --test test/core.test.mjs test/crossing.test.mjs test/github-artifact.test.mjs test/webhook.test.mjs && npm audit --omit=dev && npm run deploy:dry`

Expected: all tests PASS; Wrangler dry run succeeds; output contains no secret values.

- [ ] **Step 10: Commit Task 2**

```bash
git add cloudflare/releasewarden-worker/src cloudflare/releasewarden-worker/test cloudflare/releasewarden-worker/migrations/0002_crossing_receipts.sql cloudflare/releasewarden-worker/package.json cloudflare/releasewarden-worker/package-lock.json
git commit -m "feat: persist ReleaseWarden continuity receipts"
```

### Task 3: Build the harmless immutable effect fixture

**Files:**
- Create: `cloudflare/releasewarden-crossing-fixture/src/index.mjs`
- Create: `cloudflare/releasewarden-crossing-fixture/test/index.test.mjs`
- Create: `cloudflare/releasewarden-crossing-fixture/package.json`
- Create: `cloudflare/releasewarden-crossing-fixture/wrangler.jsonc`

**Interfaces:**
- Produces: `fixtureResponse(env): object` with schema, full SHA, artifact digest, mandate ID, and policy digest.
- HTTP `GET /effect` returns only that JSON with `cache-control: no-store`.
- All other methods/routes return `404`; the Worker has no service, D1, KV, R2, AI, Queue, Durable Object, or route bindings.

- [ ] **Step 1: Write failing fixture tests**

Assert exact keys and values, no environment dump, `GET /effect` success, no-store caching, and 404 for `/`, other routes, POST, query-based attempts to override values, and malformed configuration.

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `cd cloudflare/releasewarden-crossing-fixture && npm test`

Expected: FAIL because the implementation does not exist.

- [ ] **Step 3: Implement the minimal read-only Worker and configuration**

Use only build-time non-secret vars supplied by Wrangler for the four receipt fields. Set `preview_urls: false` and use the fixed name `releasewarden-crossing-fixture`.

- [ ] **Step 4: Verify no paid bindings or write paths exist**

Run: `cd cloudflare/releasewarden-crossing-fixture && npm test && npx wrangler deploy --dry-run`

Expected: all tests PASS; dry-run bindings list contains only non-secret vars.

- [ ] **Step 5: Commit Task 3**

```bash
git add cloudflare/releasewarden-crossing-fixture
git commit -m "feat: add harmless crossing fixture"
```

### Task 4: Create and verify the workflow evidence bundle

**Files:**
- Create: `scripts/releasewarden-crossing.mjs`
- Create: `tests/releasewarden-crossing-cli.test.mjs`
- Create: `.github/workflows/releasewarden-crossing.yml`
- Modify: `.gitignore`

**Interfaces:**
- CLI `create --context <json> --policy <json> --out <directory>` writes canonical `mandate.json`, `effect.json`, and `manifest.json`.
- CLI `verify --manifest <json> --response <json> --out <receipt.json>` checks exact SHA/digests/IDs and writes a sanitized effect receipt.
- CLI never reads process environment wholesale and never serializes secret variables.

- [ ] **Step 1: Write failing CLI tests**

Test deterministic output, full-SHA requirement, bounded validity, random 128-bit nonce, policy digest, artifact digest, wrong-SHA/target/body rejection, symlink output rejection, non-empty output-directory rejection, extra response-field rejection, and secret-shaped value rejection in the final bundle.

- [ ] **Step 2: Implement the CLI with explicit input allowlists**

Use Node standard library only. Write files with owner-only permissions locally; workflow artifacts contain only the sanitized manifest/mandate/effect receipt.

- [ ] **Step 3: Write the manual crossing workflow**

Use `workflow_dispatch` restricted at runtime to `refs/heads/main`, pinned actions, minimal top-level permissions, a build job with read-only contents/actions/checks, and a deployment job with `environment: releasewarden-sandbox`. Wait for the exact configured checks with a bounded timeout, invoke the CLI, upload exactly `mandate.json` as `releasewarden-mandate-v1` before the environment job, deploy the fixture using scoped environment secrets, fetch `/effect`, invoke `verify`, upload only the sanitized result bundle, and always label Gate decision separately from actual GitHub approval.

- [ ] **Step 4: Add workflow static assertions**

In the CLI test suite, parse the workflow text and assert: manual-only trigger; hard failure outside `refs/heads/main`; exact environment name; no `pull_request_target`; no shell tracing; no broad `write-all`; no production environment; bounded polling; pinned action SHAs; one mandate artifact containing only `mandate.json`; and result artifact paths limited to the sanitized bundle directory.

- [ ] **Step 5: Verify Task 4 locally**

Run: `node --test tests/releasewarden-crossing-cli.test.mjs && python -m unittest discover -s tests -v && cd cloudflare/releasewarden-worker && npm test && cd ../releasewarden-crossing-fixture && npm test`

Expected: all tests PASS.

- [ ] **Step 6: Scan the staged diff and generated sample bundle**

Run Semgrep locally if available, `git diff --check`, repository secret-pattern checks that report file/line but not matched secret values, and `git status --short`. Manually inspect the generated bundle key names and paths.

- [ ] **Step 7: Commit Task 4**

```bash
git add scripts/releasewarden-crossing.mjs tests/releasewarden-crossing-cli.test.mjs .github/workflows/releasewarden-crossing.yml .gitignore
git commit -m "feat: add real crossing workflow"
```

### Task 5: Document operator preflight, adversarial runs, and cleanup

**Files:**
- Modify: `RELEASEWARDEN.md`
- Modify: `cloudflare/releasewarden-worker/README.md`
- Create: `docs/releasewarden-crossing-operator-checklist.md`

**Interfaces:**
- Produces: a private-values-free checklist that records only verified App slug/owner, installed repository, permission names, event subscription, redacted webhook hostname/path, Worker names, environment name, and pass/fail timestamps.
- Produces: exact reproduction commands for the positive run and five mandatory adversarial cases.

- [ ] **Step 1: Document the three distinct outcomes**

Explain hypothetical Gate outcome, GitHub's actual shadow approval, and read-back effect verification in ELI5 language and in the receipt schema.

- [ ] **Step 2: Document authenticated preflight without secret capture**

Checklist: correct GitHub owner identity, exact App slug, installation limited to this repository, Actions read, Contents read, Deployments read/write, deployment-protection event, exact webhook `/github/webhook`, Cloudflare account identity, free-plan confirmation, dedicated fixture name, D1 migration status, and environment secrets present by name only.

- [ ] **Step 3: Document the mandatory adversarial sequence**

Run positive first, then wrong SHA, policy mutation, failed synthetic check/fixture, replay, and returned-body mutation. For cases that cannot safely alter GitHub checks, use the frozen offline corpus and label them offline rather than implying a live failure.

- [ ] **Step 4: Document rollback and cleanup**

Disable the custom protection rule, delete the dedicated fixture Worker if desired, remove the two environment secrets, preserve sanitized GitHub artifacts, and leave the ReleaseWarden control Worker in shadow mode. State which actions are reversible.

- [ ] **Step 5: Verify docs against commands and configuration**

Run every read-only command and every local example. Check all referenced paths with `test -e` and all workflow names with `rg`.

- [ ] **Step 6: Commit Task 5**

```bash
git add RELEASEWARDEN.md cloudflare/releasewarden-worker/README.md docs/releasewarden-crossing-operator-checklist.md
git commit -m "docs: add crossing operations and falsification guide"
```

### Task 6: Complete repository verification and independent review

**Files:**
- Modify only files required by verified review findings.

**Interfaces:**
- Consumes: all Tasks 1–5.
- Produces: a clean, immutable candidate commit suitable for a pull request; no live external mutations yet.

- [ ] **Step 1: Run the complete local suite from a clean dependency install**

Run Python 3.10-compatible unit tests, package build/install smoke test, Worker tests/dry run, fixture tests/dry run, CLI tests, policy examples, and `git diff --check`.

- [ ] **Step 2: Run Semgrep and repository secret scanning**

Use the configured project/rules without uploading private files. Record counts and rule identifiers, not source snippets containing possible secrets. Fix confirmed findings; document justified false positives.

- [ ] **Step 3: Review the branch against the spec**

Check every acceptance criterion and falsification vector. Pay special attention to callback idempotency, candidate-controlled policy, nonce races, receipt sanitization, and shadow labeling.

- [ ] **Step 4: Commit verified review fixes separately**

```bash
git add <reviewed-files>
git commit -m "fix: address real crossing review"
```

- [ ] **Step 5: Push the branch and open a public pull request**

Before publication, verify the GitHub sender/owner identity, repository, base branch, title, body, and absence of secret/private material. The PR must state that it is shadow-only, costs nothing under the selected tiers, and has not yet exercised live enforcement.

### Task 7: Authenticated live preflight and owner checkpoint

**Files:**
- No repository changes unless the preflight exposes a documented mismatch.

**Interfaces:**
- Produces: completed `docs/releasewarden-crossing-operator-checklist.md` locally or as a sanitized PR comment/artifact; secret values remain only in GitHub/Cloudflare secret stores.

- [ ] **Step 1: Verify the GitHub App in authenticated settings**

Record exact owner, slug, installation repository, permissions, subscribed event, active status, and webhook hostname/path. Stop on any identity or target mismatch.

- [ ] **Step 2: Verify the GitHub environment**

Confirm `releasewarden-sandbox` is the only target, has no production secrets, and supports the custom protection rule on the current plan.

- [ ] **Step 3: Verify Cloudflare identity, plan boundary, and existing host**

Confirm account, `releasewarden-experimental`, D1 binding, `/healthz`, current deployment version, and no paid bindings. Do not display OAuth tokens or secrets.

- [ ] **Step 4: Prepare narrowly scoped fixture credentials**

Create or reuse only a token restricted to Workers Scripts edit for the dedicated fixture Worker/account where Cloudflare supports that scope. Store token and account ID as environment secrets; never repository secrets or plaintext files.

- [ ] **Step 5: Present the mutation checkpoint**

Report exact App, repository, environment, Worker names, expected free-tier effect, secrets by name, migration to apply, custom rule to enable, and rollback. Obtain explicit owner approval before Tasks 8–9.

### Task 8: Deploy the shadow control update and wire the sandbox rule

**Files:**
- No new source files; this task changes Cloudflare/GitHub experimental configuration.

**Interfaces:**
- Consumes: approved Task 7 checkpoint and verified candidate commit.
- Produces: migrated D1, deployed shadow Worker, GitHub App webhook health, and one custom rule attached only to `releasewarden-sandbox`.

- [ ] **Step 1: Back up non-secret configuration metadata**

Record current Worker version ID, D1 migration list, App permission names, webhook target, and environment rules. Do not export secrets or D1 rows.

- [ ] **Step 2: Apply D1 migration remotely**

Run the version-controlled migration through Wrangler and verify the migration name appears once.

- [ ] **Step 3: Deploy the updated ReleaseWarden Worker**

Deploy from the verified commit, call `/healthz`, inspect bounded logs for errors, and retain the prior version ID for rollback.

- [ ] **Step 4: Verify or correct the GitHub App webhook configuration**

Use the exact Worker `/github/webhook` endpoint, keep the existing webhook secret, confirm SSL verification and deployment-protection subscription, and send no synthetic unsigned event.

- [ ] **Step 5: Enable the custom protection rule only on `releasewarden-sandbox`**

Verify the rule list immediately afterward. Abort and roll back if any other environment changes.

### Task 9: Run, falsify, report, and leave the system safe

**Files:**
- Add only sanitized result fixtures or documentation if the observed schema differs from the frozen expectation.

**Interfaces:**
- Produces: one positive live evidence bundle, mandatory adversarial outcomes, a comparison table of expected/observed results, and a final safe-state record.

- [ ] **Step 1: Dispatch the positive crossing at an exact commit**

Verify CI and Semgrep check identities, run the manual workflow, observe GitHub waiting on ReleaseWarden, confirm the shadow callback, deploy the fixture, and verify the HTTPS read-back receipt.

- [ ] **Step 2: Inspect sanitized operational evidence**

Confirm one D1 completed delivery, one callback, one completed nonce hash, matching policy/artifact/SHA values, and no secrets in GitHub artifacts or logs.

- [ ] **Step 3: Execute the five mandatory adversarial cases**

Run wrong-SHA, policy-mutation, failed-check, replay, and returned-body-mutation cases in the safest supported form. Never falsify or tamper with third-party Semgrep results; use synthetic/offline evidence where a live mutation would misrepresent the provider.

- [ ] **Step 4: Publish the expected/observed matrix in the pull request**

Label each row `live` or `offline`, state Gate outcome, actual GitHub shadow approval, external effect, and receipt verification separately, and link immutable run/artifact identifiers without credentials.

- [ ] **Step 5: Restore the declared safe state**

Leave the control Worker shadow-only. Disable the custom protection rule after the bounded experiment unless the owner explicitly asks to continue shadow observation. Keep or delete the harmless fixture according to the approved checkpoint; remove environment secrets if no further run is planned.

- [ ] **Step 6: Final verification and immutable completion commit**

Re-run the complete suite, verify Git status, commit only sanitized result documentation, and report exact commit, tests, live/offline matrix, remaining limitations, deployed resources, and rollback state.
