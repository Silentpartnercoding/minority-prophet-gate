# ReleaseWarden real crossing operator checklist

This checklist records identities and pass/fail facts only. Never paste a token,
private key, webhook secret, signed artifact URL, D1 row, or secret value here.

## What the three outcomes mean

Think of ReleaseWarden as a safety inspector watching a practice launch:

1. **Gate outcome** — what the inspector concluded: proceed, block, escalate,
   or review. This is journaled by ReleaseWarden.
2. **GitHub outcome** — what GitHub actually did. During this experiment the
   App is shadow-only, so its callback always releases the sandbox job even if
   Gate says block.
3. **Effect verification** — what the harmless Cloudflare endpoint actually
   returned afterward. The workflow verifies the exact SHA, Mandate, policy,
   artifact digest, and destination.

The public `releasewarden.effect-receipt.v1` records only the third outcome. It
does not turn a shadow rejection into an approval. The private
`releasewarden.receipt.v1` records Gate and callback as separate fields:

```text
gate.state / gate.action    hypothetical evidence decision
callback.state              actual GitHub release (approved in shadow)
continuity.code             exact Border comparison
```

## Authenticated preflight

Record a timestamp and `PASS` or `FAIL`; stop on any failure.

- [ ] GitHub signed-in owner is the intended owner: __________
- [ ] GitHub App owner and exact slug: __________
- [ ] Installation is limited to `Silentpartnercoding/minority-prophet-gate`
- [ ] Repository permission `Actions`: read
- [ ] Repository permission `Contents`: read
- [ ] Repository permission `Deployments`: read and write
- [ ] Subscribed event: `Deployment protection rule`
- [ ] Webhook destination is the expected redacted host plus `/github/webhook`
- [ ] Webhook SSL verification is enabled and recent delivery is successful
- [ ] GitHub environment is exactly `releasewarden-sandbox`
- [ ] No custom ReleaseWarden rule is enabled on any production environment
- [ ] Cloudflare signed-in account is the intended experimental account
- [ ] Cloudflare plan/usage shows this experiment remains within the free tier
- [ ] Control Worker is `releasewarden-experimental` and `/healthz` says shadow
- [ ] Fixture Worker name is `releasewarden-crossing-fixture`
- [ ] D1 database is `releasewarden-experimental`
- [ ] Migration `0002_crossing_receipts.sql` is applied exactly once
- [ ] Environment variable `RELEASEWARDEN_FIXTURE_URL` is present
- [ ] Environment secret name `RELEASEWARDEN_CLOUDFLARE_API_TOKEN` is present
- [ ] Environment secret name `RELEASEWARDEN_CLOUDFLARE_ACCOUNT_ID` is present
- [ ] No secret value was copied into this checklist, logs, issues, or artifacts

Verified at: __________  Operator: __________  Result: __________

## Local positive reproduction

From the repository root:

```bash
node --test tests/releasewarden-crossing-cli.test.mjs
python3 -m unittest discover -s tests -v
(cd cloudflare/releasewarden-worker && npm ci && npm test && npm audit --omit=dev && npm run deploy:dry)
(cd cloudflare/releasewarden-crossing-fixture && npm ci && npm test && npm audit --omit=dev && npm run deploy:dry)
```

For the live positive run, merge the reviewed commit to `main`, confirm its CI
and Semgrep checks, then manually dispatch `releasewarden-real-crossing`. Do not
dispatch from a feature branch. Record the immutable workflow run URL and the
sanitized `releasewarden-crossing-result-v1` artifact.

## Mandatory falsification sequence

Run the valid case first. Each result must state `live` or `offline`.

| Case | Safe method | Expected result |
|---|---|---|
| Valid crossing | Live manual workflow | Gate proceed; shadow callback approved; read-back verifies |
| Wrong SHA | Offline `attack-vectors.json` / unit test | `sha_mismatch`; no valid receipt |
| Policy mutation | Offline change to copied policy fixture | `policy_digest_mismatch`; no valid receipt |
| Failed check | Offline/synthetic check fixture; never alter Semgrep's result | Gate block |
| Replay | Worker integration test with duplicate delivery and nonce | prior receipt returned once; reused nonce rejected |
| Returned-body mutation | Offline CLI verification against modified response | effect receipt refused |

Commands:

```bash
node --test cloudflare/releasewarden-worker/test/crossing.test.mjs
node --test cloudflare/releasewarden-worker/test/webhook.test.mjs
node --test tests/releasewarden-crossing-cli.test.mjs
```

Do not describe an offline vector as a live provider failure. Do not fabricate,
cancel, or overwrite a Semgrep conclusion to create a demonstration.

## Rollback and cleanup

All experiment changes below are reversible:

1. Disable the ReleaseWarden custom protection rule on
   `releasewarden-sandbox`.
2. Confirm no other environment changed.
3. Leave `releasewarden-experimental` in shadow mode; roll its Worker deployment
   back to the recorded prior version if the new version is unhealthy.
4. Delete `releasewarden-crossing-fixture` if no more read-back runs are needed.
5. Remove the two `RELEASEWARDEN_CLOUDFLARE_*` environment secrets if no more
   workflow deployments are planned.
6. Remove `RELEASEWARDEN_FIXTURE_URL` if the fixture was deleted.
7. Preserve only sanitized GitHub run summaries and result artifacts. Let the
   one-day Mandate/build artifacts expire.

The additive D1 migration is normally left in place because old rows remain
compatible. It contains metadata, not credentials. Do not drop tables during
rollback.
