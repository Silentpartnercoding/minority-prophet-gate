# Changelog

## Unreleased

- Add an opt-in, bounded `request_evidence` outcome for unresolved selective
  decisions, bound to the exact action, subject, policy, and collection round.
- Keep evidence collection non-authorizing and outside the protected runtime;
  contradictory evidence still blocks and exhausted retries escalate.
- Add explicit policy-selected routes for the requesting agent, an epistemic
  service, a human queue, or any conforming program, with capability and
  control-domain checks rather than provider-specific logic.
- Add separately authorized dispatch, requirement/result validation, bounded
  collection, crash-safe fail-closed retries, and an optional fsynced JSONL
  hash-chain audit that excludes raw evidence.
- Add an authenticated transactional SQLite ledger for audit events, derived
  dispatch state, evidence artifacts, and pending human-review handoffs.
- Add concrete loopback HTTP epistemic, durable human-queue, and fixed-command
  program adapters without granting protected-action authority.

## 0.1.1 — 2026-08-07

- Publish the provider-neutral evidence assessment and execution-policy gate.
- Add subject binding, freshness, selective escalation, runtime integrations,
  and exhaustive model checks.
- Define verifier independence as a required property without claiming that
  Gate discovers shared organizational control.
