import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  canonicalJson,
  evaluateContinuity,
  sha256Digest,
  validateMandate,
} from "../src/crossing.mjs";

const NOW = new Date("2026-10-15T19:00:00.000Z");
const fixtureUrl = new URL("../../../examples/releasewarden/crossing/mandate.valid.json", import.meta.url);
const valid = JSON.parse(await readFile(fixtureUrl, "utf8"));

function changed(path, value) {
  const copy = structuredClone(valid);
  const parts = path.split(".");
  let current = copy;
  for (const part of parts.slice(0, -1)) current = current[part];
  current[parts.at(-1)] = value;
  return copy;
}

function deployment() {
  return {
    repositoryId: valid.repository.id,
    repository: valid.repository.full_name,
    sha: valid.sha,
    runId: valid.workflow.run_id,
    runAttempt: valid.workflow.run_attempt,
    environment: valid.environment,
  };
}

function context() {
  return {
    effectKind: valid.effect.kind,
    destination: valid.effect.destination,
    artifactDigest: valid.effect.artifact_digest,
    policyDigest: valid.policy_digest,
    now: NOW,
  };
}

test("canonical JSON sorts object keys but preserves array order", async () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 } }), '{"a":{"b":3,"y":2},"z":1}');
  assert.equal(canonicalJson({ b: 2, a: 1 }), canonicalJson({ a: 1, b: 2 }));
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
  assert.equal(await sha256Digest({ b: 2, a: 1 }), await sha256Digest({ a: 1, b: 2 }));
  assert.notEqual(await sha256Digest("alpha"), await sha256Digest("alphb"));
});

test("canonical JSON rejects values outside the JSON authority contract", () => {
  for (const value of [undefined, 1n, Number.NaN, Infinity, 2 ** 53, new Date()]) {
    assert.throws(() => canonicalJson(value), /JSON|finite|safe|plain/i);
  }
  assert.throws(() => canonicalJson({ nested: undefined }), /JSON/i);
  assert.deepEqual(JSON.parse('{"key":1,"key":2}'), { key: 2 });
});

test("validates and deeply freezes the complete mandate", () => {
  const mandate = validateMandate(valid, NOW);
  assert.equal(mandate.schema, "releasewarden.mandate.v1");
  assert.equal(mandate.sha.length, 40);
  assert.ok(Object.isFrozen(mandate));
  assert.ok(Object.isFrozen(mandate.repository));
  assert.ok(Object.isFrozen(mandate.workflow));
  assert.ok(Object.isFrozen(mandate.effect));
});

test("rejects malformed, incomplete, unknown, or unsafe mandate fields", () => {
  const cases = [
    [{ ...valid, surprise: true }, /unknown field/i],
    [changed("schema", "releasewarden.mandate.v2"), /schema/i],
    [changed("mandate_id", "bad id"), /mandate_id/i],
    [changed("sha", "main"), /sha/i],
    [changed("effect.artifact_digest", "sha256:no"), /artifact_digest/i],
    [changed("policy_digest", "sha256:no"), /policy_digest/i],
    [changed("effect.destination", ""), /destination/i],
    [changed("issued_at", "2026-10-15T19:00:01.000Z"), /future/i],
    [changed("expires_at", valid.issued_at), /after issued_at/i],
    [changed("expires_at", "2026-10-15T18:59:59.000Z"), /expired/i],
    [changed("expires_at", "2026-10-15T19:31:00.000Z"), /30 minutes/i],
    [changed("nonce", "abcd"), /nonce/i],
  ];
  for (const [candidate, message] of cases) {
    assert.throws(() => validateMandate(candidate, NOW), message);
  }
});

test("continuity accepts only an exact, fresh crossing", () => {
  const mandate = validateMandate(valid, NOW);
  assert.deepEqual(evaluateContinuity(deployment(), mandate, context()), {
    valid: true,
    code: "continuity_valid",
    details: {},
  });
});

test("continuity rejects every substituted binding with a stable code", () => {
  const mandate = validateMandate(valid, NOW);
  const cases = [
    [{ ...deployment(), repositoryId: 999 }, context(), "repository_id_mismatch"],
    [{ ...deployment(), repository: "acme/other" }, context(), "repository_mismatch"],
    [{ ...deployment(), sha: "b".repeat(40) }, context(), "sha_mismatch"],
    [{ ...deployment(), runId: 778 }, context(), "run_id_mismatch"],
    [{ ...deployment(), runAttempt: 2 }, context(), "run_attempt_mismatch"],
    [{ ...deployment(), environment: "production" }, context(), "environment_mismatch"],
    [deployment(), { ...context(), effectKind: "delete" }, "effect_kind_mismatch"],
    [deployment(), { ...context(), destination: "https://evil.example/effect" }, "destination_mismatch"],
    [deployment(), { ...context(), artifactDigest: `sha256:${"c".repeat(64)}` }, "artifact_digest_mismatch"],
    [deployment(), { ...context(), policyDigest: `sha256:${"d".repeat(64)}` }, "policy_digest_mismatch"],
    [deployment(), { ...context(), now: new Date("2026-10-15T19:20:01.000Z") }, "mandate_expired"],
  ];
  for (const [request, testContext, code] of cases) {
    const result = evaluateContinuity(request, mandate, testContext);
    assert.equal(result.valid, false);
    assert.equal(result.code, code);
    assert.equal(JSON.stringify(result).includes(valid.nonce), false);
  }
});
