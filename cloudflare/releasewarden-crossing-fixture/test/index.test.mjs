import assert from "node:assert/strict";
import { test } from "node:test";

import worker, { fixtureResponse } from "../src/index.mjs";

const env = {
  SUBJECT_SHA: "a".repeat(40),
  MANDATE_ID: "rw_01JABCD2345EFGH6789JKMNPQR",
  POLICY_DIGEST: `sha256:${"b".repeat(64)}`,
  ARTIFACT_DIGEST: `sha256:${"c".repeat(64)}`,
  SECRET_THAT_MUST_NOT_LEAK: "hidden",
};

test("fixture response exposes exactly the immutable crossing fields", () => {
  assert.deepEqual(fixtureResponse(env), {
    schema: "releasewarden.effect.v1",
    sha: env.SUBJECT_SHA,
    mandate_id: env.MANDATE_ID,
    policy_digest: env.POLICY_DIGEST,
    artifact_digest: env.ARTIFACT_DIGEST,
  });
  assert.equal(JSON.stringify(fixtureResponse(env)).includes("hidden"), false);
});

test("GET effect returns exact JSON without caching", async () => {
  const response = await worker.fetch(new Request("https://fixture.example/effect"), env);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("content-type"), "application/json; charset=utf-8");
  assert.deepEqual(await response.json(), fixtureResponse(env));
});

test("all other routes, methods, and query overrides are refused", async () => {
  const requests = [
    new Request("https://fixture.example/"),
    new Request("https://fixture.example/other"),
    new Request("https://fixture.example/effect", { method: "POST" }),
    new Request("https://fixture.example/effect?sha=" + "d".repeat(40)),
  ];
  for (const request of requests) {
    const response = await worker.fetch(request, env);
    assert.equal(response.status, 404);
  }
});

test("malformed or missing build-time values fail closed", async () => {
  for (const [field, value] of [
    ["SUBJECT_SHA", "main"],
    ["MANDATE_ID", "bad"],
    ["POLICY_DIGEST", "sha256:no"],
    ["ARTIFACT_DIGEST", "sha256:no"],
  ]) {
    const broken = { ...env, [field]: value };
    assert.throws(() => fixtureResponse(broken), /configuration/i);
    const response = await worker.fetch(new Request("https://fixture.example/effect"), broken);
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: "fixture configuration is invalid" });
  }
});
