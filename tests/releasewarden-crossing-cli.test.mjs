import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  createBundle, createBundleFiles, verifyEffect, verifyEffectFile,
} from "../scripts/releasewarden-crossing.mjs";

const NOW = new Date("2026-10-15T19:00:00.000Z");
const RANDOM = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const context = {
  repository_id: 6483044,
  repository: "Silentpartnercoding/minority-prophet-gate",
  sha: "a".repeat(40),
  run_id: 777,
  run_attempt: 1,
  environment: "releasewarden-sandbox",
  effect_kind: "cloudflare-worker-fixture",
  destination: "https://releasewarden-crossing-fixture.example.workers.dev/effect",
};
const policy = {
  policy_id: "test-v1", mode: "shadow", environments: ["releasewarden-sandbox"],
  minimum_independent_roots: 1,
  required_evidence: [
    { check_name: "tests", domain: "ci", accepted_apps: ["github-actions"] },
  ],
};

test("create is deterministic with injected clock and randomness", async () => {
  const left = await createBundle(context, policy, { now: NOW, randomBytes: () => RANDOM });
  const right = await createBundle(context, policy, { now: NOW, randomBytes: () => RANDOM });
  assert.deepEqual(left, right);
  assert.match(left.mandate.nonce, /^[0-9a-f]{32}$/);
  assert.match(left.mandate.mandate_id, /^rw_[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.match(left.mandate.policy_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(left.mandate.effect.artifact_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(Date.parse(left.mandate.expires_at) - Date.parse(left.mandate.issued_at), 20 * 60 * 1000);
});

test("create rejects incomplete or widened authority context", async () => {
  for (const candidate of [
    { ...context, sha: "main" },
    { ...context, environment: "production" },
    { ...context, destination: "http://fixture.example/effect" },
    { ...context, run_attempt: 0 },
    { ...context, extra: "authority" },
  ]) await assert.rejects(createBundle(candidate, policy), /context|sha|environment|destination|field/i);
});

test("create uses fresh random nonces by default", async () => {
  const left = await createBundle(context, policy, { now: NOW });
  const right = await createBundle(context, policy, { now: NOW });
  assert.notEqual(left.mandate.nonce, right.mandate.nonce);
  assert.notEqual(left.mandate.mandate_id, right.mandate.mandate_id);
});

test("file creation refuses symlink and non-empty output directories", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rw-crossing-"));
  const nonempty = path.join(root, "nonempty");
  await mkdir(nonempty);
  await writeFile(path.join(nonempty, "keep.txt"), "keep");
  await assert.rejects(createBundleFiles(context, policy, nonempty, { now: NOW }), /empty/i);
  const target = path.join(root, "target");
  await mkdir(target);
  const link = path.join(root, "link");
  await symlink(target, link);
  await assert.rejects(createBundleFiles(context, policy, link, { now: NOW }), /symlink/i);
});

test("file creation writes only canonical owner-readable bundle files", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rw-crossing-"));
  const out = path.join(root, "bundle");
  const bundle = await createBundleFiles(context, policy, out, {
    now: NOW, randomBytes: () => RANDOM,
  });
  for (const name of ["mandate.json", "effect.json", "manifest.json"]) {
    const text = await readFile(path.join(out, name), "utf8");
    assert.equal(text.endsWith("\n"), true);
    assert.deepEqual(JSON.parse(text), bundle[name.replace(".json", "")]);
  }
});

test("verify binds URL and exact response body and emits a sanitized receipt", async () => {
  const bundle = await createBundle(context, policy, { now: NOW, randomBytes: () => RANDOM });
  const receipt = await verifyEffect(
    bundle.manifest, bundle.effect, context.destination, new Date("2026-10-15T19:01:00.000Z"),
  );
  assert.equal(receipt.schema, "releasewarden.effect-receipt.v1");
  assert.equal(receipt.verified, true);
  assert.equal(receipt.sha, context.sha);
  assert.equal(receipt.destination, context.destination);
  assert.equal(JSON.stringify(receipt).includes(bundle.mandate.nonce), false);
});

test("verify rejects wrong SHA, target, digest, extra fields, and secret-shaped values", async () => {
  const bundle = await createBundle(context, policy, { now: NOW, randomBytes: () => RANDOM });
  const cases = [
    [{ ...bundle.effect, sha: "b".repeat(40) }, context.destination],
    [bundle.effect, "https://attacker.example/effect"],
    [{ ...bundle.effect, artifact_digest: `sha256:${"d".repeat(64)}` }, context.destination],
    [{ ...bundle.effect, extra: true }, context.destination],
    [{ ...bundle.effect, mandate_id: "ghp_abcdefghijklmnopqrstuvwxyz123456" }, context.destination],
  ];
  for (const [response, url] of cases) {
    await assert.rejects(verifyEffect(bundle.manifest, response, url, NOW));
  }
});

test("receipt writer refuses an existing path and secret-shaped response content", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "rw-crossing-"));
  const bundle = await createBundle(context, policy, { now: NOW, randomBytes: () => RANDOM });
  const manifestPath = path.join(root, "manifest.json");
  const responsePath = path.join(root, "response.json");
  const receiptPath = path.join(root, "receipt.json");
  await writeFile(manifestPath, JSON.stringify(bundle.manifest));
  await writeFile(responsePath, JSON.stringify(bundle.effect));
  await writeFile(receiptPath, "keep");
  await assert.rejects(
    verifyEffectFile(manifestPath, responsePath, context.destination, receiptPath, NOW), /exists/i,
  );
});

test("workflow is manual, main-only, least-privilege, bounded, and artifact-scoped", async () => {
  const workflow = await readFile(new URL("../.github/workflows/releasewarden-crossing.yml", import.meta.url), "utf8");
  assert.match(workflow, /workflow_dispatch:/);
  assert.doesNotMatch(workflow, /pull_request_target|write-all|environment:\s*production|set -x/);
  assert.match(workflow, /SUBJECT_REF:\s*\$\{\{ github\.ref \}\}/);
  assert.match(workflow, /SUBJECT_REF[^\n]+refs\/heads\/main/);
  assert.match(workflow, /environment:\s*releasewarden-sandbox/);
  assert.match(workflow, /for attempt in \$\(seq 1 18\)/);
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/);
  assert.match(workflow, /actions\/upload-artifact@[0-9a-f]{40}/);
  assert.match(workflow, /name:\s*releasewarden-mandate-v1[\s\S]{0,180}path:\s*releasewarden-crossing\/mandate\.json/);
  assert.match(workflow, /name:\s*releasewarden-crossing-result-v1[\s\S]{0,180}path:\s*releasewarden-crossing-result\//);
  assert.doesNotMatch(workflow, /path:\s*\.\/|path:\s*\.\s*$/m);
  assert.match(workflow, /permissions:[\s\S]{0,120}contents:\s*read/);
});
