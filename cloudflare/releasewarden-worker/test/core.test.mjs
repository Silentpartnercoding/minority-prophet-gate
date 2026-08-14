import assert from "node:assert/strict";
import { test } from "node:test";

import {
  callbackBody,
  evaluateRelease,
  parseDeploymentRequest,
  validatePolicy,
  verifyWebhookSignature,
} from "../src/index.mjs";

const SHA = "a".repeat(40);

function deployment() {
  return {
    owner: "acme",
    repository: "service",
    environment: "production",
    sha: SHA,
  };
}

function policy() {
  return validatePolicy({
    policy_id: "test-v1",
    mode: "shadow",
    environments: ["production"],
    minimum_independent_roots: 2,
    required_evidence: [
      { check_name: "tests", domain: "ci", accepted_apps: ["github-actions"] },
      { check_name: "scan", domain: "security", accepted_apps: ["security-app"] },
    ],
  });
}

function observations(scan = "success") {
  return [
    { name: "tests", status: "completed", conclusion: "success", app_slug: "github-actions", check_run_id: 1 },
    { name: "scan", status: "completed", conclusion: scan, app_slug: "security-app", check_run_id: 2 },
  ];
}

test("verifies GitHub HMAC signatures", async () => {
  const body = new TextEncoder().encode("{}");
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode("secret"),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, body));
  const hex = [...signature].map((value) => value.toString(16).padStart(2, "0")).join("");
  assert.equal(await verifyWebhookSignature("secret", body, `sha256=${hex}`), true);
  assert.equal(await verifyWebhookSignature("wrong", body, `sha256=${hex}`), false);
});

test("requires an exact SHA and exact GitHub callback route", () => {
  const payload = {
    action: "requested",
    environment: "production",
    sha: SHA,
    ref: "main",
    deployment_callback_url: "https://api.github.com/repos/acme/service/actions/runs/12/deployment_protection_rule",
    repository: { id: 1, full_name: "acme/service" },
    installation: { id: 2 },
  };
  assert.equal(parseDeploymentRequest(payload, "delivery").sha, SHA);
  assert.throws(() => parseDeploymentRequest({ ...payload, sha: "main" }, "delivery"));
  assert.throws(() => parseDeploymentRequest({
    ...payload, deployment_callback_url: "https://attacker.example/callback",
  }, "delivery"));
});

test("approves two successful independent evidence domains", () => {
  const decision = evaluateRelease(deployment(), policy(), observations());
  assert.equal(decision.state, "approved");
  assert.equal(decision.gate_action, "proceed");
  assert.equal(decision.diagnostics.roots_for, 2);
});

test("blocks failed evidence and escalates missing or wrong-provider evidence", () => {
  assert.equal(evaluateRelease(deployment(), policy(), observations("failure")).gate_action, "block");
  assert.equal(evaluateRelease(deployment(), policy(), observations().slice(0, 1)).gate_action, "escalate");
  const wrong = observations();
  wrong[1] = { ...wrong[1], app_slug: "impostor" };
  assert.equal(evaluateRelease(deployment(), policy(), wrong).gate_action, "escalate");
});

test("hosted callback always releases because preview is shadow-only", () => {
  const decision = evaluateRelease(deployment(), policy(), observations("failure"));
  const callback = callbackBody(deployment(), decision);
  assert.equal(callback.environment_name, "production");
  assert.equal(callback.state, "approved");
  assert.match(callback.comment, /Gate=block/);
});

test("refuses enforce policies in the hosted experimental worker", () => {
  const raw = { ...policy(), mode: "enforce" };
  assert.throws(() => validatePolicy(raw), /shadow mode/);
});
