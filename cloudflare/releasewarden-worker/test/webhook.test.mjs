import assert from "node:assert/strict";
import { test } from "node:test";

import { D1DeliveryJournal, processWebhook } from "../src/index.mjs";
import { canonicalJson, sha256Digest } from "../src/crossing.mjs";

const SHA = "a".repeat(40);
const NOW = "2026-10-15T19:00:00.000Z";

class FakeDB {
  constructor() { this.rows = new Map(); }
  prepare(sql) {
    return {
      bind: (...values) => ({
        first: async () => {
          const row = this.rows.get(values[0]);
          return row ? structuredClone(row) : null;
        },
        run: async () => this.run(sql, values),
      }),
    };
  }
  async run(sql, values) {
    if (sql.startsWith("INSERT")) {
      const [deliveryId, digest, createdAt] = values;
      if (this.rows.has(deliveryId)) throw new Error("unique delivery");
      this.rows.set(deliveryId, {
        delivery_id: deliveryId, body_digest: digest, status: "processing",
        decision_json: null, receipt_json: null, nonce_digest: null,
        callback_status: "pending", created_at: createdAt, completed_at: null,
      });
      return { success: true };
    }
    if (sql.includes("SET status = 'processing'") && sql.includes("status = 'failed'")) {
      const row = this.rows.get(values[0]);
      if (row?.status === "failed") Object.assign(row, {
        status: "processing", decision_json: null, receipt_json: null,
        nonce_digest: null, callback_status: "pending", completed_at: null,
      });
      return { success: true };
    }
    if (sql.includes("status = 'completed'")) {
      const [decisionJson, receiptJson, mandateId, nonceDigest, policyDigest, completedAt, deliveryId] = values;
      for (const [id, row] of this.rows) {
        if (id !== deliveryId && row.status === "completed" && row.nonce_digest === nonceDigest) {
          throw new Error("unique nonce");
        }
      }
      Object.assign(this.rows.get(deliveryId), {
        status: "completed", decision_json: decisionJson, receipt_json: receiptJson,
        mandate_id: mandateId, nonce_digest: nonceDigest, policy_digest: policyDigest,
        callback_status: "approved", completed_at: completedAt,
      });
      return { success: true };
    }
    if (sql.includes("SET status = 'failed'")) {
      const [completedAt, deliveryId] = values;
      Object.assign(this.rows.get(deliveryId), {
        status: "failed", callback_status: "failed", completed_at: completedAt,
      });
      return { success: true };
    }
    throw new Error(`unsupported SQL: ${sql}`);
  }
}

function payload() {
  return {
    action: "requested",
    environment: "releasewarden-sandbox",
    sha: SHA,
    ref: "refs/heads/main",
    deployment_callback_url: "https://api.github.com/repos/acme/service/actions/runs/777/deployment_protection_rule",
    repository: { id: 6483044, full_name: "acme/service" },
    installation: { id: 12 },
    workflow_run: { id: 777, run_attempt: 1 },
  };
}

async function signedRequest(deliveryId = "delivery-1", value = payload()) {
  const body = new TextEncoder().encode(JSON.stringify(value));
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode("webhook-secret"),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, body));
  const hex = [...signature].map((item) => item.toString(16).padStart(2, "0")).join("");
  return new Request("https://worker.example/github/webhook", {
    method: "POST", body,
    headers: {
      "content-length": String(body.byteLength),
      "x-github-event": "deployment_protection_rule",
      "x-github-delivery": deliveryId,
      "x-hub-signature-256": `sha256=${hex}`,
    },
  });
}

async function mandate(policy) {
  const policyDigest = await sha256Digest(policy);
  const effect = {
    schema: "releasewarden.effect.v1", sha: SHA,
    mandate_id: "rw_01JABCD2345EFGH6789JKMNPQR", policy_digest: policyDigest,
  };
  return {
    schema: "releasewarden.mandate.v1",
    mandate_id: effect.mandate_id,
    repository: { id: 6483044, full_name: "acme/service" },
    sha: SHA,
    workflow: { run_id: 777, run_attempt: 1 },
    environment: "releasewarden-sandbox",
    effect: {
      kind: "cloudflare-worker-fixture",
      destination: "https://releasewarden-crossing-fixture.example.workers.dev/effect",
      artifact_digest: await sha256Digest(`${canonicalJson(effect)}\n`),
    },
    issued_at: "2026-10-15T18:50:00.000Z",
    expires_at: "2026-10-15T19:20:00.000Z",
    nonce: "00112233445566778899aabbccddeeff",
    policy_digest: policyDigest,
  };
}

function policy() {
  return {
    policy_id: "test-v1", mode: "shadow", environments: ["releasewarden-sandbox"],
    minimum_independent_roots: 2,
    required_evidence: [
      { check_name: "tests", domain: "ci", accepted_apps: ["github-actions"] },
      { check_name: "scan", domain: "security", accepted_apps: ["security-app"] },
    ],
  };
}

function observations() {
  return [
    { name: "tests", status: "completed", conclusion: "success", app_slug: "github-actions", check_run_id: 1 },
    { name: "scan", status: "completed", conclusion: "success", app_slug: "security-app", check_run_id: 2 },
  ];
}

async function setup(db = new FakeDB()) {
  const rawPolicy = policy();
  const rawMandate = await mandate(rawPolicy);
  const callbacks = [];
  const dependencies = {
    now: () => new Date(NOW),
    installationToken: async () => "installation-token",
    repositoryPolicy: async () => rawPolicy,
    checkRuns: async () => observations(),
    fetchMandateArtifact: async () => ({ mandate: rawMandate, artifact: { id: 91, digest: `sha256:${"9".repeat(64)}` } }),
    githubJson: async (url, token, options) => callbacks.push({ url, token, options }),
  };
  return { db, dependencies, callbacks, rawMandate };
}

test("journal rejects body substitution, concurrent duplicates, and completed nonce reuse", async () => {
  const db = new FakeDB();
  const journal = new D1DeliveryJournal(db);
  assert.equal(await journal.begin("delivery-a", "sha256:aaa", NOW), null);
  await assert.rejects(journal.begin("delivery-a", "sha256:bbb", NOW), /different body/i);
  await assert.rejects(journal.begin("delivery-a", "sha256:aaa", NOW), /processing/i);
  await journal.complete("delivery-a", {
    decision: { state: "approved" }, receipt: { schema: "releasewarden.receipt.v1" },
    mandateId: "rw_one", nonceDigest: "sha256:nonce", policyDigest: "sha256:policy",
    completedAt: NOW,
  });
  const replay = await journal.begin("delivery-a", "sha256:aaa", NOW);
  assert.equal(replay.status, "completed");
  await journal.begin("delivery-b", "sha256:ccc", NOW);
  await assert.rejects(journal.complete("delivery-b", {
    decision: {}, receipt: {}, mandateId: "rw_two", nonceDigest: "sha256:nonce",
    policyDigest: "sha256:policy", completedAt: NOW,
  }), /nonce/i);
});

test("failed delivery becomes retryable", async () => {
  const journal = new D1DeliveryJournal(new FakeDB());
  await journal.begin("delivery-a", "sha256:aaa", NOW);
  await journal.fail("delivery-a", NOW);
  assert.equal(await journal.begin("delivery-a", "sha256:aaa", NOW), null);
});

test("webhook persists one sanitized receipt and completed replay does not callback", async () => {
  const state = await setup();
  const env = {
    DB: state.db, GITHUB_WEBHOOK_SECRET: "webhook-secret",
    CROSSING_EFFECT_KIND: "cloudflare-worker-fixture",
    CROSSING_DESTINATION: "https://releasewarden-crossing-fixture.example.workers.dev/effect",
  };
  const first = await processWebhook(await signedRequest(), env, state.dependencies);
  assert.equal(first.gate.state, "approved", JSON.stringify(first));
  assert.equal(state.callbacks.length, 1);
  const replay = await processWebhook(await signedRequest(), env, state.dependencies);
  assert.deepEqual(replay, first);
  assert.equal(state.callbacks.length, 1);
  const stored = state.db.rows.get("delivery-1");
  assert.equal(stored.status, "completed");
  assert.equal(stored.callback_status, "approved");
  assert.equal(stored.receipt_json.includes(state.rawMandate.nonce), false);
});

test("callback failure is journaled and the same delivery retries", async () => {
  const state = await setup();
  let fail = true;
  state.dependencies.githubJson = async () => {
    if (fail) { fail = false; throw new Error("callback unavailable"); }
    state.callbacks.push("approved");
  };
  const env = {
    DB: state.db, GITHUB_WEBHOOK_SECRET: "webhook-secret",
    CROSSING_EFFECT_KIND: "cloudflare-worker-fixture",
    CROSSING_DESTINATION: "https://releasewarden-crossing-fixture.example.workers.dev/effect",
  };
  await assert.rejects(processWebhook(await signedRequest(), env, state.dependencies), /callback unavailable/);
  assert.equal(state.db.rows.get("delivery-1").status, "failed");
  const receipt = await processWebhook(await signedRequest(), env, state.dependencies);
  assert.equal(receipt.callback.state, "approved");
  assert.equal(state.db.rows.get("delivery-1").status, "completed");
});

test("missing mandate evidence records escalation but shadow still releases GitHub", async () => {
  const state = await setup();
  state.dependencies.fetchMandateArtifact = async () => { throw new Error("signed-url-secret"); };
  const env = {
    DB: state.db, GITHUB_WEBHOOK_SECRET: "webhook-secret",
    CROSSING_EFFECT_KIND: "cloudflare-worker-fixture",
    CROSSING_DESTINATION: "https://releasewarden-crossing-fixture.example.workers.dev/effect",
  };
  const receipt = await processWebhook(await signedRequest(), env, state.dependencies);
  assert.equal(receipt.gate.state, "rejected");
  assert.equal(receipt.gate.action, "escalate");
  assert.equal(receipt.callback.state, "approved");
  assert.equal(state.callbacks.length, 1);
  assert.equal(state.db.rows.get("delivery-1").status, "completed");
  assert.equal(JSON.stringify(receipt).includes("signed-url-secret"), false);
});
