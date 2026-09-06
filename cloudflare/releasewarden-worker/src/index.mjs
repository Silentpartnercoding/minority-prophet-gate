const GITHUB_API = "https://api.github.com";
const MAX_BODY_BYTES = 1_000_000;
const SUCCESS = new Set(["success"]);
const FAILURE = new Set([
  "failure", "cancelled", "timed_out", "action_required", "startup_failure",
]);

export class ReleaseWardenError extends Error {
  constructor(message, status = 422) {
    super(message);
    this.name = "ReleaseWardenError";
    this.status = status;
  }
}

function jsonResponse(status, value) {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function pemBytes(pem, label) {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  if (!pem.includes(begin) || !pem.includes(end)) {
    throw new ReleaseWardenError(`GitHub App key must be ${label} PEM`, 500);
  }
  const encoded = pem.slice(pem.indexOf(begin) + begin.length, pem.indexOf(end))
    .replace(/\s/g, "");
  return Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0));
}

export async function verifyWebhookSignature(secret, body, supplied) {
  if (!secret || !supplied?.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, body));
  const providedHex = supplied.slice(7);
  if (!/^[0-9a-f]{64}$/i.test(providedHex)) return false;
  const provided = Uint8Array.from(
    providedHex.match(/.{2}/g), (pair) => Number.parseInt(pair, 16),
  );
  if (provided.length !== expected.length) return false;
  let different = 0;
  for (let index = 0; index < expected.length; index += 1) {
    different |= expected[index] ^ provided[index];
  }
  return different === 0;
}

export function parseDeploymentRequest(payload, deliveryId) {
  if (payload?.action !== "requested") {
    throw new ReleaseWardenError("deployment protection action must be requested");
  }
  const repository = payload.repository;
  const installation = payload.installation;
  const fullName = String(repository?.full_name ?? "");
  const slash = fullName.indexOf("/");
  if (slash < 1) throw new ReleaseWardenError("malformed repository identity");
  const sha = String(payload.sha ?? payload.deployment?.sha ?? "").toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new ReleaseWardenError("webhook sha is not a full commit hash");
  }
  const callbackUrl = String(payload.deployment_callback_url ?? "");
  let callback;
  try {
    callback = new URL(callbackUrl);
  } catch {
    throw new ReleaseWardenError("callback URL is malformed");
  }
  const callbackPattern = /^\/repos\/[^/]+\/[^/]+\/actions\/runs\/\d+\/deployment_protection_rule$/;
  if (callback.protocol !== "https:" || callback.hostname !== "api.github.com" ||
      !callbackPattern.test(callback.pathname) || callback.search || callback.hash) {
    throw new ReleaseWardenError("callback URL is not an approved GitHub API endpoint");
  }
  const repositoryId = Number(repository?.id);
  const installationId = Number(installation?.id);
  if (!Number.isSafeInteger(repositoryId) || !Number.isSafeInteger(installationId)) {
    throw new ReleaseWardenError("malformed repository or installation identity");
  }
  return {
    deliveryId,
    owner: fullName.slice(0, slash),
    repository: fullName.slice(slash + 1),
    repositoryId,
    installationId,
    environment: String(payload.environment ?? ""),
    sha,
    ref: String(payload.ref ?? payload.deployment?.ref ?? ""),
    callbackUrl,
  };
}

export function validatePolicy(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new ReleaseWardenError("policy must be an object");
  }
  const policy = {
    policy_id: String(raw.policy_id ?? ""),
    mode: String(raw.mode ?? "shadow"),
    environments: Array.isArray(raw.environments) ? raw.environments.map(String) : [],
    minimum_independent_roots: Number(raw.minimum_independent_roots ?? 2),
    required_evidence: Array.isArray(raw.required_evidence) ? raw.required_evidence.map((item) => ({
      check_name: String(item?.check_name ?? ""),
      domain: String(item?.domain ?? ""),
      accepted_apps: Array.isArray(item?.accepted_apps) ? item.accepted_apps.map(String) : [],
    })) : [],
  };
  if (!policy.policy_id || policy.mode !== "shadow") {
    throw new ReleaseWardenError("hosted preview policies must have an ID and use shadow mode");
  }
  if (!Number.isInteger(policy.minimum_independent_roots) ||
      policy.minimum_independent_roots < 1) {
    throw new ReleaseWardenError("minimum_independent_roots must be a positive integer");
  }
  if (!policy.environments.length || !policy.required_evidence.length) {
    throw new ReleaseWardenError("policy must configure environments and required evidence");
  }
  const domains = new Set();
  for (const requirement of policy.required_evidence) {
    if (!requirement.check_name || !requirement.domain || !requirement.accepted_apps.length) {
      throw new ReleaseWardenError("each evidence requirement needs a check, domain, and app");
    }
    domains.add(requirement.domain);
  }
  if (policy.minimum_independent_roots > domains.size) {
    throw new ReleaseWardenError("minimum roots exceeds configured independence domains");
  }
  return policy;
}

export function evaluateRelease(deployment, policy, observations) {
  const repository = `${deployment.owner}/${deployment.repository}`;
  const base = {
    schema: "releasewarden.decision.v1",
    mode: "shadow",
    repository,
    environment: deployment.environment,
    sha: deployment.sha,
    evidence: [],
  };
  if (!policy.environments.includes(deployment.environment)) {
    return {
      ...base, state: "rejected", gate_action: "block",
      reason: "environment is not covered by this repository policy",
      diagnostics: { policy_id: policy.policy_id },
    };
  }
  const selected = [];
  const missing = [];
  const pending = [];
  const wrongApp = [];
  for (const requirement of policy.required_evidence) {
    const named = observations.filter((item) => item.name === requirement.check_name);
    if (!named.length) {
      missing.push(requirement.check_name);
      continue;
    }
    const accepted = named.find((item) => requirement.accepted_apps.includes(item.app_slug));
    if (!accepted) {
      wrongApp.push(requirement.check_name);
      continue;
    }
    if (accepted.status !== "completed") pending.push(requirement.check_name);
    selected.push([requirement, accepted]);
  }
  if (missing.length || pending.length || wrongApp.length) {
    return {
      ...base, state: "rejected", gate_action: "escalate",
      reason: "required deployment evidence is incomplete or unverifiable",
      diagnostics: {
        policy_id: policy.policy_id,
        missing_checks: missing,
        pending_checks: pending,
        wrong_app_checks: wrongApp,
      },
    };
  }
  const failed = selected.filter(([, item]) => FAILURE.has(item.conclusion))
    .map(([requirement]) => requirement.check_name);
  const unknown = selected.filter(([, item]) =>
    !SUCCESS.has(item.conclusion) && !FAILURE.has(item.conclusion))
    .map(([requirement]) => requirement.check_name);
  if (failed.length) {
    return {
      ...base, state: "rejected", gate_action: "block",
      reason: "a required deployment check failed",
      diagnostics: { policy_id: policy.policy_id, failed_checks: failed },
    };
  }
  if (unknown.length) {
    return {
      ...base, state: "rejected", gate_action: "escalate",
      reason: "a required check returned an unknown conclusion",
      diagnostics: { policy_id: policy.policy_id, unknown_checks: unknown },
    };
  }
  const domains = new Map();
  for (const [requirement, item] of selected) {
    const checks = domains.get(requirement.domain) ?? [];
    checks.push({
      name: item.name,
      app: item.app_slug,
      conclusion: item.conclusion,
      check_run_id: item.check_run_id,
    });
    domains.set(requirement.domain, checks);
  }
  const evidence = [...domains].map(([domain, checks]) => ({
    domain, assertion: "SAFE", checks,
  }));
  const roots = evidence.length;
  if (roots < policy.minimum_independent_roots) {
    return {
      ...base, evidence, state: "rejected", gate_action: "review",
      reason: "evidence does not satisfy the independent-root threshold",
      diagnostics: { policy_id: policy.policy_id, roots_for: roots },
    };
  }
  return {
    ...base, evidence, state: "approved", gate_action: "proceed",
    reason: "independent evidence satisfies policy",
    diagnostics: {
      policy_id: policy.policy_id,
      roots_for: roots,
      roots_against: 0,
      flip_budget: roots,
    },
  };
}

export function callbackBody(deployment, decision) {
  return {
    environment_name: deployment.environment,
    // This public preview is deliberately shadow-only.
    state: "approved",
    comment: `ReleaseWarden shadow: ${decision.reason}. Gate=${decision.gate_action}; ` +
      `policy=${decision.diagnostics.policy_id}; sha=${deployment.sha.slice(0, 12)}.`,
  };
}

async function githubJwt(appId, pkcs8Pem) {
  const now = Math.floor(Date.now() / 1000);
  const header = base64Url(new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const payload = base64Url(new TextEncoder().encode(JSON.stringify({
    iat: now - 30, exp: now + 540, iss: appId,
  })));
  const signingInput = `${header}.${payload}`;
  const key = await crypto.subtle.importKey(
    "pkcs8", pemBytes(pkcs8Pem, "PRIVATE KEY"),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}

async function githubJson(url, token, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "user-agent": "ReleaseWarden-Cloudflare/0.1",
      "x-github-api-version": "2022-11-28",
      ...(options.headers ?? {}),
    },
  });
  const text = await boundedText(response, 2_000_000);
  if (!response.ok) {
    throw new ReleaseWardenError(`GitHub API returned ${response.status}: ${text.slice(0, 256)}`, 502);
  }
  return text ? JSON.parse(text) : {};
}

async function boundedText(response, limit) {
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > limit) throw new ReleaseWardenError("upstream response is too large", 502);
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new ReleaseWardenError("upstream response is too large", 502);
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

async function installationToken(env, deployment) {
  const jwt = await githubJwt(env.GITHUB_APP_ID, env.GITHUB_APP_PRIVATE_KEY_PKCS8);
  const result = await githubJson(
    `${GITHUB_API}/app/installations/${deployment.installationId}/access_tokens`,
    jwt,
    {
      method: "POST",
      body: JSON.stringify({
        repository_ids: [deployment.repositoryId],
        permissions: { actions: "read", contents: "read", deployments: "write" },
      }),
    },
  );
  if (typeof result.token !== "string" || !result.token) {
    throw new ReleaseWardenError("GitHub did not return an installation token", 502);
  }
  return result.token;
}

async function repositoryPolicy(deployment, token) {
  const url = `${GITHUB_API}/repos/${encodeURIComponent(deployment.owner)}/` +
    `${encodeURIComponent(deployment.repository)}/contents/.releasewarden.json?ref=${deployment.sha}`;
  const response = await fetch(url, {
    headers: {
      accept: "application/vnd.github.raw+json",
      authorization: `Bearer ${token}`,
      "user-agent": "ReleaseWarden-Cloudflare/0.1",
      "x-github-api-version": "2022-11-28",
    },
  });
  if (response.status === 404) {
    throw new ReleaseWardenError("repository has no .releasewarden.json at the deployed commit");
  }
  if (!response.ok) {
    throw new ReleaseWardenError(`GitHub policy read returned ${response.status}`, 502);
  }
  const text = await boundedText(response, 64_000);
  return validatePolicy(JSON.parse(text));
}

async function checkRuns(deployment, token) {
  const result = await githubJson(
    `${GITHUB_API}/repos/${encodeURIComponent(deployment.owner)}/` +
    `${encodeURIComponent(deployment.repository)}/commits/${deployment.sha}/check-runs?filter=latest&per_page=100`,
    token,
  );
  if (!Array.isArray(result.check_runs)) {
    throw new ReleaseWardenError("GitHub check-runs response omitted check_runs", 502);
  }
  return result.check_runs.map((run) => ({
    name: String(run?.name ?? ""),
    status: String(run?.status ?? ""),
    conclusion: run?.conclusion == null ? null : String(run.conclusion),
    app_slug: String(run?.app?.slug ?? ""),
    check_run_id: Number(run?.id ?? 0),
  }));
}

async function beginDelivery(db, deliveryId, digest) {
  const existing = await db.prepare(
    "SELECT body_digest, status, decision_json FROM deliveries WHERE delivery_id = ?1",
  ).bind(deliveryId).first();
  if (existing) {
    if (existing.body_digest !== digest) {
      throw new ReleaseWardenError("delivery ID replayed with a different body", 409);
    }
    if (existing.status === "failed") {
      await db.prepare(
        "UPDATE deliveries SET status = 'processing', decision_json = NULL, completed_at = NULL " +
        "WHERE delivery_id = ?1 AND status = 'failed'",
      ).bind(deliveryId).run();
      return null;
    }
    return existing;
  }
  try {
    await db.prepare(
      "INSERT INTO deliveries (delivery_id, body_digest, status, created_at) " +
      "VALUES (?1, ?2, 'processing', ?3)",
    ).bind(deliveryId, digest, new Date().toISOString()).run();
  } catch {
    throw new ReleaseWardenError("concurrent duplicate delivery", 409);
  }
  return null;
}

async function processWebhook(request, env) {
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (declaredLength > MAX_BODY_BYTES) {
    throw new ReleaseWardenError("webhook body is too large", 413);
  }
  const body = await request.arrayBuffer();
  if (!body.byteLength || body.byteLength > MAX_BODY_BYTES) {
    throw new ReleaseWardenError("invalid webhook body size", 413);
  }
  const valid = await verifyWebhookSignature(
    env.GITHUB_WEBHOOK_SECRET, body, request.headers.get("x-hub-signature-256"),
  );
  if (!valid) throw new ReleaseWardenError("invalid webhook signature", 401);
  if (request.headers.get("x-github-event") !== "deployment_protection_rule") {
    throw new ReleaseWardenError("unsupported GitHub event", 400);
  }
  const deliveryId = request.headers.get("x-github-delivery");
  if (!deliveryId) throw new ReleaseWardenError("missing GitHub delivery ID", 400);
  const digest = `sha256:${bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)))}`;
  const existing = await beginDelivery(env.DB, deliveryId, digest);
  if (existing?.status === "completed") {
    return JSON.parse(existing.decision_json);
  }
  if (existing?.status === "processing") {
    throw new ReleaseWardenError("delivery is already processing", 409);
  }

  try {
    const payload = JSON.parse(new TextDecoder().decode(body));
    const deployment = parseDeploymentRequest(payload, deliveryId);
    const token = await installationToken(env, deployment);
    let decision;
    try {
      const policy = await repositoryPolicy(deployment, token);
      const observations = await checkRuns(deployment, token);
      decision = evaluateRelease(deployment, policy, observations);
    } catch (error) {
      // Shadow mode releases GitHub while preserving a clear fail-closed hypothesis.
      if (!(error instanceof ReleaseWardenError)) throw error;
      decision = {
        schema: "releasewarden.decision.v1",
        state: "rejected",
        gate_action: "escalate",
        reason: error.message,
        mode: "shadow",
        repository: `${deployment.owner}/${deployment.repository}`,
        environment: deployment.environment,
        sha: deployment.sha,
        evidence: [],
        diagnostics: { policy_id: "unavailable" },
      };
    }
    await githubJson(deployment.callbackUrl, token, {
      method: "POST", body: JSON.stringify(callbackBody(deployment, decision)),
    });
    await env.DB.prepare(
      "UPDATE deliveries SET status = 'completed', decision_json = ?1, completed_at = ?2 " +
      "WHERE delivery_id = ?3 AND status = 'processing'",
    ).bind(JSON.stringify(decision), new Date().toISOString(), deliveryId).run();
    return decision;
  } catch (error) {
    await env.DB.prepare(
      "UPDATE deliveries SET status = 'failed', completed_at = ?1 " +
      "WHERE delivery_id = ?2 AND status = 'processing'",
    ).bind(new Date().toISOString(), deliveryId).run();
    throw error;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/healthz") {
      return jsonResponse(200, {
        status: "ok", mode: "shadow", service: "releasewarden-experimental",
      });
    }
    if (request.method !== "POST" || url.pathname !== "/github/webhook") {
      return jsonResponse(404, { error: "not found" });
    }
    try {
      return jsonResponse(200, await processWebhook(request, env));
    } catch (error) {
      if (error instanceof SyntaxError) {
        return jsonResponse(422, { error: "webhook JSON is malformed" });
      }
      if (error instanceof ReleaseWardenError) {
        return jsonResponse(error.status, { error: error.message });
      }
      console.error(JSON.stringify({ event: "releasewarden_failure", error: String(error) }));
      return jsonResponse(500, { error: "ReleaseWarden failed closed" });
    }
  },
};
