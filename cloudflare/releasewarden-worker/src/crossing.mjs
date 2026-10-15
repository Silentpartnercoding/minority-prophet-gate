const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const NONCE_PATTERN = /^[0-9a-f]{32}$/;
const MANDATE_ID_PATTERN = /^rw_[0-9A-HJKMNP-TV-Z]{26}$/;
const MAX_LIFETIME_MS = 30 * 60 * 1000;

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertExactFields(value, expected, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} must be a plain JSON object`);
  const unknown = Object.keys(value).filter((key) => !expected.includes(key));
  if (unknown.length) throw new TypeError(`${label} has unknown field: ${unknown.sort()[0]}`);
  const missing = expected.filter((key) => !Object.hasOwn(value, key));
  if (missing.length) throw new TypeError(`${label} is missing field: ${missing[0]}`);
}

function canonicalValue(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("JSON number must be finite");
    if (!Number.isSafeInteger(value) && Number.isInteger(value)) {
      throw new TypeError("JSON integer must be safe");
    }
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  if (!isPlainObject(value)) throw new TypeError("value must be plain JSON data");
  return `{${Object.keys(value).sort().map((key) => {
    if (value[key] === undefined) throw new TypeError("undefined is not a JSON value");
    return `${JSON.stringify(key)}:${canonicalValue(value[key])}`;
  }).join(",")}}`;
}

export function canonicalJson(value) {
  if (value === undefined || typeof value === "bigint" || typeof value === "function" ||
      typeof value === "symbol") {
    throw new TypeError("unsupported JSON value");
  }
  return canonicalValue(value);
}

function hex(bytes) {
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

export async function sha256Digest(value) {
  let bytes;
  if (value instanceof Uint8Array) bytes = value;
  else if (typeof value === "string") bytes = new TextEncoder().encode(value);
  else bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${hex(new Uint8Array(digest))}`;
}

function requiredString(value, label, pattern = null) {
  if (typeof value !== "string" || value.length === 0 || (pattern && !pattern.test(value))) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} is invalid`);
  return value;
}

function timestamp(value, label) {
  requiredString(value, label);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new TypeError(`${label} must be an ISO-8601 UTC timestamp`);
  }
  return milliseconds;
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function validateMandate(raw, now = new Date()) {
  assertExactFields(raw, [
    "schema", "mandate_id", "repository", "sha", "workflow", "environment",
    "effect", "issued_at", "expires_at", "nonce", "policy_digest",
  ], "mandate");
  assertExactFields(raw.repository, ["id", "full_name"], "mandate.repository");
  assertExactFields(raw.workflow, ["run_id", "run_attempt"], "mandate.workflow");
  assertExactFields(raw.effect, ["kind", "destination", "artifact_digest"], "mandate.effect");
  if (raw.schema !== "releasewarden.mandate.v1") throw new TypeError("mandate schema is invalid");
  requiredString(raw.mandate_id, "mandate_id", MANDATE_ID_PATTERN);
  positiveInteger(raw.repository.id, "repository.id");
  requiredString(raw.repository.full_name, "repository.full_name", /^[^/\s]+\/[^/\s]+$/);
  requiredString(raw.sha, "sha", SHA_PATTERN);
  positiveInteger(raw.workflow.run_id, "workflow.run_id");
  positiveInteger(raw.workflow.run_attempt, "workflow.run_attempt");
  requiredString(raw.environment, "environment");
  requiredString(raw.effect.kind, "effect.kind", /^[a-z0-9][a-z0-9-]*$/);
  const destination = requiredString(raw.effect.destination, "effect.destination");
  let parsedDestination;
  try { parsedDestination = new URL(destination); } catch { throw new TypeError("effect.destination is invalid"); }
  if (parsedDestination.protocol !== "https:") throw new TypeError("effect.destination must use HTTPS");
  requiredString(raw.effect.artifact_digest, "effect.artifact_digest", DIGEST_PATTERN);
  requiredString(raw.policy_digest, "policy_digest", DIGEST_PATTERN);
  requiredString(raw.nonce, "nonce", NONCE_PATTERN);
  const issued = timestamp(raw.issued_at, "issued_at");
  const expires = timestamp(raw.expires_at, "expires_at");
  const current = now.getTime();
  if (!Number.isFinite(current)) throw new TypeError("now is invalid");
  if (issued > current) throw new TypeError("issued_at is in the future");
  if (expires <= issued) throw new TypeError("expires_at must be after issued_at");
  if (expires <= current) throw new TypeError("mandate is expired");
  if (expires - issued > MAX_LIFETIME_MS) throw new TypeError("mandate lifetime exceeds 30 minutes");
  return deepFreeze(structuredClone(raw));
}

function mismatch(code, field) {
  return { valid: false, code, details: { field } };
}

export function evaluateContinuity(deployment, mandate, context) {
  const bindings = [
    [deployment.repositoryId, mandate.repository.id, "repository_id_mismatch", "repository.id"],
    [deployment.repository, mandate.repository.full_name, "repository_mismatch", "repository.full_name"],
    [deployment.sha, mandate.sha, "sha_mismatch", "sha"],
    [deployment.runId, mandate.workflow.run_id, "run_id_mismatch", "workflow.run_id"],
    [deployment.runAttempt, mandate.workflow.run_attempt, "run_attempt_mismatch", "workflow.run_attempt"],
    [deployment.environment, mandate.environment, "environment_mismatch", "environment"],
    [context.effectKind, mandate.effect.kind, "effect_kind_mismatch", "effect.kind"],
    [context.destination, mandate.effect.destination, "destination_mismatch", "effect.destination"],
    [context.artifactDigest, mandate.effect.artifact_digest, "artifact_digest_mismatch", "effect.artifact_digest"],
    [context.policyDigest, mandate.policy_digest, "policy_digest_mismatch", "policy_digest"],
  ];
  for (const [actual, expected, code, field] of bindings) {
    if (actual !== expected) return mismatch(code, field);
  }
  const now = context.now instanceof Date ? context.now.getTime() : Number.NaN;
  if (!Number.isFinite(now) || now >= Date.parse(mandate.expires_at)) {
    return mismatch("mandate_expired", "expires_at");
  }
  if (now < Date.parse(mandate.issued_at)) return mismatch("mandate_not_yet_valid", "issued_at");
  return { valid: true, code: "continuity_valid", details: {} };
}
