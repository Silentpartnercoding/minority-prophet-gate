#!/usr/bin/env node
import { constants } from "node:fs";
import { access, lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { randomBytes as nodeRandomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

import {
  canonicalJson, sha256Digest, validateMandate,
} from "../cloudflare/releasewarden-worker/src/crossing.mjs";

const CONTEXT_FIELDS = [
  "repository_id", "repository", "sha", "run_id", "run_attempt", "environment",
  "effect_kind", "destination",
];
const EFFECT_FIELDS = ["schema", "sha", "mandate_id", "policy_digest", "artifact_digest"];
const MANIFEST_FIELDS = [
  "schema", "repository_id", "repository", "sha", "run_id", "run_attempt",
  "environment", "effect_kind", "destination", "mandate_id", "policy_digest",
  "artifact_digest", "created_at",
];
const SECRET_VALUE = /(-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9_-]{20,})/;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function exactObject(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const keys = Object.keys(value);
  const unknown = keys.filter((key) => !fields.includes(key));
  const missing = fields.filter((key) => !Object.hasOwn(value, key));
  if (unknown.length) throw new TypeError(`${label} has unknown field ${unknown.sort()[0]}`);
  if (missing.length) throw new TypeError(`${label} is missing field ${missing[0]}`);
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${label} is invalid`);
}

function assertNoSecrets(value, label = "value") {
  if (typeof value === "string" && SECRET_VALUE.test(value)) {
    throw new TypeError(`${label} contains secret-shaped content`);
  }
  if (Array.isArray(value)) value.forEach((item, index) => assertNoSecrets(item, `${label}[${index}]`));
  else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (/token|secret|private.?key/i.test(key)) throw new TypeError(`${label} has forbidden key`);
      assertNoSecrets(item, `${label}.${key}`);
    }
  }
}

function bytesFrom(provider, count) {
  const value = provider(count);
  if (!(value instanceof Uint8Array) || value.byteLength < count) {
    throw new TypeError("random byte provider returned insufficient bytes");
  }
  return value.subarray(0, count);
}

function mandateId(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let encoded = "";
  for (let index = 0; index < 26; index += 1) {
    encoded = CROCKFORD[Number(value & 31n)] + encoded;
    value >>= 5n;
  }
  return `rw_${encoded}`;
}

function contextValidated(raw) {
  exactObject(raw, CONTEXT_FIELDS, "context");
  positiveInteger(raw.repository_id, "context.repository_id");
  positiveInteger(raw.run_id, "context.run_id");
  positiveInteger(raw.run_attempt, "context.run_attempt");
  if (!/^[^/\s]+\/[^/\s]+$/.test(raw.repository)) throw new TypeError("context repository is invalid");
  if (!/^[0-9a-f]{40}$/.test(raw.sha)) throw new TypeError("context sha is invalid");
  if (raw.environment !== "releasewarden-sandbox") throw new TypeError("context environment is invalid");
  if (raw.effect_kind !== "cloudflare-worker-fixture") throw new TypeError("context effect kind is invalid");
  let destination;
  try { destination = new URL(raw.destination); } catch { throw new TypeError("context destination is invalid"); }
  if (destination.protocol !== "https:" || destination.pathname !== "/effect" ||
      destination.search || destination.hash ||
      !destination.hostname.startsWith("releasewarden-crossing-fixture.")) {
    throw new TypeError("context destination is invalid");
  }
  assertNoSecrets(raw, "context");
  return structuredClone(raw);
}

function randomProvider(count) {
  return new Uint8Array(nodeRandomBytes(count));
}

function effectBase(sha, id, policyDigest) {
  return { schema: "releasewarden.effect.v1", sha, mandate_id: id, policy_digest: policyDigest };
}

export async function createBundle(rawContext, rawPolicy, options = {}) {
  const context = contextValidated(rawContext);
  if (!rawPolicy || typeof rawPolicy !== "object" || Array.isArray(rawPolicy)) {
    throw new TypeError("policy must be an object");
  }
  assertNoSecrets(rawPolicy, "policy");
  const now = options.now ?? new Date();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new TypeError("clock is invalid");
  const randomBytes = options.randomBytes ?? randomProvider;
  const entropy = bytesFrom(randomBytes, 32);
  const id = mandateId(entropy.subarray(0, 16));
  const nonce = [...entropy.subarray(16, 32)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const policyDigest = await sha256Digest(rawPolicy);
  const base = effectBase(context.sha, id, policyDigest);
  const artifactDigest = await sha256Digest(`${canonicalJson(base)}\n`);
  const effect = { ...base, artifact_digest: artifactDigest };
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 20 * 60 * 1000).toISOString();
  const mandate = validateMandate({
    schema: "releasewarden.mandate.v1",
    mandate_id: id,
    repository: { id: context.repository_id, full_name: context.repository },
    sha: context.sha,
    workflow: { run_id: context.run_id, run_attempt: context.run_attempt },
    environment: context.environment,
    effect: {
      kind: context.effect_kind,
      destination: context.destination,
      artifact_digest: artifactDigest,
    },
    issued_at: issuedAt,
    expires_at: expiresAt,
    nonce,
    policy_digest: policyDigest,
  }, now);
  const manifest = {
    schema: "releasewarden.crossing-manifest.v1",
    ...context,
    mandate_id: id,
    policy_digest: policyDigest,
    artifact_digest: artifactDigest,
    created_at: issuedAt,
  };
  return { mandate, effect, manifest };
}

async function directoryReady(out) {
  try {
    const stat = await lstat(out);
    if (stat.isSymbolicLink()) throw new TypeError("output directory may not be a symlink");
    if (!stat.isDirectory()) throw new TypeError("output path must be a directory");
    if ((await readdir(out)).length) throw new TypeError("output directory must be empty");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    await mkdir(out, { mode: 0o700 });
  }
}

async function writeCanonical(path, value) {
  await writeFile(path, `${canonicalJson(value)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
}

export async function createBundleFiles(context, policy, out, options = {}) {
  await directoryReady(out);
  const bundle = await createBundle(context, policy, options);
  await writeCanonical(`${out}/mandate.json`, bundle.mandate);
  await writeCanonical(`${out}/effect.json`, bundle.effect);
  await writeCanonical(`${out}/manifest.json`, bundle.manifest);
  return bundle;
}

export async function verifyEffect(rawManifest, rawResponse, observedUrl, now = new Date()) {
  exactObject(rawManifest, MANIFEST_FIELDS, "manifest");
  exactObject(rawResponse, EFFECT_FIELDS, "effect response");
  assertNoSecrets(rawManifest, "manifest");
  assertNoSecrets(rawResponse, "effect response");
  if (observedUrl !== rawManifest.destination) throw new TypeError("observed target does not match manifest");
  for (const field of ["sha", "mandate_id", "policy_digest", "artifact_digest"]) {
    if (rawResponse[field] !== rawManifest[field]) throw new TypeError(`effect ${field} does not match manifest`);
  }
  if (rawResponse.schema !== "releasewarden.effect.v1") throw new TypeError("effect schema is invalid");
  const computed = await sha256Digest(`${canonicalJson(effectBase(
    rawResponse.sha, rawResponse.mandate_id, rawResponse.policy_digest,
  ))}\n`);
  if (computed !== rawResponse.artifact_digest) throw new TypeError("effect artifact digest is invalid");
  const observedAt = now.toISOString();
  const responseDigest = await sha256Digest(`${canonicalJson(rawResponse)}\n`);
  return {
    schema: "releasewarden.effect-receipt.v1",
    verified: true,
    repository: rawManifest.repository,
    sha: rawManifest.sha,
    environment: rawManifest.environment,
    mandate_id: rawManifest.mandate_id,
    policy_digest: rawManifest.policy_digest,
    artifact_digest: rawManifest.artifact_digest,
    destination: rawManifest.destination,
    response_digest: responseDigest,
    observed_at: observedAt,
  };
}

export async function verifyEffectFile(manifestPath, responsePath, observedUrl, out, now = new Date()) {
  try {
    await access(out, constants.F_OK);
    throw new TypeError("receipt output already exists");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const response = JSON.parse(await readFile(responsePath, "utf8"));
  const receipt = await verifyEffect(manifest, response, observedUrl, now);
  await writeCanonical(out, receipt);
  return receipt;
}

function options(argv) {
  const result = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!value.startsWith("--")) result._.push(value);
    else {
      const next = argv[index + 1];
      if (!next || next.startsWith("--")) throw new TypeError(`missing value for ${value}`);
      result[value.slice(2)] = next;
      index += 1;
    }
  }
  return result;
}

async function main(argv) {
  const args = options(argv);
  const command = args._[0];
  if (command === "create") {
    if (!args.context || !args.policy || !args.out) throw new TypeError("create requires --context, --policy, and --out");
    await createBundleFiles(
      JSON.parse(await readFile(args.context, "utf8")),
      JSON.parse(await readFile(args.policy, "utf8")),
      args.out,
    );
    return;
  }
  if (command === "verify") {
    if (!args.manifest || !args.response || !args.url || !args.out) {
      throw new TypeError("verify requires --manifest, --response, --url, and --out");
    }
    await verifyEffectFile(args.manifest, args.response, args.url, args.out);
    return;
  }
  throw new TypeError("command must be create or verify");
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`ReleaseWarden crossing: ${error.message}\n`);
    process.exitCode = 2;
  });
}
