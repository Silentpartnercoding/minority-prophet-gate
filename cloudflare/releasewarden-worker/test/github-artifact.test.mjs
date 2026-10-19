import assert from "node:assert/strict";
import { test } from "node:test";
import { zipSync } from "fflate";

import { fetchMandateArtifact } from "../src/github-artifact.mjs";
import { sha256Digest } from "../src/crossing.mjs";

const SHA = "a".repeat(40);
const RUN_ID = 777;
const REPOSITORY_ID = 6483044;
const mandate = { schema: "releasewarden.mandate.v1", mandate_id: "rw_test" };

function archive(entries = { "mandate.json": new TextEncoder().encode(JSON.stringify(mandate)) }) {
  return zipSync(entries, { level: 0 });
}

function mutateCentral(bytes, change) {
  const copy = Uint8Array.from(bytes);
  const view = new DataView(copy.buffer);
  let offset = 0;
  while (offset + 4 <= copy.length && view.getUint32(offset, true) !== 0x02014b50) offset += 1;
  assert.ok(offset + 46 <= copy.length, "central directory exists");
  change(view, offset);
  return copy;
}

async function metadata(bytes, overrides = {}) {
  return {
    id: 91,
    name: "releasewarden-mandate-v1",
    expired: false,
    size_in_bytes: bytes.byteLength,
    digest: await sha256Digest(bytes),
    archive_download_url: "https://api.github.com/repos/acme/service/actions/artifacts/91/zip",
    workflow_run: { id: RUN_ID, repository_id: REPOSITORY_ID, head_sha: SHA },
    ...overrides,
  };
}

async function harness({ bytes = archive(), artifacts, location = "https://results-receiver.actions.githubusercontent.com/signed", downloadStatus = 200 } = {}) {
  const listed = artifacts ?? [await metadata(bytes)];
  const calls = [];
  const fetchImpl = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    if (String(url).includes(`/actions/runs/${RUN_ID}/artifacts`)) {
      return Response.json({ total_count: listed.length, artifacts: listed });
    }
    if (String(url) === listed[0]?.archive_download_url) {
      return new Response(null, { status: 302, headers: { location } });
    }
    return new Response(bytes, { status: downloadStatus, headers: { "content-length": String(bytes.byteLength) } });
  };
  return { fetchImpl, calls };
}

function deployment() {
  return { owner: "acme", repository: "service", repositoryId: REPOSITORY_ID, sha: SHA, runId: RUN_ID };
}

test("retrieves one exact-run mandate artifact through an explicit safe redirect", async () => {
  const { fetchImpl, calls } = await harness();
  const result = await fetchMandateArtifact(deployment(), "installation-token", fetchImpl);
  assert.deepEqual(result.mandate, mandate);
  assert.equal(result.artifact.id, 91);
  assert.match(result.artifact.digest, /^sha256:/);
  assert.equal(calls.length, 3);
  assert.equal(calls[1].options.redirect, "manual");
  assert.equal(calls[2].options.headers?.authorization, undefined);
});

test("rejects missing, duplicate, expired, or cross-run artifact metadata", async () => {
  const bytes = archive();
  const base = await metadata(bytes);
  const cases = [
    [],
    [base, { ...base, id: 92 }],
    [{ ...base, expired: true }],
    [{ ...base, workflow_run: { ...base.workflow_run, id: RUN_ID + 1 } }],
    [{ ...base, workflow_run: { ...base.workflow_run, repository_id: 9 } }],
    [{ ...base, workflow_run: { ...base.workflow_run, head_sha: "b".repeat(40) } }],
  ];
  for (const artifacts of cases) {
    const { fetchImpl } = await harness({ bytes, artifacts });
    await assert.rejects(fetchMandateArtifact(deployment(), "token", fetchImpl));
  }
});

test("rejects unsafe redirects, oversized archives, and digest substitution", async () => {
  const bytes = archive();
  const badDigest = await metadata(bytes, { digest: `sha256:${"0".repeat(64)}` });
  for (const options of [
    { location: "http://results-receiver.actions.githubusercontent.com/signed" },
    { location: "https://attacker.example/signed" },
    { bytes: new Uint8Array(65 * 1024) },
    { artifacts: [badDigest] },
  ]) {
    const { fetchImpl } = await harness(options);
    await assert.rejects(fetchMandateArtifact(deployment(), "token", fetchImpl));
  }
});

test("rejects extra entries, traversal, and oversized mandate content", async () => {
  const archives = [
    archive({ "mandate.json": new TextEncoder().encode("{}"), "extra.txt": new Uint8Array([1]) }),
    archive({ "../mandate.json": new TextEncoder().encode("{}") }),
    archive({ "/mandate.json": new TextEncoder().encode("{}") }),
    archive({ "mandate.json": new Uint8Array(33 * 1024) }),
  ];
  for (const bytes of archives) {
    const { fetchImpl } = await harness({ bytes });
    await assert.rejects(fetchMandateArtifact(deployment(), "token", fetchImpl));
  }
});

test("rejects encrypted, unsupported-compression, and symlink ZIP entries", async () => {
  const clean = archive();
  const archives = [
    mutateCentral(clean, (view, offset) => view.setUint16(offset + 8, view.getUint16(offset + 8, true) | 1, true)),
    mutateCentral(clean, (view, offset) => view.setUint16(offset + 10, 99, true)),
    mutateCentral(clean, (view, offset) => view.setUint32(offset + 38, 0o120777 << 16, true)),
  ];
  for (const bytes of archives) {
    const item = await metadata(bytes);
    const { fetchImpl } = await harness({ bytes, artifacts: [item] });
    await assert.rejects(fetchMandateArtifact(deployment(), "token", fetchImpl));
  }
});

test("rejects malformed JSON and signed download failures without leaking the URL", async () => {
  const malformed = archive({ "mandate.json": new TextEncoder().encode("not-json") });
  let setup = await harness({ bytes: malformed });
  await assert.rejects(fetchMandateArtifact(deployment(), "token", setup.fetchImpl), /JSON/i);
  setup = await harness({ downloadStatus: 500 });
  await assert.rejects(
    fetchMandateArtifact(deployment(), "token", setup.fetchImpl),
    (error) => !error.message.includes("results-receiver"),
  );
});

test("cancels a lengthless artifact stream as soon as it crosses the byte cap", async () => {
  const bytes = archive();
  const item = await metadata(bytes);
  let cancelled = false;
  let emitted = 0;
  const download = {
    ok: true,
    headers: new Headers(),
    body: {
      getReader: () => ({
        read: async () => emitted++ < 2 ?
          { done: false, value: new Uint8Array(40 * 1024) } : { done: true },
        cancel: async () => { cancelled = true; },
      }),
    },
  };
  const fetchImpl = async (url) => {
    if (String(url).includes(`/actions/runs/${RUN_ID}/artifacts`)) {
      return Response.json({ total_count: 1, artifacts: [item] });
    }
    if (String(url) === item.archive_download_url) {
      return new Response(null, {
        status: 302,
        headers: { location: "https://results-receiver.actions.githubusercontent.com/signed" },
      });
    }
    return download;
  };
  await assert.rejects(fetchMandateArtifact(deployment(), "token", fetchImpl), /size|large/i);
  assert.equal(cancelled, true);
});
