import { unzipSync } from "fflate";
import { sha256Digest } from "./crossing.mjs";

const MAX_ARCHIVE_BYTES = 64 * 1024;
const MAX_MANDATE_BYTES = 32 * 1024;
const ARTIFACT_NAME = "releasewarden-mandate-v1";

export class ArtifactError extends Error {
  constructor(message) {
    super(message);
    this.name = "ArtifactError";
  }
}

function authHeaders(token) {
  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "user-agent": "ReleaseWarden-Cloudflare/0.1",
    "x-github-api-version": "2022-11-28",
  };
}

function redirectAllowed(location) {
  let url;
  try { url = new URL(location); } catch { return false; }
  if (url.protocol !== "https:") return false;
  return url.hostname.endsWith(".actions.githubusercontent.com") ||
    url.hostname.endsWith(".blob.core.windows.net");
}

async function boundedBytes(response) {
  if (!response.ok) throw new ArtifactError("mandate artifact download failed");
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > MAX_ARCHIVE_BYTES) throw new ArtifactError("mandate artifact archive is too large");
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (!bytes.byteLength || bytes.byteLength > MAX_ARCHIVE_BYTES) {
    throw new ArtifactError("mandate artifact archive has an invalid size");
  }
  return bytes;
}

function centralDirectoryEntry(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = -1;
  for (let offset = bytes.byteLength - 22; offset >= Math.max(0, bytes.byteLength - 65557); offset -= 1) {
    if (view.getUint32(offset, true) === 0x06054b50) { eocd = offset; break; }
  }
  if (eocd < 0) throw new ArtifactError("mandate artifact is not a valid ZIP archive");
  const entries = view.getUint16(eocd + 10, true);
  const centralSize = view.getUint32(eocd + 12, true);
  const centralOffset = view.getUint32(eocd + 16, true);
  if (entries !== 1 || centralOffset + centralSize > bytes.byteLength) {
    throw new ArtifactError("mandate artifact must contain exactly one entry");
  }
  if (view.getUint32(centralOffset, true) !== 0x02014b50) {
    throw new ArtifactError("mandate artifact central directory is malformed");
  }
  const flags = view.getUint16(centralOffset + 8, true);
  const method = view.getUint16(centralOffset + 10, true);
  const uncompressedSize = view.getUint32(centralOffset + 24, true);
  const nameLength = view.getUint16(centralOffset + 28, true);
  const extraLength = view.getUint16(centralOffset + 30, true);
  const commentLength = view.getUint16(centralOffset + 32, true);
  const externalAttributes = view.getUint32(centralOffset + 38, true);
  const end = centralOffset + 46 + nameLength + extraLength + commentLength;
  if (end > bytes.byteLength || end !== centralOffset + centralSize) {
    throw new ArtifactError("mandate artifact central directory is malformed");
  }
  const name = new TextDecoder("utf-8", { fatal: true }).decode(
    bytes.subarray(centralOffset + 46, centralOffset + 46 + nameLength),
  );
  const unixMode = externalAttributes >>> 16;
  if ((flags & 1) !== 0) throw new ArtifactError("encrypted mandate artifacts are unsupported");
  if (![0, 8].includes(method)) throw new ArtifactError("mandate artifact compression is unsupported");
  if ((unixMode & 0o170000) === 0o120000) throw new ArtifactError("mandate artifact may not be a symlink");
  if (name !== "mandate.json") throw new ArtifactError("mandate artifact entry must be mandate.json");
  if (uncompressedSize > MAX_MANDATE_BYTES) throw new ArtifactError("mandate JSON is too large");
  return name;
}

function parseArchive(bytes) {
  const name = centralDirectoryEntry(bytes);
  let files;
  try { files = unzipSync(bytes); } catch { throw new ArtifactError("mandate artifact ZIP extraction failed"); }
  const names = Object.keys(files);
  if (names.length !== 1 || names[0] !== name || files[name].byteLength > MAX_MANDATE_BYTES) {
    throw new ArtifactError("mandate artifact contents are invalid");
  }
  let mandate;
  try { mandate = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(files[name])); }
  catch { throw new ArtifactError("mandate artifact JSON is malformed"); }
  if (!mandate || typeof mandate !== "object" || Array.isArray(mandate)) {
    throw new ArtifactError("mandate artifact JSON must be an object");
  }
  return mandate;
}

export async function fetchMandateArtifact(deployment, token, fetchImpl = fetch) {
  if (!Number.isSafeInteger(deployment.runId) || deployment.runId < 1) {
    throw new ArtifactError("deployment webhook omitted workflow run identity");
  }
  const base = `https://api.github.com/repos/${encodeURIComponent(deployment.owner)}/` +
    `${encodeURIComponent(deployment.repository)}`;
  const listingResponse = await fetchImpl(
    `${base}/actions/runs/${deployment.runId}/artifacts?per_page=100`,
    { headers: authHeaders(token), redirect: "error" },
  );
  if (!listingResponse.ok) throw new ArtifactError("mandate artifact listing failed");
  const listing = await listingResponse.json();
  if (!Array.isArray(listing.artifacts)) throw new ArtifactError("mandate artifact listing is malformed");
  const matches = listing.artifacts.filter((item) => item?.name === ARTIFACT_NAME);
  if (matches.length !== 1) throw new ArtifactError("workflow run must have exactly one mandate artifact");
  const artifact = matches[0];
  if (artifact.expired || artifact.workflow_run?.id !== deployment.runId ||
      artifact.workflow_run?.repository_id !== deployment.repositoryId ||
      artifact.workflow_run?.head_sha !== deployment.sha) {
    throw new ArtifactError("mandate artifact identity does not match the deployment");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(String(artifact.digest ?? ""))) {
    throw new ArtifactError("mandate artifact has no usable digest");
  }
  const redirect = await fetchImpl(artifact.archive_download_url, {
    headers: authHeaders(token), redirect: "manual",
  });
  const location = redirect.headers.get("location") ?? "";
  if (redirect.status !== 302 || !redirectAllowed(location)) {
    throw new ArtifactError("mandate artifact redirect was refused");
  }
  const bytes = await boundedBytes(await fetchImpl(location, { redirect: "error", headers: {} }));
  if (await sha256Digest(bytes) !== artifact.digest) {
    throw new ArtifactError("mandate artifact digest does not match GitHub metadata");
  }
  return {
    mandate: parseArchive(bytes),
    artifact: { id: artifact.id, digest: artifact.digest, size: bytes.byteLength },
  };
}
