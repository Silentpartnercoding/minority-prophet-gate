const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const MANDATE_ID = /^rw_[0-9A-HJKMNP-TV-Z]{26}$/;

export function fixtureResponse(env) {
  if (!SHA.test(String(env.SUBJECT_SHA ?? "")) ||
      !MANDATE_ID.test(String(env.MANDATE_ID ?? "")) ||
      !DIGEST.test(String(env.POLICY_DIGEST ?? "")) ||
      !DIGEST.test(String(env.ARTIFACT_DIGEST ?? ""))) {
    throw new TypeError("fixture configuration is invalid");
  }
  return {
    schema: "releasewarden.effect.v1",
    sha: env.SUBJECT_SHA,
    mandate_id: env.MANDATE_ID,
    policy_digest: env.POLICY_DIGEST,
    artifact_digest: env.ARTIFACT_DIGEST,
  };
}

function json(status, value) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "GET" || url.pathname !== "/effect" || url.search || url.hash) {
      return json(404, { error: "not found" });
    }
    try {
      return json(200, fixtureResponse(env));
    } catch {
      return json(500, { error: "fixture configuration is invalid" });
    }
  },
};
