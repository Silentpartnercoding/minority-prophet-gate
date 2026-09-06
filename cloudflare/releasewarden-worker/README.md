# ReleaseWarden Cloudflare experimental host

This is the smallest permanently hosted version of ReleaseWarden. It is a
separate adapter around the same release-policy contract; it does not replace
the Python package, Gate, Border, or any other repository.

The hosted preview is deliberately **shadow-only**. It records the decision it
would make, but always approves GitHub's callback. Do not use it as production
enforcement.

## Free-tier shape

- One Cloudflare Worker receives GitHub webhooks and calls GitHub's API.
- One D1 database stores delivery replay guards and decision records.
- No Workers AI, paid model API, Queue, R2, Durable Object, or paid Cloudflare
  plan is required.
- On the Workers Free plan, traffic stops with a Cloudflare error when the free
  request quota is exhausted; it does not silently create usage charges.

## Repository-owned policy

Each installed repository supplies `.releasewarden.json` at the exact commit
being deployed. Copy the structure from
`../../examples/releasewarden/policy.shadow.json`. Hosted policies must remain
in `shadow` mode.

The GitHub App needs only:

- Actions: read
- Contents: read (to fetch `.releasewarden.json` at the exact SHA)
- Deployments: read and write
- Metadata: read (mandatory)
- Event: Deployment protection rule

## One-time setup

Requires Wrangler 4.x and an authenticated Cloudflare account:

```bash
npm install
npx wrangler whoami
npx wrangler d1 create releasewarden-experimental
```

Put the returned D1 `database_id` into `wrangler.jsonc`, then:

```bash
npx wrangler d1 migrations apply releasewarden-experimental --remote
npx wrangler secret put GITHUB_WEBHOOK_SECRET
npx wrangler secret put GITHUB_APP_ID
```

Cloudflare Web Crypto imports PKCS#8 keys. Convert the downloaded GitHub App
key locally without overwriting it, then upload the converted value as a
Worker secret:

```bash
openssl pkcs8 -topk8 -nocrypt \
  -in /absolute/path/github-app.private-key.pem \
  -out /private/tmp/releasewarden-app.pkcs8.pem
npx wrangler secret put GITHUB_APP_PRIVATE_KEY_PKCS8 \
  < /private/tmp/releasewarden-app.pkcs8.pem
```

Validate before deployment:

```bash
npm test
npx wrangler deploy --dry-run
npx wrangler deploy
```

Set the GitHub App webhook URL to the resulting
`https://releasewarden-experimental.<account>.workers.dev/github/webhook` and
retain SSL verification. Test `/healthz`, then install the App only on a public
sandbox repository and enable it on a harmless GitHub environment.

## Public-test boundary

Making the GitHub App public allows other accounts to install it, but it does
not make this preview production-ready. Testers must use a public disposable
repository, commit their own `.releasewarden.json`, and keep the App in shadow
mode. Never send them the webhook secret or private key.
