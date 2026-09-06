# ReleaseWarden experimental preview

> Production deployment approval backed by evidence. Powered by Minority
> Prophet.

ReleaseWarden is a focused GitHub App pathway inside Minority Prophet Gate. It
protects one action only:

```text
deploy commit SHA to named GitHub environment
```

It does not scan code, run tests, deploy software, or replace GitHub's safety
features. It decides whether the evidence already produced for that exact
commit satisfies an operator-owned release policy.

## What works in this preview

- Validates GitHub's HMAC-SHA256 webhook signature before parsing the event.
- Accepts only `deployment_protection_rule/requested` events with a full commit
  SHA and an `api.github.com` callback.
- Mints a repository-scoped GitHub App installation token, or accepts a
  short-lived installation token for a one-session test.
- Reads the latest GitHub check runs for the exact commit.
- Requires configured check names and exact accepted GitHub App slugs.
- Blocks deterministically when a required check fails.
- Rejects or escalates missing, pending, unknown, or wrong-provider evidence.
- Counts one evidence root per explicitly configured independence domain.
- Stores webhook delivery IDs and decisions in SQLite to suppress replayed
  callbacks in the normal completed-delivery case.
- Defaults to shadow mode. Shadow reports the hypothetical decision but sends
  an approval to GitHub so this rule does not block the deployment.

## Important boundary

ReleaseWarden **does not discover independence**. A policy author declares an
independence domain for each required check. Checks controlled by the same
workflow, credential, team, or mutable configuration should share a domain.
Giving copied checks different domain names manufactures evidence and defeats
the product. The preview also does not yet prove that an untrusted pull request
could not modify the workflow that judges it.

Do not use `enforce` on a consequential production system yet. The current
release is for a public sandbox repository, shadow observation, and adversarial
testing.

## 1. Offline test — no GitHub account and zero effects

From the repository root:

```bash
python3 -m minority_prophet.release_warden simulate \
  --policy examples/releasewarden/policy.shadow.json \
  --payload examples/releasewarden/deployment-request.json \
  --checks examples/releasewarden/checks.pass.json
```

Expected result: `state` is `approved`, `gate_action` is `proceed`, and
`roots_for` is `2`. Change a conclusion to `failure`, remove a required check,
change its `app_slug`, or give both requirements one domain and run it again.

The command returns `0` for an approval and `2` for a rejection. It never calls
GitHub.

## 2. GitHub limitation before the live test

GitHub custom deployment protection rules are in public preview. GitHub's
current documentation says they work for public repositories on all plans, but
private or internal repositories require GitHub Enterprise.

Therefore the cheapest first live test is a disposable **public sandbox
repository with no secrets or customer code**. Your brother's company can use a
private repository only if its GitHub plan supports custom deployment
protection rules. If not, keep ReleaseWarden in offline/shadow-event mode until
we add the ordinary status-check integration.

## 3. Register the GitHub App

Create a GitHub App owned by the test account or organization. Use:

- Name: `ReleaseWarden Experimental` (GitHub App names must be globally unique,
  so add your organization name if needed).
- Webhook URL: `https://YOUR-HTTPS-HOST/github/webhook`
- Webhook secret: a new random value stored only in your secret manager.
- Repository permission `Actions`: read-only.
- Repository permission `Deployments`: read and write.
- Subscribe to `Deployment protection rule` events only.
- Install only on the disposable test repository.

Generate and download the App private key. Never commit it. The repository
ignores `*.pem`, `.env`, and the default SQLite database as a backstop, not as a
secret-management system.

## 4. Configure the release policy

Copy `examples/releasewarden/policy.shadow.json`. Keep `mode` as `shadow` for
the first live run. The checked-in sample is wired to this repository's GitHub
Actions matrix and independently installed Semgrep App. For another repository,
match `check_name` and `accepted_apps` to its observed check runs.

An independence domain is not a label for a check. It means one failure/control
boundary. If both checks can be changed by the same unprotected workflow, they
belong to the same domain and will count once.

The sample intentionally asks for two different domains. A real test therefore
needs two genuinely separated sources, such as a protected GitHub Actions test
workflow and an independently administered security integration.

## 5. Run the webhook service

Create an isolated environment and install the App-auth dependency:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e '.[releasewarden]'
```

Set secrets in the process environment; do not paste them into issue reports or
terminal transcripts:

```bash
export RELEASEWARDEN_WEBHOOK_SECRET='your-generated-webhook-secret'
export RELEASEWARDEN_GITHUB_APP_ID='your-app-id'
export RELEASEWARDEN_PRIVATE_KEY_PATH='/absolute/private/path/app-key.pem'
releasewarden serve --policy /absolute/path/policy.shadow.json
```

The service listens on `127.0.0.1:8787` by default. Put it behind an HTTPS
reverse proxy or a temporary HTTPS development tunnel. Do not expose the raw
development server directly to the public internet for anything beyond a
disposable preview.

For one short test, `RELEASEWARDEN_INSTALLATION_TOKEN` can replace the App ID
and private key. That token must be an actual short-lived GitHub App
installation token with Actions read and Deployments write permissions. A
personal access token is not the supported production path.

## 6. Wire the disposable deployment

In the sandbox repository:

1. Create an environment named `production`.
2. Install ReleaseWarden on that repository.
3. Enable ReleaseWarden as a custom deployment protection rule for the
   environment.
4. Add a workflow job that references `environment: production`.
5. Run the required test/security checks for the same commit.
6. Trigger the deployment job.

In `shadow`, GitHub receives `approved` even when the recorded ReleaseWarden
decision says `rejected`; that is intentional. Inspect the JSON response and
SQLite journal. After the policy and domains are independently reviewed, switch
the copied policy to `enforce` only in the disposable sandbox and repeat the
failure cases.

### Zero-host dogfood workflow

This repository also includes `releasewarden-dogfood.yml` for the first,
non-blocking dogfood stage. Run it manually on an exact commit after the normal
CI and Semgrep checks start. It reads those live check runs with a read-only
`GITHUB_TOKEN`, waits for the bounded evidence set, evaluates the real
ReleaseWarden shadow policy, and writes a harmless receipt to the GitHub run
summary under the `releasewarden-sandbox` environment.

This proves live evidence collection, exact-SHA binding, Gate evaluation, and
the gated job dependency. It is deliberately **not** described as a custom
deployment-protection test: it does not exercise the public webhook, App
installation token, GitHub callback, or enforcement mode. Those remain the
next hosted test.

## Handoff to a brother or outside developer

Give them:

- This repository at the exact commit being tested.
- `RELEASEWARDEN.md`.
- Their own copy of the sample policy with no secrets.
- The adversarial task below.

Do **not** send your App private key, webhook secret, installation token,
database, customer logs, or live repository data. They create their own GitHub
App and test repository so their result is operationally independent.

Suggested task for their agent:

> Install ReleaseWarden in an isolated environment. Run the offline simulation,
> read `minority_prophet/release_warden.py` and
> `tests/test_release_warden.py`, then design tests that try to obtain approval
> with a missing check, pending check, wrong App slug, duplicate delivery ID,
> substituted SHA, non-GitHub callback, two checks assigned to one domain, and
> many copied checks from one provider. Do not target any system you do not own.
> Report the exact commit, inputs, expected outcome, observed outcome, and
> whether any protected effect occurred.

## Missing before a paid production pilot

1. Verify protected workflow provenance and detect policy/workflow changes in
   the candidate commit.
2. Replace operator-declared domains with authenticated control-domain
   attestations where providers support them.
3. Add secure multi-tenant configuration, key management, authorization, and
   an operator dashboard.
4. Add crash reconciliation for deliveries left in `processing` after a process
   failure.
5. Add pagination and rate-limit handling for repositories with more than 100
   check runs.
6. Add signed, exportable decision receipts and retention controls.
7. Conduct an independent security review and test against a real customer's
   redacted deployment history before enforcement.

## Name boundary

`ReleaseWarden` is the commercial product name used by this adapter.
`Minority Prophet` remains the evidence method and research identity. This is a
preliminary name choice, not trademark clearance.
