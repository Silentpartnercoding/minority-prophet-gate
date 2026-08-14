"""ReleaseWarden: evidence-backed GitHub deployment protection.

This module is intentionally a narrow product adapter around Minority Prophet
Gate.  GitHub remains the deployment runtime.  ReleaseWarden authenticates a
``deployment_protection_rule`` webhook, collects check-run observations for the
exact commit, conservatively groups them into operator-configured independence
domains, and asks Gate for a final decision.

It is an experimental preview.  It does not infer independence: the policy
owner must assign evidence produced by the same control mechanism to the same
domain.  Shadow mode is the default.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any, Iterable, Mapping, Protocol
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .adapter_acp import AttestationVerifier
from .selective_hybrid import DeterministicDecision, SelectiveDecision, selective_decide


GITHUB_API = "https://api.github.com"
SUCCESS_CONCLUSIONS = frozenset({"success"})
FAILURE_CONCLUSIONS = frozenset({
    "action_required", "cancelled", "failure", "stale", "startup_failure", "timed_out",
})


class ReleaseWardenError(RuntimeError):
    """A request cannot safely be evaluated or delivered."""


@dataclass(frozen=True)
class EvidenceRequirement:
    check_name: str
    domain: str
    accepted_apps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.check_name or not self.domain:
            raise ValueError("each evidence requirement needs check_name and domain")
        if not self.accepted_apps:
            raise ValueError("each evidence requirement needs at least one accepted_apps slug")


@dataclass(frozen=True)
class ReleasePolicy:
    policy_id: str
    environments: tuple[str, ...]
    required_evidence: tuple[EvidenceRequirement, ...]
    mode: str = "shadow"
    minimum_independent_roots: int = 2

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("policy_id is required")
        if self.mode not in {"shadow", "enforce"}:
            raise ValueError("mode must be shadow or enforce")
        if not self.environments:
            raise ValueError("at least one protected environment is required")
        if not self.required_evidence:
            raise ValueError("at least one evidence requirement is required")
        if isinstance(self.minimum_independent_roots, bool) or not isinstance(
            self.minimum_independent_roots, int
        ) or self.minimum_independent_roots < 1:
            raise ValueError("minimum_independent_roots must be a positive integer")
        domains = {item.domain for item in self.required_evidence}
        if self.minimum_independent_roots > len(domains):
            raise ValueError(
                "minimum_independent_roots exceeds configured independence domains"
            )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ReleasePolicy":
        allowed = {
            "policy_id", "environments", "required_evidence", "mode",
            "minimum_independent_roots",
        }
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError(f"unknown policy fields: {', '.join(sorted(unknown))}")
        requirements = []
        for item in raw.get("required_evidence", ()):
            if not isinstance(item, Mapping):
                raise ValueError("required_evidence entries must be objects")
            extra = set(item) - {"check_name", "domain", "accepted_apps"}
            if extra:
                raise ValueError(
                    f"unknown evidence requirement fields: {', '.join(sorted(extra))}"
                )
            requirements.append(EvidenceRequirement(
                str(item.get("check_name", "")),
                str(item.get("domain", "")),
                tuple(str(value) for value in item.get("accepted_apps", ())),
            ))
        return cls(
            policy_id=str(raw.get("policy_id", "")),
            environments=tuple(str(value) for value in raw.get("environments", ())),
            required_evidence=tuple(requirements),
            mode=str(raw.get("mode", "shadow")),
            minimum_independent_roots=raw.get("minimum_independent_roots", 2),
        )

    @classmethod
    def load(cls, path: str | Path) -> "ReleasePolicy":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise ValueError("policy must be a JSON object")
        return cls.from_mapping(raw)


@dataclass(frozen=True)
class DeploymentRequest:
    delivery_id: str
    owner: str
    repository: str
    repository_id: int
    installation_id: int
    environment: str
    sha: str
    ref: str
    callback_url: str
    run_id: int | None = None

    @property
    def subject(self) -> str:
        return f"github-deployment:{self.owner}/{self.repository}:{self.environment}:{self.sha}"


@dataclass(frozen=True)
class CheckObservation:
    name: str
    status: str
    conclusion: str | None
    app_slug: str
    check_run_id: int
    details_url: str | None = None


@dataclass(frozen=True)
class ReleaseDecision:
    state: str  # approved | rejected
    gate_action: str
    reason: str
    mode: str
    repository: str
    environment: str
    sha: str
    evidence: tuple[dict[str, Any], ...] = ()
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def should_callback(self) -> bool:
        return True

    @property
    def callback_state(self) -> str:
        """Shadow observes the verdict but always releases this one rule."""
        return self.state if self.mode == "enforce" else "approved"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "releasewarden.decision.v1",
            "state": self.state,
            "gate_action": self.gate_action,
            "reason": self.reason,
            "mode": self.mode,
            "repository": self.repository,
            "environment": self.environment,
            "sha": self.sha,
            "evidence": list(self.evidence),
            "diagnostics": self.diagnostics,
        }


def verify_webhook_signature(secret: bytes, body: bytes, supplied: str | None) -> bool:
    if not secret or not supplied or not supplied.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied)


def parse_deployment_request(payload: Mapping[str, Any], delivery_id: str) -> DeploymentRequest:
    try:
        if payload.get("action") != "requested":
            raise ReleaseWardenError("deployment protection action must be requested")
        repository = payload["repository"]
        installation = payload["installation"]
        full_name = str(repository["full_name"])
        owner, name = full_name.split("/", 1)
        sha = str(payload["sha"])
        if len(sha) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in sha):
            raise ReleaseWardenError("webhook sha is not a full commit hash")
        callback_url = str(payload["deployment_callback_url"])
        parsed = urlparse(callback_url)
        if parsed.scheme != "https" or parsed.hostname not in {"api.github.com"}:
            raise ReleaseWardenError("callback URL is not an approved GitHub API endpoint")
        run_id = None
        workflow_run = payload.get("workflow_run")
        if isinstance(workflow_run, Mapping) and workflow_run.get("id") is not None:
            run_id = int(workflow_run["id"])
        return DeploymentRequest(
            delivery_id=delivery_id,
            owner=owner,
            repository=name,
            repository_id=int(repository["id"]),
            installation_id=int(installation["id"]),
            environment=str(payload["environment"]),
            sha=sha.lower(),
            ref=str(payload["ref"]),
            callback_url=callback_url,
            run_id=run_id,
        )
    except ReleaseWardenError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseWardenError("malformed deployment protection payload") from exc


class GitHubTransport(Protocol):
    def checks_for_commit(self, request: DeploymentRequest) -> tuple[CheckObservation, ...]: ...
    def review(self, request: DeploymentRequest, state: str, comment: str) -> None: ...


class TokenProvider(Protocol):
    def token(self, installation_id: int, repository_id: int) -> str: ...


class StaticTokenProvider:
    """Testing/one-session token provider. Production should use GitHubAppAuth."""

    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("token is required")
        self._token = token

    def token(self, installation_id: int, repository_id: int) -> str:
        del installation_id, repository_id
        return self._token


class GitHubAppAuth:
    """Mint repository-scoped installation tokens from a GitHub App key.

    Requires the optional ``releasewarden`` dependency group (PyJWT crypto).
    Private key material is read at startup and is never logged.
    """

    def __init__(self, app_id: str, private_key: bytes,
                 api_base: str = GITHUB_API) -> None:
        if not app_id or not private_key:
            raise ValueError("GitHub App ID and private key are required")
        self.app_id = app_id
        self.private_key = private_key
        self.api_base = api_base.rstrip("/")

    def _jwt(self) -> str:
        try:
            import jwt  # type: ignore
        except ImportError as exc:
            raise ReleaseWardenError(
                "GitHub App auth requires: pip install '.[releasewarden]'"
            ) from exc
        now = int(time.time())
        encoded = jwt.encode(
            {"iat": now - 30, "exp": now + 540, "iss": self.app_id},
            self.private_key,
            algorithm="RS256",
        )
        return str(encoded)

    def token(self, installation_id: int, repository_id: int) -> str:
        url = f"{self.api_base}/app/installations/{installation_id}/access_tokens"
        body = json.dumps({
            "repository_ids": [repository_id],
            "permissions": {"actions": "read", "deployments": "write"},
        }).encode()
        response = _http_json(url, self._jwt(), method="POST", body=body)
        token = response.get("token")
        if not isinstance(token, str) or not token:
            raise ReleaseWardenError("GitHub did not return an installation token")
        return token


def _http_json(url: str, token: str, *, method: str = "GET",
               body: bytes | None = None) -> Mapping[str, Any]:
    request = Request(url, data=body, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "ReleaseWarden/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urlopen(request, timeout=15) as response:
            data = response.read()
    except HTTPError as exc:
        detail = exc.read(512).decode("utf-8", "replace")
        raise ReleaseWardenError(f"GitHub API returned {exc.code}: {detail}") from exc
    except OSError as exc:
        raise ReleaseWardenError("GitHub API request failed") from exc
    if not data:
        return {}
    decoded = json.loads(data)
    if not isinstance(decoded, Mapping):
        raise ReleaseWardenError("GitHub API returned an unexpected response")
    return decoded


class GitHubApiTransport:
    def __init__(self, tokens: TokenProvider, api_base: str = GITHUB_API) -> None:
        self.tokens = tokens
        self.api_base = api_base.rstrip("/")

    def checks_for_commit(self, request: DeploymentRequest) -> tuple[CheckObservation, ...]:
        token = self.tokens.token(request.installation_id, request.repository_id)
        url = (
            f"{self.api_base}/repos/{request.owner}/{request.repository}/commits/"
            f"{request.sha}/check-runs?filter=latest&per_page=100"
        )
        raw = _http_json(url, token)
        runs = raw.get("check_runs")
        if not isinstance(runs, list):
            raise ReleaseWardenError("GitHub check-runs response omitted check_runs")
        observations = []
        for run in runs:
            if not isinstance(run, Mapping):
                continue
            app = run.get("app") or {}
            observations.append(CheckObservation(
                name=str(run.get("name", "")),
                status=str(run.get("status", "")),
                conclusion=(str(run["conclusion"]) if run.get("conclusion") else None),
                app_slug=str(app.get("slug", "")) if isinstance(app, Mapping) else "",
                check_run_id=int(run.get("id", 0)),
                details_url=str(run["details_url"]) if run.get("details_url") else None,
            ))
        return tuple(observations)

    def review(self, request: DeploymentRequest, state: str, comment: str) -> None:
        if state not in {"approved", "rejected"}:
            raise ValueError("review state must be approved or rejected")
        token = self.tokens.token(request.installation_id, request.repository_id)
        parsed = urlparse(request.callback_url)
        if parsed.scheme != "https" or parsed.hostname != "api.github.com":
            raise ReleaseWardenError("refusing non-GitHub deployment callback")
        _http_json(
            request.callback_url,
            token,
            method="POST",
            body=json.dumps({"state": state, "comment": comment[:1024]}).encode(),
        )


class _CollectedVerifier(AttestationVerifier):
    """Accept only envelopes constructed from this authenticated API response."""

    def __init__(self, allowed: Iterable[str]) -> None:
        self.allowed = frozenset(allowed)

    def verify(self, env: dict) -> str:
        evidence_id = (env.get("attest") or {}).get("releasewarden_evidence_id")
        return "root" if evidence_id in self.allowed else "invalid"


def _evidence_id(subject: str, domain: str, checks: Iterable[CheckObservation]) -> str:
    canonical = {
        "subject": subject,
        "domain": domain,
        "checks": sorted(
            (item.name, item.status, item.conclusion, item.app_slug, item.check_run_id)
            for item in checks
        ),
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def evaluate_release(request: DeploymentRequest, policy: ReleasePolicy,
                     observations: Iterable[CheckObservation]) -> ReleaseDecision:
    repository = f"{request.owner}/{request.repository}"
    if request.environment not in policy.environments:
        return ReleaseDecision(
            "rejected", "block", "environment is outside the configured mandate",
            policy.mode, repository, request.environment, request.sha,
            diagnostics={"policy_id": policy.policy_id},
        )

    by_name: dict[str, list[CheckObservation]] = {}
    for observation in observations:
        by_name.setdefault(observation.name, []).append(observation)

    selected: list[tuple[EvidenceRequirement, CheckObservation]] = []
    missing, pending, wrong_app = [], [], []
    for requirement in policy.required_evidence:
        candidates = sorted(
            by_name.get(requirement.check_name, ()),
            key=lambda item: item.check_run_id,
            reverse=True,
        )
        if requirement.accepted_apps:
            accepted = [item for item in candidates if item.app_slug in requirement.accepted_apps]
            if candidates and not accepted:
                wrong_app.append(requirement.check_name)
            candidates = accepted
        if not candidates:
            missing.append(requirement.check_name)
            continue
        chosen = candidates[0]
        if chosen.status != "completed" or chosen.conclusion is None:
            pending.append(requirement.check_name)
            continue
        selected.append((requirement, chosen))

    if missing or pending or wrong_app:
        reason = "required deployment evidence is incomplete or unverifiable"
        return ReleaseDecision(
            "rejected", "escalate", reason, policy.mode, repository,
            request.environment, request.sha,
            diagnostics={
                "policy_id": policy.policy_id,
                "missing_checks": missing,
                "pending_checks": pending,
                "wrong_app_checks": wrong_app,
            },
        )

    failed = [
        observation.name
        for _, observation in selected
        if observation.conclusion in FAILURE_CONCLUSIONS
    ]
    unknown = [
        observation.name
        for _, observation in selected
        if observation.conclusion not in SUCCESS_CONCLUSIONS | FAILURE_CONCLUSIONS
    ]
    if failed:
        return ReleaseDecision(
            "rejected", "block", "a required deployment check failed",
            policy.mode, repository, request.environment, request.sha,
            diagnostics={"policy_id": policy.policy_id, "failed_checks": failed},
        )
    if unknown:
        return ReleaseDecision(
            "rejected", "escalate", "a required check returned an unknown conclusion",
            policy.mode, repository, request.environment, request.sha,
            diagnostics={"policy_id": policy.policy_id, "unknown_checks": unknown},
        )

    grouped: dict[str, list[CheckObservation]] = {}
    for requirement, observation in selected:
        grouped.setdefault(requirement.domain, []).append(observation)

    envelopes, evidence_report, allowed = [], [], []
    for index, (domain, checks) in enumerate(sorted(grouped.items())):
        conclusions = {item.conclusion for item in checks}
        unsafe = bool(conclusions & FAILURE_CONCLUSIONS)
        unknown_conclusions = conclusions - SUCCESS_CONCLUSIONS - FAILURE_CONCLUSIONS
        assertion = "UNSAFE" if unsafe or unknown_conclusions else "SAFE"
        evidence_id = _evidence_id(request.subject, domain, checks)
        allowed.append(evidence_id)
        claim_id = f"releasewarden-domain-{index + 1}"
        envelopes.append({
            "claim_id": claim_id,
            "agent": f"github-check-domain:{domain}",
            "assertion": assertion,
            "attest": {
                "origin": f"github-check-domain:{domain}",
                "subject": request.subject,
                "releasewarden_evidence_id": evidence_id,
            },
        })
        evidence_report.append({
            "domain": domain,
            "assertion": assertion,
            "checks": [
                {"name": item.name, "app": item.app_slug, "conclusion": item.conclusion,
                 "check_run_id": item.check_run_id}
                for item in checks
            ],
        })

    decision: SelectiveDecision = selective_decide(
        DeterministicDecision(
            "review", "production deployments require evidence",
            evidence_sensitive=True, policy_id=policy.policy_id,
        ),
        envelopes,
        _CollectedVerifier(allowed),
        decision_subject=request.subject,
        unbound_root_weight=0.0,
        min_flip_budget=float(policy.minimum_independent_roots),
        freshness=None,
    )
    approved = decision.action == "proceed"
    diagnostics = dict(decision.diagnostics)
    if decision.assessment is not None:
        diagnostics.update({
            "roots_for": decision.assessment.roots_for,
            "roots_against": decision.assessment.roots_against,
            "flip_budget": decision.assessment.flip_budget,
            "conversions_to_reverse": decision.assessment.conversions_to_reverse,
        })
    return ReleaseDecision(
        "approved" if approved else "rejected",
        decision.action,
        decision.reason,
        policy.mode,
        repository,
        request.environment,
        request.sha,
        tuple(evidence_report),
        diagnostics,
    )


class DeliveryStore:
    """Small durable replay guard and decision journal for the preview App."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS deliveries ("
                "delivery_id TEXT PRIMARY KEY, body_digest TEXT NOT NULL, "
                "status TEXT NOT NULL, decision_json TEXT, created_at TEXT NOT NULL)"
            )

    def begin(self, delivery_id: str, body_digest: str) -> str:
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT body_digest, status FROM deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
            if row:
                if row[0] != body_digest:
                    raise ReleaseWardenError("delivery ID was replayed with a different body")
                return str(row[1])
            db.execute(
                "INSERT INTO deliveries VALUES (?, ?, 'processing', NULL, ?)",
                (delivery_id, body_digest, datetime.now(timezone.utc).isoformat()),
            )
        return "new"

    def complete(self, delivery_id: str, decision: ReleaseDecision) -> None:
        encoded = json.dumps(decision.as_dict(), sort_keys=True)
        with sqlite3.connect(self.path) as db:
            db.execute(
                "UPDATE deliveries SET status = 'completed', decision_json = ? "
                "WHERE delivery_id = ? AND status = 'processing'",
                (encoded, delivery_id),
            )

    def decision(self, delivery_id: str) -> Mapping[str, Any] | None:
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT decision_json FROM deliveries WHERE delivery_id = ?",
                (delivery_id,),
            ).fetchone()
        return json.loads(row[0]) if row and row[0] else None


class ReleaseWardenService:
    def __init__(self, policy: ReleasePolicy, transport: GitHubTransport,
                 store: DeliveryStore, webhook_secret: bytes) -> None:
        if not webhook_secret:
            raise ValueError("webhook secret is required")
        self.policy = policy
        self.transport = transport
        self.store = store
        self.webhook_secret = webhook_secret

    def handle(self, body: bytes, headers: Mapping[str, str]) -> tuple[int, dict[str, Any]]:
        signature = headers.get("X-Hub-Signature-256") or headers.get("x-hub-signature-256")
        if not verify_webhook_signature(self.webhook_secret, body, signature):
            return 401, {"error": "invalid webhook signature"}
        event = headers.get("X-GitHub-Event") or headers.get("x-github-event")
        delivery = headers.get("X-GitHub-Delivery") or headers.get("x-github-delivery")
        if event != "deployment_protection_rule" or not delivery:
            return 400, {"error": "unsupported or unidentified GitHub event"}
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        state = self.store.begin(delivery, digest)
        if state == "completed":
            return 200, dict(self.store.decision(delivery) or {})
        if state == "processing":
            return 409, {"error": "delivery is already processing; no duplicate callback sent"}

        payload = json.loads(body)
        if not isinstance(payload, Mapping):
            raise ReleaseWardenError("webhook JSON must be an object")
        request = parse_deployment_request(payload, delivery)
        observations = self.transport.checks_for_commit(request)
        decision = evaluate_release(request, self.policy, observations)
        if decision.should_callback:
            comment = (
                f"ReleaseWarden: {decision.reason}. "
                f"Gate={decision.gate_action}; policy={self.policy.policy_id}; "
                f"sha={request.sha[:12]}."
            )
            self.transport.review(request, decision.callback_state, comment)
        self.store.complete(delivery, decision)
        return 200, decision.as_dict()


def _handler(service: ReleaseWardenService, max_body_bytes: int = 1_000_000):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/healthz":
                self.send_error(404)
                return
            self._json(200, {"status": "ok", "mode": service.policy.mode})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/github/webhook":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > max_body_bytes:
                    self._json(413, {"error": "invalid webhook body size"})
                    return
                body = self.rfile.read(length)
                status, response = service.handle(body, dict(self.headers.items()))
            except (ReleaseWardenError, json.JSONDecodeError, ValueError) as exc:
                status, response = 422, {"error": str(exc)}
            except Exception:
                # Never leak internals or convert a fault into an approval.
                status, response = 500, {"error": "ReleaseWarden failed closed"}
            self._json(status, response)

        def _json(self, status: int, payload: Mapping[str, Any]) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, fmt: str, *args: Any) -> None:
            print(f"releasewarden: {fmt % args}", file=sys.stderr)

    return Handler


class FixtureTransport:
    """Offline transport for the one-command simulation; it performs no callback."""

    def __init__(self, checks: Iterable[Mapping[str, Any]]) -> None:
        self.checks = tuple(CheckObservation(
            name=str(item.get("name", "")),
            status=str(item.get("status", "")),
            conclusion=str(item["conclusion"]) if item.get("conclusion") else None,
            app_slug=str(item.get("app_slug", "")),
            check_run_id=int(item.get("check_run_id", 0)),
            details_url=str(item["details_url"]) if item.get("details_url") else None,
        ) for item in checks)

    def checks_for_commit(self, request: DeploymentRequest) -> tuple[CheckObservation, ...]:
        del request
        return self.checks

    def review(self, request: DeploymentRequest, state: str, comment: str) -> None:
        raise ReleaseWardenError("fixture transport must never review a GitHub deployment")


def _simulate(args: argparse.Namespace) -> int:
    policy = ReleasePolicy.load(args.policy)
    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    checks = json.loads(Path(args.checks).read_text(encoding="utf-8"))
    request = parse_deployment_request(payload, "offline-simulation")
    decision = evaluate_release(request, policy, FixtureTransport(checks).checks)
    print(json.dumps(decision.as_dict(), indent=2, sort_keys=True))
    return 0 if decision.state == "approved" else 2


def _serve(args: argparse.Namespace) -> int:
    policy = ReleasePolicy.load(args.policy)
    secret = os.environ.get("RELEASEWARDEN_WEBHOOK_SECRET", "").encode()
    static = os.environ.get("RELEASEWARDEN_INSTALLATION_TOKEN")
    if static:
        tokens: TokenProvider = StaticTokenProvider(static)
    else:
        app_id = os.environ.get("RELEASEWARDEN_GITHUB_APP_ID", "")
        key_path = os.environ.get("RELEASEWARDEN_PRIVATE_KEY_PATH", "")
        if not key_path:
            raise ReleaseWardenError(
                "set RELEASEWARDEN_PRIVATE_KEY_PATH or a one-session installation token"
            )
        tokens = GitHubAppAuth(app_id, Path(key_path).read_bytes())
    service = ReleaseWardenService(
        policy, GitHubApiTransport(tokens), DeliveryStore(args.database), secret,
    )
    server = ThreadingHTTPServer((args.host, args.port), _handler(service))
    print(
        f"ReleaseWarden listening on http://{args.host}:{args.port} "
        f"in {policy.mode} mode",
        file=sys.stderr,
    )
    server.serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="releasewarden", description="Evidence-backed GitHub deployment protection"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    simulate = sub.add_parser("simulate", help="evaluate fixture data with zero effects")
    simulate.add_argument("--policy", required=True)
    simulate.add_argument("--payload", required=True)
    simulate.add_argument("--checks", required=True)
    simulate.set_defaults(func=_simulate)
    serve = sub.add_parser("serve", help="serve the GitHub App webhook")
    serve.add_argument("--policy", required=True)
    serve.add_argument("--database", default="releasewarden.sqlite3")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8787, type=int)
    serve.set_defaults(func=_serve)
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ReleaseWardenError, ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
