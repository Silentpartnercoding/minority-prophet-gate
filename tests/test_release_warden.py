import hashlib
import hmac
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from minority_prophet.release_warden import (
    CheckObservation,
    DeliveryStore,
    DeploymentRequest,
    EvidenceRequirement,
    GitHubApiTransport,
    ReleasePolicy,
    ReleaseWardenError,
    ReleaseWardenService,
    StaticTokenProvider,
    evaluate_release,
    parse_deployment_request,
    verify_webhook_signature,
)


SHA = "a" * 40


def policy(*, mode="shadow", domains=("tests", "security")):
    return ReleasePolicy(
        "releasewarden-production-v1",
        ("production",),
        (
            EvidenceRequirement("test-suite", domains[0], ("github-actions",)),
            EvidenceRequirement("security-scan", domains[1], ("security-app",)),
        ),
        mode,
        2,
    )


def request():
    return DeploymentRequest(
        "delivery-1", "acme", "service", 10, 20, "production", SHA, "main",
        "https://api.github.com/repos/acme/service/actions/runs/123/deployment_protection_rule",
        123,
    )


def checks(*, security="success"):
    return (
        CheckObservation("test-suite", "completed", "success", "github-actions", 101),
        CheckObservation("security-scan", "completed", security, "security-app", 102),
    )


def payload():
    return {
        "action": "requested",
        "environment": "production",
        "sha": SHA,
        "ref": "main",
        "deployment_callback_url": (
            "https://api.github.com/repos/acme/service/actions/runs/123/"
            "deployment_protection_rule"
        ),
        "repository": {"id": 10, "full_name": "acme/service"},
        "installation": {"id": 20},
        "workflow_run": {"id": 123},
    }


class Transport:
    def __init__(self, observations=None):
        self.observations = tuple(observations or checks())
        self.reviews = []

    def checks_for_commit(self, deployment):
        self.last_request = deployment
        return self.observations

    def review(self, deployment, state, comment):
        self.reviews.append((deployment, state, comment))


class ReleaseWardenTests(unittest.TestCase):
    def test_github_review_includes_required_environment_name(self):
        transport = GitHubApiTransport(StaticTokenProvider("test-token"))
        with patch("minority_prophet.release_warden._http_json", return_value={}) as call:
            transport.review(request(), "approved", "evidence passed")
        sent = json.loads(call.call_args.kwargs["body"])
        self.assertEqual(sent, {
            "environment_name": "production",
            "state": "approved",
            "comment": "evidence passed",
        })

    def test_two_independent_successful_domains_approve(self):
        result = evaluate_release(request(), policy(), checks())
        self.assertEqual(result.state, "approved")
        self.assertEqual(result.gate_action, "proceed")
        self.assertEqual(result.diagnostics["roots_for"], 2)

    def test_shared_domain_is_not_counted_twice(self):
        with self.assertRaisesRegex(ValueError, "exceeds configured"):
            policy(domains=("shared", "shared"))

    def test_failed_check_blocks(self):
        result = evaluate_release(request(), policy(), checks(security="failure"))
        self.assertEqual(result.state, "rejected")
        self.assertEqual(result.gate_action, "block")
        self.assertEqual(result.diagnostics["failed_checks"], ["security-scan"])

    def test_missing_check_escalates_without_permission(self):
        result = evaluate_release(request(), policy(), checks()[:1])
        self.assertEqual(result.state, "rejected")
        self.assertEqual(result.gate_action, "escalate")
        self.assertEqual(result.diagnostics["missing_checks"], ["security-scan"])

    def test_check_from_wrong_app_does_not_count(self):
        observations = (
            checks()[0],
            CheckObservation("security-scan", "completed", "success", "impostor", 102),
        )
        result = evaluate_release(request(), policy(), observations)
        self.assertEqual(result.state, "rejected")
        self.assertEqual(result.diagnostics["wrong_app_checks"], ["security-scan"])

    def test_skipped_or_neutral_is_not_positive_evidence(self):
        observations = (
            CheckObservation("test-suite", "completed", "skipped", "github-actions", 101),
            checks()[1],
        )
        result = evaluate_release(request(), policy(), observations)
        self.assertEqual(result.state, "rejected")
        self.assertEqual(result.gate_action, "escalate")
        self.assertEqual(result.diagnostics["unknown_checks"], ["test-suite"])

    def test_unconfigured_environment_is_deterministically_blocked(self):
        other = DeploymentRequest(**{
            **request().__dict__, "environment": "customer-production",
        })
        result = evaluate_release(other, policy(), checks())
        self.assertEqual(result.gate_action, "block")

    def test_payload_requires_full_sha_and_github_callback(self):
        bad = payload()
        bad["sha"] = "main"
        with self.assertRaisesRegex(ReleaseWardenError, "full commit"):
            parse_deployment_request(bad, "d")
        bad = payload()
        bad["deployment_callback_url"] = "https://attacker.example/callback"
        with self.assertRaisesRegex(ReleaseWardenError, "approved GitHub"):
            parse_deployment_request(bad, "d")

    def test_signature_is_constant_time_comparable_contract(self):
        body = b"{}"
        signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_webhook_signature(b"secret", body, signature))
        self.assertFalse(verify_webhook_signature(b"wrong", body, signature))
        self.assertFalse(verify_webhook_signature(b"secret", body, None))

    def test_shadow_service_records_hypothesis_but_releases_github(self):
        body = json.dumps(payload(), sort_keys=True).encode()
        # This matches the title-casing produced by BaseHTTPRequestHandler in
        # the real GitHub App webhook path.
        headers = {
            "X-Github-Event": "deployment_protection_rule",
            "X-Github-Delivery": "delivery-shadow",
            "X-Hub-Signature-256": "sha256=" + hmac.new(
                b"secret", body, hashlib.sha256
            ).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            transport = Transport()
            service = ReleaseWardenService(
                policy(), transport, DeliveryStore(Path(directory) / "events.db"), b"secret"
            )
            status, result = service.handle(body, headers)
            self.assertEqual(status, 200)
            self.assertEqual(result["state"], "approved")
            self.assertEqual(len(transport.reviews), 1)
            self.assertEqual(transport.reviews[0][1], "approved")
            status, replay = service.handle(body, headers)
            self.assertEqual(status, 200)
            self.assertEqual(replay, result)
            self.assertEqual(len(transport.reviews), 1)

    def test_shadow_reports_reject_but_callback_still_releases(self):
        body = json.dumps(payload(), sort_keys=True).encode()
        headers = {
            "X-GitHub-Event": "deployment_protection_rule",
            "X-GitHub-Delivery": "delivery-shadow-reject",
            "X-Hub-Signature-256": "sha256=" + hmac.new(
                b"secret", body, hashlib.sha256
            ).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            transport = Transport(checks(security="failure"))
            service = ReleaseWardenService(
                policy(), transport, DeliveryStore(Path(directory) / "events.db"), b"secret"
            )
            _, result = service.handle(body, headers)
            self.assertEqual(result["state"], "rejected")
            self.assertEqual(transport.reviews[0][1], "approved")

    def test_enforce_service_sends_one_approved_callback(self):
        body = json.dumps(payload(), sort_keys=True).encode()
        headers = {
            "X-GitHub-Event": "deployment_protection_rule",
            "X-GitHub-Delivery": "delivery-enforce",
            "X-Hub-Signature-256": "sha256=" + hmac.new(
                b"secret", body, hashlib.sha256
            ).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            transport = Transport()
            service = ReleaseWardenService(
                policy(mode="enforce"), transport,
                DeliveryStore(Path(directory) / "events.db"), b"secret",
            )
            status, result = service.handle(body, headers)
            self.assertEqual(status, 200)
            self.assertEqual(result["state"], "approved")
            self.assertEqual(len(transport.reviews), 1)
            self.assertEqual(transport.reviews[0][1], "approved")
            service.handle(body, headers)
            self.assertEqual(len(transport.reviews), 1)

    def test_bad_signature_never_collects_or_reviews(self):
        body = json.dumps(payload()).encode()
        with tempfile.TemporaryDirectory() as directory:
            transport = Transport()
            service = ReleaseWardenService(
                policy(mode="enforce"), transport,
                DeliveryStore(Path(directory) / "events.db"), b"secret",
            )
            status, result = service.handle(body, {
                "X-GitHub-Event": "deployment_protection_rule",
                "X-GitHub-Delivery": "delivery-bad",
                "X-Hub-Signature-256": "sha256:wrong",
            })
            self.assertEqual(status, 401)
            self.assertEqual(transport.reviews, [])


if __name__ == "__main__":
    unittest.main()
