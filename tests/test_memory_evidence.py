import unittest
from datetime import datetime, timezone

from minority_prophet import (
    DeterministicDecision,
    TrustAllVerifier,
    assess_memory_evidence,
    selective_decide,
)


def profile(**overrides):
    result = {
        "profile": "memory-evidence-profile-v0.1",
        "proposition": "the user approved request 7",
        "claims": [{
            "id": "receipt-1",
            "value": True,
            "source": "approval-record",
            "derived_from": [],
            "claim_digest": "sha256:" + "1" * 64,
            "root_authentication": {
                "status": "authenticated",
                "issuer": "authority-provider",
                "key_id": "key-1",
                "method": "external-receipt",
            },
        }],
        "search": {"scope": "request 7 approvals", "coverage": "complete", "queried": 1, "total_known": 1},
        "verifiers": [{"id": "verifier-1", "controller": "operator-1", "controller_basis": "signed inventory"}],
        "binding": {
            "proposition_digest": "sha256:" + "a" * 64,
            "memory_object_digest": "sha256:" + "b" * 64,
            "request_digest": "sha256:" + "c" * 64,
            "action_digest": "sha256:" + "d" * 64,
        },
        "lifecycle": {
            "observed_at": "2026-08-08T10:00:00Z",
            "expires_at": "2026-08-09T10:00:00Z",
            "nonce": "memory-example-001",
            "revocation_status": "active",
        },
        "conclusion": {
            "kind": "support",
            "strength": 0.8,
            "uncertainty": "External authentication is provider asserted.",
            "method": "example-method-v0.1",
            "input_claims": ["receipt-1"],
        },
    }
    for key, value in overrides.items():
        result[key] = value
    return result


NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)


def context():
    return {
        "expected_proposition_digest": "sha256:" + "a" * 64,
        "expected_memory_object_digest": "sha256:" + "b" * 64,
        "expected_request_digest": "sha256:" + "c" * 64,
        "expected_action_digest": "sha256:" + "d" * 64,
        "now": NOW,
    }


class MemoryEvidenceTests(unittest.TestCase):
    def test_valid_profile_is_accepted_as_evidence_not_authority(self):
        result = assess_memory_evidence(
            profile(),
            **context(),
        )
        self.assertEqual(result.action, "accept")
        self.assertFalse(result.grants_authority)

    def test_revoked_expired_or_wrong_binding_blocks(self):
        cases = []
        revoked = profile()
        revoked["lifecycle"]["revocation_status"] = "revoked"
        cases.append(revoked)
        expired = profile()
        expired["lifecycle"]["expires_at"] = "2026-08-08T11:00:00Z"
        cases.append(expired)
        wrong = profile()
        wrong["binding"]["action_digest"] = "sha256:" + "e" * 64
        cases.append(wrong)
        for evidence in cases:
            result = assess_memory_evidence(
                evidence,
                **context(),
            )
            self.assertEqual(result.action, "block")

    def test_unknown_partial_or_declared_root_escalates(self):
        unknown = profile()
        unknown["lifecycle"]["revocation_status"] = "unknown"
        partial = profile()
        partial["search"]["coverage"] = "partial"
        declared = profile()
        declared["claims"][0]["root_authentication"] = {
            "status": "declared", "issuer": None, "key_id": None, "method": None,
        }
        for evidence in (unknown, partial, declared):
            result = assess_memory_evidence(evidence, **context())
            self.assertEqual(result.action, "escalate")

    def test_replayed_nonce_blocks(self):
        result = assess_memory_evidence(profile(), used_nonces={"memory-example-001"}, **context())
        self.assertEqual(result.action, "block")

    def test_malformed_profile_escalates_fail_closed(self):
        result = assess_memory_evidence({"profile": "memory-evidence-profile-v0.1"}, now=NOW)
        self.assertEqual(result.action, "escalate")

    def test_accepted_memory_cannot_create_permission_without_evidence(self):
        decision = selective_decide(
            DeterministicDecision("review", "memory-dependent request", evidence_sensitive=True),
            [],
            TrustAllVerifier(),
            memory_evidence=profile(),
            memory_evidence_context=context(),
        )
        self.assertEqual((decision.action, decision.route), ("escalate", "human"))
        self.assertFalse(decision.diagnostics["memory_evidence"]["grants_authority"])

    def test_revoked_memory_stops_evidence_sensitive_path(self):
        evidence = profile()
        evidence["lifecycle"]["revocation_status"] = "revoked"
        decision = selective_decide(
            DeterministicDecision("allow", "base policy allows", evidence_sensitive=True),
            [],
            TrustAllVerifier(),
            memory_evidence=evidence,
            memory_evidence_context=context(),
        )
        self.assertEqual((decision.action, decision.route), ("block", "evidence"))


if __name__ == "__main__":
    unittest.main()
