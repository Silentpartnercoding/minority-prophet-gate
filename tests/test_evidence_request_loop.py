"""The Gate may ask an agent to collect evidence without granting authority."""

from dataclasses import replace
import unittest

from minority_prophet import (
    DeterministicDecision,
    EvidenceRequestError,
    EvidenceRequestPolicy,
    EvidenceRequirement,
    TrustAllVerifier,
    selective_decide,
    verify_evidence_request,
)


ACTION_DIGEST = "sha256:action-v1"
SUBJECT = "action-1"
PRIMARY = DeterministicDecision(
    "review", "deployment requires current evidence", policy_id="deploy-policy-v3"
)
POLICY = EvidenceRequestPolicy(
    requirements=(
        EvidenceRequirement(
            "fresh-test-receipt",
            "Collect fresh test-run receipts bound to this action",
            ("test.receipt",),
        ),
        EvidenceRequirement(
            "source-lineage",
            "Retain the source and derivation lineage for every returned claim",
            ("provenance.envelope",),
        ),
    ),
    allowed_collection_actions=("repository.read", "test.run"),
    max_rounds=2,
    max_evidence_items_per_round=20,
)


def root(claim_id, assertion):
    return {
        "claim_id": claim_id,
        "agent": claim_id,
        "assertion": assertion,
        "attest": {"origin": claim_id, "subject": SUBJECT},
    }


def evaluate(envelopes, *, prior=None, action_digest=ACTION_DIGEST,
             primary=PRIMARY, policy=POLICY):
    return selective_decide(
        primary,
        envelopes,
        TrustAllVerifier(),
        decision_subject=SUBJECT,
        action_digest=action_digest,
        evidence_request_policy=policy,
        prior_evidence_request=prior,
    )


class EvidenceRequestLoopTests(unittest.TestCase):
    def test_missing_evidence_returns_a_bounded_non_authorizing_request(self):
        decision = evaluate([])
        request = decision.evidence_request

        self.assertEqual(
            (decision.action, decision.route),
            ("request_evidence", "evidence_collection"),
        )
        self.assertIsNotNone(request)
        self.assertFalse(request.grants_authority)
        self.assertFalse(decision.diagnostics["grants_authority"])
        self.assertEqual(request.round, 1)
        self.assertEqual(request.max_rounds, 2)
        self.assertEqual(request.max_evidence_items, 20)
        self.assertEqual(request.action_digest, ACTION_DIGEST)
        self.assertEqual(request.decision_subject, SUBJECT)
        self.assertEqual(request.reason_code, "missing_verifiable_evidence")
        self.assertNotIn("SAFE", request.to_dict().values())
        verify_evidence_request(request)

    def test_agent_can_return_independent_evidence_and_reach_a_final_decision(self):
        first = evaluate([])
        final = evaluate([root("test-a", "SAFE"), root("test-b", "SAFE")],
                         prior=first.evidence_request)

        self.assertEqual((final.action, final.route), ("proceed", "evidence"))
        self.assertIsNone(final.evidence_request)
        self.assertEqual(
            final.diagnostics["returned_for_challenge_id"],
            first.evidence_request.challenge_id,
        )

    def test_searching_harder_cannot_force_allow_when_evidence_contradicts(self):
        first = evaluate([])
        final = evaluate([root("test-a", "UNSAFE"), root("test-b", "UNSAFE")],
                         prior=first.evidence_request)

        self.assertEqual((final.action, final.route), ("block", "evidence"))
        self.assertIsNone(final.evidence_request)

    def test_unresolved_returns_are_bounded_then_escalate(self):
        first = evaluate([])
        second = evaluate([], prior=first.evidence_request)
        exhausted = evaluate([], prior=second.evidence_request)

        self.assertEqual(second.action, "request_evidence")
        self.assertEqual(second.evidence_request.round, 2)
        self.assertEqual(
            second.evidence_request.previous_challenge_id,
            first.evidence_request.challenge_id,
        )
        self.assertEqual((exhausted.action, exhausted.route), ("escalate", "human"))
        self.assertTrue(exhausted.diagnostics["evidence_collection_exhausted"])
        self.assertIn("budget exhausted", exhausted.reason)

    def test_action_substitution_on_return_is_rejected(self):
        request = evaluate([]).evidence_request
        with self.assertRaisesRegex(EvidenceRequestError, "action_digest"):
            evaluate([], prior=request, action_digest="sha256:other-action")

    def test_policy_substitution_on_return_is_rejected(self):
        request = evaluate([]).evidence_request
        changed = EvidenceRequestPolicy(
            POLICY.requirements,
            ("repository.read", "network.search"),
            max_rounds=2,
        )
        with self.assertRaisesRegex(EvidenceRequestError, "policy_digest"):
            evaluate([], prior=request, policy=changed)

    def test_returned_evidence_item_cap_is_enforced_before_assessment(self):
        request = evaluate([]).evidence_request
        oversized = [root(f"test-{index}", "SAFE") for index in range(21)]
        with self.assertRaisesRegex(ValueError, "item limit"):
            evaluate(oversized, prior=request)

    def test_modified_request_fails_integrity_check(self):
        request = evaluate([]).evidence_request
        modified = replace(request, reason_code="prove_the_desired_answer")
        with self.assertRaisesRegex(EvidenceRequestError, "integrity"):
            verify_evidence_request(modified)

    def test_deterministic_deny_is_final_and_never_requests_collection(self):
        denied = evaluate(
            [root("many", "SAFE")],
            primary=DeterministicDecision(
                "deny", "action exceeds scope", evidence_sensitive=True,
                policy_id="deploy-policy-v3",
            ),
        )
        self.assertEqual((denied.action, denied.route), ("block", "deterministic"))
        self.assertIsNone(denied.evidence_request)

    def test_feature_is_opt_in_and_preserves_existing_escalation(self):
        decision = selective_decide(
            PRIMARY, [], TrustAllVerifier(), decision_subject=SUBJECT,
        )
        self.assertEqual((decision.action, decision.route), ("escalate", "human"))

    def test_challenge_requires_exact_action_subject_and_policy_bindings(self):
        for kwargs, message in (
            ({"action_digest": None}, "action_digest"),
            ({"decision_subject": None}, "decision_subject"),
            ({"primary": DeterministicDecision("review", "needs evidence")},
             "policy_id"),
        ):
            call = {
                "primary": PRIMARY,
                "envelopes": [],
                "verifier": TrustAllVerifier(),
                "decision_subject": SUBJECT,
                "action_digest": ACTION_DIGEST,
                "evidence_request_policy": POLICY,
            }
            call.update(kwargs)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                selective_decide(**call)


if __name__ == "__main__":
    unittest.main()
