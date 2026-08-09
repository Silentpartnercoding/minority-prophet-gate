import unittest
from unittest.mock import patch

from minority_prophet import (
    DeterministicDecision,
    EvidenceAssessment,
    TrustAllVerifier,
    selective_decide,
)


def roots(for_count, against_count):
    result = []
    for value, count in (("SAFE", for_count), ("UNSAFE", against_count)):
        for index in range(count):
            root = f"{value.lower()}-{index}"
            result.append({"claim_id": root, "agent": root, "assertion": value,
                           "attest": {"origin": root, "subject": "action-1"}})
    return result


class SelectiveHybridTests(unittest.TestCase):
    def test_clear_allow_stays_on_deterministic_fast_path(self):
        decision = selective_decide(
            DeterministicDecision("allow", "ordinary action", policy_id="p1"),
            [], TrustAllVerifier(), decision_subject="action-1",
        )
        self.assertEqual((decision.action, decision.route), ("proceed", "deterministic"))

    def test_deterministic_deny_cannot_be_overridden_by_evidence(self):
        decision = selective_decide(
            DeterministicDecision("deny", "scope exceeded", evidence_sensitive=True),
            roots(20, 0), TrustAllVerifier(), decision_subject="action-1",
        )
        self.assertEqual((decision.action, decision.route), ("block", "deterministic"))

    def test_evidence_sensitive_allow_invokes_provenance_challenger(self):
        decision = selective_decide(
            DeterministicDecision("allow", "base policy allows", evidence_sensitive=True),
            roots(1, 2), TrustAllVerifier(), decision_subject="action-1",
        )
        self.assertEqual((decision.action, decision.route), ("block", "evidence"))

    def test_tie_or_missing_evidence_escalates_to_human(self):
        for evidence in ([], roots(1, 1)):
            decision = selective_decide(
                DeterministicDecision("review", "policy needs evidence"),
                evidence, TrustAllVerifier(), decision_subject="action-1",
            )
            self.assertEqual((decision.action, decision.route), ("escalate", "human"))

    def test_independent_support_can_complete_evidence_sensitive_allow(self):
        decision = selective_decide(
            DeterministicDecision("allow", "base policy allows", evidence_sensitive=True),
            roots(2, 1), TrustAllVerifier(), decision_subject="action-1",
        )
        self.assertEqual((decision.action, decision.route), ("proceed", "evidence"))

    def test_conversion_resistance_can_be_required_for_proceed(self):
        primary = DeterministicDecision(
            "allow", "base policy allows", evidence_sensitive=True,
        )
        sufficient = selective_decide(
            primary, roots(5, 2), TrustAllVerifier(), decision_subject="action-1",
            min_conversions_to_reverse=2,
        )
        thin = selective_decide(
            primary, roots(5, 2), TrustAllVerifier(), decision_subject="action-1",
            min_conversions_to_reverse=3,
        )
        self.assertEqual(sufficient.assessment.flip_budget, 3.0)
        self.assertEqual(sufficient.assessment.conversions_to_reverse, 2)
        self.assertEqual((sufficient.action, sufficient.route), ("proceed", "evidence"))
        self.assertEqual((thin.action, thin.route), ("escalate", "human"))
        self.assertEqual(thin.reason, "conversion resistance is below policy threshold")
        self.assertEqual(thin.diagnostics["observed_conversions_to_reverse"], 2)

    def test_unavailable_conversion_price_fails_closed(self):
        assessment = EvidenceAssessment(1, 4.0, 1.0, 4, 0,
                                        conversions_to_reverse=None)
        with patch("minority_prophet.selective_hybrid.assess", return_value=assessment):
            decision = selective_decide(
                DeterministicDecision("review", "check evidence"),
                [], TrustAllVerifier(), min_conversions_to_reverse=1,
            )
        self.assertEqual((decision.action, decision.route), ("escalate", "human"))
        self.assertEqual(decision.reason, "conversion resistance is unavailable")

    def test_conversion_threshold_must_be_a_positive_integer(self):
        primary = DeterministicDecision("review", "check evidence")
        for invalid in (0, -1, 1.5, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                selective_decide(primary, [], TrustAllVerifier(),
                                 min_conversions_to_reverse=invalid)


if __name__ == "__main__":
    unittest.main()
