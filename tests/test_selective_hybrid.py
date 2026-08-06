import unittest

from minority_prophet import DeterministicDecision, TrustAllVerifier, selective_decide


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


if __name__ == "__main__":
    unittest.main()
