import unittest

from minority_prophet import TrustAllVerifier, assess, decide


SUBJECT = "belief:demo"


def root(claim_id, side):
    return {"claim_id": claim_id, "agent": "observer", "assertion": side,
            "attest": {"origin": claim_id, "subject": SUBJECT, "sig": "test"}}


class EvidenceAssessmentTests(unittest.TestCase):
    def test_assessment_is_action_neutral_and_gate_interprets_it(self):
        evidence = [root("for-1", 1), root("for-2", 1), root("against-1", 0)]
        assessment = assess(evidence, TrustAllVerifier(), decision_subject=SUBJECT)
        self.assertEqual(assessment.verdict, 1)
        self.assertFalse(hasattr(assessment, "action"))
        gate = decide(evidence, TrustAllVerifier(), decision_subject=SUBJECT,
                      proceed_side=1, min_flip_budget=1.0)
        self.assertEqual(gate.action, "proceed")

    def test_same_assessment_can_be_interpreted_by_opposite_action_policy(self):
        evidence = [root("for-1", 1)]
        self.assertEqual(assess(evidence, TrustAllVerifier(),
                                decision_subject=SUBJECT).verdict, 1)
        self.assertEqual(decide(evidence, TrustAllVerifier(), decision_subject=SUBJECT,
                                proceed_side=1).action, "proceed")
        self.assertEqual(decide(evidence, TrustAllVerifier(), decision_subject=SUBJECT,
                                proceed_side=0).action, "block")


if __name__ == "__main__":
    unittest.main()
