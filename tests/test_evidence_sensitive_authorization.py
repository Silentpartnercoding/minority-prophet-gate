import importlib.util
from pathlib import Path
import unittest


EXAMPLE = Path(__file__).parents[1] / "examples" / "evidence_sensitive_authorization.py"
SPEC = importlib.util.spec_from_file_location("evidence_sensitive_authorization", EXAMPLE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class EvidenceSensitiveAuthorizationTests(unittest.TestCase):
    def test_copied_approval_cannot_authorize_deployment(self):
        result = MODULE.run_case()

        self.assertEqual(result["voices"], {"safe": 7, "unsafe": 2})
        self.assertEqual(result["independent_roots"], {"safe": 1, "unsafe": 2})
        self.assertEqual(result["evidence_assessment"]["verdict"], 0)
        self.assertEqual(result["authority_decision"], "block")
        self.assertEqual(result["runtime_receipt"]["status"], "prevented")
        self.assertEqual(result["runtime_receipt"]["attempt_count"], 0)
        self.assertEqual(result["effects_executed"], 0)

    def test_more_copies_never_change_the_decision(self):
        baseline = MODULE.manufactured_consensus()
        copies = [
            MODULE._claim(f"extra-echo-{index}", "SAFE", "scan-one", parent="safe-scan")
            for index in range(100)
        ]
        assessment = MODULE.assess(
            baseline + copies,
            MODULE.CallbackVerifier(MODULE.fixture_verifier),
            decision_subject=MODULE.SUBJECT,
            unbound_root_weight=0.0,
            freshness=None,
        )

        self.assertEqual(assessment.verdict, 0)
        self.assertEqual(assessment.roots_for, 1)
        self.assertEqual(assessment.roots_against, 2)
        self.assertEqual(MODULE.authority_policy(assessment).action, "block")

    def test_independent_approval_can_execute_the_exact_action(self):
        result = MODULE.evaluate_and_apply(MODULE.independently_verified_approval())

        self.assertEqual(result["voices"], {"safe": 2, "unsafe": 1})
        self.assertEqual(result["independent_roots"], {"safe": 2, "unsafe": 1})
        self.assertEqual(result["evidence_assessment"]["verdict"], 1)
        self.assertEqual(result["authority_decision"], "proceed")
        self.assertEqual(result["runtime_receipt"]["status"], "succeeded")
        self.assertEqual(result["runtime_receipt"]["attempt_count"], 1)
        self.assertEqual(result["effects_executed"], 1)

    def test_tough_case_beats_voice_based_trust_measures(self):
        result = MODULE.benchmark_trust_measures()

        self.assertEqual(result["known_correct_action"], "UNSAFE")
        self.assertEqual(result["measures"], {
            "head_count": "SAFE",
            "verified_identity_or_signature": "SAFE",
            "signature_plus_subject_plus_freshness": "SAFE",
            "independent_evidence_roots": "UNSAFE",
        })
        self.assertEqual(result["details"]["voices"], {"safe": 12, "unsafe": 3})
        self.assertEqual(
            result["details"]["independent_roots"], {"safe": 2, "unsafe": 3}
        )
        self.assertEqual(result["root_measure_authority_decision"], "block")
        self.assertEqual(result["root_measure_effects_executed"], 0)


if __name__ == "__main__":
    unittest.main()
