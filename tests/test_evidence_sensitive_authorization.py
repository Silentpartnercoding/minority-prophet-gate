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


if __name__ == "__main__":
    unittest.main()
