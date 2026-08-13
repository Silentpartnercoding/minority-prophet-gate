import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from minority_prophet.byom_cli import evaluate, main


POLICY = {
    "decision_subject": "job:1",
    "proceed_side": 1,
    "min_flip_budget": 1.0,
    "unbound_root_weight": 0.0,
}


def claim(claim_id, assertion, verdict="root", parent=None):
    attest = {"origin": claim_id, "subject": "job:1"}
    if parent:
        attest["derived_from"] = parent
    return {
        "claim_id": claim_id, "agent": claim_id, "assertion": assertion,
        "mp_test_verdict": verdict, "attest": attest,
    }


class BringYourOwnMessTests(unittest.TestCase):
    def test_many_copies_do_not_outvote_independent_roots(self):
        evidence = [claim("safe-root", "SAFE")]
        evidence.extend(claim(f"copy-{i}", "SAFE", "derived", "safe-root")
                        for i in range(100))
        evidence.extend((claim("unsafe-a", "UNSAFE"), claim("unsafe-b", "UNSAFE")))
        result = evaluate(evidence, POLICY)
        self.assertEqual(result["outcome"], "block")
        self.assertEqual(result["runtime_effects"], 0)
        self.assertEqual((result["roots_for"], result["roots_against"]), (1, 2))

    def test_invalid_lab_verdict_fails_closed(self):
        result = evaluate([claim("fake", "SAFE", "pretend-root")], POLICY)
        self.assertEqual(result["outcome"], "escalate")
        self.assertEqual(result["runtime_effects"], 0)

    def test_cli_writes_feedback_without_raw_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence.json"
            policy = root / "policy.json"
            report = root / "feedback.json"
            evidence.write_text(json.dumps([claim("safe", "SAFE")]))
            policy.write_text(json.dumps(POLICY))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["evaluate", "--evidence", str(evidence),
                             "--policy", str(policy), "--feedback", str(report)])
            self.assertEqual(code, 0)
            returned = json.loads(output.getvalue())
            feedback = json.loads(report.read_text())
            self.assertEqual(returned["runtime_effects"], 0)
            self.assertNotIn("raw_evidence", feedback)
            self.assertIn("evidence_sha256", feedback["input_fingerprints"])

    def test_malformed_json_is_machine_readable_and_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "bad.json"
            policy = root / "policy.json"
            evidence.write_text("{not-json")
            policy.write_text(json.dumps(POLICY))
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(["evaluate", "--evidence", str(evidence),
                             "--policy", str(policy)])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(errors.getvalue())["runtime_effects"], 0)


if __name__ == "__main__":
    unittest.main()
