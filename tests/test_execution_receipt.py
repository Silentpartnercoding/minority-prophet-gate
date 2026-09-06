import copy
import unittest

from minority_prophet.execution_receipt import (
    hmac_signer, hmac_verifier, issue_execution_receipt, verify_execution_receipt,
)
from minority_prophet.gate import GateDecision
from minority_prophet.runtime_adapter import RuntimeAction, RuntimeReceipt


class ExecutionReceiptTests(unittest.TestCase):
    def setUp(self):
        self.key = b"runtime-execution-receipt-test-key"
        self.action = RuntimeAction("act-1", "http.request", "https://vendor.example",
                                    "sha256:effect", "idem-1")
        self.result = RuntimeReceipt("act-1", "idem-1", "succeeded", 1, "sha256:result")
        self.gate = GateDecision("proceed", 1, 1, 1, 1, 0, {
            "authority_continuity": True, "effect_digest": "sha256:effect",
            "chain_digest": "sha256:chain",
        })

    def envelope(self):
        return issue_execution_receipt(
            self.action, self.result, self.gate, runtime_id="runtime:one",
            key_id="runtime-key", executed_at="2026-09-06T19:00:00Z",
            signer=hmac_signer(self.key))

    def test_exact_execution_receipt_verifies(self):
        self.assertTrue(verify_execution_receipt(
            self.envelope(), self.action,
            verifier=hmac_verifier({"runtime-key": self.key})))

    def test_mutation_and_wrong_key_fail(self):
        envelope = self.envelope()
        changed = copy.deepcopy(envelope)
        changed["statement"]["result_digest"] = "sha256:other"
        self.assertFalse(verify_execution_receipt(
            changed, self.action, verifier=hmac_verifier({"runtime-key": self.key})))
        self.assertFalse(verify_execution_receipt(
            envelope, self.action, verifier=hmac_verifier({"other": self.key})))

    def test_non_authorized_or_substituted_execution_cannot_be_signed(self):
        blocked = GateDecision("block", 0, 0, 1, 0, 1, {})
        with self.assertRaises(ValueError):
            issue_execution_receipt(self.action, self.result, blocked, runtime_id="runtime:one",
                                    key_id="key", executed_at="now", signer=lambda _: "sig")
        with self.assertRaises(ValueError):
            issue_execution_receipt(
                self.action, RuntimeReceipt("other", "idem-1", "succeeded", 1), self.gate,
                runtime_id="runtime:one", key_id="key", executed_at="now", signer=lambda _: "sig")


if __name__ == "__main__": unittest.main()
