import sqlite3
import tempfile
import unittest
from pathlib import Path

from minority_prophet import (
    AuthenticatedSqliteCaseStore,
    EvidenceRoutingError,
    RECEIPT_SCHEMA,
    SignedReceiptVerifier,
    decide,
    sign_receipt_envelope,
)


KEY_A = b"a" * 32
KEY_B = b"b" * 32
SUBJECT = "action:pay-invoice-742"


def receipt(claim_id, root_id, *, issuer="warehouse", assertion="SAFE",
            parent=None, key=KEY_A):
    attest = {
        "schema": RECEIPT_SCHEMA,
        "issuer": issuer,
        "control_domain": "warehouse" if issuer == "warehouse" else "finance",
        "root_id": root_id,
        "origin": "record",
        "subject": SUBJECT,
        "observed_at_age_s": 0,
    }
    if parent is not None:
        attest["derived_from"] = parent
    return sign_receipt_envelope(
        {"claim_id": claim_id, "agent": issuer, "assertion": assertion,
         "attest": attest}, key,
    )


class SignedReceiptVerifierTests(unittest.TestCase):
    def verifier(self):
        return SignedReceiptVerifier(
            {"warehouse": KEY_A, "finance": KEY_B},
            {"warehouse": "warehouse", "finance": "finance"},
        )

    def test_shared_root_counts_once_across_agents(self):
        evidence = (
            receipt("a", "delivery-991"),
            receipt("b", "delivery-991", issuer="finance", parent="a", key=KEY_B),
        )
        decision = decide(evidence, self.verifier(), decision_subject=SUBJECT)
        self.assertEqual(decision.roots_for, 1)

    def test_undeclared_reuse_cannot_manufacture_a_root(self):
        evidence = (receipt("a", "delivery-991"), receipt("b", "delivery-991"))
        decision = decide(evidence, self.verifier(), decision_subject=SUBJECT)
        self.assertEqual(decision.roots_for, 1)
        self.assertEqual(decision.diagnostics["quarantined"], 1)

    def test_tampering_is_rejected(self):
        envelope = receipt("a", "delivery-991")
        envelope["assertion"] = "UNSAFE"
        self.assertEqual(self.verifier().verify(envelope), "invalid")


class CaseStoreTests(unittest.TestCase):
    def test_case_survives_reopen_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.sqlite"
            with AuthenticatedSqliteCaseStore(path, KEY_A) as store:
                store.open_case("case-742", "sha256:action", "sha256:policy")
                envelope = receipt("a", "delivery-991")
                store.append("case-742", envelope)
                store.append("case-742", envelope)
                store.transition("case-742", "ready")
            with AuthenticatedSqliteCaseStore(path, KEY_A) as store:
                self.assertEqual(store.case("case-742")["state"], "ready")
                self.assertEqual(len(store.envelopes("case-742")), 1)
                store.transition("case-742", "decided")

    def test_deleted_evidence_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.sqlite"
            with AuthenticatedSqliteCaseStore(path, KEY_A) as store:
                store.open_case("case-742", "sha256:action", "sha256:policy")
                store.append("case-742", receipt("a", "delivery-991"))
            connection = sqlite3.connect(path)
            connection.execute("DELETE FROM case_envelopes")
            connection.commit()
            connection.close()
            with AuthenticatedSqliteCaseStore(path, KEY_A) as store:
                with self.assertRaisesRegex(EvidenceRoutingError, "missing"):
                    store.envelopes("case-742")


if __name__ == "__main__":
    unittest.main()
