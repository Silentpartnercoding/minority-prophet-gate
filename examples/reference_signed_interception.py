"""Runnable, harmless signed-receipt -> Gate -> tool interception example."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from minority_prophet import (
    AuthenticatedSqliteCaseStore,
    InProcessToolRuntime,
    RECEIPT_SCHEMA,
    RuntimeAction,
    RuntimeController,
    SignedReceiptVerifier,
    decide,
    sign_receipt_envelope,
)
from minority_prophet.runtime_integrations import payload_digest


WAREHOUSE_KEY = b"warehouse-reference-key-32-bytes!"
FINANCE_KEY = b"finance-reference-key-is-32-bytes!"
SUBJECT = "action:pay-invoice-742"


def evidence(claim_id, assertion, root_id, issuer, key, *, parent=None):
    attestation = {
        "schema": RECEIPT_SCHEMA,
        "issuer": issuer,
        "control_domain": issuer,
        "root_id": root_id,
        "origin": "record",
        "subject": SUBJECT,
        "observed_at_age_s": 0,
    }
    if parent:
        attestation["derived_from"] = parent
    return sign_receipt_envelope({
        "claim_id": claim_id,
        "agent": issuer,
        "assertion": assertion,
        "attest": attestation,
    }, key)


def main():
    payload = {"invoice_id": "742", "amount": 8000}
    action = RuntimeAction(
        "pay-742", "tool.call", "demo:payment",
        payload_digest(payload), "pay-742-once", payload,
    )
    submitted = (
        evidence("delivery", "SAFE", "warehouse-record-991",
                 "warehouse", WAREHOUSE_KEY),
        # A second agent repeats the warehouse record. It is an echo, not a vote.
        evidence("delivery-summary", "SAFE", "warehouse-record-991",
                 "finance", FINANCE_KEY, parent="delivery"),
        evidence("invoice", "SAFE", "accounting-record-742",
                 "finance", FINANCE_KEY),
    )
    verifier = SignedReceiptVerifier(
        {"warehouse": WAREHOUSE_KEY, "finance": FINANCE_KEY},
        {"warehouse": "warehouse", "finance": "finance"},
    )
    effects = []
    runtime = InProcessToolRuntime({
        ("tool.call", "demo:payment"):
            lambda body, key: effects.append((body, key)) or {"demo": "paid"}
    })

    with tempfile.TemporaryDirectory() as directory:
        with AuthenticatedSqliteCaseStore(
            Path(directory) / "cases.sqlite", b"case-reference-key-is-32-bytes!!"
        ) as cases:
            cases.open_case(SUBJECT, action.binding_digest, "sha256:demo-policy")
            for envelope in submitted:
                cases.append(SUBJECT, envelope)
            cases.transition(SUBJECT, "ready")
            decision = decide(
                cases.envelopes(SUBJECT), verifier,
                decision_subject=SUBJECT, proceed_side=1,
            )
            receipt = RuntimeController().apply(decision, action, runtime)
            cases.transition(SUBJECT, "decided")

    print(json.dumps({
        "gate_action": decision.action,
        "independent_roots_for": decision.roots_for,
        "submitted_agent_claims": len(submitted),
        "runtime_status": receipt.status,
        "runtime_effects": len(effects),
    }, indent=2))


if __name__ == "__main__":
    main()
