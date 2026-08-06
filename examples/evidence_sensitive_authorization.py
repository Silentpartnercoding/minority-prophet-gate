"""Runnable evidence-sensitive authorization example.

Seven agents approve a consequential deployment, but all seven reports descend
from one scan. Two independent test runs reject it. Minority Prophet assesses
the evidence; a separate authority policy decides whether the runtime may act.

Run from the repository root with:
    python -m examples.evidence_sensitive_authorization
"""

from __future__ import annotations

from dataclasses import asdict
import json

from minority_prophet import EvidenceAssessment, GateDecision, assess
from minority_prophet.adapter_acp import CallbackVerifier
from minority_prophet.runtime_adapter import RuntimeAction, RuntimeController
from minority_prophet.runtime_integrations import InProcessToolRuntime, payload_digest


SUBJECT = "buzz:deploy:payments-api:release-2026-08-05"


def _claim(claim_id: str, assertion: str, origin: str, *, parent: str | None = None) -> dict:
    attest = {
        "origin": origin,
        "subject": SUBJECT,
        "proof": "verified-derived" if parent else "verified-root",
    }
    if parent:
        attest["derived_from"] = parent
    return {
        "claim_id": claim_id,
        "agent": claim_id,
        "assertion": assertion,
        "attest": attest,
    }


def manufactured_consensus() -> list[dict]:
    """Seven SAFE voices from one root, versus two independent UNSAFE roots."""
    evidence = [_claim("safe-scan", "SAFE", "scan-one")]
    evidence.extend(
        _claim(f"safe-echo-{index}", "SAFE", "scan-one", parent="safe-scan")
        for index in range(1, 7)
    )
    evidence.extend([
        _claim("unsafe-test-a", "UNSAFE", "test-run-a"),
        _claim("unsafe-test-b", "UNSAFE", "test-run-b"),
    ])
    return evidence


def independently_verified_approval() -> list[dict]:
    """Two independent SAFE roots versus one independent UNSAFE root."""
    return [
        _claim("safe-test-a", "SAFE", "safe-test-run-a"),
        _claim("safe-test-b", "SAFE", "safe-test-run-b"),
        _claim("unsafe-test-a", "UNSAFE", "unsafe-test-run-a"),
    ]


def fixture_verifier(envelope: dict) -> str:
    """Deterministic demo verifier; production must verify real signatures."""
    proof = (envelope.get("attest") or {}).get("proof")
    if proof == "verified-root":
        return "root"
    if proof == "verified-derived":
        return "derived"
    return "invalid"


def authority_policy(assessment: EvidenceAssessment) -> GateDecision:
    """Example provider-owned policy; assessment itself grants no permission."""
    if assessment.verdict is None:
        action = "escalate"
    elif assessment.verdict == 1 and assessment.flip_budget >= 1.0:
        action = "proceed"
    else:
        action = "block"
    return GateDecision(
        action=action,
        decision=assessment.verdict,
        flip_budget=assessment.flip_budget,
        confidence=assessment.confidence,
        roots_for=assessment.roots_for,
        roots_against=assessment.roots_against,
        diagnostics=dict(assessment.diagnostics, policy="demo-authority-policy-v1"),
    )


def evaluate_and_apply(evidence: list[dict]) -> dict:
    assessment = assess(
        evidence,
        CallbackVerifier(fixture_verifier),
        decision_subject=SUBJECT,
        unbound_root_weight=0.0,
        freshness=None,
    )
    authorization = authority_policy(assessment)

    effects: list[dict] = []

    def deploy(payload: dict, idempotency_key: str) -> dict:
        effects.append(payload)
        return {"deployment": "started", "idempotency_key": idempotency_key}

    payload = {"service": "payments-api", "release": "2026-08-05"}
    runtime = InProcessToolRuntime({("deploy", "production"): deploy})
    receipt = RuntimeController().apply(
        authorization,
        RuntimeAction(
            action_id="deploy-payments-2026-08-05",
            action_type="deploy",
            target="production",
            payload_digest=payload_digest(payload),
            idempotency_key="deploy-payments-2026-08-05-v1",
            payload=payload,
        ),
        runtime,
    )
    return {
        "voices": {
            "safe": sum(item["assertion"] == "SAFE" for item in evidence),
            "unsafe": sum(item["assertion"] == "UNSAFE" for item in evidence),
        },
        "independent_roots": {
            "safe": assessment.roots_for,
            "unsafe": assessment.roots_against,
        },
        "evidence_assessment": asdict(assessment),
        "authority_decision": authorization.action,
        "runtime_receipt": asdict(receipt),
        "effects_executed": len(effects),
    }


def run_case() -> dict:
    return evaluate_and_apply(manufactured_consensus())


if __name__ == "__main__":
    print(json.dumps({
        "manufactured_consensus": run_case(),
        "independently_verified_approval": evaluate_and_apply(
            independently_verified_approval()
        ),
    }, indent=2, sort_keys=True))
