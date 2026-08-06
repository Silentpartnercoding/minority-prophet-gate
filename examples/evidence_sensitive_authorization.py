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
from minority_prophet.adapter_acp import (
    DEFAULT_FRESHNESS,
    CallbackVerifier,
    envelopes_to_claims,
)
from minority_prophet.runtime_adapter import RuntimeAction, RuntimeController
from minority_prophet.runtime_integrations import InProcessToolRuntime, payload_digest


SUBJECT = "buzz:deploy:payments-api:release-2026-08-05"


def _claim(claim_id: str, assertion: str, origin: str, *, parent: str | None = None,
           subject: str = SUBJECT, proof: str | None = None,
           origin_class: str | None = None, age_s: float | None = None) -> dict:
    attest = {
        "origin": origin,
        "subject": subject,
        "proof": proof or ("verified-derived" if parent else "verified-root"),
    }
    if parent:
        attest["derived_from"] = parent
    if origin_class:
        attest["origin_class"] = origin_class
    if age_s is not None:
        attest["observed_at_age_s"] = age_s
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


def adversarial_mixed_evidence() -> list[dict]:
    """A harder case: copying, forgery, stale evidence, and subject substitution.

    Twelve SAFE voices face three UNSAFE voices. After signature, subject, and
    freshness checks, eight SAFE voices remain—but seven share one root. The
    final independent-root count is two SAFE versus three UNSAFE.
    """
    evidence = [_claim("safe-scan", "SAFE", "scan-one")]
    evidence.extend(
        _claim(f"safe-echo-{index}", "SAFE", "scan-one", parent="safe-scan")
        for index in range(1, 7)
    )
    evidence.extend([
        _claim("safe-independent", "SAFE", "safe-test-independent"),
        _claim("safe-forgery-a", "SAFE", "forged-a", proof="forged"),
        _claim("safe-forgery-b", "SAFE", "forged-b", proof="forged"),
        _claim("safe-stale", "SAFE", "start-event-old", origin_class="start-event",
               age_s=48 * 60 * 60),
        _claim("safe-wrong-action", "SAFE", "safe-other-action",
               subject="buzz:deploy:unrelated-service:release-old"),
        _claim("unsafe-test-a", "UNSAFE", "unsafe-test-run-a"),
        _claim("unsafe-test-b", "UNSAFE", "unsafe-test-run-b"),
        _claim("unsafe-test-c", "UNSAFE", "unsafe-test-run-c"),
    ])
    return evidence


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
        freshness=DEFAULT_FRESHNESS,
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


def _label(bit: int) -> str:
    return "SAFE" if bit == 1 else "UNSAFE"


def _head_count(evidence: list[dict]) -> str:
    safe = sum(item["assertion"] == "SAFE" for item in evidence)
    return _label(int(safe * 2 > len(evidence)))


def _verified_voice_count(evidence: list[dict]) -> str:
    accepted = [item for item in evidence if fixture_verifier(item) != "invalid"]
    return _head_count(accepted)


def _bound_fresh_voice_count(evidence: list[dict]) -> str:
    report = envelopes_to_claims(
        evidence,
        CallbackVerifier(fixture_verifier),
        decision_subject=SUBJECT,
        unbound_root_weight=0.0,
        freshness=DEFAULT_FRESHNESS,
    )
    accepted = [claim for claim in report.claims if claim.weight > 0]
    safe = sum(claim.assertion == 1 for claim in accepted)
    return _label(int(safe * 2 > len(accepted)))


def benchmark_trust_measures() -> dict:
    """Compare common checks with provenance-aware root counting on one case."""
    evidence = adversarial_mixed_evidence()
    result = evaluate_and_apply(evidence)
    return {
        "known_correct_action": "UNSAFE",
        "measures": {
            "head_count": _head_count(evidence),
            "verified_identity_or_signature": _verified_voice_count(evidence),
            "signature_plus_subject_plus_freshness": _bound_fresh_voice_count(evidence),
            "independent_evidence_roots": _label(
                result["evidence_assessment"]["verdict"]
            ),
        },
        "root_measure_authority_decision": result["authority_decision"],
        "root_measure_effects_executed": result["effects_executed"],
        "details": result,
    }


def run_case() -> dict:
    return evaluate_and_apply(manufactured_consensus())


if __name__ == "__main__":
    print(json.dumps({
        "manufactured_consensus": run_case(),
        "independently_verified_approval": evaluate_and_apply(
            independently_verified_approval()
        ),
        "adversarial_trust_measure_benchmark": benchmark_trust_measures(),
    }, indent=2, sort_keys=True))
