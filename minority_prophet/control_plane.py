"""Evidence-control plane for consequential runtime actions.

This is the small composition layer that always sits in front of an effect. It
freezes an action, applies deterministic policy, requests only policy-approved
evidence when necessary, routes collection through separately authorized
adapters, re-evaluates within a bounded budget, and gives the runtime exactly
one final decision.

The layer is deliberately vendor-neutral. A light deployment supplies local
collectors, a verifier, and a runtime adapter. In a hardened deployment Border
may admit evidence before this layer receives it, but returned evidence always
comes back to Gate for the next decision. Border is not the enforcement target.
In every deployment collectors remain unable to authorize the protected action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .adapter_acp import AttestationVerifier
from .autonomy import (
    AutonomyController,
    AutonomyLevel,
    AutonomyMandate,
    AutonomyOutcome,
    EmergencyNotifier,
    resolve_gate_release,
)
from .evidence_audit import EvidenceRoutingError
from .evidence_request import EvidenceRequest, EvidenceRequestPolicy
from .evidence_router import EvidenceCollectionResult, EvidenceRouter
from .gate import GateDecision
from .runtime_adapter import (
    RuntimeAction,
    RuntimeAdapter,
    RuntimeBoundaryError,
    RuntimeController,
    RuntimeReceipt,
)
from .selective_hybrid import DeterministicDecision, SelectiveDecision, selective_decide


@dataclass(frozen=True)
class VerifiedEvidenceBatch:
    """Trusted output of the verifier boundary, never of a collector directly."""

    envelopes: tuple[dict, ...]
    verifier: AttestationVerifier
    diagnostics: dict = field(default_factory=dict)


class EvidenceVerifierBridge(Protocol):
    """Resolve candidate evidence and verification artifacts into Gate input.

    A light installation can use ``CandidateEvidenceBridge`` below. A hardened
    installation can provide an adapter for evidence already admitted by Border
    or another trust service. Gate remains the decision point in both cases.
    """

    def verify(
        self,
        request: EvidenceRequest,
        results: tuple[EvidenceCollectionResult, ...],
        previous: VerifiedEvidenceBatch,
    ) -> VerifiedEvidenceBatch:
        """Return the complete evidence batch for reassessment of the frozen action."""


class CandidateEvidenceBridge:
    """Minimal bridge for an embedded install with an injected real verifier.

    Candidate assertions are sent back to Gate. Verification artifacts are not
    assertions and therefore never become extra votes. The injected verifier is
    the security boundary; ``TrustAllVerifier`` must only be used in tests.
    """

    def __init__(self, verifier: AttestationVerifier) -> None:
        if not isinstance(verifier, AttestationVerifier):
            raise TypeError("verifier must implement AttestationVerifier")
        self.verifier = verifier

    def verify(self, request: EvidenceRequest,
               results: tuple[EvidenceCollectionResult, ...],
               previous: VerifiedEvidenceBatch) -> VerifiedEvidenceBatch:
        del request
        returned = tuple(
            envelope
            for result in results if result.status == "completed"
            for envelope in result.envelopes
            if "assertion" in envelope
        )
        envelopes = previous.envelopes + returned
        return VerifiedEvidenceBatch(envelopes, self.verifier, {
            "previous_envelopes": len(previous.envelopes),
            "returned_candidate_envelopes": len(returned),
            "complete_candidate_envelopes": len(envelopes),
            "verification_occurs_at_gate": True,
        })


@dataclass(frozen=True)
class EvidenceControlPolicy:
    primary: DeterministicDecision
    evidence_requests: EvidenceRequestPolicy
    decision_subject: str
    requester_control_domain: str
    proceed_side: int = 1
    min_flip_budget: float = 1.0
    min_conversions_to_reverse: int | None = None
    unbound_root_weight: float = 0.0

    def __post_init__(self) -> None:
        if not self.decision_subject or not self.requester_control_domain:
            raise ValueError("decision_subject and requester_control_domain are required")
        if not self.primary.policy_id:
            raise ValueError("the primary policy requires a stable policy_id")


@dataclass(frozen=True)
class EvidenceControlOutcome:
    action: RuntimeAction
    decision: SelectiveDecision
    receipt: RuntimeReceipt | None
    collection_rounds: int
    collected_results: tuple[EvidenceCollectionResult, ...]
    transitions: tuple[str, ...]
    autonomy: AutonomyOutcome | None = None


class EvidenceControlPlane:
    """Bounded orchestrator that stands between an agent and an effect."""

    def __init__(self, router: EvidenceRouter, verifier_bridge: EvidenceVerifierBridge,
                 runtime_controller: RuntimeController | None = None) -> None:
        self.router = router
        self.verifier_bridge = verifier_bridge
        self.runtime_controller = runtime_controller or RuntimeController()
        self.autonomy_controller = AutonomyController(self.runtime_controller)
        self._outcomes: dict[str, tuple[tuple, EvidenceControlOutcome]] = {}

    @staticmethod
    def _request_fingerprint(action: RuntimeAction,
                             policy: EvidenceControlPolicy) -> tuple:
        primary = policy.primary
        return (
            action.fingerprint,
            primary.action,
            primary.reason,
            primary.evidence_sensitive,
            primary.policy_id,
            policy.evidence_requests.digest,
            policy.decision_subject,
            policy.requester_control_domain,
            policy.proceed_side,
            policy.min_flip_budget,
            policy.min_conversions_to_reverse,
            policy.unbound_root_weight,
        )

    @staticmethod
    def _runtime_decision(decision: SelectiveDecision) -> GateDecision:
        if decision.action not in {"proceed", "block", "escalate"}:
            raise EvidenceRoutingError("only a final Gate outcome may reach the runtime")
        assessment = decision.assessment
        diagnostics = dict(assessment.diagnostics) if assessment else {}
        diagnostics.update(decision.diagnostics)
        diagnostics.update(route=decision.route, reason=decision.reason)
        return GateDecision(
            decision.action,
            assessment.verdict if assessment else None,
            assessment.flip_budget if assessment else 0.0,
            assessment.confidence if assessment else 0.0,
            assessment.roots_for if assessment else 0,
            assessment.roots_against if assessment else 0,
            diagnostics,
            assessment.conversions_to_reverse if assessment else None,
        )

    def run(self, action: RuntimeAction, policy: EvidenceControlPolicy,
            initial_evidence: VerifiedEvidenceBatch, runtime: RuntimeAdapter, *,
            autonomy_mandate: AutonomyMandate | None = None,
            requested_autonomy: AutonomyLevel | str | None = None,
            emergency_notifier: EmergencyNotifier | None = None,
            ) -> EvidenceControlOutcome:
        """Evaluate, collect, re-evaluate, then execute or prevent exactly once."""
        if not isinstance(action, RuntimeAction):
            raise TypeError("action must be a frozen RuntimeAction")
        if not isinstance(policy, EvidenceControlPolicy):
            raise TypeError("policy must be EvidenceControlPolicy")
        if not isinstance(initial_evidence, VerifiedEvidenceBatch):
            raise TypeError("initial_evidence must be VerifiedEvidenceBatch")
        request_fingerprint = self._request_fingerprint(action, policy) + (
            autonomy_mandate.digest if autonomy_mandate else None,
            AutonomyLevel.parse(requested_autonomy).label
            if requested_autonomy is not None else None,
        )
        existing = self._outcomes.get(action.idempotency_key)
        if existing is not None:
            fingerprint, outcome = existing
            if fingerprint != request_fingerprint:
                raise RuntimeBoundaryError(
                    "idempotency key substituted across control-plane action or policy"
                )
            return outcome
        batch = initial_evidence
        prior_request = None
        results: list[EvidenceCollectionResult] = []
        transitions = ["action_frozen", "policy_evaluated"]
        rounds = 0

        while True:
            decision = selective_decide(
                policy.primary,
                batch.envelopes,
                batch.verifier,
                proceed_side=policy.proceed_side,
                min_flip_budget=policy.min_flip_budget,
                min_conversions_to_reverse=policy.min_conversions_to_reverse,
                decision_subject=policy.decision_subject,
                unbound_root_weight=policy.unbound_root_weight,
                evidence_request_policy=policy.evidence_requests,
                prior_evidence_request=prior_request,
                action_digest=action.binding_digest,
            )
            transitions.append(decision.action)
            if decision.action != "request_evidence":
                if prior_request is not None:
                    self.router.record_gate_decision(prior_request, decision)
                break

            request = decision.evidence_request
            if request is None:  # defensive: selective_decide promises this pairing
                raise EvidenceRoutingError("evidence request outcome omitted its challenge")
            rounds += 1
            try:
                returned = self.router.collect(
                    request,
                    requester_control_domain=policy.requester_control_domain,
                )
                batch = self.verifier_bridge.verify(request, returned, batch)
                if not isinstance(batch, VerifiedEvidenceBatch):
                    raise EvidenceRoutingError("verifier bridge returned an invalid batch")
                results.extend(returned)
                transitions.extend(("evidence_collected", "evidence_verified"))
            except Exception as exc:
                decision = SelectiveDecision(
                    "escalate", "human",
                    "evidence collection or verification failed closed",
                    diagnostics={
                        "policy_id": policy.primary.policy_id,
                        "returned_for_challenge_id": request.challenge_id,
                        "error_type": type(exc).__name__,
                    },
                )
                transitions.append("escalate")
                self.router.record_gate_decision(request, decision)
                break
            prior_request = request

        runtime_decision = self._runtime_decision(decision)
        autonomy = None
        if autonomy_mandate is None:
            if requested_autonomy is not None or emergency_notifier is not None:
                raise EvidenceRoutingError(
                    "autonomy level or notifier supplied without an autonomy mandate"
                )
            receipt = self.runtime_controller.apply(runtime_decision, action, runtime)
            transitions.append("effect_executed" if decision.action == "proceed"
                               else "effect_prevented")
        else:
            level = (autonomy_mandate.max_level if requested_autonomy is None
                     else AutonomyLevel.parse(requested_autonomy))
            release = resolve_gate_release(
                runtime_decision, action, autonomy_mandate, level,
            )
            autonomy = self.autonomy_controller.apply(
                release, runtime_decision, action, runtime, autonomy_mandate,
                emergency_notifier,
            )
            receipt = autonomy.receipt
            transitions.append(f"autonomy_{autonomy.status}")
        outcome = EvidenceControlOutcome(
            action, decision, receipt, rounds, tuple(results), tuple(transitions),
            autonomy,
        )
        self._outcomes[action.idempotency_key] = (request_fingerprint, outcome)
        return outcome
