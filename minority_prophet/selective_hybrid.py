"""Selective decision ladder: deterministic first, evidence challenger second.

The provenance method is not a universal policy engine. Ordinary explicit
policy remains primary. It is invoked only when that policy marks the action as
evidence-sensitive. Ambiguity escalates; it never becomes permission.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .adapter_acp import AttestationVerifier, DEFAULT_FRESHNESS
from .evidence_request import (
    EvidenceRequest,
    EvidenceRequestError,
    EvidenceRequestExhausted,
    EvidenceRequestPolicy,
    issue_evidence_request,
    validate_evidence_return,
)
from .gate import EvidenceAssessment, assess
from .memory_evidence import assess_memory_evidence


@dataclass(frozen=True)
class DeterministicDecision:
    action: str  # "allow" | "deny" | "review"
    reason: str
    evidence_sensitive: bool = False
    policy_id: str = ""

    def __post_init__(self) -> None:
        if self.action not in {"allow", "deny", "review"}:
            raise ValueError("deterministic action must be allow, deny, or review")


@dataclass(frozen=True)
class SelectiveDecision:
    action: str  # "proceed" | "block" | "request_evidence" | "escalate"
    route: str  # "deterministic" | "evidence" | "evidence_collection" | "human"
    reason: str
    assessment: Optional[EvidenceAssessment] = None
    diagnostics: dict = field(default_factory=dict)
    evidence_request: Optional[EvidenceRequest] = None


def _unresolved(
    reason: str,
    reason_code: str,
    assessment: Optional[EvidenceAssessment],
    diagnostics: dict,
    *,
    evidence_request_policy: Optional[EvidenceRequestPolicy],
    prior_evidence_request: Optional[EvidenceRequest],
    action_digest: Optional[str],
    decision_subject,
    policy_id: str,
) -> SelectiveDecision:
    """Request bounded collection when possible; otherwise ask a human."""
    if evidence_request_policy is None:
        return SelectiveDecision("escalate", "human", reason, assessment, diagnostics)

    try:
        request = issue_evidence_request(
            evidence_request_policy,
            action_digest=action_digest,
            decision_subject=decision_subject,
            policy_id=policy_id,
            reason_code=reason_code,
            previous=prior_evidence_request,
        )
    except EvidenceRequestExhausted:
        return SelectiveDecision(
            "escalate", "human", f"{reason}; evidence collection budget exhausted",
            assessment,
            dict(diagnostics, evidence_collection_exhausted=True,
                 completed_collection_rounds=prior_evidence_request.round),
        )
    return SelectiveDecision(
        "request_evidence", "evidence_collection", reason, assessment,
        dict(diagnostics, evidence_challenge_id=request.challenge_id,
             evidence_collection_round=request.round,
             evidence_collection_max_rounds=request.max_rounds,
             grants_authority=False),
        request,
    )


def selective_decide(
    primary: DeterministicDecision,
    envelopes: Iterable[dict],
    verifier: AttestationVerifier,
    *,
    proceed_side: int = 1,
    min_flip_budget: float = 1.0,
    min_conversions_to_reverse: Optional[int] = None,
    decision_subject=None,
    unbound_root_weight: float = 0.0,
    freshness: Optional[dict] = DEFAULT_FRESHNESS,
    memory_evidence: Optional[dict] = None,
    memory_evidence_context: Optional[dict] = None,
    evidence_request_policy: Optional[EvidenceRequestPolicy] = None,
    prior_evidence_request: Optional[EvidenceRequest] = None,
    action_digest: Optional[str] = None,
) -> SelectiveDecision:
    """Apply the deterministic → evidence → collection-or-human ladder.

    A deterministic deny is final. A deterministic allow proceeds when policy
    does not require evidence review. ``review`` and evidence-sensitive allows
    invoke provenance assessment. By default, missing, tied, or thin evidence
    escalates to a separately authorized human. When an
    ``evidence_request_policy`` is supplied, those unresolved states instead
    produce a bounded, action-bound ``request_evidence`` challenge until its
    round budget is exhausted. Neither outcome inherits the primary allow.

    ``min_flip_budget`` prices newly forged opposing root mass.
    ``min_conversions_to_reverse`` optionally prices compromised winning roots.
    When configured, unavailable conversion pricing fails closed to escalation.
    """
    diagnostics = {"policy_id": primary.policy_id, "primary": primary.action}
    if primary.action == "deny":
        return SelectiveDecision("block", "deterministic", primary.reason,
                                 diagnostics=diagnostics)
    if primary.action == "allow" and not primary.evidence_sensitive:
        return SelectiveDecision("proceed", "deterministic", primary.reason,
                                 diagnostics=diagnostics)

    if prior_evidence_request is not None and evidence_request_policy is None:
        raise ValueError("prior_evidence_request requires evidence_request_policy")
    if evidence_request_policy is not None:
        if not action_digest or decision_subject is None or not primary.policy_id:
            raise ValueError(
                "evidence requests require action_digest, decision_subject, and policy_id"
            )
        if prior_evidence_request is not None:
            validate_evidence_return(
                prior_evidence_request, evidence_request_policy,
                action_digest=action_digest,
                decision_subject=decision_subject,
                policy_id=primary.policy_id,
            )
            diagnostics["returned_for_challenge_id"] = prior_evidence_request.challenge_id
            diagnostics["returned_after_collection_round"] = prior_evidence_request.round
            envelopes = tuple(envelopes)
            if len(envelopes) > prior_evidence_request.max_evidence_items:
                raise EvidenceRequestError(
                    "returned evidence exceeds the challenge item limit"
                )

    if (min_conversions_to_reverse is not None and
            (isinstance(min_conversions_to_reverse, bool) or
             not isinstance(min_conversions_to_reverse, int) or
             min_conversions_to_reverse < 1)):
        raise ValueError("min_conversions_to_reverse must be a positive integer or None")

    if memory_evidence is not None:
        memory = assess_memory_evidence(
            memory_evidence, **(memory_evidence_context or {})
        )
        diagnostics["memory_evidence"] = {
            "action": memory.action,
            "reason": memory.reason,
            "grants_authority": False,
        }
        if memory.action == "block":
            return SelectiveDecision("block", "evidence", memory.reason,
                                     diagnostics=diagnostics)
        if memory.action == "escalate":
            return _unresolved(
                memory.reason, "memory_evidence_unresolved", None, diagnostics,
                evidence_request_policy=evidence_request_policy,
                prior_evidence_request=prior_evidence_request,
                action_digest=action_digest, decision_subject=decision_subject,
                policy_id=primary.policy_id,
            )

    assessment = assess(
        envelopes, verifier, decision_subject=decision_subject,
        unbound_root_weight=unbound_root_weight, freshness=freshness,
    )
    if assessment.verdict is None:
        reason_code = (
            "balanced_evidence"
            if assessment.diagnostics.get("reason") == "abstained: evidence balanced"
            else "missing_verifiable_evidence"
        )
        return _unresolved(
            "evidence is unresolved", reason_code, assessment,
            dict(diagnostics, evidence_reason=assessment.diagnostics.get("reason")),
            evidence_request_policy=evidence_request_policy,
            prior_evidence_request=prior_evidence_request,
            action_digest=action_digest, decision_subject=decision_subject,
            policy_id=primary.policy_id,
        )
    if assessment.flip_budget < min_flip_budget:
        return _unresolved(
            "evidence margin is below policy threshold", "thin_evidence", assessment,
            dict(diagnostics, required_flip_budget=min_flip_budget,
                 observed_flip_budget=assessment.flip_budget),
            evidence_request_policy=evidence_request_policy,
            prior_evidence_request=prior_evidence_request,
            action_digest=action_digest, decision_subject=decision_subject,
            policy_id=primary.policy_id,
        )
    if min_conversions_to_reverse is not None:
        conversion_diagnostics = dict(
            diagnostics,
            required_conversions_to_reverse=min_conversions_to_reverse,
            observed_conversions_to_reverse=assessment.conversions_to_reverse,
        )
        if assessment.conversions_to_reverse is None:
            return _unresolved(
                "conversion resistance is unavailable",
                "conversion_resistance_unavailable", assessment,
                conversion_diagnostics,
                evidence_request_policy=evidence_request_policy,
                prior_evidence_request=prior_evidence_request,
                action_digest=action_digest, decision_subject=decision_subject,
                policy_id=primary.policy_id,
            )
        if assessment.conversions_to_reverse < min_conversions_to_reverse:
            return _unresolved(
                "conversion resistance is below policy threshold",
                "conversion_resistance_below_threshold", assessment,
                conversion_diagnostics,
                evidence_request_policy=evidence_request_policy,
                prior_evidence_request=prior_evidence_request,
                action_digest=action_digest, decision_subject=decision_subject,
                policy_id=primary.policy_id,
            )
        diagnostics = conversion_diagnostics
    if assessment.verdict == proceed_side:
        return SelectiveDecision(
            "proceed", "evidence", "independent evidence satisfies policy",
            assessment, diagnostics,
        )
    return SelectiveDecision(
        "block", "evidence", "independent evidence contradicts the action",
        assessment, diagnostics,
    )
