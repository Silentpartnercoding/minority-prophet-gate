"""Selective decision ladder: deterministic first, evidence challenger second.

The provenance method is not a universal policy engine. Ordinary explicit
policy remains primary. It is invoked only when that policy marks the action as
evidence-sensitive. Ambiguity escalates; it never becomes permission.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from .adapter_acp import AttestationVerifier, DEFAULT_FRESHNESS
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
    action: str  # "proceed" | "block" | "escalate"
    route: str  # "deterministic" | "evidence" | "human"
    reason: str
    assessment: Optional[EvidenceAssessment] = None
    diagnostics: dict = field(default_factory=dict)


def selective_decide(
    primary: DeterministicDecision,
    envelopes: Iterable[dict],
    verifier: AttestationVerifier,
    *,
    proceed_side: int = 1,
    min_flip_budget: float = 1.0,
    decision_subject=None,
    unbound_root_weight: float = 0.0,
    freshness: Optional[dict] = DEFAULT_FRESHNESS,
    memory_evidence: Optional[dict] = None,
    memory_evidence_context: Optional[dict] = None,
) -> SelectiveDecision:
    """Apply the narrow deterministic → evidence → human ladder.

    A deterministic deny is final. A deterministic allow proceeds when policy
    does not require evidence review. ``review`` and evidence-sensitive allows
    invoke provenance assessment. Missing, tied, or thin evidence escalates to
    a separately authorized human; it never inherits the primary allow.
    """
    diagnostics = {"policy_id": primary.policy_id, "primary": primary.action}
    if primary.action == "deny":
        return SelectiveDecision("block", "deterministic", primary.reason,
                                 diagnostics=diagnostics)
    if primary.action == "allow" and not primary.evidence_sensitive:
        return SelectiveDecision("proceed", "deterministic", primary.reason,
                                 diagnostics=diagnostics)

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
            return SelectiveDecision("escalate", "human", memory.reason,
                                     diagnostics=diagnostics)

    assessment = assess(
        envelopes, verifier, decision_subject=decision_subject,
        unbound_root_weight=unbound_root_weight, freshness=freshness,
    )
    if assessment.verdict is None:
        return SelectiveDecision(
            "escalate", "human", "evidence is unresolved", assessment,
            dict(diagnostics, evidence_reason=assessment.diagnostics.get("reason")),
        )
    if assessment.flip_budget < min_flip_budget:
        return SelectiveDecision(
            "escalate", "human", "evidence margin is below policy threshold",
            assessment, diagnostics,
        )
    if assessment.verdict == proceed_side:
        return SelectiveDecision(
            "proceed", "evidence", "independent evidence satisfies policy",
            assessment, diagnostics,
        )
    return SelectiveDecision(
        "block", "evidence", "independent evidence contradicts the action",
        assessment, diagnostics,
    )
