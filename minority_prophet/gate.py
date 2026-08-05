"""The gate: the twelve lines that replace `if enough_agents_agree`."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable, Optional
from .aggregator import aggregate
from .adapter_acp import AttestationVerifier, DEFAULT_FRESHNESS, envelopes_to_claims

@dataclass
class GateDecision:
    action: str                # "proceed" | "block" | "escalate"
    decision: Optional[int]    # winning side, None on abstain
    flip_budget: float         # forged independent roots needed to change this
    confidence: float
    roots_for: int
    roots_against: int
    diagnostics: dict = field(default_factory=dict)

def decide(envelopes: Iterable[dict], verifier: AttestationVerifier, *,
           proceed_side: int = 1, min_flip_budget: float = 1.0,
           abstain_margin: float = 0.0, decision_subject=None,
           unbound_root_weight: float = 0.5, freshness: Optional[dict] = DEFAULT_FRESHNESS
           ) -> GateDecision:
    """Aggregate attested envelopes and gate the action.
    - proceed only if the verdict favors `proceed_side` AND the flip budget
      (attack price) meets `min_flip_budget`
    - escalate on abstention or thin margins: no independent evidence is a
      reason to ask a human, never a reason to proceed
    """
    rep = envelopes_to_claims(envelopes, verifier,
                              decision_subject=decision_subject,
                              unbound_root_weight=unbound_root_weight,
                              freshness=freshness)
    if not rep.claims:
        return GateDecision("escalate", None, 0.0, 0.5, 0, 0,
                            {"reason": "no verifiable claims",
                             "quarantined": len(rep.quarantined)})
    v = aggregate(rep.claims, abstain_margin=abstain_margin, use_weights=True)
    diag = dict(v.diagnostics, quarantined=len(rep.quarantined),
                unattested_singletons=rep.unattested_singletons,
                subject=decision_subject, exclusions=rep.exclusions,
                bound_roots=len(rep.bound_root_ids),
                unbound_roots=len(rep.unbound_root_ids))
    # In migration mode legacy unbound roots may guide the ordinary verdict at
    # reduced weight, but cannot purchase confidence. Strength is the margin of
    # matching bound roots alone; it is deliberately conservative.
    strength_margin = v.margin
    if decision_subject is not None:
        bound_claims = [c for c in rep.claims if c.id in rep.bound_root_ids]
        if not bound_claims:
            return GateDecision("escalate", None, 0.0, 0.5, 0, 0,
                                dict(diag, reason="no bound roots",
                                     migration_flip_budget_conservative=True))
        bound = aggregate(bound_claims, abstain_margin=0.0, use_weights=True)
        strength_margin = bound.margin
        diag["bound_root_mass"] = bound.root_mass
        diag["migration_flip_budget_conservative"] = True
    w = {c.id: c.weight for c in rep.claims}
    r1 = sum(1 for r in v.roots.get(1, set()) if w.get(r, 1.0) > 0)
    r0 = sum(1 for r in v.roots.get(0, set()) if w.get(r, 1.0) > 0)
    if v.decision is None:
        return GateDecision("escalate", None, strength_margin, v.confidence, r1, r0,
                            dict(diag, reason="abstained: evidence balanced"))
    if v.decision == proceed_side and strength_margin >= min_flip_budget:
        return GateDecision("proceed", v.decision, strength_margin, v.confidence,
                            r1, r0, diag)
    if v.decision == proceed_side:
        return GateDecision("escalate", v.decision, strength_margin, v.confidence,
                            r1, r0, dict(diag, reason="margin below threshold"))
    return GateDecision("block", v.decision, strength_margin, v.confidence,
                        r1, r0, diag)
