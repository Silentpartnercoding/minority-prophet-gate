"""The gate: the twelve lines that replace `if enough_agents_agree`."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable, Optional
from .aggregator import aggregate
from .adapter_acp import (AttestationVerifier, DEFAULT_FRESHNESS,
                          WITNESS_DEPTHS, envelopes_to_claims)

@dataclass
class GateDecision:
    action: str                # "proceed" | "block" | "escalate"
    decision: Optional[int]    # winning side, None on abstain
    flip_budget: float         # price in FORGED roots (see conversions_to_reverse)
    confidence: float
    roots_for: int
    roots_against: int
    diagnostics: dict = field(default_factory=dict)
    conversions_to_reverse: Optional[int] = None
    """Price in COMPROMISED roots -- roughly half `flip_budget`, and the number
    that matters when the threat is root-key compromise rather than pure
    forgery. A compromised root leaves the winning side and joins the losing
    one, moving the margin by two units instead of one (CE-03)."""

@dataclass
class EvidenceAssessment:
    """Action-neutral result of evaluating independently grounded evidence."""
    verdict: Optional[int]
    flip_budget: float
    confidence: float
    roots_for: int
    roots_against: int
    diagnostics: dict = field(default_factory=dict)
    conversions_to_reverse: Optional[int] = None
    flip_budget_upper: Optional[float] = None
    """Attack price if every unstated root turns out to have observed.

    `flip_budget` is the price if none of them did. When the two differ, the
    evidence does not determine a single price and the gap is the cost of the
    silence, not a fact about the sources."""

    @property
    def depth_determined(self) -> bool:
        """True when no unstated root could change the price."""
        return (self.flip_budget_upper is None
                or self.flip_budget_upper == self.flip_budget)

def assess(envelopes: Iterable[dict], verifier: AttestationVerifier, *,
           abstain_margin: float = 0.0, decision_subject=None,
           unbound_root_weight: float = 0.5,
           freshness: Optional[dict] = DEFAULT_FRESHNESS,
           depth_weights: Optional[dict] = None) -> EvidenceAssessment:
    """Evaluate evidence without deciding what any runtime may do."""
    rep = envelopes_to_claims(envelopes, verifier,
                              decision_subject=decision_subject,
                              unbound_root_weight=unbound_root_weight,
                              freshness=freshness,
                              depth_weights=depth_weights)
    if not rep.claims:
        return EvidenceAssessment(None, 0.0, 0.5, 0, 0,
                                  {"reason": "no verifiable claims",
                                   "quarantined": len(rep.quarantined)})
    v = aggregate(rep.claims, abstain_margin=abstain_margin, use_weights=True)
    diag = dict(v.diagnostics, quarantined=len(rep.quarantined),
                depth_profile=rep.depth_profile,
                roots_assumed_observing=rep.depth_profile.get("unstated", 0),
                unattested_singletons=rep.unattested_singletons,
                subject=decision_subject, exclusions=rep.exclusions,
                bound_roots=len(rep.bound_root_ids),
                unbound_roots=len(rep.unbound_root_ids))
    strength_margin = v.margin
    if decision_subject is not None:
        bound_claims = [c for c in rep.claims if c.id in rep.bound_root_ids]
        if not bound_claims:
            return EvidenceAssessment(None, 0.0, 0.5, 0, 0,
                                      dict(diag, reason="no bound roots",
                                           migration_flip_budget_conservative=True))
        bound = aggregate(bound_claims, abstain_margin=0.0, use_weights=True)
        strength_margin = bound.margin
        diag["bound_root_mass"] = bound.root_mass
        diag["migration_flip_budget_conservative"] = True
        # flip_budget is now the BOUND margin, so the conversion price must be
        # recomputed over the same claim set. Carrying `v`'s figures here would
        # price an attack on a population that no longer determines the verdict.
        for key in ("conversions_to_reverse", "conversions_to_abstention",
                    "abstention_reachable_by_conversion", "flip_budget_unit",
                    "flip_budget_is_root_count"):
            diag[key] = bound.diagnostics[key]
    weights = {claim.id: claim.weight for claim in rep.claims}
    roots_for = sum(1 for root in v.roots.get(1, set()) if weights.get(root, 1.0) > 0)
    roots_against = sum(1 for root in v.roots.get(0, set()) if weights.get(root, 1.0) > 0)
    if v.decision is None:
        diag = dict(diag, reason="abstained: evidence balanced")
    return EvidenceAssessment(v.decision, strength_margin, v.confidence,
                              roots_for, roots_against, diag,
                              diag.get("conversions_to_reverse"))

def assess_bounds(envelopes: Iterable[dict], verifier: AttestationVerifier, *,
                  depth_weights: Optional[dict] = None, **kwargs) -> EvidenceAssessment:
    """Assess with unstated depth read both ways, and report the range.

    An unstated depth is not a weak depth. It is an unknown one, and the honest
    report is the interval it supports rather than either endpoint dressed as a
    measurement. The lower bound assumes every silent root reached only the
    weakest rung; the upper assumes every one of them observed.
    """
    if depth_weights is None:
        return assess(envelopes, verifier, depth_weights=None, **kwargs)
    envelopes = list(envelopes)
    floor = dict(depth_weights)
    ceiling = dict(depth_weights, unstated=max(
        float(depth_weights.get(rung, 1.0)) for rung in WITNESS_DEPTHS))
    low = assess(envelopes, verifier, depth_weights=floor, **kwargs)
    high = assess(envelopes, verifier, depth_weights=ceiling, **kwargs)
    low.flip_budget_upper = high.flip_budget
    low.diagnostics["flip_budget_bounds"] = (low.flip_budget, high.flip_budget)
    low.diagnostics["verdict_bounds"] = (low.verdict, high.verdict)
    low.diagnostics["depth_determined"] = (
        low.flip_budget == high.flip_budget and low.verdict == high.verdict)
    return low


def decide(envelopes: Iterable[dict], verifier: AttestationVerifier, *,
           proceed_side: int = 1, min_flip_budget: float = 1.0,
           abstain_margin: float = 0.0, decision_subject=None,
           unbound_root_weight: float = 0.5, freshness: Optional[dict] = DEFAULT_FRESHNESS,
           depth_weights: Optional[dict] = None) -> GateDecision:
    """Aggregate attested envelopes and gate the action.
    - proceed only if the verdict favors `proceed_side` AND the flip budget
      (attack price) meets `min_flip_budget`
    - escalate on abstention or thin margins: no independent evidence is a
      reason to ask a human, never a reason to proceed
    """
    assessment = assess(envelopes, verifier, abstain_margin=abstain_margin,
                        decision_subject=decision_subject,
                        unbound_root_weight=unbound_root_weight,
                        freshness=freshness,
                        depth_weights=depth_weights)
    if assessment.verdict is None:
        return GateDecision("escalate", None, assessment.flip_budget,
                            assessment.confidence, assessment.roots_for,
                            assessment.roots_against, assessment.diagnostics,
                            assessment.conversions_to_reverse)
    if not assessment.diagnostics.get("immunity_applicable", True):
        # T1's precondition does not hold on this input: some root carries both
        # assertions, so the immunity theorem says NOTHING about this verdict --
        # it is the absence of a guarantee, not a claim the verdict is wrong.
        # Proceeding here would translate evidential uncertainty into permission,
        # which is the one thing this gate exists not to do. The research
        # reference fails closed on the same input (CE-11: resolving a conflicting
        # root either way makes the result depend on claim order).
        return GateDecision("escalate", assessment.verdict, assessment.flip_budget,
                            assessment.confidence, assessment.roots_for,
                            assessment.roots_against,
                            dict(assessment.diagnostics,
                                 reason="immunity precondition violated: a root "
                                        "carries conflicting assertions (T1 gives "
                                        "no guarantee on this input)"),
                            assessment.conversions_to_reverse)
    if assessment.verdict == proceed_side and assessment.flip_budget >= min_flip_budget:
        action = "proceed"
        diagnostics = assessment.diagnostics
    elif assessment.verdict == proceed_side:
        action = "escalate"
        diagnostics = dict(assessment.diagnostics, reason="margin below threshold")
    else:
        action = "block"
        diagnostics = assessment.diagnostics
    return GateDecision(action, assessment.verdict, assessment.flip_budget,
                        assessment.confidence, assessment.roots_for,
                        assessment.roots_against, diagnostics,
                        assessment.conversions_to_reverse)
