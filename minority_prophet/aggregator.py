"""minority_prophet -- provenance-aware truth aggregation (reference library).

Implements the evidence-root aggregator whose core properties are proved in
formal/PROOFS.md and machine-verified by formal/verify_proofs.py:
  T1 Immunity: verdicts invariant under side-preserving, root-preserving
     lineage rewiring.
  T2 Copy invariance: duplicating claims never changes the verdict.
  T4 Margin flip condition: phantom root flow equal to the margin forces
     abstention; one additional unit reverses the verdict.
Pure stdlib. API: Claim, EvidenceGraph, aggregate().
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, Iterable, Hashable

__version__ = "0.1.0"
__all__ = ["Claim", "EvidenceGraph", "Verdict", "aggregate"]

@dataclass(frozen=True)
class Claim:
    id: Hashable
    assertion: Hashable                 # binary values remain a special case
    parent: Optional[Hashable] = None  # None => evidence root
    weight: float = 1.0                # optional stake/attestation weight

    def __post_init__(self):
        try:
            hash(self.assertion)
        except TypeError as exc:
            raise ValueError("assertion must be hashable") from exc
        if self.weight < 0:
            raise ValueError("weight must be non-negative")

@dataclass
class Verdict:
    decision: Optional[Hashable]       # winning value, or None (abstain)
    confidence: float                  # share of root mass on winning side
    roots: dict                        # assertion value -> set of root ids
    margin: float                      # top mass - runner-up mass
    root_mass: dict = field(default_factory=dict)
    ranked_margins: tuple = ()         # values ranked by independent root mass
    diagnostics: dict = field(default_factory=dict)

class EvidenceGraph:
    def __init__(self, claims: Iterable[Claim]):
        self.claims = {c.id: c for c in claims}
        if len(self.claims) == 0:
            raise ValueError("empty graph")
        for c in self.claims.values():
            if c.parent is not None and c.parent not in self.claims:
                raise ValueError(f"claim {c.id!r}: unknown parent {c.parent!r}")
        self._roots = {}
        for cid in self.claims:
            self._root(cid, _stack=set())

    def _root(self, cid, _stack):
        if cid in self._roots:
            return self._roots[cid]
        if cid in _stack:
            raise ValueError(f"lineage cycle involving {cid!r}")
        _stack.add(cid)
        p = self.claims[cid].parent
        r = cid if p is None else self._root(p, _stack)
        self._roots[cid] = r
        return r

    def root_of(self, cid):
        return self._roots[cid]

    def side_roots(self):
        sides = {}
        for c in self.claims.values():
            sides.setdefault(c.assertion, set()).add(self._roots[c.id])
        return sides

    def value_consistency_violations(self):
        """Edges joining different assertion values. Nonzero => T1 preconditions do
        not hold and the verdict inherits no immunity guarantee."""
        return [(c.id, c.parent) for c in self.claims.values()
                if c.parent is not None
                and self.claims[c.parent].assertion != c.assertion]

def aggregate(claims: Iterable[Claim], *, abstain_margin: float = 0.0,
              use_weights: bool = False) -> Verdict:
    """Evidence-root verdict. Counts independent roots per assertion value (optionally
    weighting each root by its own claim weight), abstains when the
    normalized margin is <= abstain_margin."""
    g = EvidenceGraph(claims)
    sides = g.side_roots()
    mass = {a: (sum(g.claims[r].weight for r in roots) if use_weights
                else float(len(roots))) for a, roots in sides.items()}
    ranked = tuple(sorted(mass.items(), key=lambda item: (-item[1], repr(item[0]))))
    top_value, top_mass = ranked[0]
    runner_up_mass = ranked[1][1] if len(ranked) > 1 else 0.0
    total = sum(mass.values())
    margin = top_mass - runner_up_mass
    if total == 0 or margin / max(total, 1e-12) <= abstain_margin:
        decision, conf = None, 0.5
    else:
        decision = top_value
        conf = mass[decision] / total
    viol = g.value_consistency_violations()
    return Verdict(decision=decision, confidence=conf, roots=sides,
                   margin=margin, root_mass=mass, ranked_margins=ranked,
                   diagnostics=dict(
                       n_claims=len(g.claims),
                       n_roots=len(set(g._roots.values())),
                       n_values=len(mass),
                       value_consistency_violations=len(viol),
                       immunity_applicable=not viol,
                       flip_budget=margin))
