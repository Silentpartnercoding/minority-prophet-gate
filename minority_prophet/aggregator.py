"""minority_prophet -- provenance-aware truth aggregation (reference library).

Implements the evidence-root aggregator whose core properties are proved in
formal/PROOFS.md and machine-verified by formal/verify_proofs.py:
  T1 Immunity: verdicts invariant under side-preserving, root-preserving
     lineage rewiring.
  T2 Copy invariance: duplicating claims never changes the verdict.
  T4 Margin flip condition: phantom root flow equal to the margin forces
     abstention; one additional unit reverses the verdict. "Flow" is NET
     PER-SIDE gain (p0 - p1), not the number of roots crossing sides -- under
     the second reading T4 is false (CE-03). A root that crosses sides moves two
     units, so `conversions_to_reverse` is the price of a key compromise and
     `flip_budget` is the price of pure forgery. Both are reported.
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

_OTHER_SIDE = object()  # the value a converted root asserts when no rival exists


def _convert(g, root_ids, to_value) -> list:
    """Move whole root subtrees to `to_value`.

    Converting the descendants too, not just the root claim, is what keeps this a
    side CONVERSION rather than an injected side-confusion: it preserves
    value-consistency, so the converted input still satisfies T1's precondition.
    """
    return [Claim(id=c.id, parent=c.parent, weight=c.weight,
                  assertion=to_value if g._roots[c.id] in root_ids else c.assertion)
            for c in g.claims.values()]


def _conversion_attack(g, sides, mass, top_value, ranked, abstain_margin,
                       use_weights, base_decision) -> dict:
    """Cheapest side-CONVERSION attack on this verdict (CE-03).

    `flip_budget` prices only *forged additions*: a new phantom root on the losing
    side moves the margin by one unit. A CONVERSION compromises a root that
    already supports the winner and flips it, so the root leaves the winning side
    AND joins the losing one -- two units per action. Reporting `flip_budget`
    alone therefore overstates the attacker's cost by roughly 2x, and root-key
    compromise (the threat this library exists for) is a conversion, not an
    addition.

    Computed by actually re-aggregating the converted inputs rather than by a
    closed-form margin formula, so it stays correct under weights, >2 assertion
    values, and any abstain_margin. On unit weights it reproduces the research
    reference's `margin // 2 + 1` exactly; that equivalence is a test.
    """
    winner_roots = sides[top_value]
    rival = next((v for v, _ in ranked if v != top_value), _OTHER_SIDE)
    order = sorted(winner_roots,  # heaviest first: fewest actions for the attacker
                   key=lambda r: (-(g.claims[r].weight if use_weights else 1.0), repr(r)))
    # A verdict that already abstains is already in the safe state: abstention is
    # reachable at zero cost. (Research reference agrees -- its parity rule calls
    # even flip_budget reachable, and a tie has flip_budget 0.)
    converted, reversal = set(), None
    abstention = 0 if base_decision is None else None
    for k, root in enumerate(order, start=1):
        converted.add(root)
        v = aggregate(_convert(g, converted, rival), abstain_margin=abstain_margin,
                      use_weights=use_weights, _attack_analysis=False)
        if v.decision is None and abstention is None:
            abstention = k
        if v.decision is not None and v.decision != top_value:
            reversal = k
            break
    return {"conversions_to_reverse": reversal,
            "conversions_to_abstention": abstention,
            "abstention_reachable_by_conversion": abstention is not None}


def aggregate(claims: Iterable[Claim], *, abstain_margin: float = 0.0,
              use_weights: bool = False, _attack_analysis: bool = True) -> Verdict:
    """Evidence-root verdict. Counts independent roots per assertion value (optionally
    weighting each root by its own claim weight), abstains when the
    normalized margin is <= abstain_margin.

    Two attack prices are reported, because they differ and the smaller one is the
    real one (CE-03). See `_conversion_attack`.
    """
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
    # flip_budget is in units of net per-side root MASS, which equals a count of
    # forged roots only when every contributing root has weight 1.0. In migration
    # mode (unbound_root_weight=0.5) it is fractional and "half a forged root" is
    # not a thing an attacker can buy -- so the unit is reported alongside it.
    unit_weighted = use_weights and any(
        g.claims[r].weight != 1.0 for roots in sides.values() for r in roots)
    diagnostics = dict(
        n_claims=len(g.claims),
        n_roots=len(set(g._roots.values())),
        n_values=len(mass),
        value_consistency_violations=len(viol),
        immunity_applicable=not viol,
        flip_budget=margin,
        flip_budget_unit="weighted root mass" if unit_weighted else "independent roots",
        flip_budget_is_root_count=not unit_weighted)
    if _attack_analysis:
        diagnostics.update(_conversion_attack(g, sides, mass, top_value, ranked,
                                              abstain_margin, use_weights, decision))
    return Verdict(decision=decision, confidence=conf, roots=sides,
                   margin=margin, root_mass=mass, ranked_margins=ranked,
                   diagnostics=diagnostics)
