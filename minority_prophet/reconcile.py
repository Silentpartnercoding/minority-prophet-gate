"""State Reconciliation: derive one job state from independent receipts.

Receipts are roots; everything else is derived, and derived claims never
outrank a root.  This module is observation-only: it performs no writes and
does not control a scheduler or board.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import pow
from typing import Hashable, Iterable, Optional

from .aggregator import Claim, Verdict, aggregate


@dataclass
class StateVerdict:
    state: Optional[Hashable]
    confidence: float
    flip_budget: float
    root_mass: dict[Hashable, float]
    excluded: dict[str, int]
    roots: dict[Hashable, set] = field(default_factory=dict)
    diagnostics: dict = field(default_factory=dict)


def _age_seconds(attest: dict) -> Optional[float]:
    if "observed_at_age_s" in attest:
        return float(attest["observed_at_age_s"])
    observed_at = attest.get("observed_at")
    if observed_at is None:
        return None
    if isinstance(observed_at, (int, float)):
        return max(0.0, datetime.now(timezone.utc).timestamp() - float(observed_at))
    try:
        stamp = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - stamp).total_seconds())


def _policy(attest: dict, freshness: dict) -> dict:
    if "ttl_s" in freshness or "half_life_s" in freshness:
        return freshness
    origin = str(attest.get("origin", ""))
    origin_class = attest.get("origin_class") or origin.split("-", 1)[0]
    return freshness.get(origin_class, freshness.get("default", {}))


def reconcile(status_claims: Iterable[dict], *, freshness: Optional[dict] = None,
              abstain_margin: float = 0.0) -> StateVerdict:
    """Reconcile status envelopes into a state, or ``None`` when unverified.

    Freshness is applied only to roots.  A policy may contain ``ttl_s`` or
    ``half_life_s`` directly, or map origin classes to those policies.  Under
    a policy, a root without a usable observation time contributes no mass.
    """
    envelopes = list(status_claims)
    excluded: Counter[str] = Counter()
    known_ids = {entry.get("claim_id") for entry in envelopes}
    claims: list[Claim] = []
    for entry in envelopes:
        attest = entry.get("attest", {})
        claim_id = entry.get("claim_id")
        parent = attest.get("derived_from")
        if claim_id is None or "assertion" not in entry:
            excluded["malformed"] += 1
            continue
        if parent is not None and parent not in known_ids:
            excluded["unknown_parent"] += 1
            continue
        weight = 1.0
        if parent is None and freshness:
            policy = _policy(attest, freshness)
            if policy:
                age = _age_seconds(attest)
                if age is None:
                    weight = 0.0
                    excluded["unknown_age"] += 1
                elif "ttl_s" in policy and age > float(policy["ttl_s"]):
                    weight = 0.0
                    excluded["expired"] += 1
                elif "half_life_s" in policy:
                    half_life = float(policy["half_life_s"])
                    if half_life <= 0:
                        raise ValueError("half_life_s must be positive")
                    weight = pow(0.5, age / half_life)
        claims.append(Claim(claim_id, entry["assertion"], parent, weight))
    if not claims:
        return StateVerdict(None, 0.5, 0.0, {}, dict(excluded), diagnostics={
            "reason": "no usable status claims", "immunity_applicable": False,
        })
    verdict: Verdict = aggregate(claims, abstain_margin=abstain_margin,
                                 use_weights=True)
    diagnostics = dict(verdict.diagnostics, excluded=dict(excluded))
    return StateVerdict(verdict.decision, verdict.confidence,
                        verdict.diagnostics["flip_budget"], verdict.root_mass,
                        dict(excluded), verdict.roots, diagnostics)
