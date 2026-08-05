"""ACP/Buzz envelope adapter: verified message dicts -> Claim objects.

Envelope shape (fields beyond these are ignored):
{
  "claim_id": "c3",
  "agent": "claude-writer",
  "assertion": "SAFE" | "UNSAFE" | 1 | 0,
  "attest": {
    "origin": "scan-7f2c",        # root id this claim descends from
    "derived_from": "c2",         # optional: parent claim id (echo)
    "sig": "attestation:..."      # signature over the entry-stamp payload
  }
}

SECURITY MODEL (read before deploying):
- Verification is delegated to an AttestationVerifier. This package ships
  only TrustAllVerifier (testing) and CallbackVerifier (bring your own,
  e.g. a production attestation client). The aggregator trusts whatever the verifier
  passes: THE GUARANTEE IS ONLY AS STRONG AS THE VERIFIER.
- Default-derived rule: a claim WITHOUT a verified fresh-root attestation
  is treated as an echo. If it names a parent/origin, it collapses into
  that family; if it names nothing verifiable, it is quarantined as an
  UNATTESTED SINGLETON and contributes zero roots. Copying is the
  presumption; independence requires proof.
- Subject binding and freshness are checked at the adapter boundary. A root
  is bound by its signed entry-stamp subject; manifests remain pure identity
  and scope under the two-ID rule.
- Side-consistency is checked downstream (Verdict.diagnostics); a claim
  whose verified origin asserts the opposite side is rejected here as
  malformed, because sign-time fusion of (assertion, origin) makes that
  combination impossible to produce honestly.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from math import pow
from typing import Callable, Iterable, Optional
from .aggregator import Claim

_TRUTHY = {"1", "true", "safe", "yes", "pass", "approve"}
_FALSY = {"0", "false", "unsafe", "no", "fail", "reject"}

# Approved R2.5 defaults. Unknown origin classes deliberately have no policy
# and therefore do not decay; callers may replace or extend this mapping.
DEFAULT_FRESHNESS = {
    "probe": {"half_life_s": 5 * 60},
    "start-event": {"ttl_s": 24 * 60 * 60},
}

def _to_bit(a) -> int:
    if isinstance(a, bool): return int(a)
    if isinstance(a, int) and a in (0, 1): return a
    s = str(a).strip().lower()
    if s in _TRUTHY: return 1
    if s in _FALSY: return 0
    raise ValueError(f"unmappable assertion {a!r}: pass assertion_map=")

class AttestationVerifier:
    """Interface. verify(envelope) -> one of:
    "root"    : signature valid and attests a fresh observation
    "derived" : signature valid and attests derivation (or no root claim)
    "invalid" : signature invalid or missing where required -> quarantined
    """
    def verify(self, env: dict) -> str:
        raise NotImplementedError

class TrustAllVerifier(AttestationVerifier):
    """TESTING ONLY. Believes the envelope's own structure: an attest block
    with an origin equal to nothing-derived is a root. Provides NO security."""
    def verify(self, env: dict) -> str:
        at = env.get("attest") or {}
        if not at:
            return "invalid"
        return "derived" if at.get("derived_from") else "root"

class CallbackVerifier(AttestationVerifier):
    def __init__(self, fn: Callable[[dict], str]):
        self.fn = fn
    def verify(self, env: dict) -> str:
        return self.fn(env)

@dataclass
class AdapterReport:
    claims: list
    quarantined: list          # envelopes dropped (invalid/malformed)
    unattested_singletons: int # claims contributing zero evidence
    bound_root_ids: set
    unbound_root_ids: set
    exclusions: dict


def _age_seconds(attest: dict) -> Optional[float]:
    """Return age from a testable age override or RFC 3339 timestamp."""
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


def _freshness_policy(attest: dict, freshness: Optional[dict]) -> dict:
    if freshness is None:
        return {}
    if "ttl_s" in freshness or "half_life_s" in freshness:
        return freshness
    origin = str(attest.get("origin", ""))
    origin_class = attest.get("origin_class")
    if origin_class is None:
        if origin.startswith("start-event-"):
            origin_class = "start-event"
        elif origin.startswith("probe-"):
            origin_class = "probe"
        else:
            origin_class = origin.split("-", 1)[0]
    return freshness.get(origin_class, freshness.get("default", {}))


def _root_weight(attest: dict, *, freshness: Optional[dict], exclusions: dict) -> float:
    policy = _freshness_policy(attest, freshness)
    if not policy:  # No policy means no decay, including a missing timestamp.
        return 1.0
    age = _age_seconds(attest)
    if age is None:
        exclusions["expired_missing_observed_at"] = exclusions.get("expired_missing_observed_at", 0) + 1
        return 0.0
    if "ttl_s" in policy and age > float(policy["ttl_s"]):
        exclusions["expired"] = exclusions.get("expired", 0) + 1
        return 0.0
    if "half_life_s" in policy:
        half_life = float(policy["half_life_s"])
        if half_life <= 0:
            raise ValueError("half_life_s must be positive")
        return pow(0.5, age / half_life)
    return 1.0

def envelopes_to_claims(envelopes: Iterable[dict],
                        verifier: AttestationVerifier,
                        assertion_map: Optional[Callable] = None,
                        *, decision_subject=None,
                        unbound_root_weight: float = 0.5,
                        freshness: Optional[dict] = DEFAULT_FRESHNESS,
                        ) -> AdapterReport:
    """Convert verified envelopes while enforcing R2.5 subject/freshness rules.

    Subject matching is opt-in for backwards compatibility. When supplied,
    unmatched roots contribute zero, legacy unbound roots contribute the
    configurable migration weight, and only matching bound roots are exposed
    for strength/flip-budget calculation. Derived claims must retain the root
    subject or are quarantined.
    """
    if not 0.0 <= unbound_root_weight <= 1.0:
        raise ValueError("unbound_root_weight must be between 0 and 1")
    to_bit = assertion_map or _to_bit
    records, quarantine, exclusions = {}, [], {}
    for env in envelopes:
        try:
            bit = to_bit(env["assertion"])
            cid = env["claim_id"]
        except (KeyError, ValueError):
            quarantine.append(env); continue
        status = verifier.verify(env)
        if status == "invalid":
            quarantine.append(env); continue
        at = env.get("attest") or {}
        parent = at.get("derived_from") if status == "derived" else None
        records[cid] = dict(env=env, assertion=bit, attest=at, parent=parent,
                            status=status, subject=at.get("subject"))

    valid, invalid = set(records), set()
    # A derived claim must carry exactly its ancestor root's subject. Iterate so
    # descendants of a rejected claim are rejected too, rather than becoming a
    # new evidence root.
    changed = True
    while changed:
        changed = False
        for cid, record in records.items():
            if cid in invalid or record["parent"] is None:
                continue
            parent = record["parent"]
            if parent not in valid or parent in invalid:
                invalid.add(cid); changed = True; continue
            ancestor, lineage = records[parent], {cid}
            while ancestor["parent"] is not None and ancestor["parent"] in records:
                if ancestor["parent"] in lineage:
                    invalid.add(cid); changed = True
                    exclusions["lineage_cycle"] = exclusions.get("lineage_cycle", 0) + 1
                    break
                lineage.add(ancestor["parent"])
                ancestor = records[ancestor["parent"]]
            if cid in invalid:
                continue
            root_subject = ancestor["subject"]
            if root_subject is not None and record["subject"] != root_subject:
                invalid.add(cid); changed = True
                exclusions["subject_mismatch"] = exclusions.get("subject_mismatch", 0) + 1
    for cid in invalid:
        quarantine.append(records[cid]["env"])

    claims, bound_root_ids, unbound_root_ids = [], set(), set()
    for cid, record in records.items():
        if cid in invalid:
            continue
        parent, attest = record["parent"], record["attest"]
        weight = 1.0
        if parent is None:
            weight = _root_weight(attest, freshness=freshness, exclusions=exclusions)
            if decision_subject is not None:
                if record["subject"] == decision_subject:
                    bound_root_ids.add(cid)
                elif record["subject"] is None:
                    unbound_root_ids.add(cid)
                    weight *= unbound_root_weight
                    exclusions["unbound_root"] = exclusions.get("unbound_root", 0) + 1
                else:
                    weight = 0.0
                    exclusions["subject_mismatch"] = exclusions.get("subject_mismatch", 0) + 1
        claims.append(Claim(id=cid, assertion=record["assertion"], parent=parent,
                            weight=weight))

    # A bad/missing parent cannot manufacture a fresh root. Preserve the
    # legacy zero-weight singleton behavior for valid envelopes only.
    ids = {c.id for c in claims}
    fixed, singletons = [], 0
    for claim in claims:
        if claim.parent is not None and claim.parent not in ids:
            fixed.append(Claim(id=claim.id, assertion=claim.assertion, parent=None,
                               weight=0.0))
            singletons += 1
        else:
            fixed.append(claim)
    return AdapterReport(claims=fixed, quarantined=quarantine,
                         unattested_singletons=singletons,
                         bound_root_ids=bound_root_ids,
                         unbound_root_ids=unbound_root_ids,
                         exclusions=exclusions)
