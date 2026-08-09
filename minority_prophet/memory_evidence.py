"""Optional consumer for the neutral Memory Evidence Interoperability Profile.

This module checks whether memory evidence may enter an evidence-sensitive Gate
decision. It never establishes truth, identity, or authority, and it never
turns memory into permission.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping, Optional


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class MemoryEvidenceAssessment:
    action: str  # "accept" | "block" | "escalate"
    reason: str
    grants_authority: bool = False
    diagnostics: dict = field(default_factory=dict)


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("memory evidence timestamp must include a timezone")
    return parsed


def assess_memory_evidence(
    profile: Mapping,
    *,
    expected_proposition_digest: Optional[str] = None,
    expected_memory_object_digest: Optional[str] = None,
    expected_request_digest: Optional[str] = None,
    expected_action_digest: Optional[str] = None,
    used_nonces: Iterable[str] = (),
    now: Optional[datetime] = None,
) -> MemoryEvidenceAssessment:
    """Fail closed while preserving the difference between invalid and unknown.

    Definite corruption, stale/revoked state, replay, or binding substitution
    blocks. Missing proof, partial coverage, unknown revocation, or an
    inconclusive profile escalates. Acceptance only admits the record as bounded
    evidence to the next decision layer; it does not grant authority.
    """
    try:
        if profile["profile"] != "memory-evidence-profile-v0.1":
            return MemoryEvidenceAssessment("escalate", "unsupported memory evidence profile")
        claims = profile["claims"]
        search = profile["search"]
        binding = profile["binding"]
        lifecycle = profile["lifecycle"]
        conclusion = profile["conclusion"]
        if not isinstance(claims, list) or not claims:
            raise ValueError("claims are missing")
        for field in ("proposition_digest", "memory_object_digest"):
            if not DIGEST.fullmatch(binding[field]):
                raise ValueError(f"invalid {field}")
        for field in ("request_digest", "action_digest"):
            if binding[field] is not None and not DIGEST.fullmatch(binding[field]):
                raise ValueError(f"invalid {field}")
        observed = _time(lifecycle["observed_at"])
        expires = _time(lifecycle["expires_at"])
        nonce = lifecycle["nonce"]
        if not isinstance(nonce, str) or len(nonce) < 16:
            raise ValueError("invalid nonce")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return MemoryEvidenceAssessment("escalate", "malformed memory evidence", diagnostics={"error": str(exc)})

    expectations = {
        "proposition_digest": expected_proposition_digest,
        "memory_object_digest": expected_memory_object_digest,
        "request_digest": expected_request_digest,
        "action_digest": expected_action_digest,
    }
    for field, expected in expectations.items():
        if field in {"request_digest", "action_digest"} and binding[field] is not None and expected is None:
            return MemoryEvidenceAssessment("escalate", f"expected {field} was not supplied")
        if expected is not None and binding[field] != expected:
            return MemoryEvidenceAssessment("block", f"memory evidence {field} mismatch")
    if expires <= observed:
        return MemoryEvidenceAssessment("block", "memory evidence has an invalid lifetime")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        return MemoryEvidenceAssessment("escalate", "decision clock has no timezone")
    if current >= expires:
        return MemoryEvidenceAssessment("block", "memory evidence is expired")
    if nonce in set(used_nonces):
        return MemoryEvidenceAssessment("block", "memory evidence nonce was already used")

    revocation = lifecycle.get("revocation_status")
    if revocation == "revoked":
        return MemoryEvidenceAssessment("block", "memory evidence is revoked")
    if revocation != "active":
        return MemoryEvidenceAssessment("escalate", "memory evidence revocation is unknown")
    if search.get("coverage") != "complete":
        return MemoryEvidenceAssessment("escalate", "memory search coverage is incomplete")
    if conclusion.get("kind") == "inconclusive":
        return MemoryEvidenceAssessment("escalate", "memory evidence is inconclusive")

    try:
        claim_map = {claim["id"]: claim for claim in claims}
        if len(claim_map) != len(claims):
            raise ValueError("duplicate claim id")
        for claim in claims:
            if not DIGEST.fullmatch(claim["claim_digest"]):
                raise ValueError("invalid claim digest")
            if not isinstance(claim["derived_from"], list):
                raise ValueError("invalid derivation list")
            if not set(claim["derived_from"]) <= set(claim_map):
                raise ValueError("unknown derivation parent")

        def visit(claim_id: str, stack: tuple[str, ...] = ()) -> None:
            if claim_id in stack:
                raise ValueError("derivation cycle")
            for parent in claim_map[claim_id]["derived_from"]:
                visit(parent, stack + (claim_id,))

        for claim_id in claim_map:
            visit(claim_id)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        return MemoryEvidenceAssessment("escalate", "malformed memory lineage", diagnostics={"error": str(exc)})

    roots = {claim_id: claim for claim_id, claim in claim_map.items() if not claim["derived_from"]}
    inputs = set(conclusion.get("input_claims", []))
    if not inputs or not inputs <= set(claim_map):
        return MemoryEvidenceAssessment("escalate", "memory conclusion inputs are unresolved")
    if not roots:
        return MemoryEvidenceAssessment("escalate", "memory evidence has no declared roots")
    if any(root.get("root_authentication", {}).get("status") != "authenticated" for root in roots.values()):
        return MemoryEvidenceAssessment("escalate", "memory root authentication is insufficient")

    return MemoryEvidenceAssessment(
        "accept",
        "bounded memory evidence may enter evidence assessment",
        grants_authority=False,
        diagnostics={
            "authenticated_roots": len(roots),
            "search_coverage": "complete",
            "conclusion_method": conclusion.get("method"),
        },
    )
