"""Bounded, provider-neutral requests for additional evidence.

An evidence request is a challenge, not authority.  It tells an orchestrator
which *kinds* of missing evidence may be collected and returned, while binding
that work to the same action, subject, and policy.  It never says which verdict
the evidence should support and it never authorizes the protected action.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, replace

SCHEMA_VERSION = "minority-prophet.evidence-request.v1"
COLLECTOR_KINDS = frozenset({
    "requesting_agent", "epistemic_service", "human", "program"
})
OUTPUT_ROLES = frozenset({
    "candidate_evidence", "verification_artifact", "human_handoff"
})


class EvidenceRequestError(ValueError):
    """The evidence challenge is malformed, substituted, or exhausted."""


class EvidenceRequestExhausted(EvidenceRequestError):
    """The configured machine-collection round budget has been consumed."""


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceRequestError(f"{name} must be a non-empty string")
    return value.strip()


def _unique_text(values: Iterable[str], name: str) -> tuple[str, ...]:
    result = tuple(_text(value, name) for value in values)
    if len(result) != len(set(result)):
        raise EvidenceRequestError(f"{name} values must be unique")
    return result


def _digest(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    # This is a digest helper, not an HTTP/Flask response.
    return "sha256:" + hashlib.sha256(encoded).hexdigest()  # nosemgrep: directly-returned-format-string


@dataclass(frozen=True)
class CollectorRoute:
    """Policy-selected destination for one kind of missing evidence.

    The route names a capability, never a vendor.  ``route_id`` is the stable
    local binding used by an orchestrator to select a configured adapter.
    """

    route_id: str
    collector_kind: str
    capability: str
    output_role: str
    allowed_actions: tuple[str, ...]
    requires_independence: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "route_id", _text(self.route_id, "route_id"))
        kind = _text(self.collector_kind, "collector_kind")
        if kind not in COLLECTOR_KINDS:
            raise EvidenceRequestError(
                f"collector_kind must be one of {sorted(COLLECTOR_KINDS)}"
            )
        object.__setattr__(self, "collector_kind", kind)
        object.__setattr__(self, "capability",
                           _text(self.capability, "capability"))
        role = _text(self.output_role, "output_role")
        if role not in OUTPUT_ROLES:
            raise EvidenceRequestError(
                f"output_role must be one of {sorted(OUTPUT_ROLES)}"
            )
        expected_roles = {
            "requesting_agent": "candidate_evidence",
            "epistemic_service": "verification_artifact",
            "human": "human_handoff",
        }
        if kind in expected_roles and role != expected_roles[kind]:
            raise EvidenceRequestError(
                f"{kind} routes require output_role={expected_roles[kind]}"
            )
        object.__setattr__(self, "output_role", role)
        actions = _unique_text(self.allowed_actions, "allowed_action")
        if not actions:
            raise EvidenceRequestError("a collector route requires an allowed action")
        object.__setattr__(self, "allowed_actions", actions)
        if not isinstance(self.requires_independence, bool):
            raise EvidenceRequestError("requires_independence must be boolean")
        if kind == "requesting_agent" and self.requires_independence:
            raise EvidenceRequestError(
                "the requesting agent cannot satisfy an independence-required route"
            )

    def to_dict(self) -> dict:
        return {
            "route_id": self.route_id,
            "collector_kind": self.collector_kind,
            "capability": self.capability,
            "output_role": self.output_role,
            "allowed_actions": list(self.allowed_actions),
            "requires_independence": self.requires_independence,
            "route_grants_protected_action_authority": False,
        }


@dataclass(frozen=True)
class EvidenceRequirement:
    """A conclusion-neutral description of evidence the policy accepts.

    ``description`` should name an observation or artifact to collect (for
    example, "fresh test-run receipt for this action"), never the answer the
    agent is expected to prove.
    """

    requirement_id: str
    description: str
    collector_route: CollectorRoute
    accepted_kinds: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "requirement_id",
                           _text(self.requirement_id, "requirement_id"))
        object.__setattr__(self, "description",
                           _text(self.description, "description"))
        if not isinstance(self.collector_route, CollectorRoute):
            raise EvidenceRequestError(
                "collector_route must be an explicit CollectorRoute"
            )
        kinds = _unique_text(self.accepted_kinds, "accepted_kind")
        if not kinds:
            raise EvidenceRequestError(
                "an evidence requirement needs an accepted evidence kind"
            )
        object.__setattr__(self, "accepted_kinds", kinds)

    def to_dict(self) -> dict:
        return {
            "requirement_id": self.requirement_id,
            "description": self.description,
            "collector_route": self.collector_route.to_dict(),
            "accepted_kinds": list(self.accepted_kinds),
        }


@dataclass(frozen=True)
class EvidenceRequestPolicy:
    """Bounds what an agent may try before a human becomes necessary.

    Every requirement carries a provider-neutral collector route and a
    least-privilege action scope. Listing a route does not grant permission to
    perform it; the caller must authorize every dispatch independently.
    """

    requirements: tuple[EvidenceRequirement, ...]
    max_rounds: int = 2
    max_evidence_items_per_round: int = 50

    def __post_init__(self) -> None:
        requirements = tuple(self.requirements)
        if not requirements:
            raise EvidenceRequestError("at least one evidence requirement is required")
        if any(not isinstance(item, EvidenceRequirement) for item in requirements):
            raise EvidenceRequestError("requirements must be EvidenceRequirement values")
        ids = [item.requirement_id for item in requirements]
        if len(ids) != len(set(ids)):
            raise EvidenceRequestError("requirement_id values must be unique")
        if (isinstance(self.max_rounds, bool) or not isinstance(self.max_rounds, int)
                or not 1 <= self.max_rounds <= 10):
            raise EvidenceRequestError("max_rounds must be an integer from 1 to 10")
        if (isinstance(self.max_evidence_items_per_round, bool)
                or not isinstance(self.max_evidence_items_per_round, int)
                or not 1 <= self.max_evidence_items_per_round <= 1000):
            raise EvidenceRequestError(
                "max_evidence_items_per_round must be an integer from 1 to 1000"
            )
        if self.max_evidence_items_per_round < len(requirements):
            raise EvidenceRequestError(
                "max_evidence_items_per_round must cover every requirement"
            )
        object.__setattr__(self, "requirements", requirements)

    def payload(self) -> dict:
        return {
            "requirements": [item.to_dict() for item in self.requirements],
            "max_rounds": self.max_rounds,
            "max_evidence_items_per_round": self.max_evidence_items_per_round,
            "collection_scope_grants_authority": False,
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload())


@dataclass(frozen=True)
class EvidenceRequest:
    """Machine-readable challenge returned by the selective Gate policy."""

    challenge_id: str
    action_digest: str
    decision_subject: str
    policy_id: str
    policy_digest: str
    reason_code: str
    round: int
    max_rounds: int
    max_evidence_items: int
    requirements: tuple[EvidenceRequirement, ...]
    previous_challenge_id: str | None = None
    schema: str = SCHEMA_VERSION
    grants_authority: bool = False

    def unsigned_payload(self) -> dict:
        return {
            "schema": self.schema,
            "action_digest": self.action_digest,
            "decision_subject": self.decision_subject,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "reason_code": self.reason_code,
            "round": self.round,
            "max_rounds": self.max_rounds,
            "max_evidence_items": self.max_evidence_items,
            "requirements": [item.to_dict() for item in self.requirements],
            "previous_challenge_id": self.previous_challenge_id,
            "grants_authority": False,
        }

    def to_dict(self) -> dict:
        return dict(self.unsigned_payload(), challenge_id=self.challenge_id)


def verify_evidence_request(request: EvidenceRequest) -> None:
    """Fail closed if any hashed challenge field was changed."""
    if not isinstance(request, EvidenceRequest):
        raise EvidenceRequestError("prior request must be an EvidenceRequest")
    if request.schema != SCHEMA_VERSION:
        raise EvidenceRequestError("unsupported evidence request schema")
    if request.grants_authority is not False:
        raise EvidenceRequestError("an evidence request cannot grant authority")
    expected = _digest(request.unsigned_payload())
    if request.challenge_id != expected:
        raise EvidenceRequestError("evidence request integrity check failed")


def validate_evidence_return(
    request: EvidenceRequest,
    policy: EvidenceRequestPolicy,
    *,
    action_digest: str,
    decision_subject: str,
    policy_id: str,
) -> None:
    """Bind a resubmission to the exact action, subject, and policy challenge."""
    verify_evidence_request(request)
    bindings = {
        "action_digest": (_text(action_digest, "action_digest"), request.action_digest),
        "decision_subject": (
            _text(decision_subject, "decision_subject"), request.decision_subject
        ),
        "policy_id": (_text(policy_id, "policy_id"), request.policy_id),
        "policy_digest": (policy.digest, request.policy_digest),
    }
    for name, (actual, expected) in bindings.items():
        if actual != expected:
            raise EvidenceRequestError(f"evidence return substituted {name}")
    policy_fields = {
        "requirements": (request.requirements, policy.requirements),
        "max_rounds": (request.max_rounds, policy.max_rounds),
        "max_evidence_items": (
            request.max_evidence_items, policy.max_evidence_items_per_round
        ),
    }
    for name, (actual, expected) in policy_fields.items():
        if actual != expected:
            raise EvidenceRequestError(f"evidence return substituted {name}")
    if (isinstance(request.round, bool) or not isinstance(request.round, int)
            or not 1 <= request.round <= policy.max_rounds):
        raise EvidenceRequestError("evidence request round is invalid")


def issue_evidence_request(
    policy: EvidenceRequestPolicy,
    *,
    action_digest: str,
    decision_subject: str,
    policy_id: str,
    reason_code: str,
    previous: EvidenceRequest | None = None,
) -> EvidenceRequest:
    """Create the next hash-bound challenge or report budget exhaustion."""
    action_digest = _text(action_digest, "action_digest")
    decision_subject = _text(decision_subject, "decision_subject")
    policy_id = _text(policy_id, "policy_id")
    reason_code = _text(reason_code, "reason_code")

    if previous is not None:
        validate_evidence_return(
            previous, policy, action_digest=action_digest,
            decision_subject=decision_subject, policy_id=policy_id,
        )
        if previous.round >= policy.max_rounds:
            raise EvidenceRequestExhausted("evidence collection round budget exhausted")
        round_number = previous.round + 1
        previous_id = previous.challenge_id
    else:
        round_number = 1
        previous_id = None

    prototype = EvidenceRequest(
        challenge_id="pending",
        action_digest=action_digest,
        decision_subject=decision_subject,
        policy_id=policy_id,
        policy_digest=policy.digest,
        reason_code=reason_code,
        round=round_number,
        max_rounds=policy.max_rounds,
        max_evidence_items=policy.max_evidence_items_per_round,
        requirements=policy.requirements,
        previous_challenge_id=previous_id,
    )
    return replace(prototype, challenge_id=_digest(prototype.unsigned_payload()))
