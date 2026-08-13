"""Vendor-neutral routing and audit for bounded evidence collection.

The Gate says what evidence is missing.  This module deterministically groups
those requirements by policy-selected route, verifies the configured collector
has the required kind and capability, obtains separate collection authority,
and records a hash-chained audit event before and after dispatch.

No route, authorization, collector, or result grants authority to perform the
protected action.  Returned envelopes must still pass the ordinary Gate
verifier and evidence assessment.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Protocol

from .evidence_audit import (
    EvidenceAuditLog,
    EvidenceRoutingError,
    canonical_json_bytes,
    hash_json,
)
from .evidence_request import (
    COLLECTOR_KINDS,
    CollectorRoute,
    EvidenceRequest,
    EvidenceRequirement,
    verify_evidence_request,
)

RESULT_STATUSES = frozenset({"completed", "unavailable", "needs_human", "failed"})


@dataclass(frozen=True)
class CollectorDescriptor:
    collector_id: str
    collector_kind: str
    capabilities: tuple[str, ...]
    control_domain: str

    def __post_init__(self) -> None:
        for name in ("collector_id", "collector_kind", "control_domain"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name).strip():
                raise EvidenceRoutingError(f"{name} must be a non-empty string")
        if self.collector_kind not in COLLECTOR_KINDS:
            raise EvidenceRoutingError("collector_kind is invalid")
        if (not isinstance(self.capabilities, tuple) or not self.capabilities or
                any(not isinstance(item, str) or not item.strip()
                    for item in self.capabilities)):
            raise EvidenceRoutingError("capabilities must be a non-empty tuple")
        if len(self.capabilities) != len(set(self.capabilities)):
            raise EvidenceRoutingError("collector capabilities must be unique")


@dataclass(frozen=True)
class EvidenceDispatch:
    dispatch_id: str
    challenge_id: str
    action_digest: str
    decision_subject: str
    policy_id: str
    collection_round: int
    requester_control_domain: str
    route: CollectorRoute
    requirements: tuple[EvidenceRequirement, ...]
    max_evidence_items: int
    grants_protected_action_authority: bool = False

    def unsigned_payload(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "action_digest": self.action_digest,
            "decision_subject": self.decision_subject,
            "policy_id": self.policy_id,
            "collection_round": self.collection_round,
            "requester_control_domain": self.requester_control_domain,
            "route": self.route.to_dict(),
            "requirements": [item.to_dict() for item in self.requirements],
            "max_evidence_items": self.max_evidence_items,
            "grants_protected_action_authority": False,
        }

    def to_dict(self) -> dict:
        return dict(self.unsigned_payload(), dispatch_id=self.dispatch_id)


@dataclass(frozen=True)
class CollectionAuthorization:
    authorization_id: str
    dispatch_id: str
    challenge_id: str
    collector_id: str
    allowed_actions: tuple[str, ...]
    grants_protected_action_authority: bool = False


@dataclass(frozen=True)
class CollectedEvidence:
    requirement_id: str
    evidence_kind: str
    envelope: dict
    envelope_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not self.requirement_id or not self.evidence_kind:
            raise EvidenceRoutingError(
                "collected evidence requires requirement_id and evidence_kind"
            )
        if not isinstance(self.envelope, dict):
            raise EvidenceRoutingError("collected evidence envelope must be an object")
        safe_envelope = json.loads(canonical_json_bytes(self.envelope).decode("utf-8"))
        object.__setattr__(self, "envelope", safe_envelope)
        object.__setattr__(self, "envelope_digest", hash_json(safe_envelope))

    def verify_integrity(self) -> None:
        if hash_json(self.envelope) != self.envelope_digest:
            raise EvidenceRoutingError("collected evidence was mutated after return")

    def envelope_copy(self) -> dict:
        self.verify_integrity()
        return json.loads(canonical_json_bytes(self.envelope).decode("utf-8"))

    @property
    def digest(self) -> str:
        self.verify_integrity()
        return hash_json({
            "requirement_id": self.requirement_id,
            "evidence_kind": self.evidence_kind,
            "envelope_digest": self.envelope_digest,
        })


@dataclass(frozen=True)
class EvidenceCollectionResult:
    dispatch_id: str
    challenge_id: str
    collector_id: str
    status: str
    items: tuple[CollectedEvidence, ...] = ()
    diagnostics: dict = field(default_factory=dict)
    grants_protected_action_authority: bool = False

    @property
    def envelopes(self) -> tuple[dict, ...]:
        return tuple(item.envelope_copy() for item in self.items)


class EvidenceCollector(Protocol):
    descriptor: CollectorDescriptor

    def collect(self, dispatch: EvidenceDispatch) -> EvidenceCollectionResult:
        """Collect evidence within the dispatch scope; never authorize the action."""


class CollectionAuthorizer(Protocol):
    def authorize(self, dispatch: EvidenceDispatch,
                  collector: CollectorDescriptor) -> CollectionAuthorization | None:
        """Return a separately authorized, exactly bound collection permit."""


class CallbackEvidenceCollector:
    """Small adapter for an agent, MP service, human queue, or other program."""

    def __init__(self, descriptor: CollectorDescriptor,
                 callback: Callable[[EvidenceDispatch], EvidenceCollectionResult]):
        self.descriptor = descriptor
        self.callback = callback

    def collect(self, dispatch: EvidenceDispatch) -> EvidenceCollectionResult:
        return self.callback(dispatch)


class EvidenceRouter:
    """Plan and execute policy-selected collection through neutral adapters."""

    _TERMINAL_EVENTS = frozenset({
        "collection_returned", "collection_failed", "dispatch_denied"
    })

    def __init__(self, collectors: dict[str, EvidenceCollector],
                 authorizer: CollectionAuthorizer,
                 audit_log: EvidenceAuditLog) -> None:
        self.collectors = dict(collectors)
        self.authorizer = authorizer
        self.audit_log = audit_log
        self._results: dict[str, EvidenceCollectionResult] = {}

    def plan(self, request: EvidenceRequest, *,
             requester_control_domain: str) -> tuple[EvidenceDispatch, ...]:
        verify_evidence_request(request)
        if not requester_control_domain:
            raise EvidenceRoutingError("requester_control_domain is required")
        if not self.audit_log.has_challenge("challenge_received", request.challenge_id):
            self.audit_log.append(
                "challenge_received", request.challenge_id,
                details={
                    "action_digest": request.action_digest,
                    "policy_id": request.policy_id,
                    "collection_round": request.round,
                    "reason_code": request.reason_code,
                    "grants_protected_action_authority": False,
                },
            )
        grouped: dict[str, tuple[CollectorRoute, list[EvidenceRequirement]]] = {}
        for requirement in request.requirements:
            route = requirement.collector_route
            if route.route_id in grouped and grouped[route.route_id][0] != route:
                raise EvidenceRoutingError(
                    "one route_id cannot carry conflicting route definitions"
                )
            grouped.setdefault(route.route_id, (route, []))[1].append(requirement)

        dispatches = []
        route_ids = sorted(grouped)
        remaining = request.max_evidence_items - len(request.requirements)
        bonus_each, bonus_remainder = divmod(remaining, len(route_ids))
        for route_index, route_id in enumerate(route_ids):
            route, requirements = grouped[route_id]
            route_item_cap = (
                len(requirements) + bonus_each +
                (1 if route_index < bonus_remainder else 0)
            )
            prototype = EvidenceDispatch(
                dispatch_id="pending",
                challenge_id=request.challenge_id,
                action_digest=request.action_digest,
                decision_subject=request.decision_subject,
                policy_id=request.policy_id,
                collection_round=request.round,
                requester_control_domain=requester_control_domain,
                route=route,
                requirements=tuple(requirements),
                max_evidence_items=route_item_cap,
            )
            dispatch = replace(
                prototype, dispatch_id=hash_json(prototype.unsigned_payload())
            )
            if not self.audit_log.has("route_planned", dispatch.dispatch_id):
                self.audit_log.append(
                    "route_planned", request.challenge_id,
                    dispatch_id=dispatch.dispatch_id, route_id=route.route_id,
                    details={
                        "collector_kind": route.collector_kind,
                        "capability": route.capability,
                        "output_role": route.output_role,
                        "requirement_ids": [r.requirement_id for r in requirements],
                        "allowed_actions": list(route.allowed_actions),
                        "requires_independence": route.requires_independence,
                        "grants_protected_action_authority": False,
                    },
                )
            dispatches.append(dispatch)
        return tuple(dispatches)

    @staticmethod
    def _verify_dispatch(dispatch: EvidenceDispatch) -> None:
        if dispatch.grants_protected_action_authority is not False:
            raise EvidenceRoutingError("an evidence dispatch cannot authorize the action")
        if dispatch.dispatch_id != hash_json(dispatch.unsigned_payload()):
            raise EvidenceRoutingError("evidence dispatch integrity check failed")

    @staticmethod
    def _verify_collector(dispatch: EvidenceDispatch,
                          descriptor: CollectorDescriptor) -> None:
        if not isinstance(descriptor, CollectorDescriptor):
            raise EvidenceRoutingError("collector descriptor is invalid")
        route = dispatch.route
        if descriptor.collector_kind != route.collector_kind:
            raise EvidenceRoutingError("collector kind does not satisfy route policy")
        if route.capability not in descriptor.capabilities:
            raise EvidenceRoutingError("collector lacks the required capability")
        if (route.collector_kind == "requesting_agent" and
                descriptor.control_domain != dispatch.requester_control_domain):
            raise EvidenceRoutingError("requesting-agent route substituted another agent")
        if (route.requires_independence and
                descriptor.control_domain == dispatch.requester_control_domain):
            raise EvidenceRoutingError(
                "collector is not independent of the requesting control domain"
            )

    @staticmethod
    def _verify_authorization(dispatch: EvidenceDispatch,
                              descriptor: CollectorDescriptor,
                              authorization: CollectionAuthorization) -> None:
        if not isinstance(authorization, CollectionAuthorization):
            raise EvidenceRoutingError("collection authorization is missing")
        if authorization.grants_protected_action_authority is not False:
            raise EvidenceRoutingError("collection authority cannot authorize the action")
        expected = {
            "dispatch_id": dispatch.dispatch_id,
            "challenge_id": dispatch.challenge_id,
            "collector_id": descriptor.collector_id,
            "allowed_actions": dispatch.route.allowed_actions,
        }
        for name, value in expected.items():
            if getattr(authorization, name) != value:
                raise EvidenceRoutingError(f"collection authorization substituted {name}")
        if not authorization.authorization_id:
            raise EvidenceRoutingError("collection authorization_id is required")

    @staticmethod
    def _verify_result(dispatch: EvidenceDispatch,
                       descriptor: CollectorDescriptor,
                       result: EvidenceCollectionResult) -> None:
        if not isinstance(result, EvidenceCollectionResult):
            raise EvidenceRoutingError("collector returned an invalid result type")
        if result.grants_protected_action_authority is not False:
            raise EvidenceRoutingError("collection result cannot authorize the action")
        bindings = {
            "dispatch_id": dispatch.dispatch_id,
            "challenge_id": dispatch.challenge_id,
            "collector_id": descriptor.collector_id,
        }
        for name, expected in bindings.items():
            if getattr(result, name) != expected:
                raise EvidenceRoutingError(f"collection result substituted {name}")
        if result.status not in RESULT_STATUSES:
            raise EvidenceRoutingError("collection result status is invalid")
        if (not isinstance(result.items, tuple) or
                any(not isinstance(item, CollectedEvidence) for item in result.items)):
            raise EvidenceRoutingError(
                "collection result items must be CollectedEvidence values"
            )
        if len(result.items) > dispatch.max_evidence_items:
            raise EvidenceRoutingError("collection result exceeds the evidence item cap")
        if result.status != "completed" and result.items:
            raise EvidenceRoutingError("non-completed collection cannot return evidence")
        if (dispatch.route.output_role == "human_handoff" and
                result.status not in {"needs_human", "unavailable", "failed"}):
            raise EvidenceRoutingError(
                "a human handoff cannot be converted into collected evidence"
            )

        requirements = {item.requirement_id: item for item in dispatch.requirements}
        satisfied = set()
        for item in result.items:
            item.verify_integrity()
            requirement = requirements.get(item.requirement_id)
            if requirement is None:
                raise EvidenceRoutingError("result references an unknown requirement")
            if (requirement.accepted_kinds and
                    item.evidence_kind not in requirement.accepted_kinds):
                raise EvidenceRoutingError("result returned a disallowed evidence kind")
            attested_kind = (item.envelope.get("attest") or {}).get("evidence_kind")
            if attested_kind != item.evidence_kind:
                raise EvidenceRoutingError(
                    "evidence kind is not bound inside the attested envelope"
                )
            if (dispatch.route.output_role == "candidate_evidence" and
                    "assertion" not in item.envelope):
                raise EvidenceRoutingError(
                    "candidate evidence must carry an assertion for Gate verification"
                )
            if (dispatch.route.output_role == "verification_artifact" and
                    "assertion" in item.envelope):
                raise EvidenceRoutingError(
                    "a verification artifact cannot become an additional assertion"
                )
            canonical_json_bytes(item.envelope)
            satisfied.add(item.requirement_id)
        if result.status == "completed" and satisfied != set(requirements):
            raise EvidenceRoutingError(
                "completed result did not satisfy every routed requirement"
            )

    def _terminal_event_exists(self, dispatch_id: str) -> bool:
        return any(event.dispatch_id == dispatch_id and
                   event.event_type in self._TERMINAL_EVENTS
                   for event in self.audit_log.events)

    def dispatch(self, dispatch: EvidenceDispatch) -> EvidenceCollectionResult:
        self._verify_dispatch(dispatch)
        if dispatch.dispatch_id in self._results:
            return self._results[dispatch.dispatch_id]
        if self._terminal_event_exists(dispatch.dispatch_id):
            raise EvidenceRoutingError(
                "dispatch already reached a terminal audit state; recover its "
                "evidence artifact instead of collecting again"
            )
        if self.audit_log.has("dispatch_started", dispatch.dispatch_id):
            raise EvidenceRoutingError(
                "a previous collection attempt is unresolved; reconcile it before retrying"
            )

        collector = self.collectors.get(dispatch.route.route_id)
        if collector is None:
            self.audit_log.append(
                "route_unavailable", dispatch.challenge_id,
                dispatch_id=dispatch.dispatch_id,
                route_id=dispatch.route.route_id,
                details={"error_type": "collector_not_configured"},
            )
            raise EvidenceRoutingError("no collector is configured for this route")
        descriptor = getattr(collector, "descriptor", None)
        try:
            self._verify_collector(dispatch, descriptor)
        except EvidenceRoutingError:
            self.audit_log.append(
                "route_rejected", dispatch.challenge_id,
                dispatch_id=dispatch.dispatch_id,
                route_id=dispatch.route.route_id,
                details={
                    "collector_id": getattr(descriptor, "collector_id", "unknown"),
                    "error_type": "collector_policy_mismatch",
                },
            )
            raise

        try:
            authorization = self.authorizer.authorize(dispatch, descriptor)
        except Exception as exc:
            self.audit_log.append(
                "dispatch_denied", dispatch.challenge_id,
                dispatch_id=dispatch.dispatch_id,
                route_id=dispatch.route.route_id,
                details={
                    "collector_id": descriptor.collector_id,
                    "error_type": type(exc).__name__,
                },
            )
            raise EvidenceRoutingError(
                "collection authorizer failed; see audit event type"
            ) from exc
        if authorization is None:
            self.audit_log.append(
                "dispatch_denied", dispatch.challenge_id,
                dispatch_id=dispatch.dispatch_id,
                route_id=dispatch.route.route_id,
                details={"collector_id": descriptor.collector_id},
            )
            raise EvidenceRoutingError("collection dispatch was not authorized")
        try:
            self._verify_authorization(dispatch, descriptor, authorization)
        except EvidenceRoutingError:
            self.audit_log.append(
                "dispatch_denied", dispatch.challenge_id,
                dispatch_id=dispatch.dispatch_id,
                route_id=dispatch.route.route_id,
                details={
                    "collector_id": descriptor.collector_id,
                    "error_type": "authorization_binding_invalid",
                },
            )
            raise
        self.audit_log.append(
            "dispatch_authorized", dispatch.challenge_id,
            dispatch_id=dispatch.dispatch_id, route_id=dispatch.route.route_id,
            details={
                "authorization_id": authorization.authorization_id,
                "collector_id": descriptor.collector_id,
                "allowed_actions": list(authorization.allowed_actions),
                "grants_protected_action_authority": False,
            },
        )
        # Intent is durable before the collector is called. A crash afterwards
        # leaves an unresolved dispatch that fails closed instead of re-running.
        self.audit_log.append(
            "dispatch_started", dispatch.challenge_id,
            dispatch_id=dispatch.dispatch_id, route_id=dispatch.route.route_id,
            details={"collector_id": descriptor.collector_id},
        )
        try:
            result = collector.collect(dispatch)
            self._verify_result(dispatch, descriptor, result)
        except Exception as exc:
            self.audit_log.append(
                "collection_failed", dispatch.challenge_id,
                dispatch_id=dispatch.dispatch_id,
                route_id=dispatch.route.route_id,
                details={
                    "collector_id": descriptor.collector_id,
                    "error_type": type(exc).__name__,
                },
            )
            if isinstance(exc, EvidenceRoutingError):
                raise
            raise EvidenceRoutingError("collector failed; see audit event type") from exc

        self.audit_log.append(
            "collection_returned", dispatch.challenge_id,
            dispatch_id=dispatch.dispatch_id, route_id=dispatch.route.route_id,
            details={
                "collector_id": descriptor.collector_id,
                "status": result.status,
                "evidence_item_digests": [item.digest for item in result.items],
                "evidence_item_count": len(result.items),
                "grants_protected_action_authority": False,
            },
        )
        self._results[dispatch.dispatch_id] = result
        return result

    def record_gate_decision(self, request: EvidenceRequest, decision: object) -> None:
        """Append the post-collection Gate outcome without raw evidence."""
        verify_evidence_request(request)
        action = getattr(decision, "action", None)
        route = getattr(decision, "route", None)
        if action not in {"proceed", "block", "request_evidence", "escalate"}:
            raise EvidenceRoutingError("cannot audit an unknown Gate outcome")
        if not isinstance(route, str) or not route:
            raise EvidenceRoutingError("Gate outcome route is required")
        diagnostics = getattr(decision, "diagnostics", None)
        if (not isinstance(diagnostics, dict) or
                diagnostics.get("returned_for_challenge_id") != request.challenge_id):
            raise EvidenceRoutingError(
                "Gate outcome is not bound to the evidence challenge"
            )
        if self.audit_log.has_challenge("gate_reassessed", request.challenge_id):
            raise EvidenceRoutingError("Gate outcome was already recorded")
        self.audit_log.append(
            "gate_reassessed", request.challenge_id,
            details={
                "action": action,
                "route": route,
                "collection_round": request.round,
                "grants_protected_action_authority": action == "proceed",
            },
        )

    def collect(self, request: EvidenceRequest, *,
                requester_control_domain: str) -> tuple[EvidenceCollectionResult, ...]:
        return tuple(self.dispatch(dispatch) for dispatch in self.plan(
            request, requester_control_domain=requester_control_domain
        ))
