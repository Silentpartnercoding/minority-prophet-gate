"""Bounded autonomy releases layered on top of a final Gate decision.

Gate still decides whether evidence permits the proposed action.  This module
decides how far a permitted action may progress under an authenticated owner
mandate.  It never upgrades block, escalate, or request-evidence into action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
import hashlib
import json
from typing import Protocol

from .gate import GateDecision
from .runtime_adapter import (
    RuntimeAction,
    RuntimeAdapter,
    RuntimeBoundaryError,
    RuntimeController,
    RuntimeReceipt,
)


class AutonomyLevel(IntEnum):
    OBSERVE = 0
    RECOMMEND = 1
    PREPARE = 2
    ACT = 3
    EMERGENCY_ACT = 4

    @classmethod
    def parse(cls, value: "AutonomyLevel | str") -> "AutonomyLevel":
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown autonomy level: {value!r}") from exc

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class AutonomyMandate:
    """Owner-defined ceiling and conditions for autonomous release.

    This object is policy input, not proof of its own authenticity. A hardened
    deployment admits it through Border, Nxtlinq, IAM, or another authenticated
    mandate store before passing it here.
    """

    mandate_id: str
    decision_subject: str
    max_level: AutonomyLevel | str
    allowed_action_types: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    expires_at: str
    min_flip_budget: float = 1.0
    min_roots_for: int = 1
    allowed_action_digests: tuple[str, ...] = ()
    emergency_allowed: bool = False
    require_reversible: bool = True
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        level = AutonomyLevel.parse(self.max_level)
        object.__setattr__(self, "max_level", level)
        if not self.mandate_id or not self.decision_subject or not self.expires_at:
            raise ValueError("mandate id, decision subject, and expiry are required")
        if not self.allowed_action_types or not self.allowed_targets:
            raise ValueError("mandate requires allowed action types and targets")
        if self.min_flip_budget < 0 or self.min_roots_for < 1:
            raise ValueError("mandate evidence thresholds are invalid")
        if level is AutonomyLevel.EMERGENCY_ACT and not self.emergency_allowed:
            raise ValueError("emergency autonomy requires emergency_allowed")
        _parse_time(self.expires_at)

    @property
    def digest(self) -> str:
        value = {
            "mandate_id": self.mandate_id,
            "decision_subject": self.decision_subject,
            "max_level": self.max_level.label,
            "allowed_action_types": self.allowed_action_types,
            "allowed_targets": self.allowed_targets,
            "expires_at": self.expires_at,
            "min_flip_budget": self.min_flip_budget,
            "min_roots_for": self.min_roots_for,
            "allowed_action_digests": self.allowed_action_digests,
            "emergency_allowed": self.emergency_allowed,
            "require_reversible": self.require_reversible,
            "metadata": self.metadata,
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class GateRelease:
    gate_action: str
    requested_level: AutonomyLevel
    released_level: AutonomyLevel
    authorized: bool
    mandate_id: str
    reason: str
    diagnostics: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AutonomyOutcome:
    release: GateRelease
    status: str
    receipt: RuntimeReceipt | None = None
    prepared: bool = False


class EmergencyNotifier(Protocol):
    def notify(self, release: GateRelease, action: RuntimeAction) -> None:
        """Durably notify the owner before an emergency effect is attempted."""


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("expires_at must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("expires_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def resolve_gate_release(
    decision: GateDecision,
    action: RuntimeAction,
    mandate: AutonomyMandate,
    requested_level: AutonomyLevel | str,
    *,
    now: datetime | None = None,
) -> GateRelease:
    """Resolve the highest fail-closed behavior permitted for this decision."""
    requested = AutonomyLevel.parse(requested_level)
    diagnostics = {
        "decision_subject": mandate.decision_subject,
        "action_binding_digest": action.binding_digest,
        "mandate_max_level": mandate.max_level.label,
    }

    def observe(reason: str) -> GateRelease:
        return GateRelease(decision.action, requested, AutonomyLevel.OBSERVE,
                           False, mandate.mandate_id, reason, diagnostics)

    if decision.action != "proceed":
        return observe(f"Gate returned {decision.action}")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current >= _parse_time(mandate.expires_at):
        return observe("mandate expired")
    if decision.diagnostics.get("subject") != mandate.decision_subject:
        return observe("Gate evidence is not bound to the mandate subject")
    if action.action_type not in mandate.allowed_action_types:
        return observe("action type is outside the mandate")
    if action.target not in mandate.allowed_targets:
        return observe("action target is outside the mandate")
    if (mandate.allowed_action_digests and
            action.binding_digest not in mandate.allowed_action_digests):
        return observe("exact action is outside the mandate")
    if decision.flip_budget < mandate.min_flip_budget:
        return observe("evidence attack price is below the mandate threshold")
    if decision.roots_for < mandate.min_roots_for:
        return observe("independent evidence roots are below the mandate threshold")
    if requested is AutonomyLevel.EMERGENCY_ACT and not mandate.emergency_allowed:
        return observe("emergency action is not authorized by the mandate")

    released = min(requested, mandate.max_level)
    if released >= AutonomyLevel.ACT and mandate.require_reversible:
        if action.payload.get("reversible") is not True:
            return observe("mandate requires an explicitly reversible action")
    return GateRelease(
        decision.action, requested, released, True, mandate.mandate_id,
        "released within mandate",
        dict(diagnostics, capped=requested > mandate.max_level),
    )


class AutonomyController:
    """Enforce a resolved Gate release without upgrading its authority."""

    def __init__(self, runtime_controller: RuntimeController | None = None) -> None:
        self.runtime_controller = runtime_controller or RuntimeController()
        self._prepared: dict[str, tuple[str, str, str, str]] = {}

    def apply(self, release: GateRelease, decision: GateDecision,
              action: RuntimeAction, runtime: RuntimeAdapter,
              mandate: AutonomyMandate,
              notifier: EmergencyNotifier | None = None) -> AutonomyOutcome:
        if release.gate_action != decision.action:
            raise RuntimeBoundaryError("autonomy release substituted Gate action")
        expected = resolve_gate_release(
            decision, action, mandate, release.requested_level,
        )
        if (expected.authorized != release.authorized or
                expected.released_level != release.released_level or
                expected.mandate_id != release.mandate_id or
                expected.reason != release.reason):
            raise RuntimeBoundaryError(
                "autonomy release does not match the current mandate, action, "
                "or Gate decision"
            )
        if not release.authorized:
            if decision.action in {"block", "escalate"}:
                receipt = self.runtime_controller.apply(decision, action, runtime)
                return AutonomyOutcome(release, "prevented", receipt=receipt)
            if decision.action == "proceed":
                denied = GateDecision(
                    "escalate", decision.decision, decision.flip_budget,
                    decision.confidence, decision.roots_for,
                    decision.roots_against,
                    dict(decision.diagnostics, autonomy_reason=release.reason),
                    decision.conversions_to_reverse,
                )
                receipt = self.runtime_controller.apply(denied, action, runtime)
                return AutonomyOutcome(release, "prevented", receipt=receipt)
            return AutonomyOutcome(release, "observed")
        level = release.released_level
        if level is AutonomyLevel.OBSERVE:
            return AutonomyOutcome(release, "observed")
        if level is AutonomyLevel.RECOMMEND:
            return AutonomyOutcome(release, "recommended")
        if level is AutonomyLevel.PREPARE:
            fingerprint = self._prepared.get(action.idempotency_key)
            if fingerprint is not None and fingerprint != action.fingerprint:
                raise RuntimeBoundaryError("prepared key substituted across actions")
            if fingerprint is None:
                runtime.prepare(action)
                self._prepared[action.idempotency_key] = action.fingerprint
            return AutonomyOutcome(release, "prepared", prepared=True)
        if level is AutonomyLevel.EMERGENCY_ACT:
            if notifier is None:
                raise RuntimeBoundaryError("emergency action requires an owner notifier")
            notifier.notify(release, action)
        receipt = self.runtime_controller.apply(decision, action, runtime)
        return AutonomyOutcome(release, "executed", receipt=receipt)
