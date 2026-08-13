"""Append-only audit primitives for evidence challenge routing."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

AUDIT_SCHEMA = "minority-prophet.evidence-audit.v1"


class EvidenceRoutingError(RuntimeError):
    """Routing, authorization, collection, or audit validation failed closed."""


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceRoutingError("audit and evidence values must be JSON-safe") from exc


def hash_json(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class EvidenceAuditEvent:
    sequence: int
    occurred_at: str
    event_type: str
    challenge_id: str
    dispatch_id: str | None
    route_id: str | None
    details: dict
    previous_event_hash: str | None
    event_hash: str
    schema: str = AUDIT_SCHEMA

    def unsigned_payload(self) -> dict:
        return {
            "schema": self.schema,
            "sequence": self.sequence,
            "occurred_at": self.occurred_at,
            "event_type": self.event_type,
            "challenge_id": self.challenge_id,
            "dispatch_id": self.dispatch_id,
            "route_id": self.route_id,
            "details": self.details,
            "previous_event_hash": self.previous_event_hash,
        }

    def to_dict(self) -> dict:
        return dict(self.unsigned_payload(), event_hash=self.event_hash)


class EvidenceAuditLog:
    """Append-only hash chain with optional single-process JSONL persistence.

    The JSONL mode flushes and fsyncs every event. It is a local reference, not
    a multi-process transactional database and not an authentication mechanism.
    Production deployments should back the same event contract with their
    durable ledger and integrity authority.
    """

    def __init__(
        self, path: str | Path | None = None, clock: Callable[[], str] = _now
    ) -> None:
        self.path = Path(path) if path is not None else None
        self.clock = clock
        self._events: list[EvidenceAuditEvent] = []
        if self.path is not None and self.path.exists():
            self._load()

    @property
    def events(self) -> tuple[EvidenceAuditEvent, ...]:
        return tuple(self._copy_event(event) for event in self._events)

    @staticmethod
    def _copy_event(event: EvidenceAuditEvent) -> EvidenceAuditEvent:
        details = json.loads(canonical_json_bytes(event.details).decode("utf-8"))
        return replace(event, details=details)

    def _load(self) -> None:
        previous = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                    event = EvidenceAuditEvent(**raw)
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise EvidenceRoutingError(
                        f"invalid audit event at line {line_number}"
                    ) from exc
                self._verify_event(event, len(self._events), previous)
                self._events.append(event)
                previous = event.event_hash

    @staticmethod
    def _verify_event(
        event: EvidenceAuditEvent, expected_sequence: int, previous: str | None
    ) -> None:
        if event.schema != AUDIT_SCHEMA:
            raise EvidenceRoutingError("unsupported evidence audit schema")
        if event.sequence != expected_sequence:
            raise EvidenceRoutingError("evidence audit sequence is not contiguous")
        if event.previous_event_hash != previous:
            raise EvidenceRoutingError("evidence audit hash chain is broken")
        if event.event_hash != hash_json(event.unsigned_payload()):
            raise EvidenceRoutingError("evidence audit event hash is invalid")

    def append(
        self,
        event_type: str,
        challenge_id: str,
        *,
        dispatch_id: str | None = None,
        route_id: str | None = None,
        details: dict | None = None,
    ) -> EvidenceAuditEvent:
        if not event_type or not challenge_id:
            raise EvidenceRoutingError("event_type and challenge_id are required")
        if details is not None and not isinstance(details, dict):
            raise EvidenceRoutingError("audit details must be an object")
        # Canonical round-trip makes a deep copy so callers cannot mutate an
        # already-hashed event through a nested dict or list reference.
        safe_details = json.loads(canonical_json_bytes(details or {}).decode("utf-8"))
        previous = self._events[-1].event_hash if self._events else None
        prototype = EvidenceAuditEvent(
            sequence=len(self._events),
            occurred_at=self.clock(),
            event_type=event_type,
            challenge_id=challenge_id,
            dispatch_id=dispatch_id,
            route_id=route_id,
            details=safe_details,
            previous_event_hash=previous,
            event_hash="pending",
        )
        event = replace(
            prototype, event_hash=hash_json(prototype.unsigned_payload())
        )
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        self._events.append(event)
        return self._copy_event(event)

    def has(self, event_type: str, dispatch_id: str) -> bool:
        return any(
            event.event_type == event_type and event.dispatch_id == dispatch_id
            for event in self._events
        )

    def has_challenge(self, event_type: str, challenge_id: str) -> bool:
        return any(
            event.event_type == event_type and event.challenge_id == challenge_id
            for event in self._events
        )
