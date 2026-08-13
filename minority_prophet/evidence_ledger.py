"""Authenticated transactional persistence for evidence routing.

The ledger authenticates its audit chain and stored artifacts with an
operator-supplied HMAC key.  The key is never written to the database.  This
is a local reference boundary: key custody, backup, and process identity stay
with the embedding system.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from .evidence_audit import (
    AUDIT_SCHEMA,
    EvidenceAuditEvent,
    EvidenceRoutingError,
    _now,
    canonical_json_bytes,
    hash_json,
)

LEDGER_SCHEMA = "minority-prophet.evidence-ledger.v1"


class AuthenticatedSqliteEvidenceLedger:
    """SQLite audit, artifact, dispatch-state, and human-queue ledger."""

    def __init__(
        self,
        path: str | Path,
        authentication_key: bytes,
        clock: Callable[[], str] = _now,
    ) -> None:
        if not isinstance(authentication_key, bytes) or len(authentication_key) < 32:
            raise EvidenceRoutingError(
                "ledger authentication_key must contain at least 32 bytes"
            )
        self.path = Path(path)
        self._key = authentication_key
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            self.path, isolation_level=None, timeout=30
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._create_schema()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        try:
            self.verify_integrity()
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ledger_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY,
                event_json TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE,
                previous_event_hash TEXT,
                previous_authentication_tag TEXT,
                authentication_tag TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dispatch_state (
                dispatch_id TEXT PRIMARY KEY,
                challenge_id TEXT NOT NULL,
                route_id TEXT,
                state TEXT NOT NULL,
                updated_sequence INTEGER NOT NULL,
                FOREIGN KEY(updated_sequence) REFERENCES audit_events(sequence)
            );
            CREATE TABLE IF NOT EXISTS evidence_artifacts (
                evidence_digest TEXT PRIMARY KEY,
                challenge_id TEXT NOT NULL,
                dispatch_id TEXT NOT NULL,
                requirement_id TEXT NOT NULL,
                evidence_kind TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                envelope_digest TEXT NOT NULL,
                stored_at TEXT NOT NULL,
                authentication_tag TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS human_review_queue (
                dispatch_id TEXT PRIMARY KEY,
                challenge_id TEXT NOT NULL,
                route_id TEXT NOT NULL,
                request_json TEXT NOT NULL,
                status TEXT NOT NULL,
                queued_at TEXT NOT NULL,
                resolved_at TEXT,
                resolution_digest TEXT,
                authentication_tag TEXT NOT NULL
            );
            """
        )
        row = self._connection.execute(
            "SELECT value FROM ledger_metadata WHERE key = 'schema'"
        ).fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO ledger_metadata(key, value) VALUES ('schema', ?)",
                (LEDGER_SCHEMA,),
            )
        elif row["value"] != LEDGER_SCHEMA:
            raise EvidenceRoutingError("unsupported evidence ledger schema")

    def _authenticate(self, purpose: str, payload: object) -> str:
        message = purpose.encode("ascii") + b"\0" + canonical_json_bytes(payload)
        return "hmac-sha256:" + hmac.new(
            self._key, message, hashlib.sha256
        ).hexdigest()

    @staticmethod
    def _event_from_json(raw: str) -> EvidenceAuditEvent:
        try:
            value = json.loads(raw)
            return EvidenceAuditEvent(**value)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise EvidenceRoutingError("invalid persisted audit event") from exc

    @property
    def events(self) -> tuple[EvidenceAuditEvent, ...]:
        self._connection.execute("BEGIN")
        try:
            events = self._verify_integrity_in_transaction()
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise
        return events

    def verify_integrity(self) -> None:
        self._connection.execute("BEGIN")
        try:
            self._verify_integrity_in_transaction()
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def _verify_integrity_in_transaction(self) -> tuple[EvidenceAuditEvent, ...]:
        previous_hash = None
        previous_tag = None
        expected_dispatch_state: dict[str, tuple[str, int]] = {}
        verified_events = []
        rows = self._connection.execute(
            "SELECT * FROM audit_events ORDER BY sequence"
        ).fetchall()
        for expected_sequence, row in enumerate(rows):
            event = self._event_from_json(row["event_json"])
            if event.schema != AUDIT_SCHEMA or event.sequence != expected_sequence:
                raise EvidenceRoutingError("evidence ledger sequence is invalid")
            if event.previous_event_hash != previous_hash:
                raise EvidenceRoutingError("evidence ledger hash chain is broken")
            if event.event_hash != hash_json(event.unsigned_payload()):
                raise EvidenceRoutingError("evidence ledger event hash is invalid")
            if row["event_hash"] != event.event_hash:
                raise EvidenceRoutingError("evidence ledger event index is invalid")
            if row["previous_authentication_tag"] != previous_tag:
                raise EvidenceRoutingError("evidence ledger authentication chain is broken")
            expected_tag = self._authenticate(
                "audit-event",
                {"event": event.to_dict(), "previous_authentication_tag": previous_tag},
            )
            if not hmac.compare_digest(row["authentication_tag"], expected_tag):
                raise EvidenceRoutingError("evidence ledger authentication failed")
            previous_hash = event.event_hash
            previous_tag = row["authentication_tag"]
            verified_events.append(event)
            if event.dispatch_id is not None:
                state = {
                    "route_planned": "PLANNED",
                    "dispatch_authorized": "AUTHORIZED",
                    "dispatch_started": "STARTED",
                    "dispatch_denied": "DENIED",
                    "collection_returned": "RETURNED",
                    "collection_failed": "FAILED",
                }.get(event.event_type)
                if state is not None:
                    expected_dispatch_state[event.dispatch_id] = (state, event.sequence)
        actual_dispatch_state = {
            row["dispatch_id"]: (row["state"], row["updated_sequence"])
            for row in self._connection.execute(
                "SELECT dispatch_id, state, updated_sequence FROM dispatch_state"
            )
        }
        if actual_dispatch_state != expected_dispatch_state:
            raise EvidenceRoutingError("derived dispatch state does not match audit chain")
        for row in self._connection.execute("SELECT * FROM evidence_artifacts"):
            self._verified_artifact(row)
        for row in self._connection.execute("SELECT * FROM human_review_queue"):
            self._verified_human_review(row)
        return tuple(verified_events)

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
        safe_details = json.loads(canonical_json_bytes(details or {}).decode("utf-8"))
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._verify_integrity_in_transaction()
            prior = self._connection.execute(
                "SELECT sequence, event_hash, authentication_tag "
                "FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 0 if prior is None else prior["sequence"] + 1
            previous_hash = None if prior is None else prior["event_hash"]
            previous_tag = None if prior is None else prior["authentication_tag"]
            prototype = EvidenceAuditEvent(
                sequence=sequence,
                occurred_at=self.clock(),
                event_type=event_type,
                challenge_id=challenge_id,
                dispatch_id=dispatch_id,
                route_id=route_id,
                details=safe_details,
                previous_event_hash=previous_hash,
                event_hash="pending",
            )
            event = replace(
                prototype, event_hash=hash_json(prototype.unsigned_payload())
            )
            tag = self._authenticate(
                "audit-event",
                {"event": event.to_dict(), "previous_authentication_tag": previous_tag},
            )
            event_json = canonical_json_bytes(event.to_dict()).decode("utf-8")
            self._connection.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
                (sequence, event_json, event.event_hash, previous_hash, previous_tag, tag),
            )
            if dispatch_id is not None:
                state = {
                    "route_planned": "PLANNED",
                    "dispatch_authorized": "AUTHORIZED",
                    "dispatch_started": "STARTED",
                    "dispatch_denied": "DENIED",
                    "collection_returned": "RETURNED",
                    "collection_failed": "FAILED",
                }.get(event_type)
                if state is not None:
                    prior_state = self._connection.execute(
                        "SELECT state FROM dispatch_state WHERE dispatch_id = ?",
                        (dispatch_id,),
                    ).fetchone()
                    allowed = {
                        None: {"PLANNED"},
                        "PLANNED": {"AUTHORIZED", "DENIED"},
                        "AUTHORIZED": {"STARTED"},
                        "STARTED": {"RETURNED", "FAILED"},
                    }
                    current = None if prior_state is None else prior_state["state"]
                    if state not in allowed.get(current, set()):
                        raise EvidenceRoutingError(
                            f"invalid dispatch state transition {current!r} -> {state!r}"
                        )
                    self._connection.execute(
                        """INSERT INTO dispatch_state
                           (dispatch_id, challenge_id, route_id, state, updated_sequence)
                           VALUES (?, ?, ?, ?, ?)
                           ON CONFLICT(dispatch_id) DO UPDATE SET
                             state=excluded.state,
                             updated_sequence=excluded.updated_sequence""",
                        (dispatch_id, challenge_id, route_id, state, sequence),
                    )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise
        return event

    def has(self, event_type: str, dispatch_id: str) -> bool:
        return any(
            event.event_type == event_type and event.dispatch_id == dispatch_id
            for event in self.events
        )

    def has_challenge(self, event_type: str, challenge_id: str) -> bool:
        return any(
            event.event_type == event_type and event.challenge_id == challenge_id
            for event in self.events
        )

    def persist_collection_result(self, dispatch: object, result: object) -> None:
        """Persist verified returned envelopes atomically, keyed by digest."""
        items = getattr(result, "items", ())
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            for item in items:
                envelope = item.envelope_copy()
                record = {
                    "evidence_digest": item.digest,
                    "challenge_id": dispatch.challenge_id,
                    "dispatch_id": dispatch.dispatch_id,
                    "requirement_id": item.requirement_id,
                    "evidence_kind": item.evidence_kind,
                    "envelope": envelope,
                    "envelope_digest": item.envelope_digest,
                }
                tag = self._authenticate("evidence-artifact", record)
                self._connection.execute(
                    """INSERT INTO evidence_artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(evidence_digest) DO NOTHING""",
                    (
                        item.digest,
                        dispatch.challenge_id,
                        dispatch.dispatch_id,
                        item.requirement_id,
                        item.evidence_kind,
                        canonical_json_bytes(envelope).decode("utf-8"),
                        item.envelope_digest,
                        self.clock(),
                        tag,
                    ),
                )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def artifact(self, evidence_digest: str) -> dict:
        row = self._connection.execute(
            "SELECT * FROM evidence_artifacts WHERE evidence_digest = ?",
            (evidence_digest,),
        ).fetchone()
        if row is None:
            raise EvidenceRoutingError("evidence artifact was not found")
        return self._verified_artifact(row)

    def _verified_artifact(self, row: sqlite3.Row) -> dict:
        try:
            envelope = json.loads(row["envelope_json"])
        except json.JSONDecodeError as exc:
            raise EvidenceRoutingError("evidence artifact JSON is invalid") from exc
        if hash_json(envelope) != row["envelope_digest"]:
            raise EvidenceRoutingError("evidence artifact envelope digest is invalid")
        expected_digest = hash_json({
            "requirement_id": row["requirement_id"],
            "evidence_kind": row["evidence_kind"],
            "envelope_digest": row["envelope_digest"],
        })
        if not hmac.compare_digest(row["evidence_digest"], expected_digest):
            raise EvidenceRoutingError("evidence artifact digest is invalid")
        record = {
            "evidence_digest": row["evidence_digest"],
            "challenge_id": row["challenge_id"],
            "dispatch_id": row["dispatch_id"],
            "requirement_id": row["requirement_id"],
            "evidence_kind": row["evidence_kind"],
            "envelope": envelope,
            "envelope_digest": row["envelope_digest"],
        }
        expected = self._authenticate("evidence-artifact", record)
        if not hmac.compare_digest(row["authentication_tag"], expected):
            raise EvidenceRoutingError("evidence artifact authentication failed")
        return record

    def enqueue_human_review(self, dispatch: object) -> None:
        request = dispatch.to_dict()
        record = {
            "dispatch_id": dispatch.dispatch_id,
            "challenge_id": dispatch.challenge_id,
            "route_id": dispatch.route.route_id,
            "request": request,
            "status": "PENDING",
        }
        tag = self._authenticate("human-review", record)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                """INSERT INTO human_review_queue
                   (dispatch_id, challenge_id, route_id, request_json, status,
                    queued_at, resolved_at, resolution_digest, authentication_tag)
                   VALUES (?, ?, ?, ?, 'PENDING', ?, NULL, NULL, ?)
                   ON CONFLICT(dispatch_id) DO NOTHING""",
                (
                    dispatch.dispatch_id,
                    dispatch.challenge_id,
                    dispatch.route.route_id,
                    canonical_json_bytes(request).decode("utf-8"),
                    self.clock(),
                    tag,
                ),
            )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def pending_human_reviews(self) -> tuple[dict, ...]:
        rows = self._connection.execute(
            "SELECT * FROM human_review_queue WHERE status = 'PENDING' ORDER BY queued_at"
        ).fetchall()
        reviews = []
        for row in rows:
            reviews.append(self._verified_human_review(row))
        return tuple(reviews)

    def _verified_human_review(self, row: sqlite3.Row) -> dict:
        try:
            request = json.loads(row["request_json"])
        except json.JSONDecodeError as exc:
            raise EvidenceRoutingError("human-review request JSON is invalid") from exc
        record = {
            "dispatch_id": row["dispatch_id"],
            "challenge_id": row["challenge_id"],
            "route_id": row["route_id"],
            "request": request,
            "status": row["status"],
        }
        expected = self._authenticate("human-review", record)
        if not hmac.compare_digest(row["authentication_tag"], expected):
            raise EvidenceRoutingError("human-review queue authentication failed")
        return record
