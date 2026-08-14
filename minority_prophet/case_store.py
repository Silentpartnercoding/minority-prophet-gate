"""Authenticated SQLite assembly for asynchronous multi-agent evidence cases."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from collections.abc import Callable
from pathlib import Path

from .evidence_audit import EvidenceRoutingError, _now, canonical_json_bytes


CASE_SCHEMA = "minority-prophet.evidence-case.v1"
CASE_STATES = frozenset({"collecting", "ready", "decided", "expired"})


class AuthenticatedSqliteCaseStore:
    """Durably group agent submissions under one frozen action.

    This store assembles evidence; it does not verify evidence or authorize an
    effect.  The embedding process reopens the case, passes ``envelopes()`` to
    its verifier/Gate, and records the resulting terminal state.
    """

    def __init__(self, path: str | Path, authentication_key: bytes,
                 clock: Callable[[], str] = _now) -> None:
        if not isinstance(authentication_key, bytes) or len(authentication_key) < 32:
            raise EvidenceRoutingError("case-store authentication key needs 32 bytes")
        self.path, self._key, self.clock = Path(path), authentication_key, clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS evidence_cases (
                case_id TEXT PRIMARY KEY, action_digest TEXT NOT NULL,
                policy_digest TEXT NOT NULL, state TEXT NOT NULL,
                opened_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                envelope_count INTEGER NOT NULL,
                authentication_tag TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS case_envelopes (
                case_id TEXT NOT NULL, claim_id TEXT NOT NULL,
                envelope_json TEXT NOT NULL, envelope_digest TEXT NOT NULL,
                submitted_at TEXT NOT NULL, authentication_tag TEXT NOT NULL,
                PRIMARY KEY(case_id, claim_id),
                FOREIGN KEY(case_id) REFERENCES evidence_cases(case_id)
            );
        """)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _tag(self, purpose: str, value: object) -> str:
        return "hmac-sha256:" + hmac.new(
            self._key, purpose.encode("ascii") + b"\0" + canonical_json_bytes(value),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _case_value(row: sqlite3.Row) -> dict:
        return {key: row[key] for key in
                ("case_id", "action_digest", "policy_digest", "state",
                 "opened_at", "updated_at", "envelope_count")}

    def open_case(self, case_id: str, action_digest: str, policy_digest: str) -> None:
        if not all(isinstance(value, str) and value for value in
                   (case_id, action_digest, policy_digest)):
            raise EvidenceRoutingError("case id and digests are required")
        stamp = self.clock()
        value = {"case_id": case_id, "action_digest": action_digest,
                 "policy_digest": policy_digest, "state": "collecting",
                 "opened_at": stamp, "updated_at": stamp, "envelope_count": 0}
        try:
            self._db.execute(
                "INSERT INTO evidence_cases VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (*value.values(), self._tag("case", value)),
            )
        except sqlite3.IntegrityError:
            existing = self.case(case_id)
            if (existing["action_digest"], existing["policy_digest"]) != (
                    action_digest, policy_digest):
                raise EvidenceRoutingError("case id was rebound to another action or policy")

    def case(self, case_id: str) -> dict:
        row = self._db.execute(
            "SELECT * FROM evidence_cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if row is None:
            raise EvidenceRoutingError("unknown evidence case")
        value = self._case_value(row)
        if not hmac.compare_digest(row["authentication_tag"], self._tag("case", value)):
            raise EvidenceRoutingError("evidence case authentication failed")
        return value

    def append(self, case_id: str, envelope: dict) -> None:
        case = self.case(case_id)
        if case["state"] != "collecting":
            raise EvidenceRoutingError("evidence case no longer accepts submissions")
        claim_id = envelope.get("claim_id") if isinstance(envelope, dict) else None
        if not isinstance(claim_id, str) or not claim_id:
            raise EvidenceRoutingError("evidence envelope needs a claim_id")
        raw = canonical_json_bytes(envelope).decode("utf-8")
        digest = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
        stamp = self.clock()
        value = {"case_id": case_id, "claim_id": claim_id,
                 "envelope_digest": digest, "submitted_at": stamp}
        self._db.execute("BEGIN IMMEDIATE")
        try:
            try:
                self._db.execute(
                    "INSERT INTO case_envelopes VALUES (?, ?, ?, ?, ?, ?)",
                    (case_id, claim_id, raw, digest, stamp,
                     self._tag("envelope", value)),
                )
            except sqlite3.IntegrityError:
                row = self._db.execute(
                    "SELECT envelope_digest FROM case_envelopes "
                    "WHERE case_id=? AND claim_id=?", (case_id, claim_id),
                ).fetchone()
                if row is None or row["envelope_digest"] != digest:
                    raise EvidenceRoutingError(
                        "claim id was rebound to different evidence"
                    )
                self._db.execute("COMMIT")
                return
            updated = dict(case, envelope_count=case["envelope_count"] + 1,
                           updated_at=stamp)
            self._db.execute(
                "UPDATE evidence_cases SET updated_at=?, envelope_count=?, "
                "authentication_tag=? WHERE case_id=?",
                (stamp, updated["envelope_count"], self._tag("case", updated),
                 case_id),
            )
            self._db.execute("COMMIT")
        except Exception:
            self._db.execute("ROLLBACK")
            raise

    def envelopes(self, case_id: str) -> tuple[dict, ...]:
        self.case(case_id)
        rows = self._db.execute(
            "SELECT * FROM case_envelopes WHERE case_id=? ORDER BY rowid", (case_id,)
        ).fetchall()
        if len(rows) != self.case(case_id)["envelope_count"]:
            raise EvidenceRoutingError("evidence case is missing stored envelopes")
        result = []
        for row in rows:
            value = {"case_id": case_id, "claim_id": row["claim_id"],
                     "envelope_digest": row["envelope_digest"],
                     "submitted_at": row["submitted_at"]}
            if not hmac.compare_digest(row["authentication_tag"],
                                       self._tag("envelope", value)):
                raise EvidenceRoutingError("case envelope authentication failed")
            raw = row["envelope_json"]
            if "sha256:" + hashlib.sha256(raw.encode()).hexdigest() != row["envelope_digest"]:
                raise EvidenceRoutingError("case envelope digest failed")
            result.append(json.loads(raw))
        return tuple(result)

    def transition(self, case_id: str, state: str) -> None:
        if state not in CASE_STATES - {"collecting"}:
            raise EvidenceRoutingError("invalid evidence case state")
        case = self.case(case_id)
        allowed = {"collecting": {"ready", "expired"},
                   "ready": {"decided", "expired"}, "decided": set(), "expired": set()}
        if state not in allowed[case["state"]]:
            raise EvidenceRoutingError("invalid evidence case transition")
        value = dict(case, state=state, updated_at=self.clock())
        self._db.execute(
            "UPDATE evidence_cases SET state=?, updated_at=?, authentication_tag=? WHERE case_id=?",
            (state, value["updated_at"], self._tag("case", value), case_id),
        )
