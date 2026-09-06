"""Fail-closed Gate consumer for Border intent-continuity receipts.

Border proves that authority survived protocol translations.  This module does
not repeat that work: it verifies Border's signed result, rebinds it to the exact
candidate effect at the last responsible moment, rechecks freshness/revocation,
and consumes the receipt nonce before returning ``proceed``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from threading import Lock
from typing import Any, Callable, Protocol

from .gate import GateDecision


class ContinuityGateError(ValueError):
    """The candidate effect lacks valid, current authority continuity."""


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ContinuityGateError(f"{field} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContinuityGateError(f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise ContinuityGateError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


class NonceStore(Protocol):
    def consume(self, nonce: str, binding_digest: str) -> bool:
        """Atomically return True only for the first consumption."""


class InMemoryNonceStore:
    """Thread-safe reference store; production must inject durable storage."""

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}
        self._lock = Lock()

    def consume(self, nonce: str, binding_digest: str) -> bool:
        with self._lock:
            if nonce in self._seen:
                return False
            self._seen[nonce] = binding_digest
            return True


class SqliteNonceStore:
    """Durable, process-safe first-use store for a single deployment."""

    def __init__(self, database: str) -> None:
        if not database:
            raise ValueError("database path is required")
        self.database = database
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS continuity_nonces ("
                "nonce TEXT PRIMARY KEY, binding_digest TEXT NOT NULL, "
                "consumed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30)
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def consume(self, nonce: str, binding_digest: str) -> bool:
        if not nonce or not binding_digest:
            raise ValueError("nonce and binding digest are required")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO continuity_nonces (nonce, binding_digest) VALUES (?, ?)",
                    (nonce, binding_digest),
                )
            return True
        except sqlite3.IntegrityError:
            return False


VerifyReceipt = Callable[[dict[str, Any]], bool]
IsCurrent = Callable[[str], bool]


class GateContinuityTrustProvider(Protocol):
    """Deployment-owned verification and revocation checks used by Gate."""

    def verify_border_receipt(self, receipt: dict[str, Any]) -> bool: ...
    def mandate_is_current(self, mandate_id: str) -> bool: ...


def authorize_continuous_effect(
    receipt: dict[str, Any],
    candidate_effect: dict[str, Any],
    *,
    expected_audience: str,
    verify_border_receipt: VerifyReceipt,
    mandate_is_current: IsCurrent,
    nonce_store: NonceStore,
    now: datetime | None = None,
) -> GateDecision:
    """Authorize exactly one effect or fail closed with a typed reason."""

    required = {
        "schema", "verification", "mandate_id", "mandate_digest",
        "chain_digest", "owner_id", "task_id", "final_actor_id",
        "final_actor_key_thumbprint", "final_machine_id", "audience",
        "final_effect_digest", "issued_at", "expires_at", "nonce",
    }
    try:
        if not isinstance(receipt, dict) or set(receipt) != required:
            raise ContinuityGateError("unknown or incomplete continuity receipt")
        if receipt["schema"] != "border-intent-continuity/v0.1":
            raise ContinuityGateError("unsupported continuity receipt schema")
        try:
            receipt_verified = verify_border_receipt(receipt)
        except Exception as exc:
            raise ContinuityGateError("Border receipt verification unavailable") from exc
        if receipt["verification"] != "verified" or not receipt_verified:
            raise ContinuityGateError("Border receipt signature verification failed")
        if not expected_audience or receipt["audience"] != expected_audience:
            raise ContinuityGateError("Gate audience mismatch")
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise ContinuityGateError("Gate clock must include a timezone")
        current = current.astimezone(timezone.utc)
        issued = _time(receipt["issued_at"], "receipt.issued_at")
        if not issued <= current < _time(receipt["expires_at"], "receipt.expires_at"):
            raise ContinuityGateError("continuity receipt is stale")
        try:
            mandate_current = mandate_is_current(receipt["mandate_id"])
        except Exception as exc:
            raise ContinuityGateError("mandate currency check unavailable") from exc
        if not mandate_current:
            raise ContinuityGateError("mandate is revoked or indeterminate")
        effect_digest = _digest(candidate_effect)
        if receipt["final_effect_digest"] != effect_digest:
            raise ContinuityGateError("candidate effect does not match continuity receipt")
        nonce = receipt["nonce"]
        if not isinstance(nonce, str) or len(nonce) < 16:
            raise ContinuityGateError("invalid continuity nonce")
        try:
            first_use = nonce_store.consume(nonce, effect_digest)
        except Exception as exc:
            raise ContinuityGateError("nonce store unavailable") from exc
        if not first_use:
            raise ContinuityGateError("continuity receipt replayed")
    except (ContinuityGateError, TypeError, ValueError) as exc:
        return GateDecision("block", 0, 0.0, 1.0, 0, 1,
                            {"reason": str(exc), "authority_continuity": False})

    return GateDecision("proceed", 1, 1.0, 1.0, 1, 0, {
        "authority_continuity": True,
        "mandate_id": receipt["mandate_id"],
        "chain_digest": receipt["chain_digest"],
        "effect_digest": receipt["final_effect_digest"],
    })


def authorize_continuous_effect_with_provider(
    receipt: dict[str, Any], candidate_effect: dict[str, Any], *,
    expected_audience: str, trust: GateContinuityTrustProvider,
    nonce_store: NonceStore, now: datetime | None = None,
) -> GateDecision:
    """Provider-oriented entry point preserving Gate's fail-closed behavior."""
    return authorize_continuous_effect(
        receipt, candidate_effect, expected_audience=expected_audience,
        verify_border_receipt=trust.verify_border_receipt,
        mandate_is_current=trust.mandate_is_current,
        nonce_store=nonce_store, now=now,
    )
