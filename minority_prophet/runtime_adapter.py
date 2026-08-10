"""Provider-neutral runtime adapter contract and exactly-once controller."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .gate import GateDecision


class RuntimeBoundaryError(RuntimeError):
    """Raised when a runtime violates the neutral execution boundary."""


@dataclass(frozen=True)
class RuntimeAction:
    action_id: str
    action_type: str
    target: str
    payload_digest: str
    idempotency_key: str
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("action_id", "action_type", "target", "payload_digest", "idempotency_key"):
            if not getattr(self, name):
                raise ValueError(f"{name} is required")

    @property
    def fingerprint(self) -> tuple[str, str, str, str]:
        return (self.action_id, self.action_type, self.target, self.payload_digest)


@dataclass(frozen=True)
class RuntimeReceipt:
    action_id: str
    idempotency_key: str
    status: str  # succeeded | prevented
    attempt_count: int
    result_digest: str | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)


class RuntimeAdapter(Protocol):
    """Provider-blind interface implemented by private runtime integrations."""

    def prepare(self, action: RuntimeAction) -> object:
        """Validate and freeze the exact action without executing it."""

    def execute_once(self, prepared: object) -> RuntimeReceipt:
        """Execute one previously prepared action exactly once."""

    def prevent(self, action: RuntimeAction, reason: str) -> RuntimeReceipt:
        """Record that an action was prevented without attempting execution."""


class RuntimeController:
    """Turns a Gate decision into exactly one neutral runtime outcome.

    INTENT IS RECORDED BEFORE THE EFFECT, and this ordering is the guarantee.

    An earlier version executed first and recorded afterwards. Anything failing in
    between -- a dropped connection after the effect landed, or a receipt that
    failed validation -- left no record, so a retrying caller executed again.
    Measured at three retries, three effects, on a transfer. The module called
    itself an exactly-once controller and was not one.

    A durable ledger does not fix that. The defect is the ORDER, not the storage:
    nothing can record an execution the code does not mention until after it has
    happened. So a `pending` entry is written first, and an unresolved `pending`
    entry on a later attempt FAILS CLOSED rather than re-executing. Resolving it
    requires asking the runtime what actually happened, which is a question only
    the integration can answer.

    The in-memory ledger remains a reference implementation. Production callers
    must provide a durable, transactional ledger -- and must preserve this
    ordering, which is the part that carries the guarantee.
    """

    _PENDING = "pending"

    def __init__(self) -> None:
        self._ledger: dict[str, tuple[tuple[str, str, str, str], object]] = {}

    def apply(self, decision: GateDecision, action: RuntimeAction,
              adapter: RuntimeAdapter) -> RuntimeReceipt:
        existing = self._ledger.get(action.idempotency_key)
        if existing is not None:
            fingerprint, receipt = existing
            if fingerprint != action.fingerprint:
                raise RuntimeBoundaryError("idempotency key substituted across actions")
            if receipt is self._PENDING:
                raise RuntimeBoundaryError(
                    "a previous attempt for this idempotency key is unresolved: the "
                    "effect may or may not have happened. Reconcile with the runtime "
                    "before retrying; this controller will not execute again.")
            return receipt

        if decision.action == "proceed":
            prepared = adapter.prepare(action)
            # Record intent BEFORE the effect. If anything below fails, the entry
            # stays pending and a retry fails closed instead of executing twice.
            self._ledger[action.idempotency_key] = (action.fingerprint, self._PENDING)
            receipt = adapter.execute_once(prepared)
            self._validate_receipt(action, receipt, expected_status="succeeded", attempts=1)
        elif decision.action in ("block", "escalate"):
            # prevent() performs no effect, so there is no window to protect.
            receipt = adapter.prevent(action, decision.action)
            self._validate_receipt(action, receipt, expected_status="prevented", attempts=0)
        else:
            raise RuntimeBoundaryError(f"unknown Gate action: {decision.action}")

        self._ledger[action.idempotency_key] = (action.fingerprint, receipt)
        return receipt

    @staticmethod
    def _validate_receipt(action: RuntimeAction, receipt: RuntimeReceipt, *,
                          expected_status: str, attempts: int) -> None:
        if receipt.action_id != action.action_id:
            raise RuntimeBoundaryError("runtime receipt substituted action_id")
        if receipt.idempotency_key != action.idempotency_key:
            raise RuntimeBoundaryError("runtime receipt substituted idempotency_key")
        if receipt.status != expected_status or receipt.attempt_count != attempts:
            raise RuntimeBoundaryError(
                f"runtime effect mismatch: expected {expected_status}/{attempts}"
            )
