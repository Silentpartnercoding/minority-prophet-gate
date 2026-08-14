"""Provider-neutral Border Mandate consumption at the runtime boundary.

The module is intentionally a narrow seam.  Border remains the authority
verifier, a private adapter remains the runtime owner, and a Knowledge Ledger
sink remains the evidence owner.  Gate only binds the verified relationship to
the exact runtime action, prevents cross-relationship cache reuse, executes the
existing runtime contract, and emits a neutral lineage record.
It does not mint a new evidence root or absorb the surrounding runtime.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Any, Protocol

from .gate import GateDecision
from .runtime_adapter import (
    RuntimeAction,
    RuntimeAdapter,
    RuntimeBoundaryError,
    RuntimeController,
    RuntimeReceipt,
)


class MandateGateError(RuntimeError):
    """Raised when Gate cannot safely consume a verified Mandate."""


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class MandateBundle:
    """Opaque Border inputs retained so the verifier can recheck live state.

    Gate does not interpret these records as authority.  In particular, a
    receipt field saying ``verified`` cannot select the verifier or policy.
    """

    receipt: dict[str, Any]
    mandate: dict[str, Any]
    request_authority: dict[str, Any]
    executor_authority: dict[str, Any]
    executor_credential: dict[str, Any]
    border_envelope: dict[str, Any]


class BorderMandateVerifier(Protocol):
    """Trusted adapter around Border's full Mandate verification path."""

    def verify(
        self,
        bundle: MandateBundle,
        candidate_action: dict[str, str],
        *,
        expected_audience: str,
    ) -> None:
        """Return only after every Border binding and live authority check passes."""


class MandateNonceStore(Protocol):
    """Atomically consume one Mandate nonce before its authorized effect."""

    def consume(self, nonce: str, fingerprint: tuple[str, ...]) -> None:
        """Consume once; every replay fails closed, including an identical one."""


class InMemoryMandateNonceStore:
    """Reference nonce store; production must use durable atomic storage."""

    def __init__(self) -> None:
        self._reservations: dict[str, tuple[str, ...]] = {}

    def consume(self, nonce: str, fingerprint: tuple[str, ...]) -> None:
        if not isinstance(nonce, str) or len(nonce) < 16:
            raise MandateGateError("verified Mandate nonce is missing or malformed")
        prior = self._reservations.get(nonce)
        if prior is not None:
            if prior == fingerprint:
                raise MandateGateError("Mandate nonce was already consumed")
            raise MandateGateError("Mandate nonce was consumed by another execution")
        self._reservations[nonce] = fingerprint


@dataclass(frozen=True)
class AuthorityRuntimeContext:
    """Verified relationship bindings carried to a provider-blind runtime.

    This is context, not a new credential.  A runtime cannot use it to grant
    itself authority, and a cache entry cannot substitute for live verification.
    """

    relation_id: str
    request_id: str
    requester_id: str
    request_principal_id: str
    executor_id: str
    executor_principal_id: str
    action_digest: str
    audience: str
    request_authority_receipt_digest: str
    executor_authority_receipt_digest: str
    executor_credential_digest: str
    mandate_digest: str
    expires_at: str
    nonce: str

    def as_dict(self) -> dict[str, str]:
        return {
            "schema": "authority-runtime-context/v1",
            "verification": "verified",
            **self.__dict__,
        }

    def scope_key(self, action: RuntimeAction) -> str:
        return _digest(
            {
                "context": self.as_dict(),
                "action": _candidate_action(action),
                "caller_idempotency_key": action.idempotency_key,
            }
        )


@dataclass(frozen=True)
class CachedAuthorityExecution:
    fingerprint: tuple[str, ...]
    receipt: RuntimeReceipt
    lineage: dict[str, Any]


class AuthorityReceiptCache(Protocol):
    """Relation-scoped result cache; never an authority source."""

    def get(self, scope_key: str) -> CachedAuthorityExecution | None: ...

    def put(self, scope_key: str, value: CachedAuthorityExecution) -> None: ...


class InMemoryAuthorityReceiptCache:
    """Reference cache with substitution detection."""

    def __init__(self) -> None:
        self._values: dict[str, CachedAuthorityExecution] = {}

    def get(self, scope_key: str) -> CachedAuthorityExecution | None:
        return self._values.get(scope_key)

    def put(self, scope_key: str, value: CachedAuthorityExecution) -> None:
        prior = self._values.get(scope_key)
        if prior is not None and prior != value:
            raise MandateGateError("authority receipt cache substitution")
        self._values[scope_key] = value


class KnowledgeLedgerSink(Protocol):
    """Append a neutral lineage record without treating it as a truth root."""

    def append(self, record: dict[str, Any]) -> None: ...


class InMemoryKnowledgeLedger:
    """Idempotent reference sink; production may adapt any durable ledger."""

    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}

    def append(self, record: dict[str, Any]) -> None:
        record_id = record.get("record_id")
        if not isinstance(record_id, str) or not record_id:
            raise MandateGateError("lineage record_id is required")
        prior = self.records.get(record_id)
        if prior is not None and prior != record:
            raise MandateGateError("Knowledge Ledger lineage substitution")
        self.records[record_id] = record


def _candidate_action(action: RuntimeAction) -> dict[str, str]:
    return {
        "type": action.action_type,
        "target": action.target,
        "payload_digest": action.payload_digest,
    }


_CONTEXT_FIELDS = (
    "relation_id",
    "request_id",
    "requester_id",
    "request_principal_id",
    "executor_id",
    "executor_principal_id",
    "action_digest",
    "audience",
    "request_authority_receipt_digest",
    "executor_authority_receipt_digest",
    "executor_credential_digest",
    "mandate_digest",
    "expires_at",
    "nonce",
)


def _authority_context(
    bundle: MandateBundle, expected_audience: str
) -> AuthorityRuntimeContext:
    receipt = bundle.receipt
    missing = [
        name
        for name in _CONTEXT_FIELDS
        if not isinstance(receipt.get(name), str) or not receipt[name]
    ]
    if missing:
        raise MandateGateError(
            "verified Border receipt is missing execution bindings: "
            + ", ".join(missing)
        )
    if receipt["audience"] != expected_audience:
        raise MandateGateError(
            "verified Border receipt audience differs from Gate audience"
        )
    return AuthorityRuntimeContext(**{name: receipt[name] for name in _CONTEXT_FIELDS})


def _execution_fingerprint(
    context: AuthorityRuntimeContext, action: RuntimeAction
) -> tuple[str, ...]:
    return (
        context.relation_id,
        context.request_id,
        context.requester_id,
        context.executor_id,
        context.action_digest,
        context.audience,
        action.action_id,
        action.action_type,
        action.target,
        action.payload_digest,
        action.idempotency_key,
    )


def _scoped_action(
    context: AuthorityRuntimeContext, action: RuntimeAction, scope_key: str
) -> RuntimeAction:
    return replace(
        action,
        idempotency_key=scope_key,
        authority_context=context.as_dict(),
    )


def _prevent(runtime: RuntimeAdapter, action: RuntimeAction, reason: str) -> RuntimeReceipt:
    receipt = runtime.prevent(action, reason)
    if (
        receipt.action_id != action.action_id
        or receipt.idempotency_key != action.idempotency_key
        or receipt.status != "prevented"
        or receipt.attempt_count != 0
    ):
        raise RuntimeBoundaryError("runtime prevention receipt is not bound to the action")
    return receipt


def _lineage_record(
    context: AuthorityRuntimeContext,
    action: RuntimeAction,
    runtime_receipt: RuntimeReceipt,
) -> dict[str, Any]:
    body = {
        "schema": "authority-execution-lineage/v1",
        "authority_anchor": context.as_dict(),
        "action": {
            "action_id": action.action_id,
            **_candidate_action(action),
            "caller_idempotency_key": action.idempotency_key,
        },
        # The authority relationship was independently verified.  The runtime
        # outcome is merely observed unless a runtime-specific adapter supplies
        # a separate signed attestation; this record does not overclaim it.
        "execution": {
            "assessment": "observed",
            "status": runtime_receipt.status,
            "attempt_count": runtime_receipt.attempt_count,
            "result_digest": runtime_receipt.result_digest,
        },
    }
    return {**body, "record_id": "lineage-" + _digest(body).removeprefix("sha256:")}


class MandateGate:
    """Verify live authority, bind context, execute once, and record lineage.

    Cache lookup occurs only after live Border verification and the independent
    resource policy.  The cache key includes the verified relationship and exact
    action, so it cannot leak an earlier result across authority relationships.
    """

    def __init__(
        self,
        *,
        expected_audience: str,
        verifier: BorderMandateVerifier,
        nonce_store: MandateNonceStore,
        controller: RuntimeController | None = None,
        receipt_cache: AuthorityReceiptCache | None = None,
        knowledge_ledger: KnowledgeLedgerSink | None = None,
    ) -> None:
        if not expected_audience:
            raise MandateGateError("Gate expected audience is required")
        self.expected_audience = expected_audience
        self.verifier = verifier
        self.nonce_store = nonce_store
        self.controller = controller or RuntimeController()
        self.receipt_cache = receipt_cache or InMemoryAuthorityReceiptCache()
        self.knowledge_ledger = knowledge_ledger or InMemoryKnowledgeLedger()

    def apply(
        self,
        bundle: MandateBundle,
        policy_decision: GateDecision,
        action: RuntimeAction,
        runtime: RuntimeAdapter,
    ) -> RuntimeReceipt:
        candidate = _candidate_action(action)
        try:
            self.verifier.verify(
                bundle,
                candidate,
                expected_audience=self.expected_audience,
            )
            context = _authority_context(bundle, self.expected_audience)
        except Exception as exc:
            return _prevent(
                runtime,
                action,
                "Mandate verification failed closed: " + type(exc).__name__,
            )

        if policy_decision.action != "proceed":
            # External authority is conjunctive: it never overrides resource
            # policy, and a block does not burn the Mandate nonce.
            prevented = _prevent(runtime, action, policy_decision.action)
            lineage = _lineage_record(context, action, prevented)
            self.knowledge_ledger.append(lineage)
            return replace(
                prevented,
                diagnostics={
                    **prevented.diagnostics,
                    "authority_context": context.as_dict(),
                    "lineage_record_id": lineage["record_id"],
                },
            )

        fingerprint = _execution_fingerprint(context, action)
        scope_key = context.scope_key(action)
        cached = self.receipt_cache.get(scope_key)
        if cached is not None:
            if cached.fingerprint != fingerprint:
                raise MandateGateError("authority receipt cache fingerprint substitution")
            # Repair a previous post-effect ledger delivery failure without
            # executing the action again.
            self.knowledge_ledger.append(cached.lineage)
            return cached.receipt

        try:
            self.nonce_store.consume(context.nonce, fingerprint)
        except Exception as exc:
            return _prevent(
                runtime,
                action,
                "Mandate nonce consumption failed closed: " + type(exc).__name__,
            )

        scoped = _scoped_action(context, action, scope_key)
        diagnostics = dict(
            policy_decision.diagnostics,
            authority_relation="MANDATE",
            relation_id=context.relation_id,
            action_digest=context.action_digest,
            audience=self.expected_audience,
            evidence_assessment_used_as_authority=False,
        )
        decision = GateDecision(
            "proceed",
            policy_decision.decision,
            policy_decision.flip_budget,
            policy_decision.confidence,
            policy_decision.roots_for,
            policy_decision.roots_against,
            diagnostics,
            policy_decision.conversions_to_reverse,
        )
        runtime_receipt = self.controller.apply(decision, scoped, runtime)
        lineage = _lineage_record(context, action, runtime_receipt)
        receipt = RuntimeReceipt(
            action_id=runtime_receipt.action_id,
            idempotency_key=action.idempotency_key,
            status=runtime_receipt.status,
            attempt_count=runtime_receipt.attempt_count,
            result_digest=runtime_receipt.result_digest,
            diagnostics={
                **runtime_receipt.diagnostics,
                "authority_context": context.as_dict(),
                "runtime_idempotency_key": scope_key,
                "lineage_record_id": lineage["record_id"],
            },
        )
        cached_value = CachedAuthorityExecution(fingerprint, receipt, lineage)
        self.receipt_cache.put(scope_key, cached_value)
        # Cache before append: if the ledger is temporarily unavailable, a retry
        # re-verifies authority and repairs lineage without a second effect.
        self.knowledge_ledger.append(lineage)
        return receipt
