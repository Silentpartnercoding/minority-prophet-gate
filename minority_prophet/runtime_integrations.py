"""Two reference runtime integrations for the neutral execution boundary."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .runtime_adapter import RuntimeAction, RuntimeBoundaryError, RuntimeReceipt


def payload_digest(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def result_digest(result: object) -> str:
    return payload_digest(result)


@dataclass(frozen=True)
class PreparedAction:
    action: RuntimeAction


def _freeze(action: RuntimeAction) -> PreparedAction:
    if payload_digest(action.payload) != action.payload_digest:
        raise RuntimeBoundaryError("runtime payload digest mismatch")
    return PreparedAction(copy.deepcopy(action))


class InProcessToolRuntime:
    """Execute an allowlisted in-process tool with target-side idempotency."""

    def __init__(self, handlers: Mapping[tuple[str, str], Callable[[dict[str, Any], str], Any]]):
        self.handlers = dict(handlers)
        self._receipts: dict[str, RuntimeReceipt] = {}

    def prepare(self, action: RuntimeAction) -> PreparedAction:
        if (action.action_type, action.target) not in self.handlers:
            raise RuntimeBoundaryError("runtime route is not allowlisted")
        return _freeze(action)

    def execute_once(self, prepared: object) -> RuntimeReceipt:
        if not isinstance(prepared, PreparedAction):
            raise RuntimeBoundaryError("runtime received an unprepared action")
        action = prepared.action
        existing = self._receipts.get(action.idempotency_key)
        if existing is not None:
            return existing
        result = self.handlers[(action.action_type, action.target)](
            copy.deepcopy(action.payload), action.idempotency_key,
        )
        receipt = RuntimeReceipt(action.action_id, action.idempotency_key, "succeeded", 1,
                                 result_digest(result))
        self._receipts[action.idempotency_key] = receipt
        return receipt

    def prevent(self, action: RuntimeAction, reason: str) -> RuntimeReceipt:
        return RuntimeReceipt(action.action_id, action.idempotency_key, "prevented", 0,
                              diagnostics={"reason": reason})


class IdempotentHttpRuntime:
    """Call an allowlisted HTTP endpoint that honors an idempotency key.

    The injected transport owns TLS and authentication. Exactly-once recovery
    across process crashes requires the target service to persist and replay
    responses for the supplied ``Idempotency-Key``.
    """

    def __init__(self, endpoints: Mapping[tuple[str, str], str],
                 transport: Callable[[str, dict[str, str], bytes], tuple[int, bytes]]):
        self.endpoints = dict(endpoints)
        self.transport = transport
        self._receipts: dict[str, RuntimeReceipt] = {}

    def prepare(self, action: RuntimeAction) -> PreparedAction:
        if (action.action_type, action.target) not in self.endpoints:
            raise RuntimeBoundaryError("runtime route is not allowlisted")
        return _freeze(action)

    def execute_once(self, prepared: object) -> RuntimeReceipt:
        if not isinstance(prepared, PreparedAction):
            raise RuntimeBoundaryError("runtime received an unprepared action")
        action = prepared.action
        existing = self._receipts.get(action.idempotency_key)
        if existing is not None:
            return existing
        body = json.dumps(action.payload, sort_keys=True, separators=(",", ":")).encode()
        status, response = self.transport(
            self.endpoints[(action.action_type, action.target)],
            {"Content-Type": "application/json", "Idempotency-Key": action.idempotency_key,
             "X-Action-Digest": action.payload_digest},
            body,
        )
        if not 200 <= status < 300:
            raise RuntimeBoundaryError(f"HTTP runtime rejected effect with status {status}")
        receipt = RuntimeReceipt(action.action_id, action.idempotency_key, "succeeded", 1,
                                 "sha256:" + hashlib.sha256(response).hexdigest(),
                                 {"status": status})
        self._receipts[action.idempotency_key] = receipt
        return receipt

    def prevent(self, action: RuntimeAction, reason: str) -> RuntimeReceipt:
        return RuntimeReceipt(action.action_id, action.idempotency_key, "prevented", 0,
                              diagnostics={"reason": reason})
