"""Signed execution evidence binding a runtime result to Gate authority."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Callable

from .gate import GateDecision
from .runtime_adapter import RuntimeAction, RuntimeReceipt

SCHEMA = "minority-prophet.execution-receipt.v0.1"
Signer = Callable[[bytes], str]
Verifier = Callable[[bytes, str, str], bool]


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def issue_execution_receipt(action: RuntimeAction, result: RuntimeReceipt,
                            gate: GateDecision, *, runtime_id: str, key_id: str,
                            executed_at: str, signer: Signer) -> dict:
    """Sign what a trusted runtime reports; this does not observe the world itself."""
    if gate.action != "proceed" or not gate.diagnostics.get("authority_continuity"):
        raise ValueError("execution receipt requires a continuity-authorized Gate decision")
    if (result.action_id != action.action_id or
            result.idempotency_key != action.idempotency_key or
            result.status != "succeeded" or result.attempt_count != 1):
        raise ValueError("runtime result does not match the authorized action")
    if gate.diagnostics.get("effect_digest") != action.payload_digest:
        raise ValueError("Gate effect digest does not match the runtime action")
    if not all(isinstance(v, str) and v for v in (runtime_id, key_id, executed_at)):
        raise ValueError("runtime_id, key_id, and executed_at are required")
    statement = {
        "schema": SCHEMA, "runtime_id": runtime_id, "key_id": key_id,
        "executed_at": executed_at, "action_id": action.action_id,
        "idempotency_key": action.idempotency_key,
        "action_binding_digest": action.binding_digest,
        "effect_digest": action.payload_digest,
        "mandate_chain_digest": gate.diagnostics["chain_digest"],
        "result_digest": result.result_digest, "status": result.status,
        "attempt_count": result.attempt_count,
    }
    signature = signer(_canonical(statement))
    if not isinstance(signature, str) or not signature:
        raise ValueError("runtime signer returned no signature")
    return {"statement": statement, "signature": signature}


def verify_execution_receipt(envelope: dict, action: RuntimeAction, *,
                             verifier: Verifier) -> bool:
    try:
        statement, signature = envelope["statement"], envelope["signature"]
        if set(envelope) != {"statement", "signature"} or statement["schema"] != SCHEMA:
            return False
        if statement["action_id"] != action.action_id:
            return False
        if statement["idempotency_key"] != action.idempotency_key:
            return False
        if statement["action_binding_digest"] != action.binding_digest:
            return False
        if statement["effect_digest"] != action.payload_digest:
            return False
        return bool(verifier(_canonical(statement), signature, statement["key_id"]))
    except (KeyError, TypeError, ValueError):
        return False


def hmac_signer(key: bytes) -> Signer:
    if len(key) < 32:
        raise ValueError("test key must contain at least 32 bytes")
    return lambda payload: "hmac-sha256:" + hmac.new(key, payload, hashlib.sha256).hexdigest()


def hmac_verifier(keys: dict[str, bytes]) -> Verifier:
    def verify(payload: bytes, signature: str, key_id: str) -> bool:
        key = keys.get(key_id)
        if key is None or not signature.startswith("hmac-sha256:"):
            return False
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature.removeprefix("hmac-sha256:"), expected)
    return verify
