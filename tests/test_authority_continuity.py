import copy
from datetime import datetime, timezone
import hashlib
import json
import unittest

from minority_prophet.authority_continuity import (
    InMemoryNonceStore,
    authorize_continuous_effect,
)


NOW = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)
EFFECT = {
    "task_id": "task:invoice-123",
    "actor_id": "agent:payments",
    "actor_key_thumbprint": "key:payments",
    "machine_id": "machine:gateway-1",
    "action": "http.request",
    "destination": "https://vendor.example/payments",
    "method": "POST",
    "resource": "invoice:123",
    "body_digest": "sha256:" + "a" * 64,
    "payment": {"network": "eip155:8453", "asset": "USDC",
                "recipient": "0xvendor", "amount_minor": 8700},
}


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def receipt():
    return {
        "schema": "border-intent-continuity/v0.1",
        "verification": "verified",
        "mandate_id": "mandate:invoice-123",
        "mandate_digest": "sha256:" + "b" * 64,
        "chain_digest": "sha256:" + "c" * 64,
        "owner_id": "owner:acme",
        "task_id": "task:invoice-123",
        "final_actor_id": "agent:payments",
        "final_actor_key_thumbprint": "key:payments",
        "final_machine_id": "machine:gateway-1",
        "audience": "vendor.example",
        "final_effect_digest": digest(EFFECT),
        "issued_at": "2026-09-06T11:59:00Z",
        "expires_at": "2026-09-06T12:05:00Z",
        "nonce": "continuity-nonce-0001",
    }


class AuthorityContinuityGateTests(unittest.TestCase):
    def authorize(self, value=None, effect=None, **overrides):
        kwargs = {
            "expected_audience": "vendor.example",
            "verify_border_receipt": lambda _r: True,
            "mandate_is_current": lambda _id: True,
            "nonce_store": InMemoryNonceStore(),
            "now": NOW,
        }
        kwargs.update(overrides)
        return authorize_continuous_effect(value or receipt(), effect or EFFECT, **kwargs)

    def test_exact_current_effect_proceeds(self):
        self.assertEqual("proceed", self.authorize().action)

    def test_every_final_effect_mutation_blocks(self):
        mutations = {
            "caller": ("actor_id", "agent:other"),
            "key": ("actor_key_thumbprint", "key:other"),
            "machine": ("machine_id", "machine:other"),
            "task": ("task_id", "task:other"),
            "destination": ("destination", "https://attacker.example/payments"),
            "method": ("method", "DELETE"),
            "body": ("body_digest", "sha256:" + "0" * 64),
            "resource": ("resource", "invoice:456"),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(EFFECT)
                changed[field] = value
                self.assertEqual("block", self.authorize(effect=changed).action)

        for field, value in (("amount_minor", 50000), ("recipient", "0xattacker")):
            with self.subTest(payment=field):
                changed = copy.deepcopy(EFFECT)
                changed["payment"][field] = value
                self.assertEqual("block", self.authorize(effect=changed).action)

    def test_bad_signature_stale_revoked_and_replay_block(self):
        self.assertEqual("block", self.authorize(
            verify_border_receipt=lambda _r: False).action)
        self.assertEqual("block", self.authorize(
            mandate_is_current=lambda _id: False).action)
        stale = receipt(); stale["expires_at"] = "2026-09-06T11:00:00Z"
        self.assertEqual("block", self.authorize(value=stale).action)
        store = InMemoryNonceStore()
        self.assertEqual("proceed", self.authorize(nonce_store=store).action)
        self.assertEqual("block", self.authorize(nonce_store=store).action)

    def test_dependency_failure_and_future_receipt_fail_closed(self):
        def unavailable(*_args):
            raise ConnectionError("offline")
        self.assertEqual("block", self.authorize(
            verify_border_receipt=unavailable).action)
        self.assertEqual("block", self.authorize(
            mandate_is_current=unavailable).action)
        future = receipt(); future["issued_at"] = "2026-09-06T12:01:00Z"
        self.assertEqual("block", self.authorize(value=future).action)


if __name__ == "__main__":
    unittest.main()
