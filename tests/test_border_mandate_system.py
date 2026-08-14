"""Optional cross-repository proof of the Border -> Gate -> runtime seam."""

import unittest
from datetime import datetime, timezone

try:
    from border.admission import document_digest
    from border.dsse import hmac_sha256_signer, hmac_sha256_verifier
    from border.mandate_adapter import (
        MandateAdapterContext,
        MandateAuthorityAdapter,
        stamp_mandate_receipt,
        verify_mandate_gate_context,
    )
except ImportError:  # Border is a sibling project, not a Gate dependency.
    document_digest = None

from minority_prophet.gate import GateDecision
from minority_prophet.mandate_gate import (
    InMemoryMandateNonceStore,
    MandateBundle,
    MandateGate,
)
from minority_prophet.runtime_adapter import RuntimeAction, RuntimeReceipt


NOW = datetime(2026, 8, 12, 10, 0, tzinfo=timezone.utc)
AUDIENCE = "notion-gateway.example"
ACTION = {
    "type": "notion.archive_page",
    "target": "notion:page:123",
    "payload_digest": "sha256:" + "a" * 64,
}
BORDER_KEY = b"border-mandate-system-test-key-32b"


def _policy():
    return GateDecision("proceed", 1, 1.0, 1.0, 1, 0, {"policy": "notion"})


class _NotionRuntime:
    def __init__(self):
        self.effects = []

    def prepare(self, action):
        return action

    def execute_once(self, prepared):
        self.effects.append((prepared.action_type, prepared.target))
        return RuntimeReceipt(
            prepared.action_id, prepared.idempotency_key, "succeeded", 1
        )

    def prevent(self, action, reason):
        return RuntimeReceipt(
            action.action_id,
            action.idempotency_key,
            "prevented",
            0,
            diagnostics={"reason": reason},
        )


@unittest.skipIf(document_digest is None, "sibling Border package is not installed")
class BorderMandateSystemTests(unittest.TestCase):
    def setUp(self):
        action_digest = document_digest(ACTION)
        self.request_authority = {
            "receipt_id": "request-authority-1",
            "request_id": "request-1",
            "subject_id": "agent-a",
            "subject_key_thumbprint": "thumbprint-agent-a",
            "principal_id": "workspace-owner",
            "action_digest": document_digest({
                "type": "notion.request_archive_page",
                "target": ACTION["target"],
                "payload_digest": ACTION["payload_digest"],
            }),
            "authorized_execution_action_digest": action_digest,
            "status": "active",
            "decision": "allow",
            "not_before": "2026-08-12T09:50:00Z",
            "expires_at": "2026-08-12T10:30:00Z",
            "issued_at": "2026-08-12T09:49:00Z",
            "key_id": "workflow-authority-key",
            "signature": "verified-request-authority",
        }
        self.executor_authority = {
            "receipt_id": "executor-authority-1",
            "subject_id": "agent-b",
            "principal_id": "notion-workspace-admin",
            "action_digest": action_digest,
            "status": "active",
            "decision": "allow",
            "not_before": "2026-08-12T09:45:00Z",
            "expires_at": "2026-08-12T11:00:00Z",
            "issued_at": "2026-08-12T09:44:00Z",
            "key_id": "notion-authority-key",
            "signature": "verified-executor-authority",
        }
        self.executor_credential = {
            "credential_id": "executor-credential-1",
            "subject_id": "agent-b",
            "subject_key_thumbprint": "thumbprint-agent-b",
            "authority_receipt_digest": document_digest(self.executor_authority),
            "action_digest": action_digest,
            "audience": AUDIENCE,
            "status": "active",
            "not_before": "2026-08-12T09:45:00Z",
            "expires_at": "2026-08-12T10:20:00Z",
            "issued_at": "2026-08-12T09:44:30Z",
            "key_id": "agent-b-key",
            "signature": "verified-executor-credential",
        }
        self.mandate = {
            "schema": "authorized-invocation/v1",
            "mandate_id": "mandate-1",
            "request_id": "request-1",
            "relationship": "MANDATE",
            "requester_id": "agent-a",
            "requester_key_thumbprint": "thumbprint-agent-a",
            "executor_id": "agent-b",
            "executor_key_thumbprint": "thumbprint-agent-b",
            "request_authority_receipt_digest": document_digest(self.request_authority),
            "action_digest": action_digest,
            "audience": AUDIENCE,
            "not_before": "2026-08-12T09:55:00Z",
            "expires_at": "2026-08-12T10:15:00Z",
            "issued_at": "2026-08-12T09:54:00Z",
            "nonce": "mandate-nonce-system-0001",
            "key_id": "agent-a-key",
            "signature": "verified-mandate",
        }
        context = MandateAdapterContext(
            audience=AUDIENCE,
            verify_request_authority=lambda value: value.get("signature") == "verified-request-authority",
            verify_executor_authority=lambda value: value.get("signature") == "verified-executor-authority",
            verify_executor_credential=lambda value: value.get("signature") == "verified-executor-credential",
            verify_mandate=lambda value: value.get("signature") == "verified-mandate",
            request_authorizes=lambda value, action: value.get(
                "authorized_execution_action_digest"
            ) == document_digest(action),
            executor_authorizes=lambda value, action: value.get("action_digest")
            == document_digest(action),
            clock=lambda: NOW,
        )
        receipt = MandateAuthorityAdapter(context).normalize(
            self.mandate,
            self.request_authority,
            self.executor_authority,
            self.executor_credential,
            ACTION,
        )
        envelope = stamp_mandate_receipt(
            receipt, "border-test-key", hmac_sha256_signer(BORDER_KEY)
        )
        self.bundle = MandateBundle(
            receipt,
            self.mandate,
            self.request_authority,
            self.executor_authority,
            self.executor_credential,
            envelope,
        )
        self.current = True

        owner = self

        class _LiveBorderVerifier:
            def verify(self, bundle, candidate_action, *, expected_audience):
                verify_mandate_gate_context(
                    bundle.receipt,
                    bundle.mandate,
                    bundle.request_authority,
                    bundle.executor_authority,
                    bundle.executor_credential,
                    candidate_action,
                    bundle.border_envelope,
                    expected_audience=expected_audience,
                    verify_border=hmac_sha256_verifier(
                        {"border-test-key": BORDER_KEY}
                    ),
                    request_authority_is_current=lambda _value: owner.current,
                    executor_authority_is_current=lambda _value: owner.current,
                    executor_credential_is_current=lambda _value: owner.current,
                    mandate_is_current=lambda _value: owner.current,
                    now=NOW,
                )

        self.gate = MandateGate(
            expected_audience=AUDIENCE,
            verifier=_LiveBorderVerifier(),
            nonce_store=InMemoryMandateNonceStore(),
        )

    def runtime_action(self, **changes):
        values = {
            "action_id": "action-1",
            "action_type": ACTION["type"],
            "target": ACTION["target"],
            "payload_digest": ACTION["payload_digest"],
            "idempotency_key": "idempotency-system-0001",
        }
        values.update(changes)
        return RuntimeAction(**values)

    def test_exact_notion_action_crosses_border_gate_and_executes_once(self):
        runtime = _NotionRuntime()
        result = self.gate.apply(
            self.bundle, _policy(), self.runtime_action(), runtime
        )
        self.assertEqual((result.status, result.attempt_count), ("succeeded", 1))
        self.assertEqual(runtime.effects, [(ACTION["type"], ACTION["target"])])

    def test_substituted_target_is_denied_before_notion(self):
        runtime = _NotionRuntime()
        result = self.gate.apply(
            self.bundle,
            _policy(),
            self.runtime_action(
                action_id="action-2",
                target="notion:page:999",
                idempotency_key="idempotency-system-0002",
            ),
            runtime,
        )
        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual(runtime.effects, [])

    def test_revoked_live_authority_is_denied_before_notion(self):
        self.current = False
        runtime = _NotionRuntime()
        result = self.gate.apply(
            self.bundle, _policy(), self.runtime_action(), runtime
        )
        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual(runtime.effects, [])
