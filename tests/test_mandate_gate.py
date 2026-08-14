import unittest

from minority_prophet.mandate_gate import (
    InMemoryAuthorityReceiptCache,
    InMemoryKnowledgeLedger,
    InMemoryMandateNonceStore,
    MandateBundle,
    MandateGate,
)
from minority_prophet.gate import GateDecision
from minority_prophet.runtime_adapter import RuntimeAction, RuntimeReceipt


AUDIENCE = "notion-gateway.example"


def receipt(**changes):
    value = {
        "schema": "border-authority-relation/v1",
        "relationship": "MANDATE",
        "relation_id": "relation-1",
        "request_id": "request-1",
        "requester_id": "agent-a",
        "request_principal_id": "workspace-owner",
        "executor_id": "agent-b",
        "executor_principal_id": "notion-workspace-admin",
        "request_authority_receipt_digest": "sha256:" + "1" * 64,
        "executor_authority_receipt_digest": "sha256:" + "2" * 64,
        "executor_credential_digest": "sha256:" + "3" * 64,
        "mandate_digest": "sha256:" + "4" * 64,
        "action_digest": "sha256:" + "d" * 64,
        "audience": AUDIENCE,
        "expires_at": "2026-08-12T10:15:00Z",
        "nonce": "mandate-nonce-0001",
    }
    value.update(changes)
    return value


def bundle(**receipt_changes):
    return MandateBundle(
        receipt=receipt(**receipt_changes),
        mandate={"kind": "opaque-mandate"},
        request_authority={"kind": "opaque-request-authority"},
        executor_authority={"kind": "opaque-executor-authority"},
        executor_credential={"kind": "opaque-executor-credential"},
        border_envelope={"kind": "opaque-dsse-envelope"},
    )


def action(**changes):
    values = {
        "action_id": "action-1",
        "action_type": "notion.archive_page",
        "target": "notion:page:123",
        "payload_digest": "sha256:" + "a" * 64,
        "idempotency_key": "idempotency-key-0001",
    }
    values.update(changes)
    return RuntimeAction(**values)


def policy(action_name="proceed"):
    return GateDecision(
        action_name,
        1 if action_name == "proceed" else 0,
        1.0,
        1.0,
        1,
        0,
        {"policy": "fixture"},
    )


class RecordingVerifier:
    def __init__(self, failure=None):
        self.failure = failure
        self.calls = []

    def verify(self, value, candidate_action, *, expected_audience):
        self.calls.append((value, candidate_action, expected_audience))
        if self.failure:
            raise self.failure


class RecordingRuntime:
    def __init__(self, order=None):
        self.order = order if order is not None else []
        self.prepared = 0
        self.executed = 0
        self.prevented = 0

    def prepare(self, value):
        self.prepared += 1
        self.order.append("prepare")
        return value

    def execute_once(self, prepared):
        self.executed += 1
        self.order.append("execute")
        return RuntimeReceipt(
            prepared.action_id,
            prepared.idempotency_key,
            "succeeded",
            1,
            "sha256:result",
        )

    def prevent(self, value, reason):
        self.prevented += 1
        self.order.append("prevent")
        return RuntimeReceipt(
            value.action_id,
            value.idempotency_key,
            "prevented",
            0,
            diagnostics={"reason": reason},
        )


class RecordingNonceStore(InMemoryMandateNonceStore):
    def __init__(self, order):
        super().__init__()
        self.order = order

    def consume(self, nonce, fingerprint):
        self.order.append("consume")
        super().consume(nonce, fingerprint)


class FailingNonceStore:
    def consume(self, nonce, fingerprint):
        raise ConnectionError("durable nonce store unavailable")


class MandateGateTests(unittest.TestCase):
    def gate(self, verifier=None, nonce_store=None, **changes):
        return MandateGate(
            expected_audience=AUDIENCE,
            verifier=verifier or RecordingVerifier(),
            nonce_store=nonce_store or InMemoryMandateNonceStore(),
            **changes,
        )

    def test_exact_verified_action_executes_once(self):
        verifier = RecordingVerifier()
        runtime = RecordingRuntime()
        gate = self.gate(verifier=verifier)

        first = gate.apply(bundle(), policy(), action(), runtime)
        second = gate.apply(bundle(), policy(), action(), runtime)

        self.assertEqual("succeeded", first.status)
        self.assertEqual((first.status, first.attempt_count), ("succeeded", 1))
        self.assertEqual((second.status, second.attempt_count), ("succeeded", 1))
        self.assertEqual((runtime.prepared, runtime.executed, runtime.prevented), (1, 1, 0))
        self.assertNotEqual(first.idempotency_key, first.diagnostics["runtime_idempotency_key"])
        self.assertEqual("verified", first.diagnostics["authority_context"]["verification"])
        self.assertEqual(
            {
                "type": "notion.archive_page",
                "target": "notion:page:123",
                "payload_digest": "sha256:" + "a" * 64,
            },
            verifier.calls[0][1],
        )
        self.assertEqual(AUDIENCE, verifier.calls[0][2])

    def test_verifier_failure_blocks_before_prepare_or_effect(self):
        runtime = RecordingRuntime()
        gate = self.gate(verifier=RecordingVerifier(ValueError("revoked")))

        result = gate.apply(bundle(), policy(), action(), runtime)

        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual((runtime.prepared, runtime.executed, runtime.prevented), (0, 0, 1))

    def test_exact_runtime_action_is_passed_to_verifier_not_receipt_fields(self):
        verifier = RecordingVerifier(ValueError("action mismatch"))
        runtime = RecordingRuntime()
        changed = action(target="notion:page:999")

        result = self.gate(verifier=verifier).apply(bundle(), policy(), changed, runtime)

        self.assertEqual("prevented", result.status)
        self.assertEqual("notion:page:999", verifier.calls[0][1]["target"])
        self.assertEqual(runtime.executed, 0)

    def test_caller_owned_audience_cannot_be_selected_by_receipt(self):
        runtime = RecordingRuntime()
        result = self.gate().apply(
            bundle(audience="attacker.example"), policy(), action(), runtime
        )
        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual(runtime.executed, 0)

    def test_nonce_is_reserved_before_runtime_prepare_and_effect(self):
        order = []
        runtime = RecordingRuntime(order)
        gate = self.gate(nonce_store=RecordingNonceStore(order))

        gate.apply(bundle(), policy(), action(), runtime)

        self.assertEqual(["consume", "prepare", "execute"], order)

    def test_nonce_cannot_be_reused_for_substituted_execution(self):
        store = InMemoryMandateNonceStore()
        first_runtime = RecordingRuntime()
        second_runtime = RecordingRuntime()
        self.gate(nonce_store=store).apply(bundle(), policy(), action(), first_runtime)

        changed = action(
            action_id="action-2",
            target="notion:page:999",
            idempotency_key="idempotency-key-0002",
        )
        result = self.gate(nonce_store=store).apply(
            bundle(), policy(), changed, second_runtime
        )

        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual(second_runtime.executed, 0)

    def test_consumed_nonce_cannot_execute_again_through_a_fresh_controller(self):
        store = InMemoryMandateNonceStore()
        first_runtime = RecordingRuntime()
        second_runtime = RecordingRuntime()
        self.gate(nonce_store=store).apply(bundle(), policy(), action(), first_runtime)

        result = self.gate(nonce_store=store).apply(
            bundle(), policy(), action(), second_runtime
        )

        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual(first_runtime.executed, 1)
        self.assertEqual(second_runtime.executed, 0)

    def test_missing_verified_receipt_bindings_fail_closed(self):
        runtime = RecordingRuntime()
        result = self.gate().apply(bundle(relation_id=""), policy(), action(), runtime)
        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual(runtime.executed, 0)

    def test_nonce_store_failure_blocks_before_prepare_or_effect(self):
        runtime = RecordingRuntime()
        result = self.gate(nonce_store=FailingNonceStore()).apply(
            bundle(), policy(), action(), runtime
        )
        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual((runtime.prepared, runtime.executed, runtime.prevented), (0, 0, 1))

    def test_valid_mandate_cannot_override_another_gate_block(self):
        runtime = RecordingRuntime()
        store = InMemoryMandateNonceStore()
        gate = self.gate(nonce_store=store)
        result = gate.apply(bundle(), policy("block"), action(), runtime)
        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual((runtime.prepared, runtime.executed, runtime.prevented), (0, 0, 1))

        # A separate policy block does not burn an otherwise valid Mandate.
        second_runtime = RecordingRuntime()
        allowed = self.gate(nonce_store=store).apply(
            bundle(), policy("proceed"), action(), second_runtime
        )
        self.assertEqual((allowed.status, allowed.attempt_count), ("succeeded", 1))
        self.assertEqual(second_runtime.executed, 1)

    def test_same_caller_key_does_not_share_cache_across_relations(self):
        cache = InMemoryAuthorityReceiptCache()
        first_runtime = RecordingRuntime()
        second_runtime = RecordingRuntime()
        self.gate(receipt_cache=cache).apply(bundle(), policy(), action(), first_runtime)
        self.gate(receipt_cache=cache).apply(
            bundle(relation_id="relation-2", nonce="mandate-nonce-0002"),
            policy(),
            action(),
            second_runtime,
        )

        self.assertEqual(first_runtime.executed, 1)
        self.assertEqual(second_runtime.executed, 1)

    def test_cache_never_bypasses_live_verification(self):
        cache = InMemoryAuthorityReceiptCache()
        first_runtime = RecordingRuntime()
        self.gate(receipt_cache=cache).apply(bundle(), policy(), action(), first_runtime)

        denied_runtime = RecordingRuntime()
        result = self.gate(
            verifier=RecordingVerifier(ValueError("revoked")),
            receipt_cache=cache,
        ).apply(bundle(), policy(), action(), denied_runtime)

        self.assertEqual((result.status, result.attempt_count), ("prevented", 0))
        self.assertEqual(denied_runtime.executed, 0)

    def test_lineage_starts_at_verified_authority_and_marks_execution_observed(self):
        ledger = InMemoryKnowledgeLedger()
        result = self.gate(knowledge_ledger=ledger).apply(
            bundle(), policy(), action(), RecordingRuntime()
        )

        record = ledger.records[result.diagnostics["lineage_record_id"]]
        self.assertEqual("verified", record["authority_anchor"]["verification"])
        self.assertEqual("observed", record["execution"]["assessment"])
        self.assertEqual("succeeded", record["execution"]["status"])
        self.assertEqual("notion.archive_page", record["action"]["type"])

    def test_relation_context_reaches_runtime_without_entering_payload(self):
        runtime = RecordingRuntime()
        self.gate().apply(bundle(), policy(), action(), runtime)
        prepared = runtime.order
        self.assertEqual(["prepare", "execute"], prepared)

        class InspectingRuntime(RecordingRuntime):
            def prepare(self, value):
                self.seen = value
                return super().prepare(value)

        inspecting = InspectingRuntime()
        self.gate().apply(
            bundle(nonce="mandate-nonce-0003"),
            policy(),
            action(idempotency_key="idempotency-key-0003"),
            inspecting,
        )
        self.assertEqual("relation-1", inspecting.seen.authority_context["relation_id"])
        self.assertNotIn("authority_context", inspecting.seen.payload)

    def test_ledger_failure_repairs_on_retry_without_second_effect(self):
        class FlakyLedger(InMemoryKnowledgeLedger):
            def __init__(self):
                super().__init__()
                self.fail = True

            def append(self, record):
                if self.fail:
                    self.fail = False
                    raise ConnectionError("ledger unavailable")
                super().append(record)

        ledger = FlakyLedger()
        cache = InMemoryAuthorityReceiptCache()
        runtime = RecordingRuntime()
        gate = self.gate(receipt_cache=cache, knowledge_ledger=ledger)

        with self.assertRaises(ConnectionError):
            gate.apply(bundle(), policy(), action(), runtime)
        result = gate.apply(bundle(), policy(), action(), runtime)

        self.assertEqual(runtime.executed, 1)
        self.assertIn(result.diagnostics["lineage_record_id"], ledger.records)

    def test_valid_policy_block_records_zero_attempt_lineage(self):
        ledger = InMemoryKnowledgeLedger()
        runtime = RecordingRuntime()
        result = self.gate(knowledge_ledger=ledger).apply(
            bundle(), policy("block"), action(), runtime
        )
        record = ledger.records[result.diagnostics["lineage_record_id"]]
        self.assertEqual((record["execution"]["status"], record["execution"]["attempt_count"]), ("prevented", 0))
        self.assertEqual(runtime.executed, 0)


if __name__ == "__main__":
    unittest.main()
