import unittest

from minority_prophet.gate import GateDecision
from minority_prophet.runtime_adapter import (
    RuntimeAction,
    RuntimeBoundaryError,
    RuntimeController,
    RuntimeReceipt,
)


def decision(action):
    return GateDecision(action, 1 if action == "proceed" else 0, 1.0, 1.0, 1, 0)


def action(action_id="a-1", key="0123456789abcdef", digest="sha256:abc"):
    return RuntimeAction(action_id, "tool.call", "tool:demo", digest, key)


class FakeRuntime:
    def __init__(self):
        self.prepared = 0
        self.executed = 0
        self.prevented = 0

    def prepare(self, value):
        self.prepared += 1
        return value

    def execute_once(self, prepared):
        self.executed += 1
        return RuntimeReceipt(prepared.action_id, prepared.idempotency_key,
                              "succeeded", 1, "sha256:result")

    def prevent(self, value, reason):
        self.prevented += 1
        return RuntimeReceipt(value.action_id, value.idempotency_key,
                              "prevented", 0, diagnostics={"reason": reason})


class RuntimeAdapterTests(unittest.TestCase):
    def test_proceed_executes_exactly_once_across_retries(self):
        runtime = FakeRuntime()
        controller = RuntimeController()
        first = controller.apply(decision("proceed"), action(), runtime)
        second = controller.apply(decision("proceed"), action(), runtime)
        self.assertEqual(first, second)
        self.assertEqual((runtime.prepared, runtime.executed, runtime.prevented), (1, 1, 0))

    def test_block_and_escalate_execute_zero_times(self):
        for gate_action in ("block", "escalate"):
            runtime = FakeRuntime()
            receipt = RuntimeController().apply(decision(gate_action), action(), runtime)
            self.assertEqual(receipt.attempt_count, 0)
            self.assertEqual((runtime.prepared, runtime.executed, runtime.prevented), (0, 0, 1))

    def test_idempotency_key_cannot_be_reused_for_another_action(self):
        runtime = FakeRuntime()
        controller = RuntimeController()
        controller.apply(decision("proceed"), action(), runtime)
        with self.assertRaisesRegex(RuntimeBoundaryError, "substituted"):
            controller.apply(decision("proceed"), action(action_id="a-2"), runtime)

    def test_runtime_cannot_substitute_receipt(self):
        class BadRuntime(FakeRuntime):
            def execute_once(self, prepared):
                return RuntimeReceipt("other-action", prepared.idempotency_key,
                                      "succeeded", 1)

        with self.assertRaisesRegex(RuntimeBoundaryError, "action_id"):
            RuntimeController().apply(decision("proceed"), action(), BadRuntime())
