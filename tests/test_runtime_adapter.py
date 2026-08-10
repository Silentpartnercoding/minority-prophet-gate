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


class ExactlyOnceAcrossFailureTests(unittest.TestCase):
    """SYS-01. A failure between the effect and the record must not double-execute.

    Found by an end-to-end composition harness, not by a unit test: the controller
    executed first and recorded afterwards, so a dropped connection after the
    effect landed -- or a receipt that failed validation -- left no ledger entry
    and a retrying caller executed again. Measured at three retries, three
    effects, on a transfer.

    A durable ledger does not fix it. The defect is the order, not the storage.
    Intent is now recorded before the effect and an unresolved entry fails closed.
    """

    class _Adapter:
        def __init__(self, effects, *, crash=False, bad_receipt=False):
            self.effects = effects
            self.crash = crash
            self.bad_receipt = bad_receipt

        def prepare(self, action):
            return action

        def execute_once(self, prepared):
            self.effects.append(prepared.action_id)     # the real side effect
            if self.crash:
                raise ConnectionError("response lost after the effect landed")
            attempts = 2 if self.bad_receipt else 1
            return RuntimeReceipt(prepared.action_id, prepared.idempotency_key,
                                  "succeeded", attempts)

        def prevent(self, action, reason):
            return RuntimeReceipt(action.action_id, action.idempotency_key,
                                  "prevented", 0)

    @staticmethod
    def _action():
        return RuntimeAction("act-1", "transfer", "acct-9", "sha256:abc", "idem-1")

    @staticmethod
    def _allow():
        return GateDecision("proceed", 1, 3.0, 1.0, 3, 0, {}, None)

    def _retry_three_times(self, adapter):
        controller = RuntimeController()
        for _ in range(3):
            try:
                controller.apply(self._allow(), self._action(), adapter)
            except (ConnectionError, RuntimeBoundaryError):
                continue
        return adapter.effects

    def test_transport_failure_after_the_effect_does_not_re_execute(self):
        effects = self._retry_three_times(self._Adapter([], crash=True))
        self.assertEqual(len(effects), 1,
                         f"retrying after a lost response executed {len(effects)} times")

    def test_invalid_receipt_does_not_re_execute(self):
        effects = self._retry_three_times(self._Adapter([], bad_receipt=True))
        self.assertEqual(len(effects), 1,
                         f"retrying after a rejected receipt executed {len(effects)} times")

    def test_an_unresolved_attempt_fails_closed_rather_than_retrying(self):
        """The controller must refuse, not guess. Whether the effect happened is a
        question only the runtime can answer."""
        controller = RuntimeController()
        adapter = self._Adapter([], crash=True)
        with self.assertRaises(ConnectionError):
            controller.apply(self._allow(), self._action(), adapter)
        with self.assertRaises(RuntimeBoundaryError) as caught:
            controller.apply(self._allow(), self._action(), adapter)
        self.assertIn("unresolved", str(caught.exception))
        self.assertEqual(len(adapter.effects), 1)

    def test_the_ordinary_paths_still_work(self):
        controller, adapter = RuntimeController(), self._Adapter([])
        first = controller.apply(self._allow(), self._action(), adapter)
        for _ in range(4):
            repeat = controller.apply(self._allow(), self._action(), adapter)
            self.assertEqual(repeat, first)
        self.assertEqual(len(adapter.effects), 1)
