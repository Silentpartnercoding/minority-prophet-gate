import unittest

from minority_prophet.gate import GateDecision
from minority_prophet.runtime_adapter import RuntimeAction, RuntimeBoundaryError, RuntimeController
from minority_prophet.runtime_integrations import (
    IdempotentHttpRuntime,
    InProcessToolRuntime,
    payload_digest,
)


PAYLOAD = {"message": "hello"}


def action(digest=None, key="idem-000000000001"):
    return RuntimeAction("action-1", "tool.call", "tool:demo",
                         digest or payload_digest(PAYLOAD), key, PAYLOAD)


def decision(name):
    return GateDecision(name, 1 if name == "proceed" else None, 2.0, .9, 2, 0)


class RuntimeIntegrationTests(unittest.TestCase):
    def test_in_process_executes_once_across_controller_retries(self):
        calls = []
        runtime = InProcessToolRuntime({("tool.call", "tool:demo"):
                                        lambda payload, key: calls.append((payload, key)) or {"ok": True}})
        controller = RuntimeController()
        first = controller.apply(decision("proceed"), action(), runtime)
        second = controller.apply(decision("proceed"), action(), runtime)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)

    def test_http_sends_exact_digest_and_idempotency_key_once(self):
        calls = []
        def transport(url, headers, body):
            calls.append((url, headers, body))
            return 201, b'{"ok":true}'
        runtime = IdempotentHttpRuntime({("tool.call", "tool:demo"): "https://runtime.example/v1"},
                                        transport)
        controller = RuntimeController()
        controller.apply(decision("proceed"), action(), runtime)
        controller.apply(decision("proceed"), action(), runtime)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["Idempotency-Key"], action().idempotency_key)
        self.assertEqual(calls[0][1]["X-Action-Digest"], action().payload_digest)

    def test_http_target_prevents_duplicate_effect_after_controller_restart(self):
        effects = []
        responses = {}
        def idempotent_target(url, headers, body):
            key = headers["Idempotency-Key"]
            if key not in responses:
                effects.append(body)
                responses[key] = (200, b'{"effect":"created"}')
            return responses[key]
        first_runtime = IdempotentHttpRuntime(
            {("tool.call", "tool:demo"): "https://runtime.example/v1"}, idempotent_target)
        RuntimeController().apply(decision("proceed"), action(), first_runtime)
        second_runtime = IdempotentHttpRuntime(
            {("tool.call", "tool:demo"): "https://runtime.example/v1"}, idempotent_target)
        RuntimeController().apply(decision("proceed"), action(), second_runtime)
        self.assertEqual(len(effects), 1)

    def test_in_process_handler_prevents_duplicate_effect_after_restart(self):
        effects = []
        responses = {}
        def idempotent_handler(payload, key):
            if key not in responses:
                effects.append(payload)
                responses[key] = {"effect": "created"}
            return responses[key]
        route = {("tool.call", "tool:demo"): idempotent_handler}
        RuntimeController().apply(decision("proceed"), action(), InProcessToolRuntime(route))
        RuntimeController().apply(decision("proceed"), action(), InProcessToolRuntime(route))
        self.assertEqual(len(effects), 1)

    def test_both_integrations_execute_zero_times_on_block_or_escalate(self):
        for gate_action in ("block", "escalate"):
            effects = []
            runtimes = (
                InProcessToolRuntime({("tool.call", "tool:demo"):
                                      lambda payload, key: effects.append("function")}),
                IdempotentHttpRuntime({("tool.call", "tool:demo"): "https://runtime.example/v1"},
                                      lambda *args: effects.append("http") or (200, b"ok")),
            )
            for runtime in runtimes:
                receipt = RuntimeController().apply(decision(gate_action), action(), runtime)
                self.assertEqual((receipt.status, receipt.attempt_count), ("prevented", 0))
            self.assertEqual(effects, [])

    def test_payload_substitution_and_unknown_routes_fail_closed(self):
        runtime = InProcessToolRuntime({("tool.call", "tool:demo"): lambda payload, key: None})
        with self.assertRaisesRegex(RuntimeBoundaryError, "digest"):
            RuntimeController().apply(decision("proceed"), action("sha256:wrong"), runtime)
        unknown = RuntimeAction("action-1", "tool.call", "tool:other",
                                payload_digest(PAYLOAD), "idem-000000000002", PAYLOAD)
        with self.assertRaisesRegex(RuntimeBoundaryError, "allowlisted"):
            RuntimeController().apply(decision("proceed"), unknown, runtime)


if __name__ == "__main__":
    unittest.main()
