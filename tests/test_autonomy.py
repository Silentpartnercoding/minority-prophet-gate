import unittest
from dataclasses import replace
from datetime import datetime, timezone

from minority_prophet import (
    AutonomyController,
    AutonomyLevel,
    AutonomyMandate,
    GateDecision,
    RuntimeAction,
    RuntimeBoundaryError,
    RuntimeReceipt,
    resolve_gate_release,
)


NOW = datetime(2026, 8, 13, tzinfo=timezone.utc)


def action(*, reversible=True, target="tool:demo"):
    return RuntimeAction(
        "a-1", "tool.call", target, "sha256:payload", "idem-a-1",
        {"reversible": reversible},
    )


def decision(name="proceed", *, roots=2, budget=2.0):
    return GateDecision(name, 1, budget, 1.0, roots, 0,
                        {"subject": "case:1"})


def mandate(level=AutonomyLevel.EMERGENCY_ACT, **changes):
    values = dict(
        mandate_id="mandate-1", decision_subject="case:1", max_level=level,
        allowed_action_types=("tool.call",), allowed_targets=("tool:demo",),
        expires_at="2099-08-14T00:00:00Z", min_flip_budget=2.0,
        min_roots_for=2, emergency_allowed=level is AutonomyLevel.EMERGENCY_ACT,
    )
    values.update(changes)
    return AutonomyMandate(**values)


class Runtime:
    def __init__(self):
        self.prepares = self.effects = self.preventions = 0

    def prepare(self, value):
        self.prepares += 1
        return value

    def execute_once(self, value):
        self.effects += 1
        return RuntimeReceipt(value.action_id, value.idempotency_key,
                              "succeeded", 1)

    def prevent(self, value, reason):
        self.preventions += 1
        return RuntimeReceipt(value.action_id, value.idempotency_key,
                              "prevented", 0)


class Notifier:
    def __init__(self, fail=False):
        self.calls, self.fail = 0, fail

    def notify(self, release, value):
        self.calls += 1
        if self.fail:
            raise RuntimeError("notification unavailable")


class AutonomyTests(unittest.TestCase):
    def release(self, level, owner=None, gate=None, value=None):
        return resolve_gate_release(
            gate or decision(), value or action(), owner or mandate(), level,
            now=NOW,
        )

    def test_all_five_levels_are_explicit_gate_releases(self):
        for level, status, prepares, effects in (
            (AutonomyLevel.OBSERVE, "observed", 0, 0),
            (AutonomyLevel.RECOMMEND, "recommended", 0, 0),
            (AutonomyLevel.PREPARE, "prepared", 1, 0),
            (AutonomyLevel.ACT, "executed", 1, 1),
        ):
            with self.subTest(level=level):
                runtime = Runtime()
                outcome = AutonomyController().apply(
                    self.release(level), decision(), action(), runtime, mandate(),
                )
                self.assertEqual(outcome.status, status)
                self.assertEqual((runtime.prepares, runtime.effects),
                                 (prepares, effects))

        runtime, notifier = Runtime(), Notifier()
        outcome = AutonomyController().apply(
            self.release(AutonomyLevel.EMERGENCY_ACT), decision(), action(),
            runtime, mandate(), notifier,
        )
        self.assertEqual(outcome.status, "executed")
        self.assertEqual((notifier.calls, runtime.effects), (1, 1))

    def test_profile_caps_requested_autonomy_without_upgrading_it(self):
        release = self.release(
            AutonomyLevel.ACT,
            mandate(AutonomyLevel.RECOMMEND, emergency_allowed=False),
        )
        self.assertTrue(release.authorized)
        self.assertEqual(release.released_level, AutonomyLevel.RECOMMEND)
        runtime = Runtime()
        AutonomyController().apply(
            release, decision(), action(), runtime,
            mandate(AutonomyLevel.RECOMMEND, emergency_allowed=False),
        )
        self.assertEqual(runtime.effects, 0)

    def test_non_proceed_never_becomes_autonomous_action(self):
        for gate_action in ("block", "escalate", "request_evidence"):
            runtime = Runtime()
            gate = decision(gate_action)
            release = self.release(AutonomyLevel.EMERGENCY_ACT, gate=gate)
            AutonomyController().apply(
                release, gate, action(), runtime, mandate(),
            )
            self.assertFalse(release.authorized)
            self.assertEqual(runtime.effects, 0)

    def test_mandate_digest_changes_with_authority(self):
        self.assertNotEqual(
            mandate(AutonomyLevel.RECOMMEND, emergency_allowed=False).digest,
            mandate(AutonomyLevel.ACT, emergency_allowed=False).digest,
        )

    def test_controller_rechecks_release_against_current_mandate(self):
        release = self.release(AutonomyLevel.RECOMMEND)
        forged = replace(release, released_level=AutonomyLevel.ACT)
        runtime = Runtime()
        with self.assertRaisesRegex(RuntimeBoundaryError, "current mandate"):
            AutonomyController().apply(
                forged, decision(), action(), runtime, mandate(),
            )
        self.assertEqual(runtime.effects, 0)

    def test_expired_weak_unbound_or_out_of_scope_mandates_fail_to_observe(self):
        cases = (
            (mandate(expires_at="2026-08-12T00:00:00Z"), decision(), action()),
            (mandate(), decision(roots=1), action()),
            (mandate(), decision(budget=1.0), action()),
            (mandate(decision_subject="case:2"), decision(), action()),
            (mandate(), decision(), action(target="tool:other")),
            (mandate(), decision(), action(reversible=False)),
        )
        for owner, gate, value in cases:
            with self.subTest(reason=(owner, gate, value)):
                release = resolve_gate_release(
                    gate, value, owner, AutonomyLevel.ACT, now=NOW,
                )
                self.assertFalse(release.authorized)
                self.assertEqual(release.released_level, AutonomyLevel.OBSERVE)

    def test_emergency_requires_prior_notification(self):
        runtime = Runtime()
        release = self.release(AutonomyLevel.EMERGENCY_ACT)
        with self.assertRaisesRegex(RuntimeBoundaryError, "notifier"):
            AutonomyController().apply(
                release, decision(), action(), runtime, mandate(),
            )
        self.assertEqual(runtime.effects, 0)

        with self.assertRaisesRegex(RuntimeError, "notification"):
            AutonomyController().apply(
                release, decision(), action(), runtime, mandate(),
                Notifier(fail=True),
            )
        self.assertEqual(runtime.effects, 0)


if __name__ == "__main__":
    unittest.main()
