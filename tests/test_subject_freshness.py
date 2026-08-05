import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from minority_prophet import TrustAllVerifier, decide
from minority_prophet.adapter_acp import envelopes_to_claims


def root(cid, assertion, *, subject=None, origin="scan-1", **attest):
    data = {"origin": origin, "sig": "demo", **attest}
    if subject is not None:
        data["subject"] = subject
    return {"claim_id": cid, "assertion": assertion, "attest": data}


def derived(cid, assertion, parent, *, subject=None):
    data = {"derived_from": parent, "sig": "demo"}
    if subject is not None:
        data["subject"] = subject
    return {"claim_id": cid, "assertion": assertion, "attest": data}


class TestSubjectBindingAndFreshness(unittest.TestCase):
    def test_no_subject_keeps_legacy_behavior(self):
        envs = [root("a", "SAFE"), root("b", "UNSAFE"), root("c", "UNSAFE")]
        decision = decide(envs, TrustAllVerifier(), proceed_side=1)
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.flip_budget, 1.0)

    def test_matching_bound_roots_supply_strength(self):
        envs = [root("a", "SAFE", subject="job:1"),
                root("b", "SAFE", subject="job:1"),
                root("c", "UNSAFE", subject="job:1")]
        decision = decide(envs, TrustAllVerifier(), proceed_side=1,
                          decision_subject="job:1")
        self.assertEqual(decision.action, "proceed")
        self.assertEqual(decision.flip_budget, 1.0)
        self.assertEqual(decision.diagnostics["bound_roots"], 3)

    def test_mismatched_subject_contributes_zero(self):
        envs = [root("a", "SAFE", subject="job:other"),
                root("b", "UNSAFE", subject="job:1")]
        decision = decide(envs, TrustAllVerifier(), proceed_side=1,
                          decision_subject="job:1")
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.diagnostics["exclusions"]["subject_mismatch"], 1)

    def test_unbound_migration_weight_never_inflates_strength(self):
        envs = [root("a", "SAFE", subject="job:1"),
                root("b", "UNSAFE", subject="job:1"), root("c", "SAFE")]
        decision = decide(envs, TrustAllVerifier(), proceed_side=1,
                          decision_subject="job:1")
        self.assertEqual(decision.action, "escalate")
        self.assertEqual(decision.decision, 1)  # 0.5 migration vote breaks the ordinary tie
        self.assertEqual(decision.flip_budget, 0.0)  # bound roots remain tied
        self.assertTrue(decision.diagnostics["migration_flip_budget_conservative"])

    def test_strict_unbound_end_state(self):
        envs = [root("a", "SAFE", subject="job:1"), root("b", "SAFE")]
        decision = decide(envs, TrustAllVerifier(), proceed_side=1,
                          decision_subject="job:1", unbound_root_weight=0.0)
        self.assertEqual(decision.action, "proceed")
        self.assertEqual(decision.flip_budget, 1.0)

    def test_derived_subject_mismatch_is_quarantined(self):
        envs = [root("a", "SAFE", subject="job:1"),
                derived("b", "SAFE", "a", subject="job:other")]
        report = envelopes_to_claims(envs, TrustAllVerifier(), decision_subject="job:1")
        self.assertEqual(len(report.quarantined), 1)
        self.assertEqual(report.exclusions["subject_mismatch"], 1)

    def test_probe_half_life_default(self):
        envs = [root("a", "SAFE", subject="job:1", origin="probe-9",
                     observed_at_age_s=600)]
        report = envelopes_to_claims(envs, TrustAllVerifier(), decision_subject="job:1")
        self.assertAlmostEqual(report.claims[0].weight, 0.25)

    def test_start_event_ttl_and_missing_time_expire(self):
        envs = [root("old", "SAFE", subject="job:1", origin="start-event-9",
                     observed_at_age_s=86401),
                root("missing", "SAFE", subject="job:1", origin="start-event-10")]
        report = envelopes_to_claims(envs, TrustAllVerifier(), decision_subject="job:1")
        self.assertEqual([claim.weight for claim in report.claims], [0.0, 0.0])
        self.assertEqual(report.exclusions["expired"], 1)
        self.assertEqual(report.exclusions["expired_missing_observed_at"], 1)

    def test_unknown_origin_has_no_decay_policy(self):
        report = envelopes_to_claims([root("a", "SAFE", subject="job:1", origin="scan-9")],
                                     TrustAllVerifier(), decision_subject="job:1")
        self.assertEqual(report.claims[0].weight, 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
