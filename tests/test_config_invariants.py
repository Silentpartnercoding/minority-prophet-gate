"""Configuration-space guardrails for the Gate's theorem-facing policy.

These tests do not prove the theorems. They ensure policy knobs cannot turn
invalid or unbound evidence into the independent, bound root strength that the
theorems and T5 floor rely on.
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from minority_prophet import decide
from minority_prophet.adapter_acp import CallbackVerifier


def root(claim_id, assertion, *, subject=None, origin="scan-1", status="root", **attest):
    stamp = {"origin": origin, "sig": "demo", **attest}
    if subject is not None:
        stamp["subject"] = subject
    return {"claim_id": claim_id, "assertion": assertion,
            "verification_status": status, "attest": stamp}


VERIFY = CallbackVerifier(lambda envelope: envelope["verification_status"])


class TestConfigurationInvariants(unittest.TestCase):
    def test_public_contract_requires_verifier_independence(self):
        readme = (Path(__file__).parents[1] / "README.md").read_text()
        self.assertIn("Verifier independence", readme)
        self.assertIn("not trusted merely because it is a\n   third party", readme)
        self.assertIn("unable to\n   mint, alter, or promote the evidence it verifies", readme)
        self.assertIn("escalates rather than\n   converting uncertainty into permission", readme)

    def test_bound_only_strength_is_invariant_under_migration_weight(self):
        bound = [root("a", "SAFE", subject="job:1", observed_at_age_s=0),
                 root("b", "UNSAFE", subject="job:1", observed_at_age_s=0)]
        migration = bound + [root("u-safe", "SAFE"), root("u-unsafe", "UNSAFE")]
        baseline = decide(bound, VERIFY, proceed_side=1, decision_subject="job:1")
        for unbound_weight in (0.0, 0.5, 1.0):
            decision = decide(migration, VERIFY, proceed_side=1,
                              decision_subject="job:1",
                              unbound_root_weight=unbound_weight)
            self.assertEqual(decision.flip_budget, baseline.flip_budget)
            self.assertTrue(decision.diagnostics["migration_flip_budget_conservative"])

    def test_bound_only_strength_is_invariant_under_freshness_corners(self):
        bound = [root("a", "SAFE", subject="job:1", observed_at_age_s=0),
                 root("b", "UNSAFE", subject="job:1", observed_at_age_s=0)]
        unbound_probe = root("u", "SAFE", origin="probe-1", observed_at_age_s=10_000)
        baseline = decide(bound, VERIFY, proceed_side=1, decision_subject="job:1")
        for freshness in ({}, {"probe": {"half_life_s": 300}},
                          {"probe": {"ttl_s": 1}}, {"default": {"ttl_s": 1}}):
            decision = decide(bound + [unbound_probe], VERIFY, proceed_side=1,
                              decision_subject="job:1", freshness=freshness)
            self.assertEqual(decision.flip_budget, baseline.flip_budget)

    def test_invalid_claims_never_change_verdict_or_strength(self):
        valid = [root("a", "SAFE", subject="job:1"),
                 root("b", "UNSAFE", subject="job:1")]
        forged = root("bad", "SAFE", subject="job:1", status="invalid")
        baseline = decide(valid, VERIFY, proceed_side=1, decision_subject="job:1")
        decision = decide(valid + [forged], VERIFY, proceed_side=1,
                          decision_subject="job:1")
        self.assertEqual(decision.action, baseline.action)
        self.assertEqual(decision.decision, baseline.decision)
        self.assertEqual(decision.flip_budget, baseline.flip_budget)
        self.assertEqual(decision.diagnostics["quarantined"], 1)

    def test_empty_or_invalid_evidence_always_escalates(self):
        for envelopes in ([], [root("bad", "SAFE", status="invalid")]):
            with self.subTest(envelopes=envelopes):
                decision = decide(envelopes, VERIFY, proceed_side=1,
                                  decision_subject="job:1")
                self.assertEqual(decision.action, "escalate")
                self.assertEqual(decision.flip_budget, 0.0)

    def test_subject_mismatch_never_becomes_bound_strength(self):
        envs = [root("right", "SAFE", subject="job:1"),
                root("wrong", "SAFE", subject="job:other")]
        decision = decide(envs, VERIFY, proceed_side=1, decision_subject="job:1")
        self.assertEqual(decision.flip_budget, 1.0)
        self.assertEqual(decision.diagnostics["bound_roots"], 1)
        self.assertEqual(decision.diagnostics["exclusions"]["subject_mismatch"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
