"""Witness depth: a signature says who is speaking, not whether they looked."""

import unittest

from minority_prophet import TrustAllVerifier, envelopes_to_claims
from minority_prophet.adapter_acp import (
    OBSERVING_DEPTHS,
    WITNESS_DEPTHS,
    stated_depth,
)
from minority_prophet.gate import assess, decide


def env(cid, assertion, depth=None, parent=None):
    attest = {"origin": f"o-{cid}"}
    if depth is not None:
        attest["witness_depth"] = depth
    if parent is not None:
        attest["derived_from"] = parent
    return {"claim_id": cid, "assertion": assertion, "attest": attest}


class VocabularyTests(unittest.TestCase):
    def test_depths_are_ordered_closest_to_the_world_first(self):
        self.assertEqual(WITNESS_DEPTHS[0], "reality")
        self.assertEqual(WITNESS_DEPTHS[-1], "text")

    def test_only_the_first_three_are_contact_with_the_world(self):
        self.assertEqual(OBSERVING_DEPTHS, {"reality", "method", "replication"})

    def test_unstated_reads_as_none(self):
        self.assertIsNone(stated_depth({}))

    def test_unrecognised_reads_as_none_not_as_an_error(self):
        """A producer sending a word this version does not know has not stated
        a depth. Silence is the conservative reading."""
        self.assertIsNone(stated_depth({"witness_depth": "vibes"}))

    def test_a_recognised_value_is_returned(self):
        self.assertEqual(stated_depth({"witness_depth": "reality"}), "reality")


class ObservabilityTests(unittest.TestCase):
    """The gap, made visible before it is enforced."""

    def test_unstated_roots_are_counted_as_unstated(self):
        rep = envelopes_to_claims([env("a", 1), env("b", 1)], TrustAllVerifier())
        self.assertEqual(rep.depth_profile, {"unstated": 2})

    def test_stated_roots_are_counted_by_depth(self):
        rep = envelopes_to_claims(
            [env("a", 1, "reality"), env("b", 1, "text")], TrustAllVerifier())
        self.assertEqual(rep.depth_profile, {"reality": 1, "text": 1})

    def test_derived_claims_are_not_counted(self):
        """Asking how deep an echo went is not a meaningful question."""
        rep = envelopes_to_claims(
            [env("a", 1, "reality"), env("b", 1, parent="a")], TrustAllVerifier())
        self.assertEqual(rep.depth_profile, {"reality": 1})

    def test_assess_reports_how_many_roots_were_assumed_to_have_observed(self):
        result = assess([env("a", 1), env("b", 1)], TrustAllVerifier())
        self.assertEqual(result.diagnostics["roots_assumed_observing"], 2)

    def test_that_number_is_the_size_of_the_silent_assumption(self):
        result = assess(
            [env("a", 1, "reality"), env("b", 1)], TrustAllVerifier())
        self.assertEqual(result.diagnostics["roots_assumed_observing"], 1)
        self.assertEqual(result.diagnostics["depth_profile"],
                         {"reality": 1, "unstated": 1})


class BackwardCompatibilityTests(unittest.TestCase):
    """Existing deployments must not change behaviour."""

    def test_default_weight_leaves_the_verdict_identical(self):
        envelopes = [env("a", 1), env("b", 1), env("c", 0)]
        before = assess(envelopes, TrustAllVerifier())
        after = assess(envelopes, TrustAllVerifier(), unstated_depth_weight=1.0)
        self.assertEqual(before.verdict, after.verdict)
        self.assertEqual(before.flip_budget, after.flip_budget)

    def test_envelopes_without_the_field_still_verify(self):
        rep = envelopes_to_claims([env("a", 1)], TrustAllVerifier())
        self.assertEqual(len(rep.claims), 1)
        self.assertEqual(rep.quarantined, [])

    def test_the_verifier_contract_is_unchanged(self):
        """Depth is stated in the envelope, not returned by the verifier, so no
        production verifier needs modifying."""
        self.assertEqual(TrustAllVerifier().verify(env("a", 1)), "root")
        self.assertEqual(
            TrustAllVerifier().verify(env("b", 1, parent="a")), "derived")

    def test_weight_bounds_are_validated(self):
        with self.assertRaises(ValueError):
            envelopes_to_claims([env("a", 1)], TrustAllVerifier(),
                                unstated_depth_weight=1.5)


class EnforcementTests(unittest.TestCase):
    """Opt-in migration: lowering the weight discounts assumed observation."""

    def test_lowering_the_weight_discounts_unstated_roots(self):
        envelopes = [env("a", 1), env("b", 1)]
        full = assess(envelopes, TrustAllVerifier())
        discounted = assess(envelopes, TrustAllVerifier(),
                            unstated_depth_weight=0.0)
        self.assertGreater(full.flip_budget, discounted.flip_budget)

    def test_a_stated_observation_survives_the_discount(self):
        stated = assess([env("a", 1, "reality"), env("b", 1, "method")],
                        TrustAllVerifier(), unstated_depth_weight=0.0)
        self.assertIsNotNone(stated.verdict)
        self.assertGreater(stated.flip_budget, 0)

    def test_a_stated_re_read_is_discounted_like_an_unstated_root(self):
        """Honesty is not penalised relative to silence -- but it is not
        rewarded as observation either."""
        result = assess([env("a", 1, "text"), env("b", 1, "analysis")],
                        TrustAllVerifier(), unstated_depth_weight=0.0)
        self.assertEqual(result.diagnostics["exclusions"].get(
            "non_observing_depth"), 2)

    def test_discounting_drives_the_gate_to_escalate_not_proceed(self):
        """Losing evidence is a reason to ask, never a reason to act."""
        envelopes = [env("a", 1), env("b", 1)]
        gated = decide(envelopes, TrustAllVerifier(), proceed_side=1,
                       min_flip_budget=1.0, unstated_depth_weight=0.0)
        self.assertNotEqual(gated.action, "proceed")

    def test_exclusions_record_why(self):
        result = assess([env("a", 1), env("b", 1)], TrustAllVerifier(),
                        unstated_depth_weight=0.0)
        self.assertEqual(result.diagnostics["exclusions"].get("unstated_depth"), 2)


if __name__ == "__main__":
    unittest.main()
