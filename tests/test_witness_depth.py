"""Witness depth: a signature says who is speaking, not whether they looked."""

import unittest

from minority_prophet import TrustAllVerifier, envelopes_to_claims
from minority_prophet.adapter_acp import (
    OBSERVING_DEPTHS,
    WITNESS_DEPTHS,
    envelopes_to_claims as _e2c,
    normalise_depth_weights,
    stated_depth,
)

LADDER = {"reality": 1.0, "method": 1.0, "replication": 0.8,
          "raw": 0.5, "analysis": 0.3, "text": 0.1}
SILENCE_ONLY = {"reality": 1.0, "method": 1.0, "replication": 1.0,
                "raw": 1.0, "analysis": 1.0, "text": 1.0, "unstated": 1.0}
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
        after = assess(envelopes, TrustAllVerifier(), depth_weights=SILENCE_ONLY)
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
                                depth_weights={"reality": 1.5})


class LadderTests(unittest.TestCase):
    """Depth is a ladder, not a switch.

    An earlier draft multiplied every non-observing rung by one scalar, which
    replaced a two-value model (root/derived) with another two-value model
    (observing/not) and discarded the gradation that motivated the change.
    """

    def test_each_rung_can_carry_its_own_weight(self):
        w = normalise_depth_weights(LADDER)
        self.assertEqual([w[d] for d in WITNESS_DEPTHS],
                         [1.0, 1.0, 0.8, 0.5, 0.3, 0.1])

    def test_rerunning_raw_data_outweighs_rereading_the_paper(self):
        """The distinction a two-value model cannot express."""
        w = normalise_depth_weights(LADDER)
        self.assertGreater(w["raw"], w["text"])

    def test_unstated_is_pinned_to_the_weakest_stated_rung(self):
        """A source that did not say what it did cannot be better than the
        weakest thing it might have done."""
        w = normalise_depth_weights(LADDER)
        self.assertEqual(w["unstated"], min(w[d] for d in WITNESS_DEPTHS))

    def test_unstated_cannot_be_given_a_privileged_weight(self):
        with self.assertRaises(ValueError) as ctx:
            normalise_depth_weights(dict(LADDER, unstated=0.9))
        self.assertIn("cannot be better than the weakest", str(ctx.exception))

    def test_unstated_may_be_set_lower_than_the_weakest_rung(self):
        w = normalise_depth_weights(dict(LADDER, unstated=0.0))
        self.assertEqual(w["unstated"], 0.0)

    def test_none_means_no_discounting_at_all(self):
        w = normalise_depth_weights(None)
        self.assertEqual(set(w.values()), {1.0})


class EnforcementTests(unittest.TestCase):
    """Opt-in migration: supplying weights discounts assumed observation."""

    ZERO = dict(LADDER, reality=1.0, method=1.0, replication=1.0,
                raw=0.0, analysis=0.0, text=0.0, unstated=0.0)

    def test_discounting_reduces_the_attack_price_of_unstated_roots(self):
        envelopes = [env("a", 1), env("b", 1)]
        full = assess(envelopes, TrustAllVerifier())
        discounted = assess(envelopes, TrustAllVerifier(),
                            depth_weights=self.ZERO)
        self.assertGreater(full.flip_budget, discounted.flip_budget)

    def test_a_stated_observation_survives_the_discount(self):
        stated = assess([env("a", 1, "reality"), env("b", 1, "method")],
                        TrustAllVerifier(), depth_weights=self.ZERO)
        self.assertIsNotNone(stated.verdict)
        self.assertGreater(stated.flip_budget, 0)

    def test_a_stated_re_read_is_graded_not_lumped_with_silence(self):
        """Under a real ladder these differ; under the earlier scalar they
        could not."""
        reread = assess([env("a", 1, "text"), env("b", 1, "text")],
                        TrustAllVerifier(), depth_weights=LADDER)
        recompute = assess([env("a", 1, "raw"), env("b", 1, "raw")],
                           TrustAllVerifier(), depth_weights=LADDER)
        self.assertGreater(recompute.flip_budget, reread.flip_budget)

    def test_discounting_drives_the_gate_to_escalate_not_proceed(self):
        """Losing evidence is a reason to ask, never a reason to act."""
        gated = decide([env("a", 1), env("b", 1)], TrustAllVerifier(),
                       proceed_side=1, min_flip_budget=1.0,
                       depth_weights=self.ZERO)
        self.assertNotEqual(gated.action, "proceed")

    def test_exclusions_name_the_rung_that_was_discounted(self):
        result = assess([env("a", 1), env("b", 1, "text")], TrustAllVerifier(),
                        depth_weights=self.ZERO)
        self.assertEqual(result.diagnostics["exclusions"].get("depth_unstated"), 1)
        self.assertEqual(result.diagnostics["exclusions"].get("depth_text"), 1)


class MigrationHazardTests(unittest.TestCase):
    """Turning weights down where nothing states a depth escalates everything.

    That is the FalseDenyRate failure, and it is the documented kill criterion
    for this programme: sensitivity analysis producing enough false escalations
    to erase the avoided errors. The profile must make it visible BEFORE anyone
    changes a weight.
    """

    def test_the_profile_shows_the_hazard_before_any_weight_changes(self):
        result = assess([env(str(i), 1) for i in range(5)], TrustAllVerifier())
        self.assertEqual(result.diagnostics["roots_assumed_observing"], 5)
        self.assertEqual(result.diagnostics["depth_profile"], {"unstated": 5})

    def test_a_fleet_that_states_nothing_would_lose_every_root(self):
        envelopes = [env(str(i), 1) for i in range(5)]
        before = assess(envelopes, TrustAllVerifier())
        after = assess(envelopes, TrustAllVerifier(),
                       depth_weights=dict(LADDER, unstated=0.0))
        self.assertGreater(before.flip_budget, 0)
        self.assertEqual(after.flip_budget, 0)


if __name__ == "__main__":
    unittest.main()
