"""The conversion attack price (CE-03), and the parity fact that makes it bite.

`flip_budget` prices FORGERY: each fabricated root on the losing side moves the
margin one unit. A CONVERSION -- compromising a root that already supports the
winner and flipping it -- moves the margin TWO units, because the root leaves one
side and joins the other. Quoting `flip_budget` as "the attack price" therefore
overstates an attacker's cost by roughly 2x, which is the wrong direction to be
wrong in for a security control.

These tests pin Gate's reported prices to the research reference's closed form
(`aggregation/root_vote.py`: `conversions_to_reverse = margin // 2 + 1`) without
importing it, so the two stay aligned even though only one of them is installed
here. The reference formula is restated as `_reference_*` below; if Gate and the
formula ever disagree, one of the two repositories has drifted.

Stdlib only, like the rest of this repository -- CI runs `unittest discover`.
"""
import itertools
import unittest

from minority_prophet.aggregator import Claim, aggregate

CASES = [(t, f) for t, f in itertools.product(range(1, 10), range(0, 10)) if t >= f]


def _roots(n_true, n_false, weight=1.0):
    return ([Claim(id=f"t{i}", assertion=True, parent=None, weight=weight)
             for i in range(n_true)] +
            [Claim(id=f"f{i}", assertion=False, parent=None, weight=weight)
             for i in range(n_false)])


def _reference_conversions_to_reverse(margin):
    """`aggregation/root_vote.py`, research repository."""
    return int(margin) // 2 + 1


def _reference_abstention_reachable(margin):
    """Conversions preserve the margin's parity, so a tie is unreachable from an
    odd margin. Research names this `no_abstention_of_odd_margin`."""
    return int(margin) % 2 == 0


class TestConversionAttackPrice(unittest.TestCase):

    def test_matches_research_reference(self):
        for n_true, n_false in CASES:
            with self.subTest(roots=(n_true, n_false)):
                v = aggregate(_roots(n_true, n_false))
                self.assertEqual(v.diagnostics["conversions_to_reverse"],
                                 _reference_conversions_to_reverse(v.margin))
                self.assertEqual(v.diagnostics["abstention_reachable_by_conversion"],
                                 _reference_abstention_reachable(v.margin))

    def test_reported_price_actually_reverses_the_verdict(self):
        """The number must survive being spent. Convert exactly that many roots
        and the verdict must really flip -- and one fewer must not."""
        for n_true, n_false in CASES:
            with self.subTest(roots=(n_true, n_false)):
                v = aggregate(_roots(n_true, n_false))
                k = v.diagnostics["conversions_to_reverse"]
                winner = v.decision if v.decision is not None else True

                def after(n):
                    moved = min(n, n_true if winner is True else n_false)
                    if winner is True:
                        return aggregate(_roots(n_true - moved, n_false + moved))
                    return aggregate(_roots(n_true + moved, n_false - moved))

                self.assertNotIn(after(k).decision, (winner, None),
                                 "the quoted price did not reverse it")
                if k > 1:
                    # One conversion short must not be a reversal. At an even
                    # margin it lands on the tie instead, which is abstention,
                    # not a flip -- so `None` counts as "not yet reversed".
                    self.assertIn(after(k - 1).decision, (winner, None),
                                  "it was already reversed for less")

    def test_conversion_is_cheaper_than_forgery_above_margin_one(self):
        """The finding, stated as a test: forgery costs margin+1, compromise
        costs about half. A deployment that budgets defence against
        `flip_budget` alone is over-confident by this ratio."""
        for n_true in range(3, 12):
            with self.subTest(roots=n_true):
                v = aggregate(_roots(n_true, 0))
                forgeries = v.diagnostics["flip_budget"] + 1
                conversions = v.diagnostics["conversions_to_reverse"]
                self.assertLess(conversions, forgeries)
                self.assertLessEqual(abs(conversions - forgeries / 2), 1.0)

    def test_abstention_is_unreachable_by_conversion_at_odd_margin(self):
        """The dangerous half of the parity fact: at odd margin the cheapest
        attack never passes through the safe 'abstain' state, so a thin margin
        does NOT degrade gracefully to 'don't know' -- it degrades to a
        confident error."""
        odd = aggregate(_roots(4, 1))                    # margin 3
        self.assertEqual(odd.margin % 2, 1)
        self.assertFalse(odd.diagnostics["abstention_reachable_by_conversion"])
        reached = {aggregate(_roots(4 - k, 1 + k)).decision for k in range(5)}
        self.assertNotIn(None, reached, "a tie was reachable after all")

        even = aggregate(_roots(4, 2))                   # margin 2
        self.assertTrue(even.diagnostics["abstention_reachable_by_conversion"])
        self.assertIsNone(aggregate(_roots(3, 3)).decision)

    def test_flip_budget_unit_is_declared_and_is_not_a_count_under_weights(self):
        """`flip_budget` is root MASS. Under the documented migration weight it
        goes fractional, and 0.5 forged roots is not a purchase an attacker can
        make -- so the unit ships with the number instead of being inferred."""
        plain = aggregate(_roots(3, 1))
        self.assertTrue(plain.diagnostics["flip_budget_is_root_count"])
        self.assertEqual(plain.diagnostics["flip_budget_unit"], "independent roots")

        mixed = aggregate([Claim(id="a", assertion=True, parent=None, weight=1.0),
                           Claim(id="b", assertion=True, parent=None, weight=1.0),
                           Claim(id="c", assertion=False, parent=None, weight=0.5)],
                          use_weights=True)
        self.assertAlmostEqual(mixed.diagnostics["flip_budget"], 1.5)
        self.assertFalse(mixed.diagnostics["flip_budget_is_root_count"])
        self.assertEqual(mixed.diagnostics["flip_budget_unit"], "weighted root mass")
        self.assertIsInstance(mixed.diagnostics["conversions_to_reverse"], int,
                              "an action count must stay countable even when "
                              "the mass does not")

    def test_conversion_preserves_side_consistency_so_immunity_still_applies(self):
        """A conversion must move whole subtrees. Moving only the root claim
        would manufacture a side-confusion violation and silently price a
        different attack -- one that breaks T1's precondition rather than the
        margin."""
        claims = [Claim(id="r", assertion=True, parent=None),
                  Claim(id="c1", assertion=True, parent="r"),
                  Claim(id="r2", assertion=True, parent=None),
                  Claim(id="o", assertion=False, parent=None)]
        v = aggregate(claims)
        self.assertTrue(v.diagnostics["immunity_applicable"])
        self.assertEqual(v.diagnostics["conversions_to_reverse"],
                         _reference_conversions_to_reverse(v.margin))

    def test_analysis_does_not_perturb_the_verdict_it_analyses(self):
        for n_true, n_false in CASES:
            with self.subTest(roots=(n_true, n_false)):
                full = aggregate(_roots(n_true, n_false))
                bare = aggregate(_roots(n_true, n_false), _attack_analysis=False)
                self.assertEqual((full.decision, full.margin, full.confidence),
                                 (bare.decision, bare.margin, bare.confidence))


if __name__ == "__main__":
    unittest.main()
