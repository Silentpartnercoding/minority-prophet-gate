"""A verdict with no immunity guarantee must escalate, not proceed.

`immunity_applicable=False` means T1's precondition fails on this input: some
root carries both assertions, so the immunity theorem says nothing about the
verdict. That is the absence of a guarantee, not a claim the verdict is wrong.

Before this change the flag was computed, written into a diagnostics dict, and
read by nothing -- `gate.py` never mentioned it -- so `decide()` returned
"proceed" on exactly the input class where the theorem is silent. That
contradicted this repository's own README ("no independent evidence is a reason
to ask a human, never a reason to proceed") and the paper's section 7
("escalate evidential uncertainty rather than translate it into permission").

The research reference fails closed on the same input (CE-11: resolving a
conflicting root either way makes the result depend on claim order). This
brings the gate's behaviour into line with it.

Stdlib only; CI runs `unittest discover`.
"""
import unittest

from minority_prophet.aggregator import Claim, aggregate
from minority_prophet.gate import assess, decide
from minority_prophet.adapter_acp import TrustAllVerifier


def _envelope(cid, assertion, derived_from=None):
    """Envelope shape per adapter_acp: lineage travels as attest.derived_from."""
    attest = {"origin": f"origin-{cid}", "sig": "attestation:demo"}
    if derived_from is not None:
        attest["derived_from"] = derived_from
    return {"claim_id": cid, "agent": "test", "assertion": assertion, "attest": attest}


class TestImmunityGating(unittest.TestCase):

    def test_conflicted_root_no_longer_yields_a_decision_from_the_aggregator_alone(self):
        """The aggregator still reports a winner and still flags the violation --
        this test pins the input shape the gate must now refuse."""
        v = aggregate([Claim(id="r", assertion=True, parent=None),
                       Claim(id="c", assertion=False, parent="r")] +
                      [Claim(id=f"s{i}", assertion=True, parent=None) for i in range(3)])
        self.assertFalse(v.diagnostics["immunity_applicable"])
        self.assertIsNotNone(v.decision, "aggregator is unchanged; only the gate refuses")

    def test_the_envelope_route_to_void_immunity_is_now_closed(self):
        """These three tests were written when the adapter passed a contradicting
        echo straight through. It no longer does, so `decide()` cannot be driven
        into the void-immunity branch from envelopes at all -- which is the
        stronger outcome, and the reason the assertions here changed."""
        envs = [_envelope("r", "SAFE"), _envelope("c", "UNSAFE", derived_from="r"),
                _envelope("s0", "SAFE"), _envelope("s1", "SAFE"), _envelope("s2", "SAFE")]
        d = decide(envs, TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)
        self.assertEqual(d.diagnostics["exclusions"].get("side_contradiction"), 1)
        self.assertTrue(d.diagnostics["immunity_applicable"],
                        "the contradiction never reaches the aggregator")
        self.assertEqual(d.action, "proceed",
                         "three honest roots remain and the guarantee holds")

    def test_the_backstop_escalates_when_the_flag_is_false(self):
        """The branch is now unreachable through the adapter, so it is exercised
        directly. It stays in the code because a different transport, a future
        adapter, or a caller using aggregate() can all reintroduce the shape, and
        a guarantee that relies on nobody upstream erring is not a guarantee."""
        import minority_prophet.gate as gate_module
        real = gate_module.assess
        try:
            def voided(*args, **kwargs):
                a = real(*args, **kwargs)
                a.diagnostics = dict(a.diagnostics, immunity_applicable=False)
                return a
            gate_module.assess = voided
            d = gate_module.decide([_envelope(f"s{i}", "SAFE") for i in range(3)],
                                   TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)
        finally:
            gate_module.assess = real
        self.assertEqual(d.action, "escalate")
        self.assertIn("immunity precondition violated", d.diagnostics["reason"])
        self.assertIsNotNone(d.decision,
                             "escalate is not block: the reviewer still sees the verdict")
        self.assertGreaterEqual(d.roots_for, 1)

    def test_a_clean_input_still_proceeds(self):
        d = decide([_envelope(f"s{i}", "SAFE") for i in range(3)],
                   TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)
        self.assertTrue(d.diagnostics["immunity_applicable"])
        self.assertEqual(d.action, "proceed")


class TestSideContradictionQuarantine(unittest.TestCase):
    """A derived claim asserting the opposite of its parent is a contradiction,
    not evidence. It says "I am an echo of X" and "X is wrong" in one breath.

    Admitting it puts one root on both sides, which voids T1's precondition, and
    the gate is left holding a verdict no theorem covers. Before this, the
    adapter passed such a claim through unflagged -- measured: quarantined=0,
    immunity_applicable=False. The escalation above is the backstop; this is the
    cause."""

    def test_a_contradicting_echo_is_quarantined_at_the_boundary(self):
        envs = [_envelope("r", "SAFE"),
                _envelope("c", "UNSAFE", derived_from="r"),
                _envelope("s", "SAFE"), _envelope("s2", "SAFE")]
        a = assess(envs, TrustAllVerifier())
        self.assertEqual(a.diagnostics["quarantined"], 1)
        self.assertEqual(a.diagnostics["exclusions"].get("side_contradiction"), 1)
        self.assertTrue(a.diagnostics["immunity_applicable"],
                        "with the contradiction removed, T1's precondition holds again")

    def test_descendants_of_a_contradiction_are_rejected_too(self):
        """Otherwise the grandchild is promoted to its own evidence root and the
        contradiction buys the attacker a root instead of costing one."""
        envs = [_envelope("r", "SAFE"),
                _envelope("c", "UNSAFE", derived_from="r"),
                _envelope("g", "UNSAFE", derived_from="c")]
        a = assess(envs, TrustAllVerifier())
        self.assertEqual(a.diagnostics["quarantined"], 2)

    def test_an_honest_echo_is_untouched(self):
        envs = [_envelope("r", "SAFE"),
                _envelope("c", "SAFE", derived_from="r"),
                _envelope("o", "UNSAFE")]
        a = assess(envs, TrustAllVerifier())
        self.assertEqual(a.diagnostics["quarantined"], 0)
        self.assertTrue(a.diagnostics["immunity_applicable"])

    def test_the_escalation_backstop_still_exists(self):
        """The adapter now removes the only route by which this shape reached the
        aggregator, so the escalation should be unreachable through decide().
        It stays anyway: a future adapter, a different transport, or a caller
        using aggregate() directly can all reintroduce it, and a guarantee that
        depends on nobody making a mistake upstream is not a guarantee."""
        v = aggregate([Claim(id="r", assertion=True, parent=None),
                       Claim(id="c", assertion=False, parent="r")] +
                      [Claim(id=f"s{i}", assertion=True, parent=None) for i in range(3)])
        self.assertFalse(v.diagnostics["immunity_applicable"])


if __name__ == "__main__":
    unittest.main()
