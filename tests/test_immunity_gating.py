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
from minority_prophet.gate import decide
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

    def test_gate_escalates_when_immunity_is_void(self):
        envs = [_envelope("r", "SAFE"), _envelope("c", "UNSAFE", derived_from="r"),
                _envelope("s0", "SAFE"), _envelope("s1", "SAFE"), _envelope("s2", "SAFE")]
        d = decide(envs, TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)
        self.assertFalse(d.diagnostics["immunity_applicable"])
        self.assertEqual(d.action, "escalate",
                         "a verdict with no immunity guarantee must not proceed")
        self.assertIn("immunity precondition violated", d.diagnostics["reason"])

    def test_the_flag_is_actually_read(self):
        """The defect was not a wrong value -- it was a correct value nobody
        consulted. Assert the gating path depends on it."""
        clean = [_envelope(f"s{i}", "SAFE") for i in range(3)]
        d_clean = decide(clean, TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)
        self.assertTrue(d_clean.diagnostics["immunity_applicable"])
        self.assertEqual(d_clean.action, "proceed")

        conflicted = clean + [_envelope("r", "SAFE"), _envelope("c", "UNSAFE", derived_from="r")]
        d_conf = decide(conflicted, TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)
        self.assertEqual(d_conf.action, "escalate")
        self.assertNotEqual(d_clean.action, d_conf.action,
                            "same proceed_side and budget; only immunity differs")

    def test_escalation_preserves_the_verdict_for_the_human(self):
        """Escalate is not block. The reviewer needs to see what the evidence
        said, and why it is not trustworthy on its own."""
        envs = [_envelope("r", "SAFE"), _envelope("c", "UNSAFE", derived_from="r"),
                _envelope("s0", "SAFE"), _envelope("s1", "SAFE"), _envelope("s2", "SAFE")]
        d = decide(envs, TrustAllVerifier(), proceed_side=1, min_flip_budget=1.0)
        self.assertEqual(d.action, "escalate")
        self.assertIsNotNone(d.decision, "the verdict is still reported, just not acted on")
        self.assertGreaterEqual(d.roots_for, 1)


if __name__ == "__main__":
    unittest.main()
