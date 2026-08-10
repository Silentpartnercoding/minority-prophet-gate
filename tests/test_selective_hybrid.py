import unittest
from unittest.mock import patch

from minority_prophet import (
    DeterministicDecision,
    EvidenceAssessment,
    TrustAllVerifier,
    selective_decide,
)


def roots(for_count, against_count):
    result = []
    for value, count in (("SAFE", for_count), ("UNSAFE", against_count)):
        for index in range(count):
            root = f"{value.lower()}-{index}"
            result.append({"claim_id": root, "agent": root, "assertion": value,
                           "attest": {"origin": root, "subject": "action-1"}})
    return result


class SelectiveHybridTests(unittest.TestCase):
    def test_clear_allow_stays_on_deterministic_fast_path(self):
        decision = selective_decide(
            DeterministicDecision("allow", "ordinary action", policy_id="p1"),
            [], TrustAllVerifier(), decision_subject="action-1",
        )
        self.assertEqual((decision.action, decision.route), ("proceed", "deterministic"))

    def test_deterministic_deny_cannot_be_overridden_by_evidence(self):
        decision = selective_decide(
            DeterministicDecision("deny", "scope exceeded", evidence_sensitive=True),
            roots(20, 0), TrustAllVerifier(), decision_subject="action-1",
        )
        self.assertEqual((decision.action, decision.route), ("block", "deterministic"))

    def test_evidence_sensitive_allow_invokes_provenance_challenger(self):
        decision = selective_decide(
            DeterministicDecision("allow", "base policy allows", evidence_sensitive=True),
            roots(1, 2), TrustAllVerifier(), decision_subject="action-1",
        )
        self.assertEqual((decision.action, decision.route), ("block", "evidence"))

    def test_tie_or_missing_evidence_escalates_to_human(self):
        for evidence in ([], roots(1, 1)):
            decision = selective_decide(
                DeterministicDecision("review", "policy needs evidence"),
                evidence, TrustAllVerifier(), decision_subject="action-1",
            )
            self.assertEqual((decision.action, decision.route), ("escalate", "human"))

    def test_independent_support_can_complete_evidence_sensitive_allow(self):
        decision = selective_decide(
            DeterministicDecision("allow", "base policy allows", evidence_sensitive=True),
            roots(2, 1), TrustAllVerifier(), decision_subject="action-1",
        )
        self.assertEqual((decision.action, decision.route), ("proceed", "evidence"))

    def test_conversion_resistance_can_be_required_for_proceed(self):
        primary = DeterministicDecision(
            "allow", "base policy allows", evidence_sensitive=True,
        )
        sufficient = selective_decide(
            primary, roots(5, 2), TrustAllVerifier(), decision_subject="action-1",
            min_conversions_to_reverse=2,
        )
        thin = selective_decide(
            primary, roots(5, 2), TrustAllVerifier(), decision_subject="action-1",
            min_conversions_to_reverse=3,
        )
        self.assertEqual(sufficient.assessment.flip_budget, 3.0)
        self.assertEqual(sufficient.assessment.conversions_to_reverse, 2)
        self.assertEqual((sufficient.action, sufficient.route), ("proceed", "evidence"))
        self.assertEqual((thin.action, thin.route), ("escalate", "human"))
        self.assertEqual(thin.reason, "conversion resistance is below policy threshold")
        self.assertEqual(thin.diagnostics["observed_conversions_to_reverse"], 2)

    def test_unavailable_conversion_price_fails_closed(self):
        assessment = EvidenceAssessment(1, 4.0, 1.0, 4, 0,
                                        conversions_to_reverse=None)
        with patch("minority_prophet.selective_hybrid.assess", return_value=assessment):
            decision = selective_decide(
                DeterministicDecision("review", "check evidence"),
                [], TrustAllVerifier(), min_conversions_to_reverse=1,
            )
        self.assertEqual((decision.action, decision.route), ("escalate", "human"))
        self.assertEqual(decision.reason, "conversion resistance is unavailable")

    def test_conversion_threshold_must_be_a_positive_integer(self):
        primary = DeterministicDecision("review", "check evidence")
        for invalid in (0, -1, 1.5, True):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                selective_decide(primary, [], TrustAllVerifier(),
                                 min_conversions_to_reverse=invalid)


if __name__ == "__main__":
    unittest.main()


class OriginSemanticsTests(unittest.TestCase):
    """GATE-01. `origin` classifies freshness; it does not collapse roots.

    The envelope contract used to describe `origin` as "root id this claim
    descends from" and said a claim naming a parent/origin "collapses into that
    family". No code path implements that: every executable use of `origin` is
    freshness-policy classification and the aggregator never reads it. Collapse
    happens only through `derived_from`.

    Found by adversarial review rather than by a failing test -- fifty claims
    sharing one origin turned a correctly-escalating tie into a proceed.

    These tests pin the real contract in both directions so the documentation and
    the code cannot drift apart again. If origin-based collapse is ever
    implemented, the second test fails and the docstring must change with it.
    """

    @staticmethod
    def _root(claim_id, origin, assertion, subject="action-1"):
        return {"claim_id": claim_id, "agent": origin, "assertion": assertion,
                "attest": {"origin": origin, "subject": subject}}

    @staticmethod
    def _derived(claim_id, parent, origin, assertion, subject="action-1"):
        return {"claim_id": claim_id, "agent": origin, "assertion": assertion,
                "attest": {"origin": origin, "subject": subject,
                           "derived_from": parent}}

    def _decide(self, envelopes):
        return selective_decide(
            DeterministicDecision("allow", "base policy allows", evidence_sensitive=True),
            envelopes, TrustAllVerifier(), decision_subject="action-1").action

    def _tie(self):
        return [self._root("s0", "safe-0", "SAFE"),
                self._root("u0", "unsafe-0", "UNSAFE")]

    def test_derived_claims_do_not_buy_independence(self):
        """T2 copy invariance, at the gate boundary. This is the guarantee."""
        tie = self._tie()
        copies = tie + [self._derived(f"c{i}", "s0", "safe-0", "SAFE")
                        for i in range(50)]
        self.assertEqual(self._decide(tie), "escalate")
        self.assertEqual(self._decide(copies), "escalate",
                         "50 derived copies must not convert a tie into a proceed")

    def test_shared_origin_alone_does_not_collapse_roots(self):
        """The documented contract, pinned. NOT a guarantee -- a warning.

        Establishing that one controller yields one root is the verifier's job.
        Neither shipped verifier does it, so claims sharing an origin remain
        independent roots and a tie becomes a proceed. If this ever changes,
        the adapter docstring must change with it.
        """
        tie = self._tie()
        shared = tie + [self._root(f"x{i}", "safe-0", "SAFE") for i in range(50)]
        self.assertEqual(self._decide(shared), "proceed",
                         "origin is not a collapse key; if this now escalates, "
                         "origin-based collapse was implemented and the adapter "
                         "docstring is stale")
