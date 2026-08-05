import json
import os
import unittest

from minority_prophet.reconcile import reconcile


def load():
    path = os.path.join(os.path.dirname(__file__), "..", "examples",
                        "state_reconciliation.jsonl")
    with open(path) as fixture:
        return [json.loads(line) for line in fixture if line.strip()]


class TestStateReconciliation(unittest.TestCase):
    def test_voices_lie(self):
        votes = {}
        for envelope in load():
            value = envelope["assertion"]
            votes[value] = votes.get(value, 0) + 1
        self.assertEqual(max(votes, key=votes.get), "running")

    def test_roots_win(self):
        verdict = reconcile(load())
        self.assertEqual(verdict.state, "exited")
        self.assertEqual(len(verdict.roots["exited"]), 2)
        self.assertEqual(len(verdict.roots["running"]), 1)
        self.assertEqual(verdict.flip_budget, 1.0)

    def test_mirrors_do_not_change_state(self):
        envelopes = load()
        for index in range(20):
            envelopes.append({"claim_id": f"m{index}", "component": "mirror",
                              "assertion": "running", "attest": {
                                  "origin": "evt-start-8812",
                                  "derived_from": "s3", "sig": "demo"}})
        self.assertEqual(reconcile(envelopes).state, "exited")

    def test_freshness_decay_widens_margin(self):
        verdict = reconcile(load(), freshness={"half_life_s": 600})
        self.assertEqual(verdict.state, "exited")
        self.assertLess(verdict.root_mass["running"], 0.01)
        self.assertGreater(verdict.flip_budget, 1.9)

    def test_single_probe_tie_is_unverified(self):
        envelopes = [entry for entry in load()
                     if entry["claim_id"] not in ("s7", "s5")]
        verdict = reconcile(envelopes)
        self.assertIsNone(verdict.state)
        self.assertEqual(verdict.flip_budget, 0.0)

    def test_value_mutation_disables_immunity(self):
        envelopes = load()
        envelopes[2]["assertion"] = "exited"
        self.assertFalse(reconcile(envelopes).diagnostics["immunity_applicable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
