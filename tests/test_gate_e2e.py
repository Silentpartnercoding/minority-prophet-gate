import json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from minority_prophet import decide, TrustAllVerifier, aggregate, Claim
from minority_prophet.adapter_acp import CallbackVerifier

def load_pr482():
    p = os.path.join(os.path.dirname(__file__), "..", "examples", "pr482.jsonl")
    return [json.loads(l) for l in open(p) if l.strip()]

class TestPR482EndToEnd(unittest.TestCase):
    def test_story_blocks_merge(self):
        # 7 SAFE voices vs 2 UNSAFE voices; 1 SAFE root vs 2 UNSAFE roots
        d = decide(load_pr482(), TrustAllVerifier(), proceed_side=1)
        self.assertEqual(d.action, "block")
        self.assertEqual(d.decision, 0)          # UNSAFE wins
        self.assertEqual(d.roots_for, 1)         # scan-7f2c
        self.assertEqual(d.roots_against, 2)     # test-9a41, test-b830
        self.assertEqual(d.flip_budget, 1.0)     # one forged root -> tie

    def test_naive_vote_would_have_merged(self):
        envs = load_pr482()
        safe_votes = sum(1 for e in envs if e["assertion"] == "SAFE")
        self.assertGreaterEqual(safe_votes, 7)   # the trap this gate removes

    def test_flood_attack_without_valid_roots_changes_nothing(self):
        envs = load_pr482()
        for i in range(5):  # MAD-Spear-style flood: no attest block at all
            envs.append({"claim_id": f"x{i}", "agent": "compromised",
                         "assertion": "SAFE"})
        d = decide(envs, TrustAllVerifier(), proceed_side=1)
        self.assertEqual(d.action, "block")
        self.assertEqual(d.diagnostics["quarantined"], 5)

    def test_flood_with_derived_attestations_collapses(self):
        envs = load_pr482()
        for i in range(50):  # flood that IS validly signed as derived
            envs.append({"claim_id": f"y{i}", "agent": "compromised",
                         "assertion": "SAFE",
                         "attest": {"origin": "scan-7f2c",
                                    "derived_from": "c2", "sig": "attestation:demo"}})
        d = decide(envs, TrustAllVerifier(), proceed_side=1)
        self.assertEqual(d.action, "block")      # T2: copies are null
        self.assertEqual(d.roots_for, 1)

    def test_forged_root_moves_to_escalate_not_proceed(self):
        envs = load_pr482()
        envs.append({"claim_id": "forged", "agent": "compromised",
                     "assertion": "SAFE",
                     "attest": {"origin": "stolen-key-root", "sig": "attestation:demo"}})
        d = decide(envs, TrustAllVerifier(), proceed_side=1)
        self.assertEqual(d.action, "escalate")   # 2 vs 2 -> abstain (T4: budget was 1)

    def test_strict_verifier_quarantines_everything_unverifiable(self):
        strict = CallbackVerifier(lambda e: "invalid")
        d = decide(load_pr482(), strict, proceed_side=1)
        self.assertEqual(d.action, "escalate")
        self.assertEqual(d.diagnostics["reason"], "no verifiable claims")

    def test_orphan_parent_becomes_zero_weight_singleton(self):
        envs = [{"claim_id": "a", "agent": "x", "assertion": "SAFE",
                 "attest": {"origin": "o1", "derived_from": "ghost",
                            "sig": "s"}},
                {"claim_id": "b", "agent": "y", "assertion": "UNSAFE",
                 "attest": {"origin": "t1", "sig": "s"}}]
        d = decide(envs, TrustAllVerifier(), proceed_side=1)
        self.assertEqual(d.action, "block")      # orphan contributes no root
        self.assertEqual(d.roots_for, 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
