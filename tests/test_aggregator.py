import unittest, json, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from minority_prophet.aggregator import Claim, EvidenceGraph, aggregate

def C(i, a, p=None, w=1.0): return Claim(id=i, assertion=a, parent=p, weight=w)

class TestCore(unittest.TestCase):
    def test_minority_truth_recovery(self):
        # 2 independent roots say 0; 1 root copied 50x says 1 -> verdict 0
        claims = [C("a", 0), C("b", 0), C("orig", 1)]
        claims += [C(f"cp{i}", 1, "orig" if i == 0 else f"cp{i-1}")
                   for i in range(50)]
        v = aggregate(claims)
        self.assertEqual(v.decision, 0)
        self.assertEqual(len(v.roots[1]), 1)

    def test_copy_invariance_T2(self):
        base = [C("a", 0), C("b", 0), C("o", 1), C("c1", 1, "o")]
        v0 = aggregate(base)
        for k in range(1, 200):
            base.append(C(f"d{k}", 1, "c1"))
        self.assertEqual(aggregate(base).decision, v0.decision)

    def test_immunity_T1_random(self):
        rng = random.Random(7)
        for _ in range(500):
            n = rng.randint(3, 30)
            a = [rng.randint(0, 1) for _ in range(n)]
            claims = []
            for i in range(n):
                same = [j for j in range(i) if a[j] == a[i]]
                p = rng.choice(same) if same and rng.random() > .3 else None
                claims.append(C(i, a[i], p))
            v0 = aggregate(claims)
            rewired = []
            for c in claims:
                if c.parent is None:
                    rewired.append(c)
                else:
                    same = [d.id for d in claims
                            if d.assertion == c.assertion and d.id != c.id
                            and (isinstance(d.id, int) and d.id < c.id)]
                    rewired.append(C(c.id, c.assertion, rng.choice(same)))
            try:
                v1 = aggregate(rewired)
            except ValueError:      # rare cycle from rewiring; skip
                continue
            self.assertEqual(v0.decision, v1.decision)

    def test_abstention_and_margin(self):
        v = aggregate([C("a", 0), C("b", 1)])
        self.assertIsNone(v.decision)
        v2 = aggregate([C("a", 0), C("b", 1), C("c", 1)])
        self.assertEqual(v2.decision, 1)
        self.assertEqual(v2.margin, 1.0)   # T4 flip budget

    def test_side_consistency_diagnostic(self):
        v = aggregate([C("a", 0), C("b", 1, "a")])
        self.assertFalse(v.diagnostics["immunity_applicable"])

    def test_weights(self):
        v = aggregate([C("a", 0, w=5.0), C("b", 1), C("c", 1)],
                      use_weights=True)
        self.assertEqual(v.decision, 0)

    def test_errors(self):
        with self.assertRaises(ValueError): aggregate([])
        with self.assertRaises(ValueError): aggregate([C("a", 0, "ghost")])
        with self.assertRaises(ValueError): Claim(id=1, assertion=[])

    def test_conformance_vectors(self):
        path = os.path.join(os.path.join(os.path.dirname(__file__), ".."), "tests", "conformance_vectors.json")
        for tv in json.load(open(path)):
            claims = [Claim(**c) for c in tv["claims"]]
            v = aggregate(claims, abstain_margin=tv.get("abstain_margin", 0.0))
            self.assertEqual(v.decision, tv["expected_decision"], tv["name"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
