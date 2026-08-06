"""Check value-local T1/T2 for finite assertion alphabets.

Worlds are enumerated EXHAUSTIVELY (all value-consistent worlds with at most
five claims over a three-letter alphabet), and duplication is checked
exhaustively for every world.

Rewiring is NOT exhaustive.  When a world admits more than `SAMPLE_THRESHOLD`
root-preserving rewirings, 200 of them are drawn instead, from a deterministic
per-world seed.  The run therefore mixes two evidence classes and reports the
split so neither can be mistaken for the other:

    worlds / duplications          finite exhaustive check
    rewirings, sampled worlds      deterministic randomized experiment

Corrected 2026-08-05.  MEASURED RESULT: at the shipped parameters (n <= 5,
three-letter alphabet) the sampling branch NEVER FIRES -- 2,955 of 2,955 worlds
are enumerated exhaustively and 0 are sampled.  The published "exhaustive"
result was therefore accurate in fact.  The hazard was latent, not active: the
fallback would begin firing silently on any increase to `n` or the alphabet,
turning an exhaustive check into a partly randomized one with no change to the
output line.  The run now reports the split explicitly so that can never happen
unnoticed.  See the parent repository's formal/THEOREM-LEDGER.json entry F3.
"""
from __future__ import annotations

import itertools
import random
import sys

from .aggregator import Claim, aggregate

SAMPLE_THRESHOLD = 200
SAMPLE_SIZE = 200


def _verdict(n, parent, values):
    claims = [Claim(i, values[i], parent[i]) for i in range(n)]
    return aggregate(claims).decision


def main() -> None:
    alphabet = ("a", "b", "c")
    worlds = rewirings = violations = 0
    sampled_worlds = enumerated_worlds = 0
    sampled_rewirings = 0
    for n in range(1, 6):
        for values in itertools.product(alphabet, repeat=n):
            options = [[None] + [j for j in range(i) if values[j] == values[i]]
                       for i in range(n)]
            for parent in itertools.product(*options):
                worlds += 1
                baseline = _verdict(n, parent, values)
                for claim in range(n):
                    if _verdict(n + 1, list(parent) + [claim],
                                list(values) + [values[claim]]) != baseline:
                        violations += 1
                rewire_options = [[parent[i]] if parent[i] is None else
                                  [j for j in range(i) if values[j] == values[i]]
                                  for i in range(n)]
                combinations = 1
                for option in rewire_options:
                    combinations *= len(option)
                is_sampled = combinations > SAMPLE_THRESHOLD
                if is_sampled:
                    sampled_worlds += 1
                    candidates = [tuple(random.Random(worlds).choice(option)
                                        for option in rewire_options)
                                  for _ in range(SAMPLE_SIZE)]
                else:
                    enumerated_worlds += 1
                    candidates = itertools.product(*rewire_options)
                for rewired_parent in candidates:
                    rewirings += 1
                    if is_sampled:
                        sampled_rewirings += 1
                    if _verdict(n, list(rewired_parent), values) != baseline:
                        violations += 1
    print(f"[multivalue] worlds={worlds} (exhaustive) "
          f"rewirings={rewirings} violations={violations}")
    print(f"[multivalue] rewiring coverage: {enumerated_worlds} world(s) "
          f"enumerated exhaustively, {sampled_worlds} world(s) sampled at "
          f"{SAMPLE_SIZE} draws each ({sampled_rewirings} sampled rewirings). "
          f"Sampled rewirings are a randomized experiment, not a proof.")
    raise SystemExit(0 if violations == 0 else 1)


if __name__ == "__main__":
    main()
