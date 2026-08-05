"""Exhaustively check value-local T1/T2 for finite assertion alphabets.

The verifier enumerates value-consistent worlds with at most five claims and
a three-letter alphabet.  It checks root-preserving rewiring and claim
duplication; any violation exits nonzero.
"""
from __future__ import annotations

import itertools
import random
import sys

from .aggregator import Claim, aggregate


def _verdict(n, parent, values):
    claims = [Claim(i, values[i], parent[i]) for i in range(n)]
    return aggregate(claims).decision


def main() -> None:
    alphabet = ("a", "b", "c")
    worlds = rewirings = violations = 0
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
                candidates = (itertools.product(*rewire_options)
                              if combinations <= 200 else
                              [tuple(random.Random(worlds).choice(option)
                                     for option in rewire_options)
                               for _ in range(200)])
                for rewired_parent in candidates:
                    rewirings += 1
                    if _verdict(n, list(rewired_parent), values) != baseline:
                        violations += 1
    print(f"[multivalue exhaustive] worlds={worlds} rewirings={rewirings} "
          f"violations={violations}")
    raise SystemExit(0 if violations == 0 else 1)


if __name__ == "__main__":
    main()
