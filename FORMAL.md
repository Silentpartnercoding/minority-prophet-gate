# Formal status

`minority_prophet/__init__.py` cites this file for the proofs. It previously cited
a file that did not exist, so a reader checking this package's central claim
followed a pointer to nothing.

**This repository is not the authority for the proofs, and this file deliberately
does not restate the theorems.** Restating them here would create a second copy
that can drift from the proved statements — and a claim drifting from its
hypotheses is a defect this programme has already found twice, once in the
research repository's own T5 and once in a document written to prevent it.

## Where the proofs live

| | |
|---|---|
| Theorem ledger | `formal/THEOREM-LEDGER.json` in the research repository |
| Lean development | `formal/lean/MinorityProphetCore/` |
| Immunity (T1) | `Immunity.lean`, theorem `MinorityProphet.immunity` |
| Copy invariance (T2) | `Copy.lean`, theorem `MinorityProphet.copy_invariance` |
| Margin bounds (T4, T5) | `Margin.lean` |
| Counterexamples | `formal/COUNTEREXAMPLES.md`, `Counterexamples.lean` |

https://github.com/Silentpartnercoding/minority-prophet

The ledger is the single normative statement of each theorem. It records, per
theorem, the exact hypotheses, `proof_status`, the Lean theorem name, the finite
verification coverage, and — importantly — whether the proved statement was
**narrowed** or **generalized** relative to the original paper. Two of six are
flagged narrowed and two generalized. Read the hypotheses there before relying on
any summary, including this package's README.

## What that means for this package

The theorems constrain the aggregation model. They do not certify this
implementation of it. `assess()` computes an `immunity_applicable` diagnostic and
`decide()` escalates rather than proceeding when T1's side-consistency
precondition fails, because the absence of a guarantee is not permission.

Root-set preservation is the other hypothesis of T1, and it is **not checkable
from a single input** — it is a property of the relationship between two worlds.
No diagnostic in this package can enforce it, and the README must therefore state
it rather than imply it away.

## Known gap

The research programme has established that the *immunity ablation* used to test
implementations measures invariance under rewiring, not the correctness of the
lineage-resolution function: two grossly broken implementations pass it, because
uniformly wrong lineage resolution preserves invariance trivially. See
`FINDING-BL058B.md` in the research repository. That does not affect T1, which is
proved, but it does mean "the ablation passes" is weaker evidence about an
implementation than it appears.
