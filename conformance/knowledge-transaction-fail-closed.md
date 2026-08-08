# Knowledge-transaction conformance — evidence gate

Extracted verbatim from `research/knowledge-ledger/CONFORMANCE-PROFILE-v1.md`
in the minority-prophet research repository, commit `754354d03401`. The rules
below are reproduced without modification; this file adds only this header.

These are **specification-local** rules: they are not theorems from
*Minority Prophet* and the paper makes no claim about them. They are the
engineering properties an implementation needs in order to produce records
that another implementation can verify.

Each rule states its evidence, including where that evidence is thin. Nothing
here is asserted without a count behind it.

Rules in this extract: P4

## P4 — Fail-closed parsing (KL-000 invariant I9)

**Normative statement.** Malformed input raises and never returns a receipt:
missing ledgers, wrong types, out-of-enum statuses, truncated documents,
empty declared scope (R2), duplicate location identifiers (I11) all refuse.
A missing evidence ledger is never read as an empty one.

**Why specification-local.** Input robustness; no paper claim concerns
malformed encodings.

**Evidence + honest coverage note.** Both implementations refuse the
adversarial suites' malformed inputs (reference A10 family; independent
A02–A07). **I9 is exercised by zero non-adversarial worlds in every run to
date** — both generators emit only well-formed documents — so its entire
evidence is adversarial, a fact carried on the open ledger since
IND-20260807-1 and never allowed to disappear into a green suite.
