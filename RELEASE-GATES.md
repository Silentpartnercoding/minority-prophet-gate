# v0.2.0 release gates

The following are release blockers, not aspirational design notes.

1. **Configuration-invariant sweep:** the Gate must prove in CI that policy
   options cannot convert invalid, mismatched, or unbound evidence into bound
   root strength. In particular, `flip_budget` and the T5 floor are calculated
   from matching bound roots only.
2. **No-TrustAll end-to-end path:** a real verifier bridge must consume DSSE
   Border predicates and approved Witness attestation collections, conjunctively
   enforce issuer manifest plus stamp, and pass a mixed-source end-to-end test
   without `TrustAllVerifier`.
3. **Known infrastructure gaps:** revocation-aware verification, a clock
   authority option for cross-organization freshness, and continuous spool
   chain-break monitoring require explicit designs before a production claim.

The mathematical core is distinct from these integration gates. A passing core
test suite does not establish that a deployment has authentic roots.
