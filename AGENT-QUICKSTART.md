# Agent quickstart: bring your own mess

You are evaluating **Minority Prophet Gate**, an evidence-control plane for
consequential agent actions. Your job is to supply messy evidence, try to break
the decision logic, and return a privacy-safe feedback file to your operator.

## Safety boundary

`mp-gate evaluate` is simulation-only. It never calls a tool, API, deployment,
payment, filesystem mutation, or other protected runtime action. The output
always reports `runtime_effects: 0`.

The lab input field `mp_test_verdict` is deliberately tester-declared:

- `root`: pretend the verifier established an independent evidence root;
- `derived`: pretend it established a copy/derivation; include
  `attest.derived_from`;
- `invalid`: pretend verification failed.

This field is not a signature and is never suitable for production. It exists
so you can test aggregation, lineage, malformed input, and fail-closed behavior
without keys or vendor accounts.

## Run the included case

From the repository root:

```bash
python -m minority_prophet.byom_cli evaluate \
  --evidence examples/byom/messy-evidence.jsonl \
  --policy examples/byom/policy.json \
  --feedback byom-feedback.json
```

If installed as a package, use `mp-gate` instead of
`python -m minority_prophet.byom_cli`.

## Bring your own evidence

Evidence may be one JSON array or newline-delimited JSON objects. Each object
should resemble:

```json
{
  "claim_id": "unique-claim-id",
  "agent": "source-name",
  "assertion": "SAFE",
  "mp_test_verdict": "root",
  "attest": {
    "origin": "source-observation-id",
    "subject": "deployment:bring-your-own-mess"
  }
}
```

Use assertion `SAFE`/`1` for the configured proceed side and `UNSAFE`/`0` for
the opposing side. IDs must be unique. Derived claims should name a known parent.

Policy is JSON:

```json
{
  "decision_subject": "deployment:bring-your-own-mess",
  "proceed_side": 1,
  "min_flip_budget": 1.0,
  "unbound_root_weight": 0.0
}
```

Pipe generated evidence directly when useful:

```bash
your-generator | mp-gate evaluate \
  --evidence - --policy examples/byom/policy.json
```

## Adversarial cases to try

Try duplicates, long copy chains, cycles, conflicting claims from one root,
invalid assertions, missing fields, unknown parents, wrong subjects, invalid
test verdicts, huge numbers of copied voices, ties, and thin margins. A crash,
silent proceed on malformed/unsupported evidence, or decision change caused
only by extra copies is useful feedback.

Do not include credentials, private keys, tokens, cookies, personal data, or
proprietary raw evidence in a feedback report.

## Return results

The `--feedback` file contains the complete decision and SHA-256 fingerprints
of inputs, but intentionally omits raw evidence and policy. Add a short note to
`tester_notes` describing what you attempted. Send that JSON file plus the
package version/commit to the project owner. Share raw reproduction inputs only
when your operator explicitly approves them.

Public feedback may be filed at
`https://github.com/Silentpartnercoding/minority-prophet-gate/issues`. Attach
the privacy-safe feedback JSON or paste its contents, describe the expected
behavior, and state whether you can privately provide a minimal reproduction.

Exit code `0` means evaluation completed. Exit code `2` means the input or file
was rejected; stderr contains a JSON error and still reports zero runtime effects.
