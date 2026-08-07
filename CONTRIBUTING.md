# Contributing

Counterexamples, adversarial tests, runtime integrations, and narrowly scoped
corrections are welcome. Open an issue before changing aggregation or execution
policy so the invariant, threat model, and compatibility impact can be agreed
first.

Every contribution must keep evidence assessment separate from authority,
fail closed on missing verification, preserve abstention, include tests, and
avoid production credentials or private provider contracts.

Run `python -m pytest -q` before opening a pull request. Report sensitive
findings through GitHub's private security-advisory interface.
