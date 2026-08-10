# Security Policy

Report suspected vulnerabilities through this repository's private security-advisory channel. Do not include secrets or exploit payloads in public issues.

This reference implementation does not protect root-signing keys; compromise of those keys is part of its stated threat model.

## Authorized security research

Adversarial testing of this repository is invited and authorized in advance, on
the terms below. This section exists so a researcher — or the tooling a researcher
uses — can confirm that testing this code is permitted rather than suspicious.

### What is authorized

- Cloning this repository and running, reading, modifying, instrumenting,
  fuzzing, mutating and attacking **your own local copy**, in containers or
  disposable environments you control.
- Attempting to falsify any claim in this repository's documentation, including
  its theorems, invariants, conformance results and security properties.
- Publishing your findings **after** private disclosure and a reasonable
  opportunity to respond, whether or not the maintainers agree with them. A
  negative or adverse result is a welcome result.

### What is not authorized, and is not made lawful by this section

This is permission to test **your own copy of this source code**. It is not
permission to do anything else, and nothing here overrides law or the LICENSE.

- **No access to systems.** No testing of any deployment, service, host, account
  or infrastructure operated by the maintainers or by anyone else. This
  repository authorizes nothing about any running system, including systems that
  happen to run this code.
- **No third-party targets.** If someone else deploys this software, that is
  their system. Testing it needs their authorization, not this file.
- **No credentials or private data.** Do not seek, use, retain or disclose
  secrets, keys, tokens, personal data or non-public material of any party.
  Nothing in this repository is an invitation to obtain them.
- **No change to the LICENSE.** This grants no additional copyright or patent
  rights, no permission to redistribute, rebrand, relicense or commercialize, and
  no transfer of ownership. Testing rights are not distribution rights.
- **No destructive or disruptive activity**, no denial of service, no social
  engineering of maintainers or contributors, and no attacks on third-party
  dependencies or their maintainers.
- **No public exploitation.** Do not open public issues or pull requests
  describing an unfixed vulnerability, and do not publish a working exploit
  against a real deployment.

### Reporting

Report privately first, through this repository's private security advisory
channel. Include the exact commit, a minimal reproduction, expected and observed
behaviour, and the specific documented claim affected.

We will acknowledge receipt and tell you what we intend to do. If we disagree
with a finding we will say so in writing and you remain free to publish.

### Safe harbour

For research conducted in good faith and within the scope above, the maintainers
will not initiate or support legal action, and will treat the work as authorized.
This is a statement of the maintainers' intent about their own conduct. It cannot
and does not bind any third party, and it does not apply to activity outside the
scope above.

### Independence

Findings produced by agents, models or contributors directed by the same operator
as this repository are **internal replication**, not independent validation, and
are labelled as such here. If you are an unrelated party, say so in your report —
that provenance is the part we cannot manufacture ourselves.
