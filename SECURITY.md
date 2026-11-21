# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** using
[GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Report a vulnerability" under the Security tab). Do not
open a public issue for security reports.

Reports are triaged against the canonical private development repository,
where fixes are reviewed before a subsequent snapshot export. Assurance
evidence must identify the exact source, exported tree, toolchain and checks;
a green development check alone does not validate the exported snapshot.

## Scope

In scope:

- Soundness or completeness defects in the Noir reference circuits under
  `noir/` (e.g. under-constrained witnesses, nullifier or note-commitment
  domain errors, non-canonical decompositions).
- Specification-level protocol vulnerabilities in
  `docs/zka_specification.md`.
- Supply-chain issues in the public CI pipeline defined in this repository.

Out of scope:

- Private-side infrastructure and unpublished implementation environments.
- Findings that require capabilities outside the published threat model of the
  specification.

## Known limitations

This experimental snapshot has no independent audit or production
certification. Unresolved Aztec compiler diagnostics remain a qualification
gate even when compilation exits zero or tests pass. The
[certification report](docs/certification/aztec.md#known-limitations) also
records the standalone Noir circuit gaps: `zka_root_update` does not require
inactive deposit-array entries to be zero, and `zka_withdrawal` does not
require its external recipient to fit 160 bits. A valid proof does not
establish either missing constraint.

The unpublished APLBridge constructs zero-padded deposit inputs and encodes
withdrawal recipients from an address type. Those integration protections do
not become circuit guarantees for consumers of this snapshot. Review the
report before reusing these circuits in another verifier or bridge.

## Disclosure

We ask for coordinated disclosure: give us a reasonable window to assess and
fix before publishing details. Credit is given in release notes unless you
prefer otherwise.
