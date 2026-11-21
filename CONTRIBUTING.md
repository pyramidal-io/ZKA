# Contributing to ZKA

Thank you for your interest in ZKA. This repository is a **published snapshot**
of the ZKA specification and Noir/BN254 reference implementation; canonical
development happens in a private repository and lands here through a reviewed,
allowlisted export (see
[docs/public-snapshot-provenance.md](docs/public-snapshot-provenance.md)).

## What contributions look like here

- **Issues** are the best way to report specification ambiguities, circuit
  soundness concerns, or documentation problems. For suspected
  vulnerabilities, use [SECURITY.md](SECURITY.md) instead of a public issue.
- **Pull requests** are welcome for focused fixes to the published surface.
  Accepted changes are ported into the private development repository and
  appear in a subsequent snapshot with attribution; a PR here may therefore be
  closed as "merged upstream" rather than merged directly.

## Developer Certificate of Origin

All commits must be signed off (`git commit -s`), certifying the
[Developer Certificate of Origin](https://developercertificate.org/). By
signing off you agree that your contribution may be redistributed under the
repository license (Apache-2.0).

## Contributor CI

Every pull request runs the self-contained [public CI](.github/workflows/ci.yml):

1. **Policy inventory** — the tracked tree must exactly equal
   `PUBLIC_ALLOWLIST` + `PUBLIC_SURFACE`, all workflow actions must be
   SHA-pinned, and workspace members, local dependencies and source modules
   must be present.
2. **Documentation links** — relative links must resolve (or be explicitly
   declared as private-side references).
3. **Noir circuits** — `nargo fmt --check`, `nargo check`, and
   `nargo test --workspace` with the pinned toolchain, plus a supply-chain pin
   check on the Poseidon2 dependency.
4. **Aztec compile and pure tests** — the pinned V6 workspace.
5. **TXE transition tests** — transfer, credential and ownerless Pay execution.
6. **Real cross-environment proof** — shared canonical note fields.
7. **Rust Aztec settlement adapter** — registry and recorded node/L1 tests.
8. **Local portal settlement tests** — the focused L1 portal.
9. **Public certification evidence** — exported evidence pointers and tier.
10. **Secret scan** — gitleaks and trufflehog with pinned binaries.

Pull-request workflows run with a read-only token and no repository secrets.
First-time contributors' workflow runs require maintainer approval before any
compute executes. All ten validation jobs must pass before a release. Their results do not
replace the qualification and activation gates described in the
[certification report](docs/certification/aztec.md).

## Changelog and release policy

Every public release must update [CHANGELOG.md](CHANGELOG.md) with the
consumer-relevant changes since the previous public release. Use the **Added**,
**Changed**, **Deprecated**, **Removed**, **Fixed**, **Security**, and
**Compatibility** headings as applicable. Ordinary internal commits,
refactoring, formatting, and other non-user-facing work do not require entries;
the changelog is not a log of every internal commit.

Add unreleased entries when a public consumer must change behavior, when a
public guarantee or limitation changes, or when a security or compatibility
boundary changes. A breaking normative or cryptographic change also requires
the corresponding specification, circuit/profile identity, artifact identity,
or wire version change. A changelog entry alone never makes incompatible bytes
compatible.

Coordinate embargoed Security entries through [SECURITY.md](SECURITY.md).
Maintain the embargo until a safe disclosure date, but do not make a misleading
production, certification, or security claim while public detail is withheld.
The tagged release gate requires the tag, specification version, and public
changelog release heading to match exactly.
