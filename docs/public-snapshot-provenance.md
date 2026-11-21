# Public snapshot provenance

This repository is generated — not developed in place. This document explains
what is published, how it is produced, how it is validated, and what
guarantees the process does and does not make.

## Snapshot scope

The published surface is exactly:

- the exported private files named in [`PUBLIC_ALLOWLIST`](../PUBLIC_ALLOWLIST)
  — the canonical ZKA specification, Noir/BN254 reference circuits, and the
  reviewed Aztec 6.0.0 L2/L1/Rust reference-integration source; and
- the public-only overlay files named in [`PUBLIC_SURFACE`](../PUBLIC_SURFACE)
  — this documentation, the public CI pipeline, and its scan configuration.

`PUBLIC_ALLOWLIST` is **default-deny**: every line names one exact file, globs
and directory rules are forbidden, and anything not listed is excluded. The
specification may therefore reference private-side design documents that are
not published; those references are explicitly inventoried in
[`.github/doc-link-exceptions.txt`](../.github/doc-link-exceptions.txt).
Private deployment tooling/endpoints, unrelated APL implementation and
operations, generated artifacts, and private operational material remain out
of scope.

## Private-to-public trust boundary

Development happens in a private repository (`ZKA.dev`) that is the
full-history system of record. Publication crosses the boundary in one
direction only:

1. A reviewed, reusable exporter resolves `PUBLIC_ALLOWLIST` at one immutable
   private commit and constructs the snapshot in a **fresh Git object
   database** containing no private refs, objects, or alternates. Only the
   selected file bytes become public blobs.
2. The exporter builds the same commit twice in independent object databases
   and requires identical inventory, tree, and commit IDs (determinism
   check), then scans the snapshot with gitleaks and trufflehog and fails
   closed on any finding or scanner error before anything is published.
3. The public root commit has **zero parents** and no merge base with private
   history. Later snapshots extend the public branch as a linear chain of
   exporter-marked commits; they never replay private history.

Consequences:

- Public commit history carries no private commit messages, deleted files, or
  intermediate states — only reviewed snapshot trees.
- Development CI and public CI cover different trees. Publication evidence
  must bind each result to its exact source and exported tree. A successful
  development run does not establish package closure, passing snapshot tests,
  secret-scan results, independent audit or production qualification.

## Snapshot commit provenance

Every exporter-generated commit carries machine-readable trailers:

```text
Public-Snapshot-Schema: 1
Public-Snapshot-Mode: bootstrap | update
Public-Snapshot-Policy-SHA256: <digest of the canonical publication policy>
Public-Snapshot-Inventory-SHA256: <digest of the resolved file inventory>
Public-Snapshot-Exporter: <exporter name/version>
```

The commit author, committer, timestamp, message, and file ordering are
normalized, so the same policy applied to the same private revision always
yields the same public commit ID. The private source revision is intentionally
not embedded in the public commit; it is recorded in the private, redacted
export report retained as review evidence.

## Compatibility source identities

The [launch source lock](../protocol-family/launch-source-lock-v2.json)
records reviewed development commits and digests for selected compatibility
inputs. Its ZKA commit identifies those reviewed inputs; it need not equal the
later source revision selected for an export. It is neither the public
snapshot commit nor a claim that any family repository has been released.
The export report binds the actual selected source revision to the resulting
public tree and commit.

## Assurance limitations

The [certification report](certification/aztec.md#known-limitations) records
unresolved Aztec compiler diagnostics and holder/runtime limitations, plus
the standalone Noir inactive-deposit-tail and withdrawal-recipient-range
gaps. Successful compilation or tests do not resolve these limitations or
establish production qualification. The unpublished APLBridge's input
construction protects its own integration against those two Noir input
shapes; consumers of the exported circuits must supply their own validated
integration constraints.

## Contributor CI

Every pull request and push runs the self-contained
[public CI](../.github/workflows/ci.yml):

| Job | Validates |
|-----|-----------|
| Policy inventory & workflow pins | Tracked tree equals `PUBLIC_ALLOWLIST` + `PUBLIC_SURFACE` exactly; all files are regular; every workflow action is pinned to a full commit SHA; local package and source-module closure holds |
| Documentation links | Relative links resolve, or are declared private-side references |
| Noir circuits | `nargo fmt --check`, `nargo check`, `nargo test --workspace` under the pinned toolchain in [`.noir-version`](../.noir-version), plus the Poseidon2 dependency pin check; the committed `Prover.toml` files are deterministic test/KAT fixtures exercised by the circuit tests |
| Aztec compile and pure tests | Aztec 6.0.0 workspace compilation and pure contract/library tests |
| TXE transition tests | In-process private/public Aztec transition coverage |
| Real cross-environment proof | Native/EVM UltraHonk proof and public-input equivalence |
| Rust Aztec settlement adapter | Registry, proven/replay gates, and recorded node/L1 wire-shape tests |
| Local portal settlement tests | Focused L1 inbox/outbox portal tests under pinned Foundry dependencies |
| Public certification evidence | Every exported certification evidence pointer resolves and the experimental-tier gate holds |
| Secret scan | gitleaks and trufflehog, installed from checksum-verified pinned binaries |

Workflow properties, by design:

- Triggers are `pull_request`, `push`, and `workflow_dispatch` only — never
  `pull_request_target`, so untrusted pull-request content never runs with
  elevated permissions.
- The workflow-level token is **read-only** (`permissions: contents: read`).
  No job uses repository secrets other than the ephemeral `GITHUB_TOKEN`.
- Fork pull requests receive a read-only token and no secrets, and first-time
  contributors require maintainer approval before workflows run.
- The only job with `contents: write` is the release job below.

## Release provenance

Releases are created exclusively by the tag-gated release job in the same
workflow. It runs only on `push` of a `v*` tag, depends on **all** validation
jobs succeeding for that exact commit, verifies the tag with
`gh release create --verify-tag`, and holds the only write-capable token in
the pipeline. No other job can publish anything.

Before release creation, the job compares the tag to the canonical
`**Version:**` header in `docs/zka_specification.md` and requires a matching
dated heading in `CHANGELOG.md`. A missing or mismatched entry fails closed.
Ordinary branch and pull-request changes do not require changelog entries.

## Scanner false-positive policy

The secret scan must be **clean** — CI fails on any finding. Inline
`gitleaks:allow` suppressions are disabled by the CI invocation. If a finding
is determined to be a false positive (for example, a hex-encoded BN254 field
element in a test fixture matching a generic rule), the only accepted remedy
is a reviewed change to [`.gitleaks.toml`](../.gitleaks.toml) with a comment
recording the triage rationale. There are currently **zero** such exceptions.

## Reproduction and verification

Anyone can verify, from this repository alone:

- **Fresh history**: `git rev-list --max-parents=0 HEAD` returns a single
  root; `git cat-file commit <root>` shows zero parent lines and the
  provenance trailers above.
- **Inventory**: `git ls-files` equals the union of `PUBLIC_ALLOWLIST` and
  `PUBLIC_SURFACE` (enforced by CI; checkable locally with
  `.github/scripts/check-public-surface.sh`).
- **Circuit behavior**: the Noir workspace builds and tests with the version
  pinned in `.noir-version`; the Aztec workspace builds and tests with Aztec
  V6.0.0 installed by `.github/scripts/install-aztec-v6.sh`. Poseidon2
  known-answer tests detect changes to the pinned hash constants. Compiler
  diagnostics and the limitations in the [certification report](certification/aztec.md)
  remain separate qualification gates.
- **Certification honesty**: `python3 scripts/validate-certification.py --public-snapshot`
  resolves the public Aztec manifest against the exact exported tree and fails
  on missing or hollow evidence.

Full regeneration of the snapshot additionally requires access to the private
repository and the exporter, and reproduces byte-identical tree and commit IDs
from the same private revision and policy. The redacted export report
(inventory digest, tree/commit IDs, scanner status, determinism status) is
retained privately as review evidence and can be disclosed to auditors under
the appropriate agreement.
