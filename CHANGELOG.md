# Changelog

This changelog records consumer-relevant changes to public ZKA releases. Its
initial public baseline is the first fresh-history release and does not reconstruct
private development releases or commit history. Earlier specification draft
numbers do not establish earlier public releases.

The format follows Keep a Changelog categories. A release uses only the
categories that apply: Added, Changed, Deprecated, Removed, Fixed, Security,
and Compatibility.

## [Unreleased]

### Changed

- Safeguard 5 no longer cites the CLARITY Act as a dependency. Its MUST
  requirements are unchanged.
- The specification corrects stale and contradictory statements: measured
  proof sizes and padded circuit sizes replace unsupported performance
  figures, verifier generation names `bb write_solidity_verifier`, the
  transfer and withdrawal interfaces match their circuits, and the circuit
  identifiers, project tree, bridge-security, conformance and Safeguard-scope
  text agree with the code and with §1.6 and §7.1. The website summary pages
  carry the same corrections. Circuits, ABIs and the family epoch are
  unchanged.
- §3.1 now defines a generic transfer context: a non-zero public input that
  the deployment profile derives and the verifier supplies from its own
  authenticated state. `zka_transfer` is rebuilt to that rule: it no longer
  recomputes the legacy Namada context, it range-checks the input and output
  values to the u64 balance domain, and its verification key changes. Its five
  public inputs and the SDK transfer path are unchanged; the SDK's
  `TransferWitness` carries a plain `context` field.
- `docs/zka_reputation.md` now cites AFP v0.3.14-draft and no longer refers
  to an AFP portable negative-history record, which AFP removed. The circuit,
  public inputs, known-answer vectors and family epoch are unchanged.

### Removed

- The Namada and Penumbra bridge profiles (former §7.2 and §7.3), their
  settlement types and circuit identifiers, and the `ZKA-MultiChain`
  conformance level are retired from the specification (ADR-0016). Section
  numbers 7.2 and 7.3 are not reused. Circuits, schemas and the family epoch
  are unchanged in this step.
- The Penumbra bridge code surface is removed (ADR-0016): the
  `zka-bridge-penumbra` crate, the `bridge_penumbra_import` and
  `bridge_penumbra_export` circuits, their verifiers, public-input schemas,
  proof fixtures, registry entries, settlement-ops wiring and runbook.
- The Namada bridge code surface is removed (ADR-0016): the
  `zka-bridge-namada` crate, the `bridge_namada_import`,
  `bridge_namada_import_v2`, `bridge_namada_import_confidential_v1` and
  `bridge_namada_export` circuits, their verifiers, public-input schemas,
  proof fixtures, registry entries, SDK and settlement-ops wiring and runbook.

### Compatibility

- Family epoch `zka:protocol-family:2026-11-19.1` reconciles the ZKC Poseidon2 inventory for successor
  circuits and Python helpers and checks the deployed code-space separators.
- Family epoch `zka:protocol-family:2026-11-18.1` retires the Namada and
  Penumbra bridges from the family: it drops the Namada import public-input
  binding and the six bridge domains from the operational Poseidon2
  inventory. It also corrects ZKM's `zkm/holder_key/v1` and
  `zkm/mandate_nullifier_key/v1` transcripts to take the holder's KDC spending
  key, lists ZKM's three `zkm/zkc-*` composition tags and ZKC's
  `zkc/apr/extensions:v1` tag as pending AFP-KDC registration, and classifies
  the ZKC and ZKM Poseidon2 sources added since the previous epoch. Protocol
  versions, compatibility tuples and golden-vector values are unchanged. The
  snapshot lock records observed epoch merge
  `cd7ecd28f13fef1f2b3bd397c1c4418e6db282e3` without a pending
  republish marker.
- Family epoch `zka:protocol-family:2026-10-28.1` selects AFP
  `0.3.14-draft`, pinning its additive native credential-envelope schema and
  interface-set identifier. The five existing ZKA compatibility tuples and
  all proof and golden-vector values retain their meanings.
- The `2026-10-28.1` snapshot lock recorded observed epoch merge `4867727db93380b45dd36d3512706a5c0224b228`
  without a pending republish marker. ZKC, ZKM, and AFP synchronized to the
  epoch. The launch-source lock records the published AFP source at
  `4642e521107eec84e3ba1e0f1e59ecf8f4226a4c` and its exact file digests.

### Changed

- The specification now names the Aztec-native production prerequisite as the
  official Aztec resolution of the Alpha V5 proving-system vulnerability plus
  the other ADR-0010 gates. This is a wording change with no normative or gate
  change.

## [0.9.2-draft] - 2026-10-28

### Added

- Initial public ZKA protocol specification and Noir/BN254 reference circuit
  baseline, prepared for a fresh-history snapshot.
- Aztec 6.0.0 transfer, credential, ownerless Pay and test-proxy packages,
  focused L1 portal, Rust settlement adapter and registry.
- Self-contained public CI for inventory and package closure, documentation
  links, circuit and contract tests, certification pointers, and secret scans.
- Bounded bilateral `zka_reputation` reference circuit, public-input schema,
  and AFP-KDC/Poseidon2 transcript contract.
- Purpose-bound AFP v2 presentation context selection using RFC 8785 JCS,
  SHA-256 reduced modulo the BN254 scalar field, and a nonzero canonical field.
- AFP result-side credential-subject AID contract and structured predicate
  records. Generic ZKC KYC or jurisdiction evidence without the required
  subject binding is rejected.

### Compatibility

- `zka_balance` uses a six-input public ABI with verifier-derived replay
  context and canonical saturating u64 comparison intervals. Four-input
  balance proofs are incompatible.
- The `zka:bundle:v1` envelope shape is unchanged by context validation;
  consumers must select the exact compatible family, profile and proof
  identities in the specification and launch source lock.
- The launch source lock records development source identities for AFP
  0.3.14-draft and the compatible family tuple. It does not establish another
  repository's public release or identify this export's public commit.
- Aztec-native values use the profile-selected `u128` bound. Cross-target
  equality covers canonical note commitments, asset projections and explicitly
  shared receipt fields; nullifiers, witnesses and proofs remain target-specific.
- Ethereum ingress/egress is supported by the design without a mandatory Base
  hop; any optional hop remains separately quoted and qualified. Target
  selection does not authorize deployment.

### Security

- This experimental draft has no independent audit and is not production-certified.
  Public-network acceptance and explicit production activation remain gated.
- Aztec compiler diagnostics, PXE randomness/recovery evidence, the bounded
  balance view, and sixteen-note spend-capacity qualification remain unresolved.
  See the certification report for the exact limitations and standalone circuit
  constraints consumers must not assume.
- `zka_reputation` remains a reference prototype. Its output must not authorize
  limit changes without the required signed history-head attachment and
  authenticated atom-to-leaf adapter.
- ZKA/Coord v2 remains unaudited and is not production-supported until its
  independent-review gate passes.
