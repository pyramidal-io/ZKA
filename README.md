# ZKA — Zero-Knowledge Agents

Public snapshot of the **ZKA protocol specification**, its **Noir/BN254
reference implementation**, and a coherent **Aztec 6.0.0 reference integration**.

> Experimental two-way reference integration targeting Aztec 6.0.0. Compile and test coverage does not establish proving-system qualification. Public-network acceptance and production activation remain gated; compiler diagnostics and holder/runtime limitations remain unresolved. No independent audit has been completed. Not production certified.

ZKA is a protocol for privacy-preserving autonomous agents: credentials,
payments, transfers, and multi-party coordination whose correctness is
enforced by zero-knowledge proofs rather than by disclosure.

## What this repository contains

| Path | Contents |
|------|----------|
| [`docs/zka_specification.md`](docs/zka_specification.md) | Canonical protocol specification (0.9.2-draft) |
| [`CHANGELOG.md`](CHANGELOG.md) | Consumer-relevant history beginning with the first public release |
| [`noir/`](noir/) | Noir/BN254 reference circuit workspace (23 packages) |
| [`aztec/`](aztec/) | Aztec 6.0.0 L2 contracts, pure/TXE tests, and cross-environment checks |
| [`contracts/ethereum/ZKAAztecPortal.sol`](contracts/ethereum/ZKAAztecPortal.sol) | Focused L1 inbox/outbox portal |
| [`src/zka-bridge-aztec/`](src/zka-bridge-aztec/) | Fail-closed Rust settlement adapter and mocked node/L1 tests |
| [`certification/aztec.json`](certification/aztec.json) | Machine-validated public certification status and evidence |
| [`PUBLIC_ALLOWLIST`](PUBLIC_ALLOWLIST) | Exact-file publication policy for this snapshot |
| [`PUBLIC_SURFACE`](PUBLIC_SURFACE) | Manifest of public-only overlay files (this README, CI, docs) |
| [`docs/public-snapshot-provenance.md`](docs/public-snapshot-provenance.md) | How this snapshot is produced, verified, and released |

This repository is a **fresh-history snapshot**: its root commit has zero
parents and shares no history with the private development repository. See the
[provenance documentation](docs/public-snapshot-provenance.md) for the trust
boundary and reproduction details.

## Building the reference circuits

The toolchain is pinned in [`.noir-version`](.noir-version) (Nargo
`1.0.0-beta.25`). With the pinned `nargo` on your `PATH`:

```bash
cd noir
nargo check            # compile all circuits
nargo test --workspace # run all circuit tests (includes Poseidon2 KATs)
nargo fmt --check      # formatting
```

The same commands run in [public CI](.github/workflows/ci.yml) on every pull
request and push.

## Aztec verification

Public CI compiles and tests the Aztec workspace, runs its TXE transition and
cross-environment proof checks, tests the Rust adapter and focused L1 portal,
and validates every certification evidence pointer. See the
[Aztec certification report](docs/certification/aztec.md) for the exact support
tier and missing production evidence.

## Scope

The published Aztec slice targets the pinned V6 toolchain. A live public
withdrawal acceptance run, complete lifecycle qualification, independent audit,
and explicit production activation remain outstanding. The
[certification report](docs/certification/aztec.md) describes known limitations.
Unrelated APL implementation and operations, private
deployments/endpoints, generated artifacts, and private history remain outside
this default-deny snapshot.

## Contributing & security

- Contribution model and DCO requirements: [CONTRIBUTING.md](CONTRIBUTING.md)
- Vulnerability reporting: [SECURITY.md](SECURITY.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
