# ZKA Aztec Integration

Wraps ZKA's privacy protocol circuits as Aztec.nr smart contracts, enabling deployment on the Aztec network with native private state management.

## Architecture

```
aztec/
├── zka_aztec_lib/          # Key adapter + note types (ZKANote, CredNote)
├── zka_transfer_aztec/     # Authenticated deposits, private transfers, withdrawals
├── zka_pay_aztec/          # Ownerless native Pay, encrypted receipts, immutable exit
├── zka_credential_aztec/   # Credential binding + selective disclosure
├── zka_cross_env_tests/    # Cross-environment credential verification tests
├── zka_authwit_test_proxy/ # TXE-only nested caller for delegated transfer tests
└── scripts/                # Local network and TXE testing tools
```

### Key Mapping: Aztec → ZKA

| Aztec Key | ZKA Key | Derivation |
|-----------|---------|------------|
| `nhk_app` (app-siloed nullifier hiding key) | `master_seed` | Direct AFP-KDC seed mapping |
| `H(DOMAIN_SPENDING, nhk_app)` | `spending_key` | `zka_lib::derive_spending_key_from_master_seed` |
| `H(DOMAIN_VIEWING, spending_key)` | `viewing_key` | `zka_lib::derive_viewing_key` |
| `H(DOMAIN_ADDRESS, vk)` | `address` | `zka_lib::derive_address` |
| `H(DOMAIN_CREDENTIAL, nhk_app)` | `credential_binding_key` | `zka_lib::derive_credential_binding_key` |

### Deployment-Scoped Keys

Aztec siloes `nhk_app` by contract address, so every key in the table above belongs to one contract deployment. A new deployment gives the same account a new spending key, ZKA address, credential binding key and credential commitment. Notes, credentials and compliance registrations do not carry over. `real_account_secret_reaches_zka_keys_through_nhk_app` in `zka_credential_aztec` pins this from a real Schnorr account secret.

**Key independence.** Aztec nullifier keys cannot be rotated, and every ZKA key derives from `nhk_m`. Generate an account's privacy secret independently of its signing key. Do not use the V6 wallet default, `deriveSecretKeyFromSigningKey`: with that default, a signing-key compromise reaches every ZKA key, and no rotation recovers them.

**Credential reissue.** A credential does not survive a new `ZKACredential` deployment, because the issuance transcript binds the chain, version, contract address and holder commitment. To move a holder to a new deployment:

1. The holder exits value from the old transfer deployment. Notes stay on the deployment that created them.
2. The holder's wallet derives the credential commitment for the new contract and sends it to the issuer.
3. The issuer checks the holder again, signs `issuance_digest(...)` for the new contract, and returns `credential_data`, the attributes and the signature. The issuer does not publish a mapping from the old commitment to the new one.
4. The holder calls `bind_credential` on the new contract, then `verify_compliance`. Registration takes effect after 24 h, so start it before the holder needs to receive compliance-gated transfers.
5. If the old deployment stays live, its admin calls `revoke(cc)` for the old commitment when the credential must stop working there. This publishes the old `cc`.

Use the same steps with a new account if the privacy secret is compromised, because the existing account cannot rotate it.

### What Aztec Handles (vs Standalone Circuits)

| Concern | Standalone Circuit | Aztec Contract |
|---------|-------------------|----------------|
| Merkle membership | Manual witness + root check | PXE provides automatically |
| Nullifier dedup | Public input verified externally | Kernel manages set |
| Context binding | Epoch/chain/app as public input | Aztec tx context |
| Proof generation | External prover | PXE compiles + proves |
| Encrypted communication | N/A | Native encrypted logs |

The active Aztec workspace has no built-in ZKA/Coord contract. Coord v2 is consumed through the canonical Rust SDK verifier and may delegate to Aztec only through an independently registered, manifest-bound profile plus a target-specific verifier implementation. Kernel composition alone does not establish the Coord v2 claim, and off-chain verification material is never used as an Aztec fallback.

`zka_authwit_test_proxy` is a test fixture exercised by the transfer contract's TXE suite. The coverage inventory explicitly checks that suite's proxy dependency, deployment, forwarding call, and delegated-transfer test; it does not exempt the fixture from test coverage.

## Quick Start

```bash
# 1. Compile contracts (Aztec v6 toolchain)
cd aztec && aztec-nargo check --workspace

# 2. Run pure unit tests (value-conservation, note-hash, cross-env consistency)
aztec-nargo test --package zka_aztec_lib
aztec-nargo test --package zka_cross_env_tests
aztec-nargo test --package zka_transfer_aztec conservation
#   NOTE: bare `nargo test` runs ONLY the pure tests. The TXE transition tests
#   (zka_transfer_aztec `test::` module) deploy the contracts and need the
#   in-process TXE oracle — run them with step 3 below (NO Docker required).

# 3. Run the TXE transition tests (in-process oracle, no Docker)
./scripts/txe-test.sh                # transfer, credential, and ownerless Pay TXE tests
./scripts/txe-test.sh test           # tests matching `test` in all three contract packages
```

### Running TXE tests: read this first

The TXE transition tests deploy `ZKATransfer` (which has public functions) and therefore need its **transpiled** artifact (public Brillig bytecode lowered to AVM, with `transpiled: true` stamped on the JSON). The stock `aztec test` command has two traps that the `scripts/txe-test.sh` wrapper avoids:

1. **Transpile-skip (deterministic).** `aztec test` runs `aztec compile`, whose postprocessing (`bb aztec_process`) only transpiles artifacts it finds in `./target/` *relative to the current directory*. nargo writes artifacts to the **workspace-root** `target/`, so running `aztec test` from a member dir (e.g. `cd zka_transfer_aztec`) leaves the artifact non-transpiled and the deploy fails with `Contract's public bytecode has not been transpiled`. A stale non-transpiled artifact also poisons the recompile cache ("No source changes detected"). Fix: use the wrapper, which runs from the workspace root with a clean/`--force` compile.

2. **World-state race (flaky).** `aztec test` hardcodes `--test-threads 16`; running the TXE tests in parallel intermittently fails one test with `mdb_txn_begin: 22 - Invalid argument` (a shared TXE LMDB race) and the count cannot be lowered through `aztec test`. The wrapper runs `nargo test` serially (`--test-threads 1`, override with `TEST_THREADS`).

The wrapper also starts `scripts/txe-trace-server.mjs` against the installed TXE
6.0.0 modules. Two read-only test oracles expose the actual public-call requests
and complete calldata passed to the public processor, including nested and
teardown requests. The registration regression requires exactly one owner-only
`_register_compliance` call; the gated-transfer regression requires no public
calls. Missing observations, stale traces, missing preimages, and incorrect
calldata lengths fail. These tests require the wrapper; stock `aztec test` does
not provide the trace oracles. No installed package files are modified. The
adapter uses Node's module hooks (Node 22.15+ or the pinned installer's Node 24).

For wallet and node connectivity checks, see [Local network checks](#local-network-checks).

## Contracts

### ZKAPay

`zka_pay_aztec` is the separate ownerless, owner-direct Pay class specified by
[ADR 0006](../docs/adr/0006-aztec-native-pay-profile.md). Its constructor is
`(portal, asset_commitment)`. Both settlement fields are immutable; the class
has no administrator, compliance configuration, pause, arbitrary-call or upgrade
entrypoint. It contains no call to `ContractInstanceRegistry.update`.
`ZKATransfer` below retains its existing compliance and authwit ABI and is not
the ownerless Pay class.

| Function | Type | Description |
|----------|------|-------------|
| `claim_private(beneficiary, amount, claim_secret, message_leaf_index)` | Private | Consume the exact portal Inbox message once and deliver its bound note |
| `transfer(to, asset_commitment, value)` | Private | Unconditional owner-directed transfer, without a payment context |
| `pay(to, asset_commitment, value, interaction_context)` | Private | Transfer and emit one constrained receipt encrypted to the same recipient |
| `withdraw(amount, asset_commitment, external_recipient)` | Private | Unconditional exit to a nonzero 20-byte L1 recipient |
| `_spend(from, asset_commitment, amount)` | Private, self-only | Pop and sum up to 16 notes in a dedicated call frame, then return the change |
| `_process_withdrawal(external_recipient, amount)` | Public, self-only | Emit the Outbox message after the private burn |
| `get_balance(owner, asset_commitment)` | Utility | Holder-local balance query; not settlement evidence |

Every spend binds the constructor-fixed asset. Values and aggregate change are
checked as `u128` before note creation; withdrawals validate the L1 recipient
before burning notes. The receipt uses the exact framework-generated opening
of the recipient output and the normative
[`zka:aztec:pay-receipt:v1`](../docs/sdd/sdd_aztec_pay_receipt.md) payload. Its
context stays in private execution and the recipient-encrypted event, outside
public storage, arguments and withdrawal inputs. Plain transfers and exits
require no context, credential, mandate or third-party approval.

The class is a local V6 implementation candidate. TXE execution does not qualify
the holder/PXE randomness and recovery boundary, public finality, independent
audit, production certification or deployment. Those remain gated by
[ADR 0010](../docs/adr/0010-aztec-flagship-and-production-gates.md). The baseline
fee route is holder-paid `aztec-protocol-fee-v1`; no FPC or in-asset fee feature
is added by the contract.

### ZKATransfer

Private single-asset transfers with value conservation and optional compliance gating.

| Function | Type | Description |
|----------|------|-------------|
| `claim_private(recipient, amount, secret, leaf_index)` | Private | Consume a portal Inbox message and create its bound note |
| `transfer(to, asset, value)` | Private | Transfer to recipient |
| `transfer_from(from, to, asset, value, authwit_nonce)` | Private | Transfer from a holder under a single-use authwit |
| `transfer_with_compliance(to, asset, value)` | Private | Compliance-gated transfer (recipient checked in private) |
| `withdraw(amount, asset, ext_recipient)` | Private | Exit shielded pool (settles L2->L1, see below) |
| `_spend(from, asset, amount)` | Private, self-only | Pop and sum up to 16 notes in a dedicated call frame, then return the change |
| `set_credential_contract(address)` | Public | Admin: set credential contract (effective after 24 h) |
| `enable_compliance(enabled)` | Public | Admin: toggle compliance mode (effective after 24 h) |
| `is_compliance_enabled()` | Public View | Check if compliance is active |
| `is_recipient_compliant(recipient)` | Public View | Check recipient compliance |
| `get_balance(owner, asset)` | Unconstrained | Query balance |

**`transfer_from` authorizes delegated spending.** The holder authorizes the full five-field argument tuple in declaration order. Aztec v6.0.0's `authorize_once` gate binds it to the caller, function selector, consuming ZKATransfer instance, chain ID, and version before spending the holder's notes. Change returns to `from`. Each delegated authorization is single-use; choose a fresh `authwit_nonce` for another otherwise-identical transfer. Direct calls where `from == msg_sender` require nonce zero. This entry has the same value checks and unconditional transfer behavior as `transfer`. See the [ZKM surface design](https://github.com/pyramidal-io/ZKM.dev/blob/3a66cd54eb592c6712e453fe93301af2d2bc3c3a/docs/aztec_binding_adapter_surface_request.md) for the standard authwit preimage and nullifier semantics.

**`claim_private` authenticates L1->L2 entry (ADR 0005).** The paired ownerless `ZKAAztecPortal.depositToAztec` escrows the immutable underlying and inserts an Inbox message binding the immutable asset, amount, beneficiary, and claim-secret hash. `claim_private` verifies and consumes that message once using Aztec's protocol nullifier before delivering the `ZKANote` to the bound beneficiary. The depositor must derive the hash with Aztec V6 `computeSecretHash(secret)` and retain the field secret until the claim succeeds; keccak/SHA hashes are not compatible with protocol message consumption. There is no unauthenticated mint entrypoint. The constructor is `(admin, portal, asset_commitment)`; the portal and asset have no setters.

**`withdraw` settles L2->L1 (ADR 0002).** Exiting the shielded pool burns the sender's notes in the private phase and then emits an Aztec **Outbox** message to an **immutable L1 portal** (a new ownerless `ZKAAztecPortal.sol`), which consumes the message and releases the underlying asset. The portal address is fixed once in the constructor and can never be changed by any admin path, preserving Safeguard 5 (unconditional exit) and Safeguard 3 (no admin can redirect/gate a note). This Outbox + L1-portal model is **separate and orthogonal** to the verifier-based `ZKABridgeEthereum` (which releases funds against a submitted UltraHonk proof on L1 for the *standalone* circuits); `withdraw` does not use it. See `docs/adr/0002` for the full design and the canonical message-content encoding.

### ZKACredential

Credential binding with selective attribute disclosure, composable compliance, and revocation.

**Attribute convention:** `[0]` KYC status, `[1]` Jurisdiction, `[2]` Source of funds, `[3]` Accreditation

| Function | Type | Description |
|----------|------|-------------|
| `bind_credential(data, attributes, issuer_signature)` | Private | Store a credential that the pinned issuer signed for the caller |
| `prove_disclosure(mask, context)` | Private | Generic selective disclosure |
| `prove_kyc(context)` | Private | Disclose KYC status (attr 0) |
| `prove_jurisdiction(context)` | Private | Disclose jurisdiction (attr 1) |
| `prove_source_of_funds(context)` | Private | Disclose source of funds (attr 2) |
| `aggregate_disclosures(mask_a, mask_b, context)` | Private | Combine two disclosure proofs |
| `disclose_to(recipient, mask, context)` | Private | Disclose to specific party |
| `verify_compliance()` | Private | Prove credential + private non-revocation, register compliant |
| `assert_compliant(owner)` | Private View | Gate check for the transfer contract (owner not published) |
| `revoke(cc)` | Private | Admin: revoke credential by commitment (emits a revocation nullifier) |
| `is_compliant(owner)` | Public View | Check compliance status |
| `is_revoked(cc)` | Public View | Check revocation status |
| `has_credential(owner)` | Unconstrained | Check credential exists |

**Issuer authentication.** The constructor is `(admin, issuer)`. `issuer` is the credential issuer's secp256k1 public key, the ZKC mandatory issuer-signature profile. It is the deployment's issuer trust policy: there is no setter, so a new issuer needs a new deployment. `bind_credential` stores a credential only with that issuer's ECDSA signature over the SHA-256 digest of a fixed 320-byte transcript: the tag `zka/aztec/credential-issuance/v1`, the chain ID, the version, the credential contract address, the caller's `cc`, `credential_data`, and the four attributes (`zka_aztec_lib::issuance_digest`). The contract derives `cc` from the caller's own key. A signature therefore works only for one holder, one contract instance and one chain, and the holder cannot change a signed value. The issuer receives `cc` from the holder's wallet and never learns the holder's Aztec address. `verify_compliance` and every disclosure use only the caller's originator note: `context == 0` and the caller's own `cc`, both enforced by the note select. A `disclose_to` note is never a credential.

This is issuer authentication for this contract, not ZKC verification. The contract verifies no ZKC proof, presentation profile, issuer registry, accumulator, or validity window. A credential stays usable until the admin revokes its `cc`. The TXE tests use TEST-ONLY keys from `scripts/issuer_test_signatures.py`. Never pin those keys in a deployment.

**§5.2 context binding (replay protection).** Every disclosure entry point takes a caller-supplied `context = H(verifierId, sessionId, timestamp)` (asserted non-zero). Per the canonical model (`docs/adr/0001`), `context` is a **separate, co-equal binding** — a constrained argument that binds the proof, and a separate `CredNote` field in `disclose_to` — and is **never folded** into the disclosed hash. The returned `disclosed_attribute_hash` is therefore the **raw, context-independent** value, byte-identical to the standalone circuit's public input `[1]` (the cross-environment equality guarantee). `verify_compliance()` takes no context: it registers compliance in public state, disclosing no attribute values and not the credential commitment.

### Compliance-Gated Transfers

The compliance pattern enables accounts to require credential proofs before receiving transfers:

```
0. Recipient: credential_contract.bind_credential(data, attributes, issuer_signature)
                                                          → stores the issuer-signed credential (refused without the pinned issuer's signature)
1. Recipient: credential_contract.verify_compliance()     → proves their OWN issued credential and, in private, its non-revocation;
                                                            schedules the address into the compliance set (effective after 24 h)
2. Sender:    transfer_contract.transfer_with_compliance(recipient, asset, value)
              → private: reads the gate config; if enabled, calls credential_contract.assert_compliant(recipient)
              → private: normal transfer logic (no public call is enqueued)

There is no open self-registration on the transfer contract: the only way an
address becomes compliant is by proving its own issuer-signed credential via
verify_compliance.
```

**Public outputs (ZKA spec §5.8).** The credential commitment `cc` is the ZKC `holderCommitment`, the stable holder anchor that linkable v1 presentations expose. It is not a pseudonym, and no holder-called function publishes it.

| Action | Published |
|--------|-----------|
| `verify_compliance()` | The registering address only. Non-revocation is a private nullifier non-inclusion proof at the anchor block. The tx expires 1 h after its anchor. |
| `revoke(cc)` | `cc`, plus the revocation nullifier `H2("zka/aztec/revocation/v1", cc)`. It is linked to no holder address (the tx carries only the admin's). |
| `transfer_with_compliance(...)` | Nothing beyond a plain `transfer`. The recipient check is a private call. |
| `disclose_to(recipient, ...)` | Nothing public, but the recipient's note carries `cc`, so recipients can link the holder. |

The compliance set and the transfer gate config are `DelayedPublicMutable` with a delay of `MAX_TX_LIFETIME` (24 h). A registration or an admin config change, including an emergency disable, therefore takes 24 h to take effect. In exchange, the private reads bound the transaction expiration no lower than the kernel already does for every private call. While an admin config change is pending, gated transfers expire just before its timestamp of change, which marks that deployment's gated transfers but not their recipients. The setters skip no-op changes so that a repeat call does not reopen that window. The sender's PXE must have the configured `ZKACredential` registered, because the gate runs as a private call.

Residual exposures: the node that serves the PXE sees the key of each private read. For a registration, that lets the node pair `cc` with the registering address. A holder can still register up to 1 h after a revocation by choosing an older anchor block. Revocation never removes a registration, and re-registration changes no state, so do not re-register on a schedule: a schedule that stops after a revocation links `cc` to the address.

Named disclosure functions (`prove_kyc`, `prove_jurisdiction`, `prove_source_of_funds`) are composable with transfers in a single Aztec transaction — the kernel proves both the disclosure and the transfer atomically.

## Cross-Environment Testing

The `zka_cross_env_tests` package verifies that credential proofs produce identical cryptographic outputs in both standalone Noir circuits and Aztec contracts. This is the interoperability guarantee enabling cross-chain verification.

| Test Category | What It Verifies |
|---------------|-----------------|
| Credential commitment | Same `master_seed` → same sibling-derived `cbk` and `cc` in both environments |
| Selective disclosure | All 16 mask combinations produce matching hashes |
| Key hierarchy | Full sibling paths `seed → sk → vk → addr` and `seed → cbk → cc` match |
| Atomic compliance | Credential proof + transfer bound to same identity |
| EVM verifier inputs | Public inputs `[cc, disclosed_hash, context]` match |
| Domain separators | Both environments use identical domain constants |
| §5.2 binding model | Context is a separate co-equal binding (ADR 0001), raw hash context-independent |
| Real proof vector | Golden `[cc, disclosed_hash, context]` KAT ties the on-chain proof to the cross-env computation |

Run cross-env tests:
```bash
cd aztec && aztec-nargo test --package zka_cross_env_tests
```

### Real native/EVM proof

The tests above assert library-level **self-consistency** (same `zka_lib` functions → same outputs) but never generate a real proof. To close that gap, `noir/scripts/cross-env-proof.sh` generates and verifies a **real UltraHonk proof** (EVM/keccak target) of the standalone `zka_credential` circuit and asserts its public inputs are byte-identical to the native/EVM golden vector — i.e. exactly what an Ethereum `UltraVerifier` checks. The Aztec credential contract remains the separate ZKC selective-disclosure surface and is not an oracle for this v2 note/holder statement. From the repository root, run:

```bash
./noir/scripts/cross-env-proof.sh   # nargo execute -> bb prove -> bb verify -> assert public inputs
```

The golden vector is pinned by the committed `noir/zka_credential/Prover.toml`; a `zka_lib` drift breaks proof generation.

## Dependencies

- **aztec-nr v6.0.0** (`aztec-labs-eng/aztec-nr`) — Aztec.nr framework and TXE target
- **Aztec JavaScript SDK v6.0.0** — installed from `aztec/benchmarks/package-lock.json` for benchmark harnesses and local network checks.
- **zka_lib** — ZKA cryptographic primitives (path dep to `../noir/zka_lib`)
- All note hashes and key derivations delegate to `zka_lib` for cross-compatibility

## Local network checks

With Node.js 24 or later, the Aztec v6.0.0 CLI and Foundry installed, start the
local network from the repository root. The node listens on port 8080 and the
admin API on port 8880, both on loopback. See `aztec/benchmarks/README.md` for
toolchain and shared-network details.

```bash
./aztec/scripts/sandbox_setup.sh
```

In a second terminal, install the pinned SDK and run the wallet checks. The
checks default to `http://127.0.0.1:8080`. Set `AZTEC_NODE_URL` to use a
different development node.

```bash
npm ci --prefix aztec/benchmarks
if [ ! -e aztec/node_modules ] && [ ! -L aztec/node_modules ]; then
  ln -s benchmarks/node_modules aztec/node_modules
fi
./aztec/benchmarks/node_modules/.bin/tsx aztec/scripts/deploy.ts
./aztec/benchmarks/node_modules/.bin/tsx aztec/scripts/test_integration.ts
```

`deploy.ts` checks that a deployment wallet can register an initial local
account. `test_integration.ts` checks that at least two test accounts can be
registered. Both checks stop after wallet setup. Run
[`./scripts/txe-test.sh`](#quick-start) from `aztec/` for contract assertions.
