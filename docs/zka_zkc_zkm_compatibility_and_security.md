# ZKA/ZKC/ZKM launch compatibility and security statement

**Statement revision:** 2026-11-18

**Protocol-family epoch:** `zka:protocol-family:2026-11-19.1`
**Status:** Launch-candidate compatibility statement; the specifications remain drafts

This document is the self-contained public launch reference for composing ZKA, ZKC, ZKM, AFP, AFP-KDC, and `zka-langgraph`. It records compatibility, proof boundaries, security assumptions, known breaks, and review status. It does not turn a draft, tested implementation, or supported adapter into an audited production deployment.

The exact version and artifact tuples below are rendered from ZKA's canonical machine-readable protocol-family manifest. Unknown, incomplete, or ambiguous tuples are incompatible and must fail closed.

## Normative roles and compatible releases

| Protocol | Normative role | Compatible release | Source snapshot |
|---|---|---|---|
| ZKA | Defines private value notes, nullifiers, transfer validity, settlement composition, custody, and unconditional exit. | `0.9.2-draft` | source commit `8df996051ebec3bd47cc8fcce6feed24fa92972f` |
| ZKC | Defines holder-controlled credentials, interaction-eligibility proofs, presentation profiles, proof envelopes, issuer state, and verifier policy. | `0.4.1-draft` | source commit `c1d4c7bd5194f620fee052b0a4522689f5f407a5` |
| AFP | Defines agent-flow/session policy and the envelope in which protocol-family evidence is composed. | `0.3.14-draft` | source commit `4642e521107eec84e3ba1e0f1e59ecf8f4226a4c` |
| AFP-KDC | Defines shared seed reduction, key derivation, and derivation-domain constants. | `1.0.3` | source commit `4642e521107eec84e3ba1e0f1e59ecf8f4226a4c` |
| ZKM | Defines principal-issued mandate artifacts, mandate transition/consumption, revocation, and spend-authorization proof statements. | `0.1.0-draft (rev 13)` | source commit `f9331aa160ebdd928fde64442d1340c8f93dec71` |

The roles are intentionally non-substitutable. A valid ZKC proof means the holder satisfies a verifier-selected interaction policy; it does not authorize a spend. A valid `zkm:spend-conjoined:v2` proof means that its particular spend fits a principal-issued mandate; it does not establish counterparty eligibility and cannot settle value by itself. Other ZKM statements have their separately versioned, non-value-moving meanings. ZKA alone accepts or rejects the private value transition under its settlement rules. Replacing or revising one protocol therefore changes only that protocol's versioned interface and a new compatibility tuple; it does not redefine its siblings.

ZKM's prose version remains `0.1.0-draft`; this epoch pins rev13 and statement set `sha256:f367e0504bcbbe4ca2a150f9c56a7640d5ed21bdb9dec1c1ce4acaa6e023ab49`. The combined surface requires positive private spend amounts while retaining both output slots, corrects recipient binding, adds verified revocation insertion and corrects policy diagnostics. Consumers atomically select the new keys and retain the shared target-owned mandate nullifier set across adapter/key replacement. An old spend key is not evidence of the positive-amount rule. The independent effect-profile registry is outside the family manifest; the reconciled ZKM source records revision 8, `sha256:fc62285f9fb7218b82a5974d8435a0e3aa0d0963419717e240398c50c2627d12`. This source reconciliation does not change that registry.

## Shared primitives and pinned toolchains

| Protocol | Nargo | Barretenberg | Proof system | Field | Hash |
|---|---|---|---|---|---|
| ZKA | `1.0.0-beta.25` | `5.0.0` | UltraHonk | BN254 | Poseidon2 |
| ZKC | `1.0.0-beta.21` | `5.0.0-nightly.20260324` | UltraHonk | BN254 | Poseidon2 |
| ZKM | `1.0.0-beta.25` | `5.0.0` | UltraHonk | BN254 | Poseidon2 |

The ZKC row records its immutable historical lane; separate manifest assertions pin its historical compiler/backend and existing beta.25/5.0.0 successors, including the KYC-v2 dual build. ZKA/ZKM Aztec 6.0.0 / Noir 1.0.0-rc.3 and ZKA's independently pinned native Barretenberg 5.2.1 verifier remain separate from the standalone producer pair.

Shared primitives do not imply interchangeable proof bytes. AFP-KDC v1.0.3 is the current ownership and registry-metadata authority. `afp-kdc:master-seed:v1.0.1` remains the retained master-seed and key-hierarchy identity/provenance for seed reduction and the sibling derivations of ZKA spending keys and ZKC credential-binding keys. `afp-kdc:poseidon2:v1.0.2` remains the immutable Poseidon2 parameters and KAT profile. ZKA, ZKC, and ZKM separately own their operational domain tags, circuit ABIs, verification keys, and proof semantics. Each proof must be generated and verified with its protocol's pinned compiler/backend pair and exact artifact identity. A verifier must never accept a proof merely because it uses BN254, Poseidon2, or UltraHonk.

## Proof and artifact compatibility

| Combination ID | ZKA | ZKC | AFP | KDC | ZKM | Bundle | Proof | Profile | Binding circuit | Transaction | Presentation context | State |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| linkable-v1-payment | 0.9.2-draft | 0.4.1-draft | 0.3.14-draft | 1.0.3 | 0.1.0-draft (rev 13) | zka:bundle:v1 | zkc:proof:v1 | zkc:presentation:linkable:v1 | zka_transfer_binding | required | afp:zkc-presentation-context:v2 | supported |
| linkable-v1-coordination | 0.9.2-draft | 0.4.1-draft | 0.3.14-draft | 1.0.3 | 0.1.0-draft (rev 13) | zka:bundle:v1 | zkc:proof:v1 | zkc:presentation:linkable:v1 | — | forbidden | afp:zkc-presentation-context:v2 | supported |
| anonymous-v2-coordination | 0.9.2-draft | 0.4.1-draft | 0.3.14-draft | 1.0.3 | 0.1.0-draft (rev 13) | zka:bundle:v1 | zkc:proof:v2 | zkc:presentation:anonymous:v1 | — | forbidden | afp:zkc-presentation-context:v2 | supported |
| scoped-v2-coordination | 0.9.2-draft | 0.4.1-draft | 0.3.14-draft | 1.0.3 | 0.1.0-draft (rev 13) | zka:bundle:v1 | zkc:proof:v2 | zkc:presentation:scoped:v1 | — | forbidden | afp:zkc-presentation-context:v2 | supported |
| scoped-v2-payment | 0.9.2-draft | 0.4.1-draft | 0.3.14-draft | 1.0.3 | 0.1.0-draft (rev 13) | zka:bundle:v1 | zkc:proof:v2 | zkc:presentation:scoped:v1 | zka_transfer_binding_v2 | required | afp:zkc-presentation-context:v2 | supported |

`zkc:proof:v1` envelope bytes remain frozen. A predicate's version belongs to its registry-selected proof type and is not inferred from the carrying envelope version; for example, ZKC's `zkc:proof:selective_disclosure:v1` is valid only in a v2 anonymous or scoped presentation envelope. Anonymous v2 is valid only where a transaction is forbidden. A scoped v2 payment requires `zka_transfer_binding_v2`, which proves control of the spent note and the ZKC presentation from the same private master seed while exposing only the scoped pseudonym and scope identifier.

ZKM's value-moving composed statement is `zkm:spend-conjoined:v2`: its proof conjoins a revocation-scheme-v2 mandate SPEND with the ZKA value-spend leg. Settlement must verify the exact 14-field public vector and atomically consume the mandate nullifier and ZKA nullifier while creating the mandate successor and ZKA outputs. `zkm:mandate-only:v2` has a 9-field non-value-moving ABI. The retired v1 statements, with their 13- and 8-field vectors, are not compatible and must never be silently upgraded or reinterpreted.

## Published artifact identities

| Artifact | Version or identity | Pinned digest | Pin scope |
|---|---|---|---|
| ZKA bundle schema | `zka:bundle:v1` | `sha256:fbe249ee089d9d22111ac2f3c7536ee859185ff4693608b44bd101102b78e49e` | Schema bytes |
| ZKC v1 envelope schema | `zkc:proof:v1` | `sha256:5e64fc61ce02a4ed9ffade43aea0ba7cbbf11ba542ac91f1a9642242b6e59d1f` | Schema bytes |
| ZKC v2 envelope schema | `zkc:proof:v2` | `sha256:4862c998a7e4f4b28741e6617f3974c65c9807652af8a0452e529e50a54cf6bf` | Schema bytes |
| ZKA scoped-payment ABI | `zka_transfer_binding_v2` | `sha256:b4650c9dce364e9a9cc8b732ac64f8d74d741c68e278f90a3278bdad46d43238` | Public-input schema bytes |
| ZKC scoped KYC ABI | `zkc_kyc_v2` | `sha256:a1a483df6294596315102083036f01d36e936a919a431603188c253c180f71b8` | Public-input schema bytes |
| Current ZKM statement set | `0.1.0-draft (rev 13)` | `sha256:f367e0504bcbbe4ca2a150f9c56a7640d5ed21bdb9dec1c1ce4acaa6e023ab49` | Statements, ABIs, VK hashes, bytecode, revocation, and toolchain |
| Retained zka-langgraph statement set | rev-10 compatible statement surface | `sha256:a0c8aa61105627d2c3a5f9fdbc7e762901f1be54f1ef23e227039e43180b2515` | Statements, ABIs, VK hashes, bytecode, revocation, and toolchain |

These pins have deliberately different scopes. The family manifest publishes schema, public-input, and KAT digests for ZKA and ZKC; it does **not** publish a VK or circuit-bytecode digest for every ZKA/ZKC row above. Those rows establish protocol-interface compatibility, not permission to accept an arbitrary artifact carrying the same logical name. A concrete deployment must separately pin its exact VK and bytecode in its reviewed verifier registry. Until that deployment pin exists, the artifact is not launch-approved. ZKM's statement-set identity is broader and commits to its current statement ABIs, VK hashes, and bytecode as described in the table.

## Proof boundaries and composition

```text
public payment intent
        |
        v
  zka-langgraph orchestration
        |
        +---- optional ----> ZKC verify eligibility evidence
        |                         |
        |                         v
        +------------------> application policy / principal approval
                                  |
                                  +---- optional ----> ZKM authorize spend
                                  |                         |
                                  |                         v
                                  +------------------> public authorization reference
                                                            |
                                                            v
                                                ZKA holder + settlement backend
                                                            |
                                                            v
                                             chain finality + authoritative receipt
```

### AFP-bound contexts and predicate meaning

AFP authenticates the exact raw session identifier `X_<64-lowercase-hex>` before any field conversion. ZKA bundle metadata, transaction, binding, and Coord slots use `session_context_field = OS2IP_BE(raw_payload) mod BN254_Fr`, serialized as exact 32-byte lowercase `0x` hexadecimal; zero is rejected without retry or substitution. The separately derived `presentation_proof_context` hashes the canonical AFP purpose record containing the original raw `X_...` value. Neither field representation may replace AFP's raw session authentication, and neither session representation may replace the presentation-purpose context.

The AFP adapter result has exactly `{proof_context, credential_subject_aid, proven_predicates}`. Each `proven_predicates` entry is a complete six-member record—predicate identifier and matching decimal version, root class and authority, attestation window, and subject AID—with unavailable values represented by explicit nulls, and is verified against its evidence snapshot as a complete record. The presentation-policy seam has authenticated comparands only for predicate ID/version and root class/authority; window and subject remain free there until Introduction binds them to its authenticated request. The caller supplies a separate required-predicate policy; it is never copied from the proof or included as a fourth result member.

| AFP trust flow | Predicate selection | Meaning-bearing verifier inputs |
|---|---|---|
| telemetry | Broader AFP closed catalog; this conformance profile requires `afp.telemetry.instance_attestation.v2` | Exact purpose/flow, profile, proof context, predicate ID/version, accepted root-class/authority pair, canonical nonempty attestation window, and nonempty instance/entity subject AID |
| bilateral | Caller-policy-selected, versioned predicate set | Exact purpose/flow, profile, proof context, required/accepted predicate IDs, and full returned predicate records; generic KYC/jurisdiction does not authenticate the result subject by itself |
| introduction | Caller-policy-selected predicate set plus AFP introduction credential rules | All bilateral bindings plus introduction credential class, issuer-authoritative accepted root, window, presenter/subject, delegation, and revocation checks |
| open-federation | Caller-policy-selected, versioned predicate set | Exact purpose/flow, profile, proof context, required/accepted predicate IDs, and full returned predicate records |

Across every row, `credential_subject_aid` is accepted only from an issuer-authenticated AID claim or an independently verified companion subject-binding proof. An instance predicate's optional `subject_aid` is not universally the same value. Unknown/missing predicate meaning, an empty proof set, flow relabeling, unsupported or unaccepted telemetry roots, stale/untrusted issuer state, and any bundle-verifier failure are default-deny interaction failures; none affects ZKA note validity or exit.

## Orchestrator compatibility

| Component | Compatible release | LangGraph dependency | Protocol pin | Source snapshot |
|---|---|---|---|---|
| `zka-langgraph` | `0.1.0.dev0` | `>=1.2.10,<2` | `zkm:spend-conjoined:v2` / `sha256:a0c8aa61105627d2c3a5f9fdbc7e762901f1be54f1ef23e227039e43180b2515` | source commit `0e7c6bf185870c30f4207f862d79c7e8be07f98e` |

`zka-langgraph` version `0.1.0.dev0` composes four explicit flows: ZKA-only, ZKC→ZKA, ZKM→ZKA, and ZKC→ZKM→ZKA. It is orchestration, not a wallet, signer, prover, verifier registry, ledger, or settlement authority. ZKC and ZKM are optional capabilities behind distinct interfaces. The workflow passes only public references and decisions; private credentials, mandate openings, note openings, witnesses, proof paths, and spending authority stay behind the holder boundary.

The retained `zka-langgraph` source above pins the rev10 statement set, so its ZKM capability is incompatible with this epoch's rev13 keys. It must remain disabled for rev13 until a separately reviewed integration cutover updates its pin; the retained source row is not evidence of that cutover.

When ZKM is configured, `zka-langgraph` pins both `zkm:spend-conjoined:v2` and the statement-set identity above; the bare ZKM version is insufficient. It prepares settlement under a deterministic idempotency key, obtains any ZKC decision before application policy, obtains a ZKM authorization only after policy, and passes the authorization reference to the ZKA settlement capability. Finality and receipts remain authoritative only at the configured settlement backend and chain observation policy.

## Security assumptions

The composed launch surface relies on all of the following:

1. The pinned Noir/Barretenberg implementations of UltraHonk are sound for the published circuit bytecode and verification keys; a toolchain or artifact change requires a new reviewed identity.
2. Poseidon2 over BN254 has the required collision-resistance, preimage, PRF, and hiding properties for each stated construction, and all implementations use the published field encoding, arity, nesting, and domain constants.
3. Holder devices protect the master seed, spending keys, credential and mandate openings, witnesses, and approval authority. Remote proving or orchestration does not receive unilateral spending authority.
4. ZKC verifiers use an explicit trust policy for issuers, predicates, accumulator roots, freshness, context, and presentation profile. A valid proof establishes only its public predicate under that policy.
5. ZKM settlement targets enforce the mandate tree, accepted roots, scheme-v2 revocation set, expiry, cap conservation, statement-set/VK registry, and a single nullifier set across every accepted ZKM VK.
6. ZKA settlement targets enforce note-root recency, asset/deployment context, immutable verifier identities, nullifier uniqueness, conservation, atomic state transition, and the target chain's finality policy.
7. Applications secure `zka-langgraph` checkpoint storage, callback endpoints, holder transport, policy configuration, logs, and operator access. Synchronous graph checkpoints are not evidence that a ledger transition committed.

These assumptions do not add a freeze, seizure, upgrade, or emergency key. Credential or mandate revocation can cause a counterparty or authorized flow to refuse a new interaction, but cannot invalidate, redirect, freeze, or seize an existing ZKA note or remove its unconditional exit path.

## Audit and launch status

| Surface | Current evidence | Launch statement |
|---|---|---|
| ZKA core and adapters | Reproducible tests, real-proof fixtures, conformance vectors, and machine-readable adapter certification. All named adapters are `supported`; none is `production`. | No adapter has independent audit evidence. The retired APLBridge Base deployments are unaudited DEV/PILOT instances. Production ZKAEthPool use remains gated on an independent audit and deployment evidence. |
| ZKA/Coord v2 | Real-proof conformance evidence, threat model, resource budget, and an explicit audit gate. | Draft, unaudited, and not production-supported until a signed independent review has no unresolved critical or high soundness findings. |
| ZKC 0.4.1 draft | Open specification, Noir circuits, reference packages, vectors, conformance tests, and threat-model material. | No independent third-party audit report was identified in the reviewed snapshot. Treat the surface as unaudited. The holder-authorized audit-disclosure feature is evidence export, not a security audit. |
| ZKM 0.1.0 draft | Eight Noir circuits, statement/VK registry, cross-protocol KATs, Foundry tests, measured proving/gas evidence, and fail-closed revision checks. | No independent third-party audit report was identified in the reviewed snapshot. Treat the surface as unaudited and draft. |
| `zka-langgraph` 0.1.0.dev0 | Unit, graph, replay, recovery, security-boundary, and settlement-backend conformance tests. | Development release. No independent third-party audit report was identified; it inherits the security and finality limits of its configured capabilities and deployment. |

The word "supported" denotes repository conformance evidence, not production fitness. Operators must not advertise this family as audited or production-ready until the relevant independent-review gates and deployment-specific evidence are complete.

## Known limitations and planned breaks

- ZKM artifact v2 is the one planned protocol break. It will add `not_before` replenishment and delegation-revocation handles as a coordinated all-VK re-bless with migration guidance. It is not implemented by either the current rev13 statement set or the retained rev10 integration.
- ZKM's remaining open research/deployment surfaces include stronger formal proofs, payment-channel interior consumption, authenticated-demand transport, first-deployment registry format, and possible association-set policies.
- ZKA/Coord v2 has no compatibility decoder for its removed pre-launch format; its EVM target remains unsupported until an exact artifact and verifier are published, and an Aztec target requires an independently registered profile.
- ZKA settlement-adapter certification stops at `supported`; production claims require an independently audited concrete deployment and live operational evidence.
- ZKC issuer trust, policy choice, accumulator publication/freshness, and a verifier's ultimate decision remain outside what a proof alone can establish.
- `zka-langgraph` ships no production tenant-to-tenant coordination transport, wallet, signer, key store, or multi-process lock service. Durable checkpoints and authoritative backend idempotency are deployment responsibilities.

## Source and public-snapshot discipline

Rows labeled `source commit` are exact observed protocol source publications. The current ZKM rev13 source is pinned at its actual Forgejo merge `f9331aa160ebdd928fde64442d1340c8f93dec71`. The predecessor epoch `2026-10-26.1` consumed the activated intent `e3e7813789120f63a6f704033b7318a21ec9b065` in substantive merge `b0f255e2340e8b0092422e50a3abac12cb452cec`, followed by canonical republish `7b900d5533183a99ee16ec6723c01e7a818d38cf`. That predecessor's snapshot lock recorded its substantive commit without a pending marker, and its ZKC, ZKM and AFP consumer syncs were delivered. The preceding epoch `2026-10-28.1` merged at `4867727db93380b45dd36d3512706a5c0224b228`. Canonical republish `63a00a185ce19b8ef6301fcdafc131c15c59ffed` recorded that substantive commit without a pending republish marker. ZKC and ZKM synchronized at Forgejo merges `7d4ea33e32c3238da288ed82439c833a277d7174` and `106e2dc49064edce980f584dafc992558db30d1c`, followed by AFP at `4642e521107eec84e3ba1e0f1e59ecf8f4226a4c`. The launch-source lock pins the published AFP 0.3.14-draft specification and snapshot lock, plus the ZKA specification and toolchain file. The ZKA source is pinned at `8df996051ebec3bd47cc8fcce6feed24fa92972f`, which carries the exact 0.9.2-draft specification bytes for the successor epoch. Epoch `2026-11-18.1` retired the Namada and Penumbra bridge bindings and corrected the ZKM holder-key transcripts. Its substantive merge `cd7ecd28f13fef1f2b3bd397c1c4418e6db282e3` is the published predecessor of `2026-11-19.1`. The successor reconciles ZKC's operational Poseidon2 inventory. Its snapshot lock records observed Forgejo merge `69bc82ac6685e91f23e386dfdacab78dd1e8cfbc`. Historical intent, predecessor, expiry and staged records remain frozen in Git history. Coord v2 remains draft and its independent-review gate remains fail closed.

This statement was reviewed against the exact source snapshots named in the version table where a `source commit` is shown, each normative specification, ZKA/ZKC/ZKM toolchain lockfiles, ZKM's statement registry, and `zka-langgraph`'s package metadata and capability constants. Published commits, protocol/integration versions, and file digests are recorded in the [launch source lock](../protocol-family/launch-source-lock-v2.json). The version-consistency command derives every declared source version from the pinned bytes when supplied the corresponding source roots. The canonical ZKA specification is available in this public snapshot at [the ZKA protocol specification](zka_specification.md).

The sibling development repositories are not files in the ZKA public snapshot, so this document cites their immutable repository-and-commit identities as text instead of publishing links that would be broken or access-controlled for a public reader. When sibling public snapshots exist, links may be added only if the link checker confirms that every target resolves anonymously. Until then, this document remains self-contained and makes no claim that private development URLs are public sources.
