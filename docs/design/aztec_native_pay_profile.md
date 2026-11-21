# Aztec-Native ZKA/Pay Deployment Profile — Investigation Memo

**Status:** Investigation (accepted deliverable of the Aztec-native ZKA/Pay deployment investigation); feeds the go/no-go for the companion benchmark requirement Aztec-native ZKA/Pay benchmark. Its dated observations and measurements remain evidence, not activation approval.
**Date:** 2026-08-15.
**Owning specs:** ZKA (§3.4, §8/§8.6, §12.1), ZKA/Pay pool SDD, ZKA/Pay economics (§6.5/§7), ADR-0002.
**Related spec section:** ZKA §8 / §8.6 / §12.1 (`ZKA-Aztec`).
**Scope:** Lever 5 of `docs/economics/zka_pay_economics.md` §6.5 — the Aztec-native deployment profile that eliminates the per-app EVM verifier because the host rollup's kernel verifies. This memo answers the four requirement items: (a) aztec.nr contract shape for a pay-pool-equivalent profile; (b) the fee-market cost structure that replaces the EVM verify-gas, DA, and aggregator terms; (c) Freedom Safeguard 3 and 5 conformance on Aztec; (d) the pilot equivalent — and closes with a go/no-go recommendation for the benchmark pass. **This memo changes no normative text.** The governing strategic and production decision is [ADR-0010](../adr/0010-aztec-flagship-and-production-gates.md): Aztec-native, owner-direct ZKA/Pay is the strategic flagship, while the Base profile is interim and non-production. Strategic flagship status is neither an executable deployment target nor a production certification.

**Related:** spec §3.4 / §8 / §8.6 / §12.1 (`ZKA-Aztec` level); [ADR-0002](../adr/0002-withdraw-l2-to-l1-settlement.md) (withdraw L2→L1 settlement — implemented); `docs/sdd/sdd_pay_pool.md` (the machinery this profile deletes); `docs/economics/zka_pay_economics.md` §6.5 lever 5 + §7 (the unmeasured-profile row the benchmark pass will replace); `docs/operations/aztec_outbox.md`, `docs/operations/aztec_v5_migration_matrix.md`; `aztec/` workspace (aztec-packages v5.1.0 at the time of this investigation; the workspace now pins v5.2.0).

External claims in this memo were collected 2026-08-15 and are cited inline with their dates; they are point-in-time observations of a fast-moving network, not committed measurements. Nothing here is a measured benchmark — producing those is exactly the companion requirement's job.

**Base comparator.** All Base gas and cost figures below use the August decision model at `bbd74e3c` and Forge isolate measurements at `066c524e` (2,863,667 gas for W=4 batch verification). The later beta.25 fixture run at `4e96d062` measured 2,866,811 gas for this verifier ([ZKA §7.1](../zka_specification.md#71-ethereum-bridge)).

**Numbers note (2026-08-15, same-day):** after this memo was drafted, the 4-of-4 fill anchors landed on `main` and **solved** the economics memo's §2.1 bookkeeping bracket. Base-profile comparators quoted below as brackets are now committed single values: W=4 full fill **$0.2730 (duty-cycle) / $0.2828 (24x7)** (was $0.2267–$0.3345 / $0.2366–$0.3444); the §6.5(b) amortization floor is a **measured $0.0804/payment** (was the $0.02–$0.16 bracket); velocity-1 lifecycle is $1.4403. Every bracket-conditioned spread in this memo collapses accordingly (e.g. §1's "≈51–76%" fixed-terms share becomes ≈61–63% at the solved values). None of this changes the structural analysis or the recommendation — the measured comparison in the companion benchmark set quotes the solved values throughout.

---

## 1. Executive summary and recommendation

**The structural claim of §6.5 lever 5 survives detailed investigation, and strengthens.** On an Aztec-native deployment, both fixed per-batch cost terms of the Base profile — the fill-invariant 2,863,667-gas `verify()` and the 11,332-byte fixed proof-calldata DA term, together ≈51–76% of the duty-cycle full-fill marginal cost (the spread is the economics memo §2.1's unmeasured bookkeeping bracket, carried in this memo's §4.1 table) and ≈81% of the ≈$0.85 lone-payment case — are not merely amortized better; the machinery that generates them ceases to exist. The rollup kernel verifies every transaction, the epoch proof amortizes L1 verification across the whole network, and DA is the protocol's blob publication, not per-app calldata. The batching apparatus that §3.4 exists to operate (W=4 recursion, pinned recursive VK, deposit queue, digest folds, canonical calldata, aggregator role, cadence SLA, under-fill economics) dissolves wholesale — see §3.

**Recommendation: GO for the benchmark pass — scoped to local-network / TXE / sandbox measurement plus read-only public-node probes, with no deployment to any public network and no value at risk.** (Alpha-testnet execution is deferred while Aztec's V5 pause guidance stands — §7.) At the time of the investigation, the measurability preconditions were all satisfied: the fee formula and its gas constants were public at the repo's then-current aztec-packages v5.1.0 pin, the existing `aztec/` workspace built the transfer and exit legs under that tag, and an end-to-end self-reported fee anchor existed to test against (Aztec claimed a fully private token transfer under $0.05 on Alpha V5). Section 7 specifies what the benchmark measured and under what provenance discipline. The workspace's later move to v5.2.0 does not relabel or invalidate the dated v5.1.0 measurements.

**A pilot deployment is explicitly NOT recommended now, and the benchmark GO does not imply one.** As of 2026-08-15 Aztec's Alpha V5 carries an unresolved critical proving-system vulnerability (discovered 2026-07-27, publicly disclosed 2026-08-07; whether it was exploited before discovery cannot be determined; official guidance is to pause V5 deployment work until contributors publish further guidance, with the fix targeted at the V6 release), and its predecessor V4 had its own critical proving flaw. Any pilot is additionally gated on the deposit leg being built (§3.2 — the Aztec L1→L2 deposit path does not exist in-repo), ADR-0002's live-endpoint acceptance smoke, and the independent-audit gate the pilot runbooks already impose. See §5.2 and §6.4.

One honest reframing this investigation forces: **"Aztec-native ZKA/Pay" is a different deployment profile, not a re-hosting of the §3.4 pool.** It settles to Ethereum L1 (not Base), prices in Aztec's fee market (not Base gas), replaces the pool's own trees and verifier with protocol primitives, and targets the spec's dedicated `ZKA-Aztec` conformance level. ADR-0010 now makes this profile the strategic flagship; the §3.4 Base WETH9 pool is interim and non-production. The decision does not activate a deployment or certify production.

The Ethereum portal is an ingress/egress boundary, not a private bridge: its deposit and withdrawal amounts are public, and timing, fees, and receipt metadata remain public residuals. Privacy claims apply to transfers within the Aztec domain, not to a cross-domain movement.

---

## 2. What "Aztec-native pay-pool-equivalent" means

Spec §8.6 already fixes the delegation boundary for the *generic* transfer machinery (§2–§3): note commitments and the Merkle tree delegate to Aztec's note hash tree, the nullifier set to the indexed nullifier tree, proof composition to the kernel circuits, the key hierarchy to app-siloed `nhk_app`, and the proof system is identical by construction (`docs/zka_specification.md:1319-1336`). What §8.6 deliberately does not address is the §3.4 *pool-profile* machinery — the deposit queue, digest folds, canonical `batchData`, pool-context fold, W=4 batch recursion, accepted-root ring, and the aggregator role. Classifying that machinery is this memo's §3.

A "pay-pool-equivalent profile" is therefore: an aztec.nr contract (plus an L1 portal pair) that delivers what the §3.4 pool delivers to AFP — single-asset shielded value entry, private payment with change and a bound interaction context, and unconditional exit — using Aztec-native primitives wherever §8.6's delegation principle applies, while preserving the additive ZKA layer (interaction/compliance binding, Freedom Safeguards discipline, cross-env note-commitment semantics) that Aztec does not provide.

---

## 3. Item (a) — Contract shape

### 3.1 The three-way classification of §3.4 machinery

Classification: **DELEGATED** (replaced by an Aztec protocol primitive), **CONTRACT LOGIC** (implemented in aztec.nr app code), **DISSOLVES** (exists only because the standalone EVM pool carries its own state, verifier, and operator; has no reason to exist on Aztec).

| §3.4 / pool-SDD mechanism | Fate on Aztec | Why |
|---|---|---|
| `zka_pay_batch` W=4 recursion + 115-field pinned recursive VK + toolchain freeze (`sdd_pay_pool.md` §3.3.1) | **DISSOLVES** | Exists to amortize per-app L1 verify gas. The private kernel folds per-call proofs; permissionless provers compress each 32-block epoch into one proof Ethereum verifies once for the whole network. App-level aggregation has nothing left to do. |
| Deposit queue + immutable 6-tuple (announcement-hash limbs, depositor proof hash) + mandatory deposit prefix + `deposit_prefix_digest` | **DISSOLVES** | The queue binds a third-party aggregator who inserts deposits and could censor/reorder/substitute. On Aztec, deposits arrive L1 portal → Inbox → the depositor's own L2 claim tx mints the note; there is no operator between deposit and note to bind. |
| `batch_data_digest` + canonical `ZKAP` calldata encoding + strict parser + `DATA_AVAILABILITY_MISMATCH` taxonomy | **DISSOLVES** | Self-provided DA. On Aztec, tx effects (note hashes, nullifiers, encrypted logs) come out of the kernel's public inputs and the rollup publishes state diffs to Ethereum blobs — DA is the protocol's job. The single largest deletion of soundness-critical app surface. |
| Root advancement (commitment root + depth-128 sparse nullifier root) + §3.4.1 canonical low-128-bit indexing + its CI constraint-inspection gate | **DELEGATED** | The base rollup circuit advances tree snapshots per tx; non-membership is native to the indexed Merkle tree. Nothing survives as app logic. |
| Accepted-root ring (64 roots) | **DELEGATED** | Private txs prove reads against a historical block anchor (archive tree); staleness policy is protocol-level. Holder-retries-on-stale-anchor is preserved by re-proving against a fresh anchor. |
| Pool-context 22-field fold (`zka/pay/pool-context/v1`) | **DISSOLVES** (small residue) | Its replay-prevention role is protocol siloing: note hashes and nullifiers are siloed by contract address automatically, and keys are app-siloed (`nhk_app`). Its circuit-identity role becomes contract class/instance identity. Residue: if AFP receipts want a cross-env-stable deployment identifier, derive one — but the 22-field fold as specified has no reason to exist. |
| `zka_pay_transition` (2-in/3-out payment) | **SPLITS** | Membership, nullifier emission/uniqueness, and keys DELEGATE to the kernel and protocol trees. Value conservation with change, asset scoping, and bounds are CONTRACT LOGIC — already implemented and conservation-audited in `ZKATransfer` (`aztec/zka_transfer_aztec/src/main.nr:335-382`). The frozen 2-in/3-out arity is an EVM-circuit artifact; Aztec's per-call read-request bound applies instead (up to 16 input notes today). |
| `zka_pay_withdrawal` + `ZKAEthPool.withdraw` | **SPLITS — exit leg EXISTS** | The Safeguard-5 semantic (exit takes no compliance/credential/admin input) is CONTRACT LOGIC, implemented and test-locked. The proof mechanism DELEGATES: no UltraHonk proof on L1 — burn → Outbox message → ownerless `ZKAAztecPortal.sol` consumes and releases (ADR-0002, implemented). |
| Fee output slot + `fee_recipient` | **DISSOLVES in EVM form** | It pays the aggregator; the aggregator dissolves. Protocol fees are paid in fee juice under mana metering. Private in-asset fee payment, if wanted, is the Fee-Paying-Contract (FPC) pattern — new contract logic, and the natural survivor of the "fee note" concept. See §4.2. |
| Aggregator role, 300s cadence SLA, under-fill economics | **DISSOLVES** | The sequencer/prover network batches and proves at protocol level, compensated through the fee market. The role's trust surface (censorship, reordering, byte substitution) generated most of the pool SDD's defensive machinery; it dissolves with the role. What replaces its *liveness* character is the host's sequencer-censorship model — a host-layer residual (§5.3), not app logic. |
| `interaction_context` binding (AFP obligation/quote/session) | **CONTRACT LOGIC — additive** | No Aztec equivalent exists. Must be carried by the aztec.nr payment function as a constrained binding, preserving the invariant that it is never a withdrawal input (`sdd_pay_interaction_binding.md`). Carrier design (constrained argument vs. log vs. note field) is an open design point (§8). |

Two boundary caveats the profile manifest must state honestly:

1. **Nullifier derivation is platform-substituted, not shared.** The Aztec adapter derives nullifiers via Aztec's `compute_note_nullifier` over `nhk_app`, not the ZKA §2.3 formula. Note *commitments* are cross-env byte-identical (pinned by `test_zka_note_hash_matches_standalone`); nullifiers are not. §8.5's "shared circuit semantics" claim must be scoped to commitments, domains, and asset-id encoding.
2. **Settlement lands on Ethereum L1, not Base.** §3.4 is frozen to Base WETH9 (`eip155:8453`); the Aztec portal escrows an ERC-20 on Ethereum L1. "Withdraw to a Base recipient" requires a further Base bridge hop outside this profile, and the exit-cost denominator becomes Ethereum mainnet gas for `outbox.consume` + transfer, not Base gas.

### 3.2 Gap analysis of the existing `aztec/` workspace

At the time of this investigation, the workspace used aztec-packages v5.1.0 across all packages and was far along on three of the four legs. The workspace now pins v5.2.0; the implementation inventory below remains the dated basis for the benchmark pass rather than a claim that its evidence was regenerated under v5.2.0.

**EXISTS.**
- Private transfer with value conservation, asset scoping, change note,
  DESC-sorted multi-note spend (`ZKATransfer.transfer`), conservation-audited
  and TXE-tested.
- Opt-in compliance gating (`transfer_with_compliance` + `ZKACredential`
  compliance set), fail-closed, with the Safeguard-3-preserving property
  that plain `transfer`/`withdraw` never touch it.
- **The exit leg, end to end**: private burn → `message_portal` with the
  canonical sha256 content encoding (soundness-hardened field→bytes
  decomposition, u160 recipient bound before burn) → ownerless,
  non-upgradeable, per-asset `ZKAAztecPortal.sol` doing v5 `outbox.consume`
  → `safeTransfer`, with the content hash triple-pinned (Noir golden, Forge
  golden, Rust reference) and the v5 Outbox witness/replay-key migration
  complete. The Rust ops slice (`zka-bridge-aztec` plus the `[aztec]`
  section of `zka-settlement-ops`' `ops.toml`) provides the proven-head
  finality gate and the once-only consumption ledger.
- Cross-env note-commitment equality with the standalone circuits, pinned
  by test.

**IMPLEMENTED DEPOSIT LEG; one remaining structural gap.**
1. **The deposit leg is implemented (ADR-0005).** The ownerless portal now escrows the immutable underlying and inserts an Inbox message binding asset, amount, beneficiary, and claim-secret hash. `ZKATransfer.claim_private` verifies the secret, consumes the message once through the protocol nullifier, and creates the bound `ZKANote`; unauthenticated `mint` is gone. Forge and TXE pin the cross-environment hash, tuple binding, secret check, replay protection, and non-redirectable front-running behavior.
2. **Fee handling remains open.** The workspace has zero fee/FPC/fee-juice surface. The profile must decide between protocol-fee-only (payer holds fee juice) and an FPC accepting the pool asset privately (§4.2). Nothing exists either way today.

**ADAPT (decisions plus small code).**
- The deposit path is constrained to a single `asset_commitment` bound at deploy, matching ADR-0002 B1's one-portal-per-asset model.
- Value-bound alignment: the deposit and note paths enforce `<= u128::MAX`; the pool circuits freeze `MAX_NOTE_VALUE_WEI = 2^120−1`; spec §2.3 declares `value: u64`. Pick and state the profile's bound.
- §2.3.1 randomness conformance: the [pinned PXE review](../security/aztec_pxe_randomness_review.md) records generation and retry evidence gaps for v5.1.0. The workspace's current v5.2.0 pin is not automatically qualified by that review. The integration remains experimental; framework-supplied randomness and standalone transition checks do not establish holder-boundary conformance.
- `interaction_context` carrier design (§3.1, table row; §8).
- The admin surface decision (§5.1): the §3.4-equivalent posture is a fully ownerless deployment.

### 3.3 Implemented deposit contract shape (ADR-0005)

```text
L1 (Ethereum):
  ZKAAztecPortal(underlying=WETH, inbox, outbox, l2Bridge,
                 rollupVersion, assetCommitment)                     [EXISTS]
    + depositToAztec(amount, to, claimSecretHash) -> Inbox message   [EXISTS]
      escrow-in; ownerless; one asset per portal (ADR-0002 B1)

L2 (aztec.nr, one contract; admin is limited to the optional compliance gate):
  claim_private(to, amount, claim_secret, message_leaf_index)        [EXISTS]
    consumes the L1 message, mints ZKANote(asset, value) bound to the
    escrowed amount — replaces mint()
  pay(to, value, interaction_context)                                [ADAPT]
    transfer + constrained interaction_context binding; change note;
    optional third output as FPC fee note if the in-asset fee route
    is chosen
  transfer_with_compliance(...)                                      [EXISTS, optional]
  withdraw(amount, external_recipient)                               [EXISTS]
    burn -> message_portal -> Outbox -> portal.withdraw on L1
```

Deployed with **no `ContractInstanceRegistry.update` call path** — on Aztec v5 an instance can only be upgraded by *itself* (`msg.sender == address`), so a contract whose code contains no update path is protocol-immutable, a stronger property than the "code absence" argument the EVM pool relies on (§5.1).

**Deposit-claim security invariants (fixed by ADR-0005 and test-pinned):**

1. The Inbox message content MUST bind the tuple *(asset, amount, recipient or claim-secret hash)* — a claim must not be able to mint a note for a different asset, amount, or beneficiary than was escrowed.
2. `claim_private` MUST verify the claim secret against the committed hash, so possession of the secret — not observation of the public L1 deposit — authorizes the mint (the canonical TokenBridge pattern's privacy property).
3. Message consumption MUST be once-only (the protocol's L1→L2 message nullifier), making double-claims impossible, and the claim MUST NOT be front-runnable or redirectable: an observer of the L1 deposit or the pending claim tx must gain nothing that lets them capture the note.
4. The L1 and L2 content-hash goldens are identical, and Forge/TXE exercise each binding against the production boundaries.

---

## 4. Item (b) — Cost structure: what replaces the EVM terms

### 4.1 Term-by-term fate of the committed Base-profile cost model

Committed values below are cited from the regenerated benchmark JSONs where prose and JSON drifted (the economics memo's prose anchors are one fixture regeneration behind `zka_pay_gas.json`, commit `54f00e86`; the fixed-calldata constant 11,332 is stable across both generations).

| Base-profile term (committed value) | Share at defaults | Fate on Aztec-native |
|---|---|---|
| `verify()` gas — 2,863,667, fill-invariant | ≈57% (low) / ≈39% (high) of duty-cycle full-fill cost — the committed 78.3% is the *whole* L2-gas category, which also contains bookkeeping | **ELIMINATED.** Committed already by §6.5 lever 5: "the host rollup's kernel verifies… not paid at all." Its economic residue is the network-amortized share of the epoch proof's L1 verification embedded in protocol fees — divided across all Aztec txs, not our app's. |
| Fixed calldata DA — 11,332 B/batch + 15 B header, amortized `/active` | ≈19% (low) / ≈13% (high) at full fill — the committed 21.4% is the *whole* DA category, which also contains the per-record announcement bytes | **ELIMINATED as a per-app term.** No per-app proof is ever posted as calldata. Replaced by the DA-mana component of the per-tx fee (blob state-diff share). |
| Per-record bookkeeping gas — bracket 71,410–870,361 (model JSON; memo prose 70,991–869,870) | (inside gas term) | **REPLACED.** No Solidity parse/fold loop. The economic role — irreducible per-payment state cost — survives as the mana charged for tree insertions: at v5.1.0 constants, 16,000 L2 mana per nullifier, 9,200 per note hash. |
| Per-record announcement DA — 401 B (committed formula; ~414 B post note-randomness regen) | ≈$0.006 | **KEPT in kind, REPLACED in pricing.** Encrypted note announcements must be published on any rail for recipient discovery. On Aztec they are private-log bytes: 2,500 L2 mana per private log plus DA mana per byte (1 mana/byte). The closest thing to a kept chain-side term. |
| Aggregator hardware ($0.50/hr; 24x7 vs duty-cycle) + 300s cadence | ~0.2% (duty-cycle) | **ELIMINATED as a role.** Batching/proving is the sequencer/prover network, paid via the fee split (70% sequencer / 30% provers of unburnt fees, plus issuance). Proving work does not vanish — part shifts to the payer's own device (below). |
| Batch width W, fill/under-fill penalty, lone-payment ≈$0.85, W=8 lever, W=2-verifier unknown | — | **ELIMINATED as concepts.** No app batch, no fill amortization: cost is flat per tx, not convex in 1/fill. The single biggest *shape* change: a lone payment costs the same as any payment. §6.5 levers 1–3 and §7 rows 1/3/5 become moot for this profile. |
| Lifecycle one-off legs — deposit $0.5675 + withdraw $0.5998 = $1.1673; velocity-1 lifecycle $1.3941 | 6.15x marginal at v=1 | **KEPT in shape, REPLACED in pricing.** The profile still has entry/exit legs, and they keep real Ethereum L1 gas components: `depositToAztec` (escrow + Inbox insert) and `portal.withdraw` (`outbox.consume` + transfer) are L1 mainnet transactions, plus an L2 claim tx and the L2 burn tx. The `marginal + one_off/velocity` formula carries over unchanged. Note: L1 *mainnet* gas replaces Base L2 gas here — the entry/exit legs may be *more* expensive than Base's, even as the marginal payment gets radically cheaper. The benchmark must price both. |
| $0.02–$0.16 amortization floor ("parity structurally unreachable") | — | **DOES NOT BIND.** The floor is constructed from Base-profile bookkeeping + record-DA terms. The Aztec analogue is Aztec's own minimum per-tx fee — the central number the benchmark pass must establish. This does not touch the positioning rule (§4.4). |
| Payer-side proving (unpriced in Base model; 555 ms browser / 140 ms native for `zka_pay_transition`) | unpriced | **KEPT and grows into a first-class term.** On Aztec the payer proves private execution + kernel locally (Aztec self-reports ~2.5 s laptop / 6.8 s browser for a private transfer on V5). The benchmark should measure this on the same M4 class as the Base numbers. |

### 4.2 The Aztec fee model, precisely enough to benchmark against

Mechanics (docs.aztec.network, fetched 2026-08-15): a transaction consumes **mana** in two dimensions — DA mana (data publication) and L2 mana (execution) — and pays `fee = daMana × feePerDaMana + l2Mana × feePerL2Mana`, EIP-1559-like (base + priority per mana, congestion multiplier). Fees are denominated in **fee juice**, a non-transferable asset obtained by bridging the AZTEC ERC-20 from L1 through the `FeeJuicePortal`. **Fee-Paying Contracts (FPCs)** provide fee abstraction: an FPC holds fee juice and accepts another asset from the user — including privately — which is how a ZKA profile would let payers pay fees in the pool asset without touching AZTEC (the "fee note" survivor from §3.1). Collected fees are pooled per epoch; a congestion portion is burned; of the remainder, 70% goes to the block proposer and 30% to provers.

Protocol gas constants at the repo's exact pin (aztec-packages v5.1.0, `constants.nr`): `DA_GAS_PER_BYTE = 1`, `DA_GAS_PER_FIELD = 32`, `L2_GAS_PER_NOTE_HASH = 9,200`, `L2_GAS_PER_NULLIFIER = 16,000`, `L2_GAS_PER_PRIVATE_LOG = 2,500`, `L2_GAS_PER_L2_TO_L1_MSG = 5,200`, `PRIVATE_TX_L2_GAS_OVERHEAD = 440,000`, `TX_DA_GAS_OVERHEAD = 96`.

**Derived floor (NOT a measurement):** a canonical 2-in/2-out private payment (2 nullifiers, 2 note hashes, 2 private logs) meters at least `440,000 + 2×16,000 + 2×9,200 + 2×2,500 ≈ 495,400 L2 mana` plus a small DA term (96 + 32/field + 1/byte of log payload). This assumes a purely-private transaction; the FPC fee route (§8 item 1) adds public setup/teardown, replacing the 440,000 private overhead with `PUBLIC_TX_L2_GAS_OVERHEAD = 540,000` plus `FIXED_AVM_STARTUP_L2_GAS = 20,000`, so the benchmark must meter both fee routes. What that costs in USD depends on the prevailing base fee per mana and the AZTEC price — neither of which this memo treats as committed. The only end-to-end anchor is Aztec's own claim for Alpha V5 (launched on mainnet 2026-07-21): an average fully private token transfer **under $0.05** — self-reported, not independently benchmarked. AZTEC traded around $0.0115–0.014 in Aug 2026.

Two structural facts that frame any Aztec fee number:

1. **The amortization actually works.** Permissionless provers compress each 32-block epoch into a single proof; Ethereum verifies one proof for the whole network (V5 also cut that L1 verify gas ~40%). This is the network-level version of what `zka_pay_batch` did for 4 payments.
2. **Current fees are issuance-subsidized.** L2BEAT reports operator-side onchain costs of ~$9.03 per L2 user operation at the network's current near-zero activity (<0.01 UOPS), against the <$0.05 user fee — bridged by 400 AZTEC/slot issuance. A long-run ZKA cost model should price the unsubsidized DA + verify amortization at realistic volumes, not extrapolate today's subsidized fee. The benchmark pass should report both.

### 4.3 What can be said numerically today (and what cannot)

Defensible now: the Base profile's two fixed per-batch terms (≈51–76% of the duty-cycle full-fill marginal cost, bracket-dependent, and ≈81% of the ≈$0.85 lone-payment case) are structurally absent, and with them the under-fill penalty itself; what survives in kind is exactly the $0.02–$0.16 floor's constituents (per-record state cost and announcement DA), repriced by Aztec's fee market. The self-reported V5 anchor (<$0.05 — an issuance-subsidized average for a canonical, non-ZKA-shaped token transfer) sits below the Base profile's full-fill band ($0.2366–$0.3444, 24x7); whether the *unsubsidized*, ZKA-shaped fee also crosses the $0.05 delegated-rail baseline is a benchmark deliverable, not a present finding.

Not defensible now: any committed per-payment USD figure. Missing inputs: the prevailing base fee per mana (no published value found; must be read from a live node), measured mana per ZKA-shaped tx (our contract does more than a canonical token transfer: interaction-context binding, compliance variant), measured DA bytes per tx (encrypted log payload size), the L1 entry/exit leg gas at the portal, and congestion behavior at any real volume. These are exactly the benchmark pass's deliverables (§7).

### 4.4 Positioning consequence (normative rule preserved)

§6.5's privacy-premium rule is declared invariant under every premium-shrinking lever, including this one: the levers "change its size, never the positioning." That survives here untouched: even at face value,
<$0.05 remains ~50x the x402 rail's ≈$0.001, and the premium framing —
state the per-payment cost and what confidentiality buys — remains the normative communication posture for any Aztec pilot. What the Aztec profile plausibly changes is the *magnitude*: from a $0.24–$0.34 full-fill premium (with an $0.85 low-volume case) toward the low single cents, pending measurement. If the benchmark confirms even the order of magnitude, the premium stops being the adoption-limiting number it is on Base — that, not parity, is the strategic content of lever 5.

---

## 5. Item (c) — Freedom Safeguard 3 and 5 conformance

Safeguard 3 (spec §1.6): note validity depends solely on cryptographic properties; no admin/governance/emergency key may invalidate, freeze, redirect, or force-transfer a note; no pausable/upgradeable/admin functions over note validity. Safeguard 5: exit MUST be unconditional; no compliance proof may gate it. §8.1 makes the Aztec-specific demand explicit: "Aztec contract code MUST NOT introduce pausable/upgradeable/admin paths over note validity."

### 5.1 App layer — conformant today, one decision recommended

The existing surface has completed its Section 1.6 conformance review and TXE-test-locked: the only admin functions (`set_credential_contract`, `enable_compliance`) gate the opt-in compliance interaction exclusively; `claim_private`/`transfer`/`withdraw` carry no admin or compliance input; a failed compliance check reverts atomically (counterparty refusal, never fund loss); the portal address is `PublicImmutable` with intentionally no setter (ADR-0002 rejected even set-once as "worse than an immutable"); the L1 portal is ownerless, non-upgradeable, non-pausable, with no sweep path and permissionless relay. Three regression tests pin Safeguards 3/5 (`withdraw_is_unconditional_even_with_compliance_enabled`, `plain_transfer_unaffected_by_compliance_mode`, `holder_can_fully_exit_under_compliance`).

Two profile-level points:

1. **Protocol-enforced immutability is available and should be claimed.** On Aztec v5 the `ContractInstanceRegistry.update` path can only be invoked by the contract instance itself (`msg.sender == address`, verified in v5.1.0 source). A pay contract with no update call path is therefore immutable *at the protocol level* — no deployer, admin, or governance can upgrade it. This is stronger than the EVM pool's "no admin functions exist" argument and the profile manifest should state it as the Safeguard-3 mechanism.
2. **Recommended: the pay profile deploys ownerless.** The §3.4-equivalent posture (ZKAEthPool takes five immutable addresses, no admin) argues for dropping even the compliance-toggle admin from the pay contract: compliance remains available through the separate credential contract and an optional gated-transfer variant, but the pay pool itself should have constructor-fixed configuration and no admin address at all. This removes the only admin surface the audit had to argue around.

### 5.2 Host layer — Safeguard 3: strong governance story, one new residual class

What ships as of Aug 2026 (external, cited in §9): Aztec is a Stage 2 rollup on L2BEAT. On-chain governance revoked rollup-contract ownership on 2026-06-22 ("Cut the Leash"); the Rollup, verifier, Inbox, Outbox, and escape-hatch code **cannot be upgraded in place**. Upgrades are opt-in and registry-based: governance deploys a *new* rollup instance (`Registry.addRollup()`), the old instance keeps running with its own verifier and Outbox, and "users can always bridge assets in or out of any historical rollup version." Governance provides ≥12 days notice before execution (3d pending + 7d voting + 2d queued + 7d grace; 66.5% approval, 20% quorum). The only remaining admin multisig is a 5/9 SlashVeto Council scoped to slashing — it has no power over state validity, messaging, or exits. A hostile governance action therefore cannot confiscate or invalidate notes in the current instance; worst case it points rewards and stake at a new deployment users may ignore, and migration is by voluntary exit — structurally the "migration-by-exit" model the eth-pool design already names for width changes.

Set against the committed Base host residual (the eth-pool design's §5.1 "Host-chain residual" paragraph discloses Base's sequencer/governance/ upgrade risk), this records a potentially stronger host-governance posture than the interim Base profile. A dated, like-for-like comparison is not made here. The spec's only nod to Aztec host risk — §11.4's "Aztec kernel upgrade | Version-pinned circuit IDs" row — is directionally right but thin; this memo's residual-risk paragraph below should be adapted into the profile manifest when one is written.

**The honest new residual class: proving-system soundness maturity.** Safeguard 3 says note validity must rest on cryptographic properties — on Aztec, those properties are enforced by Aztec's protocol circuits, which are young and have failed twice in succession: Alpha V4 had a critical proving-system vulnerability (disclosed 2026-03-27, theft-of-funds class), and Alpha V5 has one discovered 2026-07-27 and publicly disclosed 2026-08-07 (a proof can pass verification for a transaction the network should reject; exploitation before discovery cannot be ruled out; fix targeted at V6, unreleased as of 2026-08-15, with official guidance to pause V5 deployment work until contributors publish further guidance). On the Base profile, the analogous trust is our own frozen UltraHonk verifier — also fallible, but frozen, audited against a pinned toolchain, and not evolving under third- party governance. A ZKA profile manifest for Aztec must disclose this as inherited host trust: **app-layer Safeguard-3 conformance cannot immunize note validity against a host proving-system soundness failure.** The empirical record (v4→v5 rewired the Outbox ABI, witness shape, and replay key; ZKA absorbed it by migration, never by admin action) shows the absorption path works — and also that it is real, recurring work.

### 5.3 Host layer — Safeguard 5: unconditional in the limit, probabilistic in latency

The exit path itself is implemented and fail-closed (ADR-0002 + `aztec_outbox.md`): burn and message emission are atomic; after the epoch proof verifies on L1 the message is consumable by anyone, with no challenge period; the portal cannot redirect (recipient is inside the rollup-proven message); consumption is once-only by `(epoch, leafId)`. Host facts: the exit window is **infinite** (immutable contracts; L2BEAT: "passes the walkaway test — users can exit in the presence of malicious operators even if the Security Council disappears"). This means no deadline exists after which an exit is lost; it is not a promise of how soon an exit is included. DA is Ethereum blobs: once a block's data is published and included on L1, state reconstruction does not depend on Aztec-operated storage — but publication and inclusion themselves are host-layer liveness functions (sequencing, blob posting), so DA independence is a data-*retrieval* property, not a liveness one.

The honest caveats, quantified where sources allow:

- **No L1 forced-inclusion mechanism exists.** Aztec's protocol-level censorship-resistance tools are probabilistic — unlike an L1 forced-transaction queue, they do not guarantee inclusion after a fixed delay. L2BEAT's April-2026 modeling: worst-case inclusion ~20 days with 50% of sequencers censoring; ~12 h at 37.7%; and — decisive for ZKA — **censorship-by-content is impractical against private transactions**, giving <72 s expected inclusion "as if there was no censorship." A ZKA exit is a private tx; it is hard to selectively censor precisely because it is shielded.
- Backstops: permissionless sequencer entry at 200K AZTEC (low thousands of USD at Aug-2026 prices) — via a staking queue plus committee sampling, not immediate self-inclusion, and governance retains a parameter (the GSE proof-of-possession gas limit) that can block *new* validator deposits, subject to the ≥12d governance delay and without touching existing validators or the escape hatch — and a bonded escape hatch (332M AZTEC enrollment, single-digit $M; a RANDAO-designated candidate may publish ~2 epochs without committee attestations every ~3 days, slashed 9.6M AZTEC on failure). The hatch opens only when an eligible bonded candidate exists, so it is a possible backstop, not a live bypass and not a timing guarantee. The enrollment set was unverified as of this memo (§8). It was read on 2026-11-07 (Ethereum block 26360002): the V6 hatch had zero candidates, and the V5 hatch had zero on 2026-11-06. With zero candidates, no censorship bypass exists and worst-case exit time has no bound. See [ADR 0010](../adr/0010-aztec-flagship-and-production-gates.md#escape-hatch-state-as-an-activation-input).
- **Exit latency floor:** consumability waits for the epoch proof (~32-block epochs; slot time 36–72 s per conflicting sources — §8), so roughly tens of minutes to L1 finality in the normal path. A proving stall freezes consumability — liveness, never safety; the committed recovery is wait/escalate. Unlike the §3.4 pool — whose `submitBatch` and `withdraw()` are permissionless at all times with no operator gate — and unlike the standalone/APL force-exit *design* (`force_exit_path.md`, a design proposal with a 24h `T_OPERATOR_SILENCE` fallback, not implemented), there is no app-level self-help for host proving on Aztec. This is the structural Safeguard-5 delta vs. the EVM pool's always-open 64-root `withdraw()`, and the profile manifest must disclose it.
- **The residual S5 surface is ZKA-authored, not host:** Aztec's docs are explicit that the canonical messaging layer is immutable while each token's locking escrow carries its own trust assumptions. Our portal is already ownerless/immutable — the property holds, and keeping it held is our obligation, not Aztec's.

**Net assessment (c):** app layer conformance is test-locked today, with protocol-enforced contract immutability available as an upgrade to the conformance argument; the binding host residuals are (i) proving-system soundness maturity (two consecutive critical flaws; V6 pending) and (ii) probabilistic inclusion latency (mitigated for private txs, backstopped, never gated by compliance). Neither residual is an admin-key or compliance-gate in the Safeguard sense; both must be disclosed in the profile manifest. They are also activation blockers under ADR-0010.

---

## 6. Item (d) — The pilot equivalent

### 6.1 What carries over unchanged (policy layer, chain-agnostic by construction)

- **Caps as operational policy:** ≈$100/note, ≈$1,000 total escrow, FX re-derivation trigger (±25%), enforced by participant scoping — the caps were never derived from the EVM cost model. The escrow-cap monitor reads the L1 portal's `underlying` balance (the portal is the escrow).
- Participant scoping (operator wallets + invited testers, unannounced), no-rollback posture, halt-new-quotes as an AFP-side routing decision (never a fund restriction), and the audit-is-the-gate rule before any production designation or material escrow.
- The §6.5 communication rule, with Aztec-measured numbers substituted once the benchmark lands (§4.4).
- The launch-evidence checklist *structure* (real proofs on a supported testnet, DA retrievability, independent reconstruction, replay and substitution negatives, permissionless exit, recorded evidence), with Base-specific steps re-worded for Aztec.

### 6.2 What is redefined

- **No aggregator, no cadence.** The pilot operator runs no proving
  service; payers submit their own txs via PXE. The operational role that
  remains is infrastructure: an Aztec node endpoint, the
  `zka-settlement-ops` Aztec monitoring slice (configured via the `[aztec]`
  section of `ops.toml`) — which already exists — polling the proven head
  into the finality view and indexing portal `Withdrawn` consumptions, plus
  `doctor` probes (proven-head liveness
  replaces cadence-stall monitoring; the outbox ledger replaces the
  deposit-queue backlog probe).
- **Monitoring probes** become: L1 portal escrow balance vs. cap (survives
  as-is); tx inclusion latency vs. Aztec block cadence; proven-head
  advancement (frozen proven head = exits stop becoming consumable —
  liveness alert); outbox consumption ledger integrity; immutable-config
  drift check on the portal (survives as-is).
- **Asset:** the portal escrows one ERC-20 on Ethereum L1 — WETH for the
  pay-pool-equivalent (ADR-0002 B1, one portal per asset). Note this is
  L1 mainnet WETH, not Base WETH9; per spec §3.4's frozen-parameters
  discipline, this is a distinct deployment with its own identity and its
  own asset-risk statement.
- **Conformance target:** the spec's dedicated `ZKA-Aztec` level ("full
  Aztec native deployment plus an independently conforming manifest-bound
  Coord v2 Aztec profile"). The Coord v2 Aztec profile has no Base-pilot
  analog and should be explicitly deferred — the pilot targets the pay
  profile; `ZKA-Aztec` remains the eventual level, not the pilot gate.
- **Staging:** TXE + local network/sandbox (now) → alpha-testnet launch
  test (**deferred while Aztec's V5 pause guidance stands** — it is
  deployment work in the guidance's sense; §6.4 gate 1) → capped mainnet
  pilot **only after** the §6.4 gates.

### 6.3 Pilot cost communication (provisional shape)

The pilot statement mandated by §6.5 becomes, once measured numbers exist: "≈$X per private payment on Aztec (measured), versus ≈$0.001 on a public stablecoin rail; the difference is the price of confidentiality" — with the lifecycle legs (L1 deposit + claim; burn + L1 consume) stated separately, since on this profile the entry/exit legs plausibly dominate lifecycle cost at low velocity even more than on Base (§4.1).

### 6.4 Pilot gates (blocking, in order)

1. **Aztec V6 ships and the 2026-07-27 V5 proving-system vulnerability is resolved**, with Aztec's deployment-pause guidance lifted. Two consecutive critical proving flaws (V4, V5) also argue for letting V6 season before escrowing value.
2. **Satisfied in-repo:** the deposit leg exists (portal `depositToAztec` + L2 `claim_private`, with unauthenticated `mint` removed) and has TXE + Forge coverage matching the exit leg's discipline.
3. ADR-0002's remaining acceptance: the env-gated live smoke against a real v5/v6 endpoint, with the deployed portal/Outbox pairing recorded.
4. The independent audit gate the runbooks already impose (adapter public-snapshot certification: `experimental` today; `production` requires an independent audit + operator-signed live acceptance — same bar as the Base pilot).

---

## 7. Go/no-go for the benchmark pass — GO (scoped)

**GO.** All measurability preconditions hold; nothing about the V5 vulnerability blocks *measurement* on a local network/sandbox with no value at risk; and the structural analysis (§3, §4) says this is the one lever that plausibly changes the premium's order of magnitude — exactly what §7 of the economics memo mandates measuring and what the ADAMAS review needs before the Aztec community review.

Scope conditions:

- **Local network / TXE / sandbox execution only, plus read-only probes of public nodes. No deployment to alpha-testnet or mainnet; no value at risk.** Aztec's pause guidance covers V5 *deployment work*, and submitting benchmark contracts to the public testnet sits inside that; testnet execution (the launch test, live burn→consumable latency) is deferred until the guidance lifts or an explicit exemption is documented. Read-only queries of public nodes (fee probes, node info) deploy nothing and are in scope.
- For the recorded benchmark pass, the toolchain was pinned to the workspace's then-current aztec-packages v5.1.0. The workspace now pins v5.2.0; the committed v5.1.0 measurements retain that provenance and must not be silently relabeled as v5.2.0 results.

What to measure (deliverables map to the companion requirement's acceptance: committed benchmark JSONs with pinned toolchain provenance, matching the `zka_pay_gas.json` discipline, plus an economics-model extension or companion memo):

1. **Mana per transaction class** (the gas-analog, deterministic):
   private payment (ZKA-shaped: conservation + interaction-context
   binding), compliance-gated variant, the ADR-0005 claim/deposit leg, and
   withdraw/burn leg. Report DA mana and L2 mana separately, plus measured
   DA bytes (encrypted log payload) per class — and per fee route (purely
   private with fee juice vs. FPC-paid with public setup/teardown; the
   fixed overheads differ, §4.2).
2. **Fee conversion:** observed base fee per mana (DA and L2) via
   **read-only queries** of the public testnet/mainnet nodes (in scope per
   the scope conditions — nothing is deployed or submitted), fee-juice →
   USD via AZTEC price band; render USD as illustrative exactly the way
   `eth_usd=3000` is in the Base model. Each fee observation MUST record
   its provenance: network, block height, query timestamp, node/provider
   URL, price source and date, and separate DA/L2 values. Report the issuance-subsidy caveat
   (§4.2) alongside — both the subsidized fee and an unsubsidized
   DA+verify-amortization estimate at stated volumes.
3. **Client-side proving:** wall-clock p50/p95 for the private payment on
   the same M4 hardware class as the Base numbers (native + browser),
   for comparability with the 555 ms/140 ms `zka_pay_transition` anchors
   and Aztec's self-reported 2.5 s/6.8 s.
4. **Entry/exit legs:** L1 gas for `depositToAztec` and
   `portal.withdraw` (`outbox.consume` + `safeTransfer`) measured against
   the real Outbox on the local network's anvil, in `zka_pay_gas.json`
   discipline; L2 claim and burn tx mana from item 1; end-to-end exit
   latency (burn → consumable) on the **local network**, with public
   networks covered by epoch/proving-cadence arithmetic only — live
   testnet burn→consumable latency is **out of scope for this GO**
   (deferred with the testnet gate in the scope conditions above).
5. **The comparison table** the requirement asks for: Aztec-native
   marginal + lifecycle vs. the Base profile's committed
   $0.2366–$0.3444 (24x7 full fill), ≈$0.85 lone-payment, and $1.3941
   velocity-1 lifecycle, vs. the x402 ≈$0.001 comparator — quantifying
   whether the privacy premium changes order of magnitude.

Model-side: extend `scripts/economics-model.py` (or a sibling `aztec-economics-model.py`) with the same reproducibility posture — committed inputs, CLI-overridable illustrative assumptions, `--check` against committed output — and replace the §7 out-of-scope row for the Aztec-native profile with the measured comparison.

**No-go triggers checked and passed:** fee model measurable at the pinned tag (constants public, formula public; on the local network the genesis-funded test accounts pay fees in fee juice directly — no external funding needed; a sponsored FPC, a testnet/devnet-only facility per docs.aztec.network's fees documentation fetched 2026-08-15, becomes relevant only if/when the deferred testnet stage runs). The executed fee route and its evidence are not claims this memo can carry alone: they are recorded in the companion benchmark set (`docs/benchmarks/zka_aztec_bench.json`, landing with the benchmark PR), where every measurement row carries its block's base fees and reconciles `transactionFee = billedGas × feePerL2Gas` exactly, and every public-node probe records network, block, timestamp, and separate DA/L2 values. Workspace-side at the time of the pass, the workspace built the transfer and exit legs at v5.1.0, then the current-latest pin, so no forced migration occurred mid-pass. The workspace now pins v5.2.0. The deposit leg is NOT a precondition: the pass proceeds without it and reports that leg unmeasured (any stub-derived deposit figures are provisional and excluded from committed lifecycle comparisons — the real portal design is gated on §3.3's invariants).

---

## 8. Open questions carried forward

Items 1–5 below are resolved by ADR 0006 (`docs/adr/0006-aztec-native-pay-profile.md`); they are retained here as the investigation inputs to that decision. Item 6 and the external facts remain open.

Design decisions (for the profile ADR the benchmark pass should feed):

1. **Fee route:** protocol-fee-only (payer holds fee juice) vs. a WETH-denominated FPC (private in-asset fees, revives the fee-note concept). Drives both UX and the cost table's shape.
2. **`interaction_context` carrier** on Aztec: constrained argument vs. private log vs. note field — and the linkage-leak analysis of each. The interaction-binding profile v1 has no Aztec mapping today.
3. **Nullifier-equivalence boundary:** accept platform-substituted nullifiers (current workspace posture; note hashes equal, nullifiers not) or add a binding statement — affects what the profile manifest may claim under §8.5.
4. **Value bound** (2^120−1 vs 2^128 vs spec's u64) and the §2.3.1 randomness conformance statement for PXE-supplied randomness.
5. **Admin surface:** adopt the ownerless recommendation (§5.1) or keep the compliance toggle; either way, claim protocol-enforced immutability via the no-update-path property.
6. **Base reachability — resolved by [ADR 0011](../adr/0011-aztec-ethereum-exit-and-base-reachability.md):** direct Ethereum L1 ingress/egress is accepted architecturally, with no mandatory Base hop. Any optional hop needs separate destination-bound terms and qualification; this does not activate the route or rewrite Base quotes.

External facts to pin down (benchmark pass or later):

7. Prevailing base fee per mana on testnet/mainnet (no published value).
8. Mainnet slot duration (sources conflict: 36 s vs 72 s) and hence the real epoch/withdrawal-latency numbers.
9. V6 timeline and the V5 vulnerability's final disposition — the pilot gate, and worth re-checking before the benchmark pass publishes.
10. Whether the escape-hatch enrollment set is non-empty on mainnet. Read 2026-11-07 (Ethereum block 26360002, V6 EscapeHatch `0x613fF7D166C834816384FeaeA2B48568363A4D57`): `getCandidateCount()` = 0, so no bypass exists today. The owner decision to disclose this state rather than block on it is in [ADR 0010](../adr/0010-aztec-flagship-and-production-gates.md#escape-hatch-state-as-an-activation-input).
11. L2BEAT's $558M TVS vs. ~$33–41M AZTEC market cap — what TVS counts; do not quote TVS as user funds at risk until resolved.
12. Anchor-block recency window for private-tx historical reads (the delegate-target of the 64-root ring) at v5.x.

---

## 9. Sources

**Repo (committed):** `docs/zka_specification.md` §1.6/§3.4/§7.1.6/§8/§8.6/§11.4/§12.1; `docs/sdd/sdd_pay_pool.md`; `docs/sdd/sdd_pay_interaction_binding.md`; `docs/adr/0002-withdraw-l2-to-l1-settlement.md`; `docs/economics/zka_pay_economics.md` (+ `zka_pay_economics_model_output.json`); `docs/benchmarks/zka_pay_gas.{md,json}`, `zka_pay_width_sweep.json`; `docs/operations/{eth_pool_pilot,base_pilot,aztec_outbox,aztec_v5_migration_matrix}.md`; `docs/security/finality_and_bridge_security_policy.md`; `docs/superpowers/specs/2026-07-09-zka-native-eth-pool-design.md`; `aztec/` workspace (`zka_transfer_aztec`, `zka_aztec_lib`, `zka_credential_aztec`); `contracts/ethereum/ZKAAztecPortal.sol`; `certification/aztec.json`.

**External (fetched 2026-08-15; point-in-time):** docs.aztec.network — fees concepts, governance + proposal-lifecycle + upgrades, bridging/messaging, trees/indexed-merkle-tree, rollup circuits; aztec-packages v5.1.0 source (`constants.nr`, `contract_instance_registry_contract`) and GitHub releases; aztec.network blog — "Announcing the Alpha Network" (2026-03-31), "Introducing Alpha V5" (2026-07-21), "Alpha Network security: what to expect" plus the dedicated V5 proving-system disclosure post (vulnerability discovered 2026-07-27, disclosure published 2026-08-07), "Critical vulnerability in Alpha V4", "How Aztec governance works", "Inside an Aztec transaction"; AztecProtocol governance proposal AZUP-1; L2BEAT — Aztec project page (Stage 2 assessment, milestones) and "Decentralised sequencing" deep-dive (censorship/exit modeling, Apr 2026); The Defiant (Alpha V5 launch; Stage 2 note); Cointelegraph (Ignition launch, Nov 2025); CoinGecko/CoinMarketCap (AZTEC price band, Aug 2026).
