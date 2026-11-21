# Aztec reference integration certification

Experimental two-way reference integration targeting Aztec 6.0.0. Compile and test coverage does not establish proving-system qualification. Public-network acceptance and production activation remain gated; compiler diagnostics and holder/runtime limitations remain unresolved. No independent audit has been completed. Not production certified.

| Status dimension | Public status |
|---|---|
| Implementation tier | `experimental` reference integration |
| Deployment | Not activated; complete V6 lifecycle qualification is outstanding |
| Production certification | Absent |
| Independent audit | Missing |
| Public-network acceptance | Deferred pending exact-artifact public-network acceptance |

The machine-readable source of truth is
[`certification/aztec.json`](../../certification/aztec.json). Run
`python3 scripts/validate-certification.py --public-snapshot` from the repository root. The
validator fails closed if a named test, workflow job, path, or contract pattern
is missing. Local settlement coverage uses recorded Aztec-node and L1 JSON-RPC
wire shapes plus the focused portal tests; it is not public-network evidence.

## Known limitations

- The source targets Aztec 6.0.0. Historical V5 measurements and PXE reviews
  do not qualify this V6 candidate. Unresolved compiler `bug:` diagnostics
  prevent a proving-system assurance claim even when compilation exits zero
  and TXE tests pass. No diagnostic exception or production approval is
  granted by this snapshot.
- PXE/wallet randomness, reuse handling and exact-opening recovery require
  evidence for the pinned holder environment. Contract tests cannot prove
  entropy or establish that complete boundary.
- The transfer contract's `get_balance` view uses a bounded note page and
  can under-report balances with more than ten active notes. Do not use it
  as a complete balance or settlement-reconciliation oracle.
- A sixteen-note transfer has failed in TXE at the declared spend boundary;
  complete proof/network capacity qualification remains outstanding. A
  successful smaller spend is not evidence for the declared maximum.
- The standalone [`zka_root_update`](../../noir/zka_root_update/src/main.nr)
  circuit ignores public `deposit_commitments` entries at indices greater
  than or equal to `deposit_commitments_len` without requiring them to be zero.
- The standalone [`zka_withdrawal`](../../noir/zka_withdrawal/src/main.nr)
  circuit requires a nonzero `external_recipient` but does not enforce the
  intended `external_recipient < 2^160` range.

The unpublished APLBridge prevents these two input shapes by constructing a
zero-padded deposit array and encoding a typed address as the withdrawal
recipient. Those protections belong to that integration; they are absent from
the standalone circuit constraints and are not supplied by this snapshot.
Consumers must not infer either property from a valid proof or treat these
experimental circuits as a deployment gate.

The public manifest resolves evidence pointers; it does not run the referenced
checks or independently certify their results. Release evidence must bind
actual execution to the exported tree. Excluded private design and operational
records are enumerated in the documentation-link exception file and are not
part of the released evidence.
