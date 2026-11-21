# ZKA 0.9.2-draft release notes

Experimental two-way reference integration targeting Aztec 6.0.0. Compile and test coverage does not establish proving-system qualification. Public-network acceptance and production activation remain gated; compiler diagnostics and holder/runtime limitations remain unresolved. No independent audit has been completed. Not production certified.

This is the initial fresh-history public baseline. Earlier draft version
numbers describe specification evolution, not earlier public releases.
The exported source is selected from canonical development main; the public
commit is a distinct exporter-created root with no private ancestry.

The [launch source lock](../protocol-family/launch-source-lock-v2.json)
records the reviewed development source identities for
ZKA 0.9.2-draft, ZKC 0.4.1-draft, AFP 0.3.14-draft, AFP-KDC 1.0.3, ZKM rev 13,
and the LangGraph integration. These identifiers are compatibility evidence,
not public commit IDs or proof that another repository has been released.

The baseline contains the normative specification, Noir/BN254 circuits,
Aztec 6.0.0 transfer, credential and ownerless Pay reference packages, focused
L1 portal, Rust adapter, and public certification evidence pointers. It binds
AFP session and presentation contexts and preserves profile-specific value,
nullifier and receipt semantics. A reference package does not imply a
qualified deployment or a production-supported holder environment.

Read the [certification report](certification/aztec.md) for unresolved compiler,
randomness, balance-view and spend-capacity limitations. The snapshot includes
source and deterministic test fixtures; generated proofs, deployment records,
credentials, endpoints and unrelated operational tooling are excluded.
