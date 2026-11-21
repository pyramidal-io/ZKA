// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./IAztecInbox.sol";
import "./IAztecOutbox.sol";

/**
 * @title ZKAAztecPortal
 * @notice L1 settlement portal for deposits into and withdrawals from the Aztec
 *         ZKA deployment. See `docs/adr/0002` and `docs/adr/0005`.
 *
 * @dev Model: the Aztec rollup proves every transaction, so withdrawals do NOT
 *      carry an L1 proof. `ZKATransfer.withdraw` burns the sender's notes on L2
 *      and emits an L2->L1 message to this portal via the Aztec Outbox; this
 *      portal consumes that message (with a Merkle inclusion proof against the
 *      rollup's settled output root) and releases the underlying ERC-20. This is
 *      SEPARATE and orthogonal to the verifier-based `ZKAEthPool` (which
 *      releases funds against submitted ZKA/Pay UltraHonk proofs) — they are
 *      two distinct settlement models. The former ZKABridgeEthereum model is
 *      permanently retired.
 *
 * SAFEGUARD 3 & 5 (ZKA v0.6.0 §1.6). This contract is deliberately:
 *   - OWNERLESS — no owner/admin/governance role of any kind.
 *   - NON-UPGRADEABLE — no proxy, no upgrade hook.
 *   - NON-PAUSABLE — no pause/circuit-breaker; exit can never be halted.
 *   - WITHOUT a recovery/sweep path — there is intentionally NO admin function to
 *     move the escrowed funds. Such a path would let an operator seize or redirect
 *     user funds, violating Safeguard 3 ("no admin key may invalidate, freeze,
 *     redirect, or force-transfer a note") and undermining Safeguard 5.
 * All configuration (`outbox`, `inbox`, `l2Bridge`, `rollupVersion`,
 * `underlying`, `assetCommitment`) is IMMUTABLE — fixed at deploy and never
 * changeable. The portal pairs 1:1 with a single L2 ZKATransfer contract and a
 * single underlying asset (ADR 0002, B1; ADR 0005). The constructor requires
 * the Outbox and Inbox to report one rollup and `rollupVersion`.
 *
 * `withdraw` is PERMISSIONLESS: anyone may relay the inclusion proof, and funds
 * always go to the `recipient` encoded in the (rollup-proven) message — the
 * relayer cannot redirect them. The Outbox enforces strict once-only
 * consumption, which is the replay protection.
 */
contract ZKAAztecPortal {
    using SafeERC20 for IERC20;

    /// BN254 scalar field modulus used by Noir/Aztec Field values.
    uint256 internal constant AZTEC_FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// The Aztec L1 Outbox that settles this rollup's L2->L1 messages.
    IAztecOutbox public immutable outbox;

    /// The Aztec L1 Inbox that accepts this portal's L1->L2 deposit messages.
    IAztecInbox public immutable inbox;

    /// The L2 ZKATransfer contract (Aztec address) authorised as the message
    /// sender. Binding this immutably means only that contract's withdrawals can
    /// be settled here — a message from any other L2 contract reconstructs a
    /// different `L2Actor` and fails `outbox.consume`.
    bytes32 public immutable l2Bridge;

    /// The Aztec protocol/rollup version the message was emitted under.
    uint256 public immutable rollupVersion;

    /// The single ERC-20 this portal escrows and releases (one portal per asset).
    IERC20 public immutable underlying;

    /// The ZKA asset commitment represented by `underlying` on L2.
    bytes32 public immutable assetCommitment;

    event DepositedToAztec(
        address indexed depositor,
        bytes32 indexed beneficiary,
        bytes32 indexed assetCommitment,
        uint256 amount,
        bytes32 claimSecretHash,
        bytes32 messageKey,
        uint256 messageIndex
    );

    event Withdrawn(
        address indexed recipient,
        uint256 amount,
        uint256 indexed epoch,
        uint256 numCheckpointsInEpoch,
        uint256 leafIndex,
        uint256 leafId,
        bytes32 root
    );

    constructor(
        IAztecOutbox _outbox,
        IAztecInbox _inbox,
        bytes32 _l2Bridge,
        uint256 _rollupVersion,
        IERC20 _underlying,
        bytes32 _assetCommitment
    ) {
        require(address(_outbox) != address(0), "outbox=0");
        require(address(_inbox) != address(0), "inbox=0");
        require(_l2Bridge != bytes32(0), "l2Bridge=0");
        require(_rollupVersion != 0, "rollupVersion=0");
        require(address(_underlying) != address(0), "underlying=0");
        require(_assetCommitment != bytes32(0), "asset=0");
        require(uint256(_assetCommitment) < AZTEC_FIELD_MODULUS, "asset>=field");
        // Deposits pass through the Inbox and exits through the Outbox. A portal
        // paired across rollups would accept deposits it can never release, and
        // no recovery path exists, so refuse to deploy one.
        address rollup = _outbox.ROLLUP();
        require(rollup != address(0), "rollup=0");
        require(_inbox.ROLLUP() == rollup, "rollup mismatch");
        require(_outbox.VERSION() == _rollupVersion, "outbox version");
        require(_inbox.VERSION() == _rollupVersion, "inbox version");
        outbox = _outbox;
        inbox = _inbox;
        l2Bridge = _l2Bridge;
        rollupVersion = _rollupVersion;
        underlying = _underlying;
        assetCommitment = _assetCommitment;
    }

    /**
     * @notice Escrow `amount` and insert its private-claim message into Aztec.
     * @dev The content binds the immutable asset, amount, and beneficiary. The
     *      Inbox envelope separately binds `claimSecretHash`. Escrow and Inbox
     *      insertion are one EVM transaction, so either both succeed or both
     *      revert. Any account may later relay the private L2 claim, but the
     *      note is always delivered to `beneficiary`.
     *      Callers MUST derive `claimSecretHash` with Aztec V6
     *      `computeSecretHash(secret)` (domain-separated Poseidon2), retain the
     *      secret preimage, and must not substitute keccak256 or SHA-256.
     *      The beneficiary must encode an Aztec V6 address point. This checks
     *      point validity only, not key ownership or the ability to recover it.
     */
    function depositToAztec(uint256 amount, bytes32 beneficiary, bytes32 claimSecretHash)
        external
        returns (bytes32 messageKey, uint256 messageIndex)
    {
        require(amount != 0, "amount=0");
        require(amount <= type(uint128).max, "amount>u128");
        require(beneficiary != bytes32(0), "beneficiary=0");
        require(uint256(beneficiary) < AZTEC_FIELD_MODULUS, "beneficiary>=field");
        require(claimSecretHash != bytes32(0), "secretHash=0");
        require(uint256(claimSecretHash) < AZTEC_FIELD_MODULUS, "secretHash>=field");
        require(_isValidAztecPoint(uint256(beneficiary)), "beneficiary invalid");

        uint256 escrowBefore = underlying.balanceOf(address(this));
        underlying.safeTransferFrom(msg.sender, address(this), amount);
        require(underlying.balanceOf(address(this)) == escrowBefore + amount, "transfer amount mismatch");

        AztecDataStructures.L2Actor memory recipient =
            AztecDataStructures.L2Actor({actor: l2Bridge, version: rollupVersion});
        (messageKey, messageIndex) =
            inbox.sendL2Message(recipient, depositContentHash(beneficiary, amount), claimSecretHash);

        emit DepositedToAztec(
            msg.sender, beneficiary, assetCommitment, amount, claimSecretHash, messageKey, messageIndex
        );
    }

    /// Matches Aztec V6 AztecAddress.is_valid: y^2 = x^3 - 17 over the
    /// BN254 scalar field. A valid point does not establish key ownership.
    function _isValidAztecPoint(uint256 x) internal view returns (bool) {
        if (x >= AZTEC_FIELD_MODULUS) return false;
        uint256 rhs = addmod(
            mulmod(mulmod(x, x, AZTEC_FIELD_MODULUS), x, AZTEC_FIELD_MODULUS),
            AZTEC_FIELD_MODULUS - 17,
            AZTEC_FIELD_MODULUS
        );
        return _isSquareAztecFieldElement(rhs);
    }

    /// Euler's criterion for a canonical field element, including sqrt(0).
    /// Fixed 32-byte operands bound the precompile cost. Fail closed if the
    /// chain lacks modexp support or returns malformed data; no token or Inbox
    /// call has occurred when this check runs.
    function _isSquareAztecFieldElement(uint256 rhs) internal view returns (bool) {
        if (rhs == 0) return true;
        uint256[6] memory input =
            [uint256(32), uint256(32), uint256(32), rhs, (AZTEC_FIELD_MODULUS - 1) / 2, AZTEC_FIELD_MODULUS];
        uint256[1] memory output;
        bool success;
        uint256 returnSize;
        /// @solidity memory-safe-assembly
        assembly {
            success := staticcall(50000, 0x05, input, 0xc0, output, 0x20)
            returnSize := returndatasize()
        }
        return success && returnSize == 32 && output[0] == 1;
    }

    /**
     * @notice Canonical L1->L2 content hash for a private ZKA deposit claim.
     * @dev MUST equal L2 `deposit_content_hash(beneficiary, asset, amount)`:
     *      sha256_to_field(selector("claim_private(bytes32,bytes32,uint256)")
     *      ++ beneficiary_be(32) ++ asset_be(32) ++ amount_be(32)).
     */
    function depositContentHash(bytes32 beneficiary, uint256 amount) public view returns (bytes32) {
        return AztecHash.sha256ToField(
            abi.encodeWithSignature("claim_private(bytes32,bytes32,uint256)", beneficiary, assetCommitment, amount)
        );
    }

    /**
     * @notice Settle a ZKA withdrawal: consume the L2->L1 message and release
     *         `amount` of the underlying to `recipient`.
     * @dev Reconstructs the exact message `ZKATransfer._process_withdrawal`
     *      emitted, consumes it from the Outbox (reverts if not included or
     *      already consumed), then transfers. No access control — permissionless
     *      relay; the recipient/amount are fixed by the rollup-proven message.
     */
    function withdraw(
        address recipient,
        uint256 amount,
        uint256 epoch,
        uint256 numCheckpointsInEpoch,
        uint256 leafIndex,
        bytes32[] calldata path
    ) external {
        require(path.length < 256, "path too deep");
        AztecDataStructures.L2ToL1Msg memory message = AztecDataStructures.L2ToL1Msg({
            sender: AztecDataStructures.L2Actor({actor: l2Bridge, version: rollupVersion}),
            recipient: AztecDataStructures.L1Actor({actor: address(this), chainId: block.chainid}),
            content: withdrawContentHash(recipient, amount)
        });

        bytes32 root = outbox.getRootData(epoch, numCheckpointsInEpoch);
        uint256 leafId = (uint256(1) << path.length) + leafIndex;

        outbox.consume(message, epoch, numCheckpointsInEpoch, leafIndex, path);

        underlying.safeTransfer(recipient, amount);
        emit Withdrawn(recipient, amount, epoch, numCheckpointsInEpoch, leafIndex, leafId, root);
    }

    /**
     * @notice The L2->L1 content hash for a `(recipient, amount)` withdrawal.
     * @dev MUST equal the L2 `zka_transfer_aztec` `withdraw_content_hash`:
     *      `sha256_to_field( keccak256("withdraw(address,uint256)")[0..4]=0xf3fef3a3
     *       ++ recipient_be(32) ++ amount_be(32) )`. `abi.encodeWithSignature`
     *      produces exactly `selector ++ abi.encode(recipient) ++ abi.encode(amount)`
     *      = that 68-byte preimage, and `AztecHash.sha256ToField` matches Noir's
     *      `sha256_to_field`. Exposed (and unit-tested against the L2 golden) so
     *      the cross-environment encoding can be checked on-chain.
     */
    function withdrawContentHash(address recipient, uint256 amount) public pure returns (bytes32) {
        return AztecHash.sha256ToField(abi.encodeWithSignature("withdraw(address,uint256)", recipient, amount));
    }
}
