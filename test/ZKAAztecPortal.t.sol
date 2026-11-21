// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../contracts/ethereum/ZKAAztecPortal.sol";
import "../contracts/ethereum/IAztecInbox.sol";
import "../contracts/ethereum/IAztecOutbox.sol";

/// Minimal ERC-20 with a public mint, for the portal escrow tests.
contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// ERC-20 that charges one unit on every non-mint transfer. SafeERC20 sees a
/// successful call, but the recipient receives less than the declared amount.
contract FeeOnTransferERC20 is ERC20 {
    constructor() ERC20("Fee Token", "FEE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && value != 0) {
            super._update(from, to, value - 1);
            super._update(from, address(0xFEE), 1);
        } else {
            super._update(from, to, value);
        }
    }
}

/// Mock Aztec Outbox: records the last consumed message, enforces strict
/// once-only consumption per (epoch, leafId), and can be toggled to reject
/// (simulating a not-yet-settled / not-included message). AZUP-2/v5 exposes
/// multiple roots per epoch, keyed by numCheckpointsInEpoch.
contract MockOutbox is IAztecOutbox {
    uint256 internal constant MAX_CHECKPOINTS_PER_EPOCH = 32;

    address public override ROLLUP;
    uint256 public override VERSION;

    mapping(bytes32 => bool) public consumedKey;
    mapping(bytes32 => bytes32) public roots;
    bool public rejectAll;

    bytes32 public lastSenderActor;
    uint256 public lastSenderVersion;
    address public lastRecipientActor;
    uint256 public lastRecipientChainId;
    bytes32 public lastContent;
    uint256 public lastEpoch;
    uint256 public lastNumCheckpointsInEpoch;
    uint256 public lastLeafIndex;
    uint256 public lastLeafId;
    bytes32 public lastRoot;

    event RootAdded(uint256 indexed epoch, uint256 indexed numCheckpointsInEpoch, bytes32 root);
    event MessageConsumed(
        bytes32 indexed entryKey,
        uint256 indexed epoch,
        uint256 indexed leafId,
        uint256 numCheckpointsInEpoch,
        uint256 leafIndex,
        bytes32 root
    );

    constructor(address rollup, uint256 version) {
        ROLLUP = rollup;
        VERSION = version;
    }

    function setReject(bool r) external {
        rejectAll = r;
    }

    function addRoot(uint256 epoch, uint256 numCheckpointsInEpoch, bytes32 root) external {
        require(
            numCheckpointsInEpoch > 0 && numCheckpointsInEpoch <= MAX_CHECKPOINTS_PER_EPOCH, "outbox: bad root count"
        );
        roots[keccak256(abi.encode(epoch, numCheckpointsInEpoch))] = root;
        emit RootAdded(epoch, numCheckpointsInEpoch, root);
    }

    function getRootData(uint256 epoch, uint256 numCheckpointsInEpoch) external view override returns (bytes32) {
        return roots[keccak256(abi.encode(epoch, numCheckpointsInEpoch))];
    }

    function getRoots(uint256 epoch) external view override returns (bytes32[] memory result) {
        result = new bytes32[](MAX_CHECKPOINTS_PER_EPOCH);
        for (uint256 i = 1; i <= MAX_CHECKPOINTS_PER_EPOCH; i++) {
            result[i - 1] = roots[keccak256(abi.encode(epoch, i))];
        }
    }

    function consume(
        AztecDataStructures.L2ToL1Msg calldata message,
        uint256 epoch,
        uint256 numCheckpointsInEpoch,
        uint256 leafIndex,
        bytes32[] calldata path
    ) external override {
        require(!rejectAll, "outbox: not included");
        bytes32 root = roots[keccak256(abi.encode(epoch, numCheckpointsInEpoch))];
        require(root != bytes32(0), "outbox: root not found");
        uint256 leafId = (uint256(1) << path.length) + leafIndex;
        bytes32 key = keccak256(abi.encode(epoch, leafId));
        require(!consumedKey[key], "outbox: already consumed");
        consumedKey[key] = true;

        lastSenderActor = message.sender.actor;
        lastSenderVersion = message.sender.version;
        lastRecipientActor = message.recipient.actor;
        lastRecipientChainId = message.recipient.chainId;
        lastContent = message.content;
        lastEpoch = epoch;
        lastNumCheckpointsInEpoch = numCheckpointsInEpoch;
        lastLeafIndex = leafIndex;
        lastLeafId = leafId;
        lastRoot = root;
        emit MessageConsumed(key, epoch, leafId, numCheckpointsInEpoch, leafIndex, root);
    }
}

/// Mock Aztec Inbox: records the exact L1->L2 message envelope and returns a
/// deterministic key/index pair. This test double covers only the external
/// rollup boundary; escrow and content construction remain real portal code.
contract MockInbox is IAztecInbox {
    address public override ROLLUP;
    uint256 public override VERSION;

    bool public rejectAll;
    uint256 public nextIndex = 41;

    bytes32 public lastRecipientActor;
    uint256 public lastRecipientVersion;
    bytes32 public lastContent;
    bytes32 public lastSecretHash;

    constructor(address rollup, uint256 version) {
        ROLLUP = rollup;
        VERSION = version;
    }

    function setReject(bool reject) external {
        rejectAll = reject;
    }

    function sendL2Message(AztecDataStructures.L2Actor memory recipient, bytes32 content, bytes32 secretHash)
        external
        override
        returns (bytes32 key, uint256 index)
    {
        require(!rejectAll, "inbox: rejected");

        lastRecipientActor = recipient.actor;
        lastRecipientVersion = recipient.version;
        lastContent = content;
        lastSecretHash = secretHash;

        index = nextIndex++;
        key = keccak256(abi.encode(msg.sender, recipient.actor, recipient.version, content, secretHash, index));
    }
}

/// Exposes internal point arithmetic without adding a portal production API.
contract ZKAAztecPortalPointHarness is ZKAAztecPortal {
    constructor(IAztecOutbox outbox_, IAztecInbox inbox_, IERC20 token_)
        ZKAAztecPortal(outbox_, inbox_, bytes32(uint256(1)), outbox_.VERSION(), token_, bytes32(uint256(1)))
    {}

    function isValidPoint(uint256 x) external view returns (bool) {
        return _isValidAztecPoint(x);
    }

    function isSquare(uint256 rhs) external view returns (bool) {
        return _isSquareAztecFieldElement(rhs);
    }
}

contract ZKAAztecPortalTest is Test {
    ZKAAztecPortal internal portal;
    MockOutbox internal outbox;
    MockInbox internal inbox;
    MockERC20 internal token;
    ZKAAztecPortalPointHarness internal pointHarness;

    bytes32 internal constant L2_BRIDGE = bytes32(uint256(0xABCDEF));
    bytes32 internal constant ASSET_COMMITMENT = bytes32(uint256(0x1111));
    // Historical hash golden remains byte-for-byte unchanged, even though its
    // beneficiary is off-curve. Deposits use a valid point fixture instead.
    bytes32 internal constant BENEFICIARY = bytes32(uint256(0xBEEF));
    bytes32 internal constant DEPOSIT_BENEFICIARY = bytes32(uint256(1));
    uint256 internal constant CLAIM_SECRET = 0x123456;
    // Aztec v5 computeSecretHash(Fr(0x123456)); pinned against
    // @aztec/stdlib/hash's domain-separated Poseidon2 implementation.
    bytes32 internal constant AZTEC_HASH_FIXTURE = 0x1e3cf2b3d167833b6e447285a470612b27e13f01739b5325d9821594f54cda04;
    uint256 internal constant AZTEC_FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant ROLLUP_VERSION = 2_070_860_440;
    address internal constant ROLLUP = address(0xA2706);
    address internal constant OTHER_ROLLUP = address(0xB2706);
    uint256 internal constant ESCROW = 1_000_000;
    uint256 internal constant DEPOSITOR_BALANCE = 500_000;
    uint256 internal constant EPOCH = 7;
    uint256 internal constant NUM_CHECKPOINTS_IN_EPOCH = 2;
    uint256 internal constant LEAF_INDEX = 3;
    bytes32 internal constant ROOT = bytes32(uint256(0xA11CE));

    event Withdrawn(
        address indexed recipient,
        uint256 amount,
        uint256 indexed epoch,
        uint256 numCheckpointsInEpoch,
        uint256 leafIndex,
        uint256 leafId,
        bytes32 root
    );

    function setUp() public {
        outbox = new MockOutbox(ROLLUP, ROLLUP_VERSION);
        inbox = new MockInbox(ROLLUP, ROLLUP_VERSION);
        outbox.addRoot(EPOCH, NUM_CHECKPOINTS_IN_EPOCH, ROOT);
        token = new MockERC20();
        portal = new ZKAAztecPortal(outbox, inbox, L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
        pointHarness = new ZKAAztecPortalPointHarness(outbox, inbox, token);
        token.mint(address(portal), ESCROW);
        token.mint(address(this), DEPOSITOR_BALANCE);
        token.approve(address(portal), type(uint256).max);
    }

    function proofPath() internal pure returns (bytes32[] memory path) {
        path = new bytes32[](2);
        path[0] = bytes32(uint256(0xAA));
        path[1] = bytes32(uint256(0xBB));
    }

    /// THE cross-environment check: the L1 content hash for (0xbeef, 1000) must
    /// equal the value the L2 `zka_transfer_aztec::withdraw_content_hash`
    /// computes for the same inputs (golden printed from the Noir code). If the
    /// selector, byte layout, or sha256->field truncation diverged, this fails.
    function test_ContentHashMatchesL2Golden() public view {
        bytes32 golden = 0x002c54ccb6af0251a12093d39b5dd48465cf1061ebf84a15c54cb7839261ef99;
        assertEq(
            portal.withdrawContentHash(address(0xbeef), 1000),
            golden,
            "L1 content must equal the L2 withdraw_content_hash"
        );
    }

    /// Cross-environment deposit golden. This literal was independently
    /// derived from selector("claim_private(bytes32,bytes32,uint256)") plus
    /// ABI-encoded beneficiary/asset/amount, then Aztec sha256-to-field.
    function test_DepositContentHashMatchesL2Golden() public view {
        bytes32 golden = 0x0087ee5a621afb4fde01701656cff070640af03e3b4bc551975c6e3168dcb6bb;
        assertEq(
            portal.depositContentHash(BENEFICIARY, 1000), golden, "L1 deposit content must equal the L2 claim hash"
        );
    }

    function test_DepositUsesAztecV5SecretHashFixture() public {
        portal.depositToAztec(1, DEPOSIT_BENEFICIARY, AZTEC_HASH_FIXTURE);

        assertEq(CLAIM_SECRET, 0x123456, "fixture preimage");
        assertEq(inbox.lastSecretHash(), AZTEC_HASH_FIXTURE, "Inbox receives computeSecretHash(preimage)");
    }

    /// A successful deposit escrows exactly the declared amount before inserting
    /// an Inbox message for the immutable L2 bridge. The content binds the
    /// beneficiary, immutable asset, and amount; the envelope binds the secret.
    function test_DepositEscrowsAndSendsBoundInboxMessage() public {
        uint256 amount = 1000;
        uint256 beforeBalance = token.balanceOf(address(portal));

        (bytes32 key, uint256 index) = portal.depositToAztec(amount, DEPOSIT_BENEFICIARY, AZTEC_HASH_FIXTURE);

        assertEq(token.balanceOf(address(portal)), beforeBalance + amount, "escrow credited");
        assertEq(token.balanceOf(address(this)), DEPOSITOR_BALANCE - amount, "depositor debited");
        assertEq(inbox.lastRecipientActor(), L2_BRIDGE, "recipient = immutable L2 bridge");
        assertEq(inbox.lastRecipientVersion(), ROLLUP_VERSION, "recipient rollup version");
        assertEq(
            inbox.lastContent(),
            portal.depositContentHash(DEPOSIT_BENEFICIARY, amount),
            "content binds beneficiary, asset, amount"
        );
        assertEq(inbox.lastSecretHash(), AZTEC_HASH_FIXTURE, "envelope binds claim secret hash");
        assertEq(index, 41, "Inbox leaf index returned");
        assertTrue(key != bytes32(0), "Inbox message key returned");
    }

    /// Mutating any claim tuple component must select a different message.
    /// Beneficiary and amount are call inputs; asset is immutable per portal.
    function test_DepositContentBindsBeneficiaryAssetAndAmount() public {
        bytes32 baseline = portal.depositContentHash(BENEFICIARY, 1000);
        assertNotEq(baseline, portal.depositContentHash(bytes32(uint256(0xDEAD)), 1000), "beneficiary must be bound");
        assertNotEq(baseline, portal.depositContentHash(BENEFICIARY, 1001), "amount must be bound");

        ZKAAztecPortal otherAssetPortal =
            new ZKAAztecPortal(outbox, inbox, L2_BRIDGE, ROLLUP_VERSION, token, bytes32(uint256(0x2222)));
        assertNotEq(baseline, otherAssetPortal.depositContentHash(BENEFICIARY, 1000), "asset must be bound");
    }

    /// Inbox insertion and escrow are atomic: if message insertion fails, the
    /// preceding ERC-20 transfer must roll back completely.
    function test_DepositRollsBackEscrowWhenInboxRejects() public {
        inbox.setReject(true);
        uint256 portalBefore = token.balanceOf(address(portal));
        uint256 depositorBefore = token.balanceOf(address(this));

        vm.expectRevert(bytes("inbox: rejected"));
        portal.depositToAztec(1000, DEPOSIT_BENEFICIARY, AZTEC_HASH_FIXTURE);

        assertEq(token.balanceOf(address(portal)), portalBefore, "portal balance unchanged");
        assertEq(token.balanceOf(address(this)), depositorBefore, "depositor balance unchanged");
    }

    /// A successful ERC-20 return value is insufficient: the portal must reject
    /// tokens that deliver less than the amount committed into the Inbox.
    function test_DepositRejectsFeeOnTransferUndercollateralization() public {
        FeeOnTransferERC20 feeToken = new FeeOnTransferERC20();
        ZKAAztecPortal feePortal =
            new ZKAAztecPortal(outbox, inbox, L2_BRIDGE, ROLLUP_VERSION, feeToken, ASSET_COMMITMENT);
        feeToken.mint(address(this), 1000);
        feeToken.approve(address(feePortal), 1000);

        vm.expectRevert(bytes("transfer amount mismatch"));
        feePortal.depositToAztec(1000, DEPOSIT_BENEFICIARY, AZTEC_HASH_FIXTURE);

        assertEq(feeToken.balanceOf(address(feePortal)), 0, "undercollateralized escrow rolled back");
        assertEq(inbox.lastContent(), bytes32(0), "no Inbox message inserted");
    }

    function test_DepositRejectsUnclaimableInputs() public {
        vm.expectRevert(bytes("amount=0"));
        portal.depositToAztec(0, DEPOSIT_BENEFICIARY, AZTEC_HASH_FIXTURE);

        vm.expectRevert(bytes("amount>u128"));
        portal.depositToAztec(uint256(type(uint128).max) + 1, DEPOSIT_BENEFICIARY, AZTEC_HASH_FIXTURE);

        vm.expectRevert(bytes("beneficiary=0"));
        portal.depositToAztec(1, bytes32(0), AZTEC_HASH_FIXTURE);

        vm.expectRevert(bytes("secretHash=0"));
        portal.depositToAztec(1, DEPOSIT_BENEFICIARY, bytes32(0));

        vm.expectRevert(bytes("beneficiary>=field"));
        portal.depositToAztec(1, bytes32(AZTEC_FIELD_MODULUS), AZTEC_HASH_FIXTURE);

        vm.expectRevert(bytes("secretHash>=field"));
        portal.depositToAztec(1, DEPOSIT_BENEFICIARY, bytes32(AZTEC_FIELD_MODULUS));
    }

    /// Fixtures independently evaluated with Python pow(rhs, (p-1)//2, p),
    /// matching pinned Aztec V6 types/address/aztec_address.nr get_y().
    function test_PointValidityReferenceFixtures() public view {
        uint256[8] memory valid = [uint256(1), 2, 5, 8, 10, 13, AZTEC_FIELD_MODULUS - 2, AZTEC_FIELD_MODULUS - 1];
        for (uint256 i; i < valid.length; i++) {
            assertTrue(pointHarness.isValidPoint(valid[i]), "reference square must be accepted");
        }
        uint256[10] memory invalid = [uint256(0), 3, 4, 6, 7, 9, 17, 0xBEEF, 0xDEAD, AZTEC_FIELD_MODULUS - 3];
        for (uint256 i; i < invalid.length; i++) {
            assertFalse(pointHarness.isValidPoint(invalid[i]), "reference non-square must be rejected");
        }
        assertFalse(pointHarness.isValidPoint(AZTEC_FIELD_MODULUS), "modulus is not a canonical address");
        assertFalse(pointHarness.isValidPoint(type(uint256).max), "oversized address is not canonical");
    }

    /// Noir sqrt(0) returns Some(0), not None. The field helper must retain
    /// that edge even though x^3=17 has no solution in this field.
    function test_FieldSquareZeroSemantics() public view {
        assertTrue(pointHarness.isSquare(0), "zero has a square root");
        assertTrue(pointHarness.isSquare(1), "one has a square root");
        assertTrue(pointHarness.isSquare(AZTEC_FIELD_MODULUS - 1), "minus one is a square in this field");
    }

    function testFuzz_PointValidityMatchesIndependentExponentiation(uint256 x) public view {
        x = bound(x, 0, AZTEC_FIELD_MODULUS - 1);
        uint256 rhs = addmod(
            mulmod(mulmod(x, x, AZTEC_FIELD_MODULUS), x, AZTEC_FIELD_MODULUS),
            AZTEC_FIELD_MODULUS - 17,
            AZTEC_FIELD_MODULUS
        );
        // Separate square-and-multiply implementation, with no precompile.
        uint256 exponent = (AZTEC_FIELD_MODULUS - 1) / 2;
        uint256 result = 1;
        uint256 base = rhs;
        while (exponent != 0) {
            if ((exponent & 1) != 0) result = mulmod(result, base, AZTEC_FIELD_MODULUS);
            base = mulmod(base, base, AZTEC_FIELD_MODULUS);
            exponent >>= 1;
        }
        assertEq(pointHarness.isValidPoint(x), rhs == 0 || result == 1, "precompile/reference divergence");
    }

    function test_DepositRejectsInvalidPointBeforeAnyTokenOrInboxCall() public {
        vm.expectCall(address(token), abi.encodeCall(IERC20.balanceOf, (address(portal))), uint64(0));
        vm.expectCall(
            address(token), abi.encodeCall(IERC20.transferFrom, (address(this), address(portal), 1)), uint64(0)
        );
        AztecDataStructures.L2Actor memory recipient =
            AztecDataStructures.L2Actor({actor: L2_BRIDGE, version: ROLLUP_VERSION});
        vm.expectCall(
            address(inbox),
            abi.encodeCall(
                IAztecInbox.sendL2Message,
                (recipient, portal.depositContentHash(bytes32(uint256(3)), 1), AZTEC_HASH_FIXTURE)
            ),
            uint64(0)
        );
        vm.expectRevert(bytes("beneficiary invalid"));
        portal.depositToAztec(1, bytes32(uint256(3)), AZTEC_HASH_FIXTURE);
        assertEq(inbox.nextIndex(), 41, "no message inserted");
    }

    function test_DepositAcceptsValidPointsAtFieldUpperBoundary() public {
        portal.depositToAztec(1, bytes32(AZTEC_FIELD_MODULUS - 1), AZTEC_HASH_FIXTURE);
        portal.depositToAztec(1, bytes32(AZTEC_FIELD_MODULUS - 2), AZTEC_HASH_FIXTURE);
        assertEq(token.balanceOf(address(portal)), ESCROW + 2, "valid boundary points escrowed");
        assertEq(inbox.nextIndex(), 43, "both valid boundary messages inserted");
        vm.expectRevert(bytes("beneficiary invalid"));
        portal.depositToAztec(1, bytes32(AZTEC_FIELD_MODULUS - 3), AZTEC_HASH_FIXTURE);
    }

    function testFuzz_DepositRejectsNoncanonicalPoints(uint256 x) public {
        x = bound(x, AZTEC_FIELD_MODULUS, type(uint256).max);
        vm.expectRevert(bytes("beneficiary>=field"));
        portal.depositToAztec(1, bytes32(x), AZTEC_HASH_FIXTURE);
    }

    function test_PointCheckFailsClosedOnModexpFailure() public {
        vm.mockCallRevert(address(5), _pointModexpInput(1), bytes("precompile unavailable"));
        vm.expectRevert(bytes("beneficiary invalid"));
        portal.depositToAztec(1, DEPOSIT_BENEFICIARY, AZTEC_HASH_FIXTURE);
        assertEq(token.balanceOf(address(portal)), ESCROW, "no escrow after precompile failure");
        assertEq(inbox.nextIndex(), 41, "no message after precompile failure");
    }

    function test_PointCheckFailsClosedOnMalformedModexpResponse() public {
        bytes memory input = _pointModexpInput(1);
        vm.mockCall(address(5), input, bytes(""));
        assertFalse(pointHarness.isValidPoint(1), "empty response rejected");
        vm.mockCall(address(5), input, new bytes(31));
        assertFalse(pointHarness.isValidPoint(1), "short response rejected");
        vm.mockCall(address(5), input, abi.encode(uint256(1), uint256(1)));
        assertFalse(pointHarness.isValidPoint(1), "oversized response rejected");
        vm.mockCall(address(5), input, abi.encode(uint256(2)));
        assertFalse(pointHarness.isValidPoint(1), "unexpected residue value rejected");
    }

    function test_PointValidationGasIsBounded() public view {
        uint256 beforeGas = gasleft();
        bool valid = pointHarness.isValidPoint(1);
        uint256 used = beforeGas - gasleft();
        assertTrue(valid);
        assertLt(used, 50_000, "fixed-size point check must remain bounded");
    }

    function _pointModexpInput(uint256 x) internal pure returns (bytes memory) {
        uint256 rhs = addmod(
            mulmod(mulmod(x, x, AZTEC_FIELD_MODULUS), x, AZTEC_FIELD_MODULUS),
            AZTEC_FIELD_MODULUS - 17,
            AZTEC_FIELD_MODULUS
        );
        return
            abi.encode(uint256(32), uint256(32), uint256(32), rhs, (AZTEC_FIELD_MODULUS - 1) / 2, AZTEC_FIELD_MODULUS);
    }

    /// Happy path: consume the message and release the asset to the recipient,
    /// and the reconstructed message matches what the portal consumed.
    function test_WithdrawConsumesAndReleases() public {
        address recipient = address(0xbeef);
        uint256 amount = 1000;
        bytes32[] memory path = proofPath();

        portal.withdraw(recipient, amount, EPOCH, NUM_CHECKPOINTS_IN_EPOCH, LEAF_INDEX, path);

        assertEq(token.balanceOf(recipient), amount, "recipient received the asset");
        assertEq(token.balanceOf(address(portal)), ESCROW - amount, "escrow debited");
        assertEq(outbox.lastContent(), portal.withdrawContentHash(recipient, amount), "content");
        assertEq(outbox.lastSenderActor(), L2_BRIDGE, "sender = the bound L2 bridge");
        assertEq(outbox.lastSenderVersion(), ROLLUP_VERSION, "rollup version");
        assertEq(outbox.lastRecipientActor(), address(portal), "recipient actor = this portal");
        assertEq(outbox.lastRecipientChainId(), block.chainid, "chain id");
        assertEq(outbox.lastEpoch(), EPOCH, "epoch");
        assertEq(outbox.lastNumCheckpointsInEpoch(), NUM_CHECKPOINTS_IN_EPOCH, "num checkpoints");
        assertEq(outbox.lastLeafIndex(), LEAF_INDEX, "leaf index");
        assertEq(outbox.lastLeafId(), 7, "leaf id = 2^pathLen + leafIndex");
        assertEq(outbox.lastRoot(), ROOT, "root");
    }

    function test_WithdrawnEventCarriesV5ReplayKey() public {
        address recipient = address(0xbeef);
        bytes32[] memory path = proofPath();
        vm.expectEmit(true, true, false, true);
        emit Withdrawn(recipient, 1000, EPOCH, NUM_CHECKPOINTS_IN_EPOCH, LEAF_INDEX, 7, ROOT);
        portal.withdraw(recipient, 1000, EPOCH, NUM_CHECKPOINTS_IN_EPOCH, LEAF_INDEX, path);
    }

    /// Permissionless: any relayer may settle; funds still go to the encoded
    /// recipient, never the caller.
    function test_WithdrawIsPermissionless() public {
        address recipient = address(0xCAFE);
        bytes32[] memory path = proofPath();
        vm.prank(address(0xDEAD)); // arbitrary relayer
        portal.withdraw(recipient, 500, EPOCH, NUM_CHECKPOINTS_IN_EPOCH, LEAF_INDEX, path);
        assertEq(token.balanceOf(recipient), 500, "funds go to the message recipient");
        assertEq(token.balanceOf(address(0xDEAD)), 0, "relayer gets nothing");
    }

    /// If the Outbox rejects (message not settled/included), withdraw reverts and
    /// nothing is transferred.
    function test_WithdrawRevertsIfOutboxRejects() public {
        outbox.setReject(true);
        bytes32[] memory path = proofPath();
        vm.expectRevert(bytes("outbox: not included"));
        portal.withdraw(address(0xbeef), 1000, EPOCH, NUM_CHECKPOINTS_IN_EPOCH, LEAF_INDEX, path);
        assertEq(token.balanceOf(address(0xbeef)), 0, "no release on rejected message");
    }

    /// Replay protection: the Outbox consumes each message once; a second
    /// settlement of the same (epoch, leafId) reverts.
    function test_OutboxEnforcesOnceOnly() public {
        bytes32[] memory path = proofPath();
        portal.withdraw(address(0xbeef), 1000, EPOCH, NUM_CHECKPOINTS_IN_EPOCH, LEAF_INDEX, path);
        vm.expectRevert(bytes("outbox: already consumed"));
        portal.withdraw(address(0xbeef), 1000, EPOCH, NUM_CHECKPOINTS_IN_EPOCH, LEAF_INDEX, path);
    }

    function test_OutboxRejectsWrongNumCheckpoints() public {
        bytes32[] memory path = proofPath();
        vm.expectRevert(bytes("outbox: root not found"));
        portal.withdraw(address(0xbeef), 1000, EPOCH, 3, LEAF_INDEX, path);
    }

    function test_OutboxRejectsDuplicateLeafIdAcrossPartialRoots() public {
        bytes32[] memory path = proofPath();
        portal.withdraw(address(0xbeef), 1000, EPOCH, NUM_CHECKPOINTS_IN_EPOCH, LEAF_INDEX, path);

        outbox.addRoot(EPOCH, 3, bytes32(uint256(0xB0B)));
        vm.expectRevert(bytes("outbox: already consumed"));
        portal.withdraw(address(0xcafe), 500, EPOCH, 3, LEAF_INDEX, path);
    }

    /// Config is immutable and validated at deploy.
    function test_ConstructorRejectsZeroConfig() public {
        vm.expectRevert(bytes("outbox=0"));
        new ZKAAztecPortal(IAztecOutbox(address(0)), inbox, L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
        vm.expectRevert(bytes("inbox=0"));
        new ZKAAztecPortal(outbox, IAztecInbox(address(0)), L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
        vm.expectRevert(bytes("l2Bridge=0"));
        new ZKAAztecPortal(outbox, inbox, bytes32(0), ROLLUP_VERSION, token, ASSET_COMMITMENT);
        vm.expectRevert(bytes("underlying=0"));
        new ZKAAztecPortal(outbox, inbox, L2_BRIDGE, ROLLUP_VERSION, IERC20(address(0)), ASSET_COMMITMENT);
        vm.expectRevert(bytes("asset=0"));
        new ZKAAztecPortal(outbox, inbox, L2_BRIDGE, ROLLUP_VERSION, token, bytes32(0));
        vm.expectRevert(bytes("asset>=field"));
        new ZKAAztecPortal(outbox, inbox, L2_BRIDGE, ROLLUP_VERSION, token, bytes32(AZTEC_FIELD_MODULUS));
        vm.expectRevert(bytes("rollupVersion=0"));
        new ZKAAztecPortal(outbox, inbox, L2_BRIDGE, 0, token, ASSET_COMMITMENT);
    }

    /// A portal paired across rollups takes deposits it can never release, and
    /// no recovery path exists, so each mismatch must stop the deployment.
    function test_ConstructorRejectsOutboxAndInboxFromDifferentRollups() public {
        MockInbox otherRollupInbox = new MockInbox(OTHER_ROLLUP, ROLLUP_VERSION);
        vm.expectRevert(bytes("rollup mismatch"));
        new ZKAAztecPortal(outbox, otherRollupInbox, L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
    }

    function test_ConstructorRejectsUnsetRollup() public {
        MockOutbox unsetOutbox = new MockOutbox(address(0), ROLLUP_VERSION);
        MockInbox unsetInbox = new MockInbox(address(0), ROLLUP_VERSION);
        vm.expectRevert(bytes("rollup=0"));
        new ZKAAztecPortal(unsetOutbox, unsetInbox, L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
    }

    function test_ConstructorRejectsOutboxVersionMismatch() public {
        MockOutbox otherVersionOutbox = new MockOutbox(ROLLUP, ROLLUP_VERSION + 1);
        vm.expectRevert(bytes("outbox version"));
        new ZKAAztecPortal(otherVersionOutbox, inbox, L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
    }

    function test_ConstructorRejectsInboxVersionMismatch() public {
        MockInbox otherVersionInbox = new MockInbox(ROLLUP, ROLLUP_VERSION + 1);
        vm.expectRevert(bytes("inbox version"));
        new ZKAAztecPortal(outbox, otherVersionInbox, L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
    }

    /// A configured version that neither contract reports is also refused.
    function test_ConstructorRejectsVersionTheRollupDoesNotReport() public {
        vm.expectRevert(bytes("outbox version"));
        new ZKAAztecPortal(outbox, inbox, L2_BRIDGE, ROLLUP_VERSION + 1, token, ASSET_COMMITMENT);
    }

    /// An address with no code cannot be an Outbox or Inbox.
    function test_ConstructorRejectsCodelessOutboxAndInbox() public {
        vm.expectRevert();
        new ZKAAztecPortal(IAztecOutbox(address(0xdead)), inbox, L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
        vm.expectRevert();
        new ZKAAztecPortal(outbox, IAztecInbox(address(0xdead)), L2_BRIDGE, ROLLUP_VERSION, token, ASSET_COMMITMENT);
    }

    /// The immutable config is the only state — no setter can change the portal.
    function test_ConfigIsImmutable() public view {
        assertEq(address(portal.outbox()), address(outbox));
        assertEq(address(portal.inbox()), address(inbox));
        assertEq(portal.l2Bridge(), L2_BRIDGE);
        assertEq(portal.rollupVersion(), ROLLUP_VERSION);
        assertEq(address(portal.underlying()), address(token));
        assertEq(portal.assetCommitment(), ASSET_COMMITMENT);
    }
}
