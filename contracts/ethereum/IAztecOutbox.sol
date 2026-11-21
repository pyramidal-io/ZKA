// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title Aztec L2->L1 messaging — minimal vendored interface
 * @notice A minimal, self-contained subset of the Aztec L1 message-bridge
 *         `Outbox` interface and data structures (aztec-packages v5),
 *         sufficient for an L2->L1 withdrawal portal to consume a settled
 *         message. The DEPLOYED Outbox interface must match the Aztec rollup
 *         version targeted at deploy time; this mirrors the v5/AZUP-2 shape
 *         (`l1-contracts/src/core/{interfaces/messagebridge/IOutbox,libraries/DataStructures}.sol`).
 */

library AztecDataStructures {
    /// The L2 actor that sent the message (an Aztec contract address + the
    /// Aztec protocol/rollup version it ran under).
    struct L2Actor {
        bytes32 actor;
        uint256 version;
    }

    /// The intended L1 recipient (this portal) and its chain id.
    struct L1Actor {
        address actor;
        uint256 chainId;
    }

    /// A complete L2->L1 message: (sender, recipient, content).
    struct L2ToL1Msg {
        L2Actor sender;
        L1Actor recipient;
        bytes32 content;
    }
}

interface IAztecOutbox {
    /**
     * @notice Consume an L2->L1 message, proving its inclusion in the rollup's
     *         settled output tree at
     *         (`epoch`, `numCheckpointsInEpoch`, `leafIndex`) via `path`.
     * @dev Reverts if the message is not included, or if it was already consumed
     *      (the Outbox enforces strict once-only consumption — this is the
     *      replay protection the portal relies on; it adds no nullifier of its
     *      own). `epoch` is the Aztec `Epoch` (a uint wrapper) as a uint256.
     *      AZUP-2 adds multiple roots per epoch; the v5 Outbox indexes the
     *      chosen root by `numCheckpointsInEpoch`, and the stable once-only
     *      entry key is `(epoch, leafId)` where `leafId = 2^path.length + leafIndex`.
     */
    function consume(
        AztecDataStructures.L2ToL1Msg calldata message,
        uint256 epoch,
        uint256 numCheckpointsInEpoch,
        uint256 leafIndex,
        bytes32[] calldata path
    ) external;

    function getRootData(uint256 epoch, uint256 numCheckpointsInEpoch)
        external
        view
        returns (bytes32);

    function getRoots(uint256 epoch) external view returns (bytes32[] memory);

    /// @notice The rollup this Outbox belongs to.
    function ROLLUP() external view returns (address);

    /// @notice The rollup version this Outbox accepts messages from.
    function VERSION() external view returns (uint256);
}

/**
 * @title AztecHash
 * @notice Aztec L2->L1 content hashing: SHA-256 truncated to a field element by
 *         keeping the high 31 bytes and prepending a zero byte. This matches
 *         Noir `aztec::protocol::hash::sha256_to_field` (L2) and the Aztec
 *         `Hash.sha256ToField` (L1) so an L2-emitted content hashes to the same
 *         32-byte value the portal reconstructs.
 */
library AztecHash {
    function sha256ToField(bytes memory data) internal pure returns (bytes32) {
        return bytes32(bytes.concat(new bytes(1), bytes31(sha256(data))));
    }
}
