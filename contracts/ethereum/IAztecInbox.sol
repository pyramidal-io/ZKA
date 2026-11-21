// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {AztecDataStructures} from "./IAztecOutbox.sol";

/**
 * @title Aztec L1->L2 messaging — minimal vendored interface
 * @notice The V6 Fast Inbox call surface needed by ZKAAztecPortal. The deployed
 *         Inbox must match the rollup version fixed in the portal constructor.
 */
interface IAztecInbox {
    /**
     * @notice Insert a message addressed to an Aztec L2 actor.
     * @dev The Inbox message envelope binds the L1 sender (`msg.sender`) and
     *      `_secretHash`; the content is application-specific.
     * @return key Message-tree entry key.
     * @return index Compact cumulative insertion index. Claimants must obtain its committed L2 membership witness.
     */
    function sendL2Message(AztecDataStructures.L2Actor memory recipient, bytes32 content, bytes32 secretHash)
        external
        returns (bytes32 key, uint256 index);

    /// @notice The rollup this Inbox belongs to.
    function ROLLUP() external view returns (address);

    /// @notice The rollup version this Inbox delivers messages to.
    function VERSION() external view returns (uint256);
}
