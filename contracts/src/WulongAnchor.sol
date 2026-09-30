// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

/// @title WulongAnchor
/// @notice The latest commitment to Wulong's chest, written only by Wulong's
/// enclave-derived relayer. At boot the enclave refuses a chest that does not
/// match it, so the operator cannot roll the chest back to an older copy.
/// @dev The relayer is set by the timelock, so a rotated relayer can be
/// replaced and a replacement is public before it takes effect.
contract WulongAnchor {
    address public immutable timelock;
    address public relayer;

    bytes32 public root;
    uint64 public seq;
    uint64 public anchoredAt;

    event Anchored(uint64 indexed seq, bytes32 root);
    event RelayerSet(address indexed relayer);

    error NotTimelock();
    error NotRelayer();
    error StaleSeq(uint64 current, uint64 given);
    error ZeroAddress();

    constructor(address timelock_, address relayer_) {
        if (timelock_ == address(0)) revert ZeroAddress();
        timelock = timelock_;
        relayer = relayer_;
        emit RelayerSet(relayer_);
    }

    /// @notice Records the commitment to the chest after its `seq_`-th write.
    /// `seq_` only moves forward, so a replayed or reordered transaction
    /// cannot restore an older root.
    function anchor(bytes32 root_, uint64 seq_) external {
        if (msg.sender != relayer) revert NotRelayer();
        if (seq_ <= seq) revert StaleSeq(seq, seq_);
        root = root_;
        seq = seq_;
        anchoredAt = uint64(block.timestamp);
        emit Anchored(seq_, root_);
    }

    /// @notice Zero stops all anchoring.
    function setRelayer(address relayer_) external {
        if (msg.sender != timelock) revert NotTimelock();
        relayer = relayer_;
        emit RelayerSet(relayer_);
    }

    function latest() external view returns (bytes32, uint64, uint64) {
        return (root, seq, anchoredAt);
    }
}
