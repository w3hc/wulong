// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WulongAnchor} from "../src/WulongAnchor.sol";

contract WulongAnchorTest is Test {
    address timelock = makeAddr("timelock");
    address relayer = makeAddr("relayer");
    address stranger = makeAddr("stranger");

    WulongAnchor anchor;

    function setUp() public {
        anchor = new WulongAnchor(timelock, relayer);
    }

    function test_relayerAnchors() public {
        vm.warp(1_000);
        vm.expectEmit(true, false, false, true);
        emit WulongAnchor.Anchored(1, keccak256("a"));
        vm.prank(relayer);
        anchor.anchor(keccak256("a"), 1);

        (bytes32 root, uint64 seq, uint64 anchoredAt) = anchor.latest();
        assertEq(root, keccak256("a"));
        assertEq(seq, 1);
        assertEq(anchoredAt, 1_000);
    }

    function test_seqCanSkipAhead() public {
        vm.startPrank(relayer);
        anchor.anchor(keccak256("a"), 1);
        anchor.anchor(keccak256("b"), 5);
        vm.stopPrank();

        assertEq(anchor.seq(), 5);
        assertEq(anchor.root(), keccak256("b"));
    }

    function test_rejectsAStaleSeq() public {
        vm.startPrank(relayer);
        anchor.anchor(keccak256("b"), 2);

        vm.expectRevert(abi.encodeWithSelector(WulongAnchor.StaleSeq.selector, 2, 1));
        anchor.anchor(keccak256("a"), 1);
        vm.expectRevert(abi.encodeWithSelector(WulongAnchor.StaleSeq.selector, 2, 2));
        anchor.anchor(keccak256("a"), 2);
        vm.stopPrank();
    }

    function test_onlyTheRelayerAnchors() public {
        vm.expectRevert(WulongAnchor.NotRelayer.selector);
        vm.prank(stranger);
        anchor.anchor(keccak256("a"), 1);

        vm.expectRevert(WulongAnchor.NotRelayer.selector);
        vm.prank(timelock);
        anchor.anchor(keccak256("a"), 1);
    }

    function test_timelockReplacesTheRelayer() public {
        address rotated = makeAddr("rotated");
        vm.prank(timelock);
        anchor.setRelayer(rotated);

        vm.expectRevert(WulongAnchor.NotRelayer.selector);
        vm.prank(relayer);
        anchor.anchor(keccak256("a"), 1);

        vm.prank(rotated);
        anchor.anchor(keccak256("a"), 1);
        assertEq(anchor.seq(), 1);
    }

    function test_onlyTheTimelockSetsTheRelayer() public {
        vm.expectRevert(WulongAnchor.NotTimelock.selector);
        vm.prank(relayer);
        anchor.setRelayer(stranger);
    }

    function test_rejectsAZeroTimelock() public {
        vm.expectRevert(WulongAnchor.ZeroAddress.selector);
        new WulongAnchor(address(0), relayer);
    }
}
