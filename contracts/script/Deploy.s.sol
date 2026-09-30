// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {IDstackApp} from "../src/IDstackApp.sol";
import {WulongAppOwner} from "../src/WulongAppOwner.sol";

/// @notice Deploys the timelock and the WulongAppOwner that will own Wulong's DstackApp.
/// @dev DSTACK_APP=0x... SAFE=0x... [GUARDIAN=0x...] [TIMELOCK_DELAY=604800]
///      forge script script/Deploy.s.sol --rpc-url base --broadcast
///      Then hand the app over: see docs/GOVERNANCE.md#setup.
contract Deploy is Script {
    uint256 constant DEFAULT_DELAY = 7 days;

    function run() external returns (TimelockController timelock, WulongAppOwner appOwner) {
        IDstackApp app = IDstackApp(vm.envAddress("DSTACK_APP"));
        address safe = vm.envAddress("SAFE");
        address guardian = vm.envOr("GUARDIAN", safe);
        uint256 delay = vm.envOr("TIMELOCK_DELAY", DEFAULT_DELAY);

        vm.startBroadcast();
        (timelock, appOwner) = deploy(app, safe, guardian, delay);
        vm.stopBroadcast();

        console.log("TimelockController:", address(timelock));
        console.log("WulongAppOwner:    ", address(appOwner));
    }

    /// @notice The Safe proposes, executes and cancels. Nobody administers the
    /// timelock but itself, so changing its roles or delay is itself delayed.
    function deploy(IDstackApp app, address safe, address guardian, uint256 delay)
        public
        returns (TimelockController timelock, WulongAppOwner appOwner)
    {
        address[] memory safeOnly = new address[](1);
        safeOnly[0] = safe;
        timelock = new TimelockController(delay, safeOnly, safeOnly, address(0));
        appOwner = new WulongAppOwner(app, address(timelock), guardian);
    }
}
