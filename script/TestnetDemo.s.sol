// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {MLDSAVerifier} from "../src/MLDSAVerifier.sol";
import {IMLDSAVerifier} from "../src/interfaces/IMLDSAVerifier.sol";

/// @notice Minimal consumer so a full ML-DSA-65 verification leaves a real,
///         state-changing transaction on-chain (not just an eth_call).
contract DemoConsumer {
    IMLDSAVerifier public immutable verifier;
    bool public lastResult;
    bool public lastRan;

    event Verified(bool result, bytes32 message);

    constructor(address v) {
        verifier = IMLDSAVerifier(v);
    }

    function verifyAndStore(bytes calldata pk, bytes32 message, bytes calldata sig) external {
        bool ok = verifier.verify(pk, message, sig);
        lastResult = ok;
        lastRan = true;
        emit Verified(ok, message);
    }
}

/// @title TestnetDemo
/// @notice Deploys the verifier + a consumer and runs a real on-chain ML-DSA-65
///         verification using this repo test vector (noble-generated). Produces a tx that
///         actually executes ~163M gas of post-quantum verification on-chain.
///
/// Usage:
///   forge script script/TestnetDemo.s.sol --rpc-url https://sepolia.base.org \
///     --private-key $PK --broadcast
contract TestnetDemo is Script {
    function run() external {
        uint256 key = vm.envUint("PRIVATE_KEY");
        bytes memory pk = vm.parseBytes(vm.readFile("test/vectors/pk.hex"));
        bytes memory sig = vm.parseBytes(vm.readFile("test/vectors/sig.hex"));
        bytes32 message = 0x9e4f18281574b474df452cbac5b93cba6a36544a4b4f7c385ac3a928c66a4c84;

        vm.startBroadcast(key);
        MLDSAVerifier verifier = new MLDSAVerifier();
        DemoConsumer consumer = new DemoConsumer(address(verifier));
        consumer.verifyAndStore(pk, message, sig); // real ~163M-gas on-chain verify
        vm.stopBroadcast();

        console2.log("chainId:        ", block.chainid);
        console2.log("MLDSAVerifier:  ", address(verifier));
        console2.log("DemoConsumer:   ", address(consumer));
        console2.log("on-chain result:", consumer.lastResult());
    }
}
