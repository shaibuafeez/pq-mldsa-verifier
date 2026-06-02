// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {MLDSAVerifier} from "../src/MLDSAVerifier.sol";
import {MLDSAOptimistic} from "../src/MLDSAOptimistic.sol";

/// @title Deploy
/// @notice Deploys the pure-Solidity ML-DSA-65 verifier (and the optimistic
///         scaffold) to any EVM chain. Intended for L2 testnets/mainnets such
///         as Base or Arbitrum — full verify is ~163M gas, which exceeds
///         Ethereum L1's block limit.
///
/// Usage:
///   export PRIVATE_KEY=0x<funded key>
///   forge script script/Deploy.s.sol \
///     --rpc-url https://sepolia.base.org \
///     --broadcast --verify --verifier-url https://api-sepolia.basescan.org/api \
///     --etherscan-api-key $BASESCAN_API_KEY
///
/// Env (optional):
///   CHALLENGE_WINDOW  optimistic challenge window in blocks (default 300)
///   MIN_BOND          optimistic minimum bond in wei (default 0.001 ether)
contract Deploy is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        uint256 challengeWindow = vm.envOr("CHALLENGE_WINDOW", uint256(300));
        uint256 minBond = vm.envOr("MIN_BOND", uint256(0.001 ether));

        vm.startBroadcast(deployerKey);

        MLDSAVerifier verifier = new MLDSAVerifier();
        MLDSAOptimistic optimistic = new MLDSAOptimistic(challengeWindow, minBond);

        vm.stopBroadcast();

        console2.log("Chain ID:           ", block.chainid);
        console2.log("MLDSAVerifier:      ", address(verifier));
        console2.log("MLDSAOptimistic:    ", address(optimistic));
        console2.log("");
        console2.log("Wire into a wallet:  new PQValidatorModule(<MLDSAVerifier address>)");
    }
}
