// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IMLDSAVerifier} from "./interfaces/IMLDSAVerifier.sol";
import {MLDSAVerify} from "./libraries/MLDSAVerify.sol";
import {MLDSAParams} from "./libraries/MLDSAParams.sol";

/// @title MLDSAVerifier
/// @notice Pure-Solidity ML-DSA-65 signature verifier for EVM chains.
/// @dev Drop-in replacement for the Arbitrum Stylus verifier in pq-smart-wallet.
///      Implements the IMLDSAVerifier interface exactly as expected by PQValidatorModule.
///
///      This is a FULL on-chain verification — all FIPS 204 steps are executed within
///      a single call. For gas-optimized optimistic verification, see MLDSAOptimistic.sol.
///
///      Compatible with:
///      - PQValidatorModule.sol (quantumFDN's ERC-7579 validator)
///      - Any ERC-4337 wallet using IMLDSAVerifier
///      - Any EVM chain (Ethereum, Polygon, Base, Optimism, Arbitrum, etc.)
contract MLDSAVerifier is IMLDSAVerifier {
    /// @inheritdoc IMLDSAVerifier
    function verify(
        bytes calldata publicKey,
        bytes32 message,
        bytes calldata signature
    ) external pure returns (bool) {
        // Input size validation (fail gracefully, no revert)
        if (publicKey.length != MLDSAParams.PK_SIZE) return false;
        if (signature.length != MLDSAParams.SIG_SIZE) return false;

        // Delegate to library for full FIPS 204 verification
        return MLDSAVerify.verify(publicKey, message, signature);
    }
}
