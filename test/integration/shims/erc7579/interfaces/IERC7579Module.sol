// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Standard ERC-7579 module symbols. These are faithful copies of the upstream
// definitions from the `erc7579-implementation` library that pq-smart-wallet
// imports. They are re-declared locally ONLY so the *unmodified* upstream
// PQValidatorModule.sol can compile and run inside this verifier repo without
// vendoring the full account-abstraction + erc7579 submodule trees.
// Semantics are identical to the ERC-7579 / ERC-4337 standards.
// ─────────────────────────────────────────────────────────────────────────────

uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;

uint256 constant MODULE_TYPE_VALIDATOR = 1;

interface IModule {
    error AlreadyInitialized(address smartAccount);
    error NotInitialized(address smartAccount);

    function onInstall(bytes calldata data) external;
    function onUninstall(bytes calldata data) external;
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256);

    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4);
}
