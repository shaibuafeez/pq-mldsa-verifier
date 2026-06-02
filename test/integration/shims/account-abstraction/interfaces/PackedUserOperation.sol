// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// Standard ERC-4337 v0.7 PackedUserOperation struct (faithful copy of the
// upstream `account-abstraction` definition). Re-declared locally so the
// unmodified PQValidatorModule.sol compiles inside this repo. See:
// account-abstraction/contracts/interfaces/PackedUserOperation.sol
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}
