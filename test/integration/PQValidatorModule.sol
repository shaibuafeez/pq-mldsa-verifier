// ─────────────────────────────────────────────────────────────────────────────
// VENDORED VERBATIM from multivmlabs/pq-smart-wallet @ evm/src/PQValidatorModule.sol
// Copied unmodified for the integration test. Source of truth lives in that repo.
// ─────────────────────────────────────────────────────────────────────────────
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IValidator} from "erc7579/interfaces/IERC7579Module.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {VALIDATION_SUCCESS, VALIDATION_FAILED, MODULE_TYPE_VALIDATOR} from "erc7579/interfaces/IERC7579Module.sol";
import {IMLDSAVerifier} from "./interfaces/IMLDSAVerifier.sol";

/// @title PQValidatorModule
/// @notice ERC-7579 validator module that delegates signature verification
///         to an Arbitrum Stylus contract performing ML-DSA (FIPS 204) verification.
contract PQValidatorModule is IValidator {
    error InvalidMLDSAPublicKeyLength(uint256 actual, uint256 expected);
    bytes4 internal constant ERC1271_VALID = 0x1626ba7e;
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;

    /// @notice The Stylus ML-DSA verifier contract
    IMLDSAVerifier public immutable verifier;

    /// @notice Stored ML-DSA public keys, keyed by smart account address
    mapping(address => bytes) internal publicKeys;

    constructor(address _verifier) {
        verifier = IMLDSAVerifier(_verifier);
    }

    function onInstall(bytes calldata data) external {
        if (isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        if (data.length != 1952) {
            revert InvalidMLDSAPublicKeyLength(data.length, 1952);
        }
        publicKeys[msg.sender] = data;
    }

    function onUninstall(bytes calldata data) external {
        if (!isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        delete publicKeys[msg.sender];
    }

    function isInitialized(address smartAccount) public view returns (bool) {
        return (publicKeys[smartAccount].length > 0);
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        if (!isInitialized(msg.sender)) return VALIDATION_FAILED;
        bytes memory mlDSAPubKey = publicKeys[msg.sender];
        bytes calldata userSig = userOp.signature;
        bool isVerified = verifier.verify(mlDSAPubKey, userOpHash, userSig);
        return isVerified ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    // Bind sender-aware ERC-1271 checks to module/account/chain context so the
    // same signature cannot be replayed across different callers/protocols.
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        if (!isInitialized(msg.sender)) return ERC1271_INVALID;
        bytes memory mlDSAPubKey = publicKeys[msg.sender];
        bytes32 senderBoundHash = keccak256(abi.encodePacked(address(this), block.chainid, msg.sender, sender, hash));
        bool isVerified = verifier.verify(mlDSAPubKey, senderBoundHash, signature);
        return isVerified ? ERC1271_VALID : ERC1271_INVALID;
    }
}
