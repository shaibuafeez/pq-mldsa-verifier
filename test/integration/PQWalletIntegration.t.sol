// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {MLDSAVerifier} from "../../src/MLDSAVerifier.sol";
import {PQValidatorModule} from "./PQValidatorModule.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {VALIDATION_SUCCESS, VALIDATION_FAILED, MODULE_TYPE_VALIDATOR} from "erc7579/interfaces/IERC7579Module.sol";

/// @title PQWalletIntegration
/// @notice End-to-end integration: drives the *unmodified* upstream
///         multivmlabs/pq-smart-wallet `PQValidatorModule` against the real,
///         pure-Solidity `MLDSAVerifier` from this repo — with no mocks.
///
///         The wallet's own test suite only `vm.mockCall`s the verifier to return
///         `true` (the production verifier is an Arbitrum Stylus / WASM contract
///         that cannot execute inside the EVM). This is the first test that runs
///         the validator pipeline against a verifier that actually performs the
///         FIPS 204 ML-DSA-65 math on-chain.
///
///         Vectors are the same noble/post-quantum ML-DSA-65 vectors shipped by
///         pq-smart-wallet (test-vectors/js-noble-vectors.json) — identical
///         message and signature bytes.
contract PQWalletIntegrationTest is Test {
    // Message from pq-smart-wallet/test-vectors/js-noble-vectors.json
    bytes32 internal constant NOBLE_MESSAGE = 0x9e4f18281574b474df452cbac5b93cba6a36544a4b4f7c385ac3a928c66a4c84;

    address internal constant SMART_ACCOUNT = address(0xA11CE);

    MLDSAVerifier internal verifier;
    PQValidatorModule internal module;

    bytes internal pk;
    bytes internal sig;

    function setUp() public {
        verifier = new MLDSAVerifier();
        // The drop-in: deploy the upstream module pointed at the pure-Solidity
        // verifier instead of the Stylus contract. Constructor arg only.
        module = new PQValidatorModule(address(verifier));

        pk = vm.parseBytes(vm.readFile("test/vectors/pk.hex"));
        sig = vm.parseBytes(vm.readFile("test/vectors/sig.hex"));
        assertEq(pk.length, 1952, "pk must be ML-DSA-65 size");
        assertEq(sig.length, 3309, "sig must be ML-DSA-65 size");
    }

    function _install() internal {
        vm.prank(SMART_ACCOUNT);
        module.onInstall(pk);
        assertTrue(module.isInitialized(SMART_ACCOUNT), "account not initialized");
    }

    function _userOp(bytes memory signature) internal pure returns (PackedUserOperation memory op) {
        op.sender = SMART_ACCOUNT;
        op.signature = signature;
    }

    // ── headline: a real ML-DSA UserOp validates through the real verifier ──
    function test_ValidUserOp_PassesThroughRealVerifier() public {
        _install();

        PackedUserOperation memory op = _userOp(sig);

        vm.prank(SMART_ACCOUNT);
        uint256 g = gasleft();
        uint256 result = module.validateUserOp(op, NOBLE_MESSAGE);
        console2.log("validateUserOp gas (full on-chain ML-DSA-65 verify):", g - gasleft());

        assertEq(result, VALIDATION_SUCCESS, "valid PQ UserOp must pass");
    }

    // ── a tampered signature is rejected by the real verifier ──
    function test_TamperedSignature_Fails() public {
        _install();

        bytes memory bad = sig;
        bad[100] = bytes1(uint8(bad[100]) ^ 0xFF);

        PackedUserOperation memory op = _userOp(bad);
        vm.prank(SMART_ACCOUNT);
        uint256 result = module.validateUserOp(op, NOBLE_MESSAGE);

        assertEq(result, VALIDATION_FAILED, "tampered sig must fail");
    }

    // ── a different userOpHash is rejected (no replay on other ops) ──
    function test_WrongMessage_Fails() public {
        _install();

        PackedUserOperation memory op = _userOp(sig);
        vm.prank(SMART_ACCOUNT);
        uint256 result = module.validateUserOp(op, bytes32(uint256(1)));

        assertEq(result, VALIDATION_FAILED, "wrong message must fail");
    }

    // ── an account that never installed a key cannot validate ──
    function test_UninstalledAccount_Fails() public {
        PackedUserOperation memory op = _userOp(sig);
        vm.prank(SMART_ACCOUNT);
        uint256 result = module.validateUserOp(op, NOBLE_MESSAGE);

        assertEq(result, VALIDATION_FAILED, "uninitialized account must fail");
    }

    // ── ERC-1271 sender-bound path executes and rejects a non-matching sig ──
    //    (the vector signs NOBLE_MESSAGE, not the keccak senderBoundHash, so the
    //     correct result is INVALID — this proves the path runs the real verifier)
    function test_ERC1271_SenderBound_RejectsUnboundSig() public {
        _install();

        vm.prank(SMART_ACCOUNT);
        bytes4 magic = module.isValidSignatureWithSender(address(this), NOBLE_MESSAGE, sig);

        assertEq(magic, bytes4(0xffffffff), "unbound sig must be ERC-1271 invalid");
    }

    // ── module advertises the validator type, as the wallet expects ──
    function test_ModuleTypeIsValidator() public view {
        assertTrue(module.isModuleType(MODULE_TYPE_VALIDATOR));
        assertEq(address(module.verifier()), address(verifier));
    }
}
