// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {MLDSAVerifier} from "../src/MLDSAVerifier.sol";
import {NTT} from "../src/libraries/NTT.sol";
import {Keccak} from "../src/libraries/Keccak.sol";

contract MLDSAVerifierTest is Test {
    MLDSAVerifier public verifier;

    function setUp() public {
        verifier = new MLDSAVerifier();
    }

    // ─── Interface compliance ───────────────────────────

    function test_rejectsInvalidPkLength() public view {
        bytes memory pk = new bytes(100);
        bytes memory sig = new bytes(3309);
        assertFalse(verifier.verify(pk, bytes32(0), sig));
    }

    function test_rejectsInvalidSigLength() public view {
        bytes memory pk = new bytes(1952);
        bytes memory sig = new bytes(100);
        assertFalse(verifier.verify(pk, bytes32(0), sig));
    }

    function test_rejectsZeroPkAndSig() public view {
        bytes memory pk = new bytes(1952);
        bytes memory sig = new bytes(3309);
        assertFalse(verifier.verify(pk, bytes32(0), sig));
    }

    function test_doesNotRevertOnBadInput() public view {
        // The interface requires returning false, never reverting, for invalid sigs
        bytes memory pk = new bytes(1952);
        bytes memory sig = new bytes(3309);
        pk[0] = 0xDE;
        sig[0] = 0xAD;
        bool result = verifier.verify(pk, bytes32(uint256(42)), sig);
        assertFalse(result, "Garbage pk/sig should fail gracefully");
    }

    // ─── NTT unit tests ────────────────────────────────

    function test_nttInvNttRoundTrip() public pure {
        uint256[256] memory f;
        f[0] = 1;
        f[1] = 42;
        f[2] = 8380416; // Q - 1 = -1 mod Q
        f[100] = 12345;

        uint256 f0 = f[0];
        uint256 f1 = f[1];
        uint256 f2 = f[2];
        uint256 f100 = f[100];

        NTT.ntt(f);
        NTT.invNtt(f);

        assertEq(f[0], f0, "NTT round-trip [0]");
        assertEq(f[1], f1, "NTT round-trip [1]");
        assertEq(f[2], f2, "NTT round-trip [2]");
        assertEq(f[100], f100, "NTT round-trip [100]");
        assertEq(f[255], 0, "NTT round-trip [255]");
    }

    function test_nttInvNttFullPoly() public pure {
        // Test with all 256 coefficients populated
        uint256[256] memory f;
        for (uint256 i = 0; i < 256; i++) {
            f[i] = (i * 31337 + 42) % 8380417;
        }

        // Save copy
        uint256[256] memory orig;
        for (uint256 i = 0; i < 256; i++) {
            orig[i] = f[i];
        }

        NTT.ntt(f);
        NTT.invNtt(f);

        for (uint256 i = 0; i < 256; i++) {
            assertEq(f[i], orig[i], "Full poly NTT round-trip");
        }
    }

    function test_pointwiseMulIdentity() public pure {
        uint256[256] memory a;
        uint256[256] memory one;
        for (uint256 i = 0; i < 256; i++) {
            a[i] = (i * 7 + 3) % 8380417;
            one[i] = 1;
        }

        uint256[256] memory result = NTT.pointwiseMul(a, one);
        for (uint256 i = 0; i < 256; i++) {
            assertEq(result[i], a[i]);
        }
    }

    function test_pointwiseAddSub() public pure {
        uint256[256] memory a;
        uint256[256] memory b;
        for (uint256 i = 0; i < 256; i++) {
            a[i] = (i * 13 + 5) % 8380417;
            b[i] = (i * 7 + 2) % 8380417;
        }

        uint256[256] memory sum = NTT.pointwiseAdd(a, b);
        uint256[256] memory diff = NTT.pointwiseSub(sum, b);

        for (uint256 i = 0; i < 256; i++) {
            assertEq(diff[i], a[i]);
        }
    }

    function test_pointwiseMulZero() public pure {
        uint256[256] memory a;
        uint256[256] memory zero;
        for (uint256 i = 0; i < 256; i++) {
            a[i] = (i * 7 + 3) % 8380417;
        }

        uint256[256] memory result = NTT.pointwiseMul(a, zero);
        for (uint256 i = 0; i < 256; i++) {
            assertEq(result[i], 0);
        }
    }

    // ─── SHAKE tests ───────────────────────────────────

    function test_shake256EmptyInput() public pure {
        // NIST reference: SHAKE-256("") first byte = 0x46
        bytes memory result = Keccak.shake256("", 32);
        assertEq(result.length, 32);
        assertEq(uint8(result[0]), 0x46, "SHAKE-256 empty first byte");
    }

    function test_shake128EmptyInput() public pure {
        // NIST reference: SHAKE-128("") first byte = 0x7f
        bytes memory result = Keccak.shake128("", 32);
        assertEq(result.length, 32);
        assertEq(uint8(result[0]), 0x7f, "SHAKE-128 empty first byte");
    }

    function test_shake256KnownVector() public pure {
        // SHAKE-256("") full 32-byte output from NIST
        bytes memory result = Keccak.shake256("", 32);
        bytes memory expected = hex"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
        assertEq(keccak256(result), keccak256(expected), "SHAKE-256 empty 32-byte output");
    }

    function test_shake256Deterministic() public pure {
        bytes memory input = hex"deadbeef";
        bytes memory r1 = Keccak.shake256(input, 64);
        bytes memory r2 = Keccak.shake256(input, 64);
        assertEq(keccak256(r1), keccak256(r2));
    }

    function test_shake128Deterministic() public pure {
        bytes memory input = hex"cafebabe";
        bytes memory r1 = Keccak.shake128(input, 48);
        bytes memory r2 = Keccak.shake128(input, 48);
        assertEq(keccak256(r1), keccak256(r2));
    }

    function test_shake256LongOutput() public pure {
        // Request more than one rate block (136 bytes) to test squeezing
        bytes memory result = Keccak.shake256(hex"01", 256);
        assertEq(result.length, 256);
        // Should be non-zero
        bool hasNonZero = false;
        for (uint256 i = 0; i < 256; i++) {
            if (uint8(result[i]) != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Long output should have non-zero bytes");
    }

    // ─── Integration test with real ML-DSA-65 vector ────

    function test_verifyNobleSignature() public {
        // Load test vectors generated by @noble/post-quantum v0.5.4
        // Cross-validated against Rust ml-dsa crate in pq-smart-wallet
        string memory pkHex = vm.readFile("test/vectors/pk.hex");
        string memory sigHex = vm.readFile("test/vectors/sig.hex");
        bytes memory pk = vm.parseBytes(pkHex);
        bytes memory sig = vm.parseBytes(sigHex);
        bytes32 message = 0x9e4f18281574b474df452cbac5b93cba6a36544a4b4f7c385ac3a928c66a4c84;

        assertEq(pk.length, 1952, "PK size mismatch");
        assertEq(sig.length, 3309, "Sig size mismatch");

        bool result = verifier.verify(pk, message, sig);
        assertTrue(result, "Valid noble ML-DSA-65 signature should verify");
    }

    function test_verifyNobleSignatureWrongMessage() public {
        string memory pkHex = vm.readFile("test/vectors/pk.hex");
        string memory sigHex = vm.readFile("test/vectors/sig.hex");
        bytes memory pk = vm.parseBytes(pkHex);
        bytes memory sig = vm.parseBytes(sigHex);
        // Wrong message
        bytes32 message = 0x0000000000000000000000000000000000000000000000000000000000000001;

        bool result = verifier.verify(pk, message, sig);
        assertFalse(result, "Wrong message should fail verification");
    }

    function test_verifyNobleSignatureTamperedSig() public {
        string memory pkHex = vm.readFile("test/vectors/pk.hex");
        string memory sigHex = vm.readFile("test/vectors/sig.hex");
        bytes memory pk = vm.parseBytes(pkHex);
        bytes memory sig = vm.parseBytes(sigHex);
        bytes32 message = 0x9e4f18281574b474df452cbac5b93cba6a36544a4b4f7c385ac3a928c66a4c84;

        // Flip a byte in the signature
        sig[0] = sig[0] ^ 0xFF;

        bool result = verifier.verify(pk, message, sig);
        assertFalse(result, "Tampered signature should fail verification");
    }
}
