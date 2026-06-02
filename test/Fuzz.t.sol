// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {MLDSAVerifier} from "../src/MLDSAVerifier.sol";
import {MLDSAOptimistic} from "../src/MLDSAOptimistic.sol";

contract FuzzHarness is MLDSAOptimistic {
    constructor() MLDSAOptimistic(300, 0.01 ether) {}

    function exec(uint8 opcode, bytes calldata input) external pure returns (bytes memory) {
        return executeStep(opcode, input);
    }
}

/// @title Fuzz / adversarial properties
/// @notice Property-based hardening for the cryptographic core. These target the
///         cheap, high-value invariants (NTT round-trip, pointwise correctness,
///         graceful failure) — NOT the 163M-gas full-verify path, which is
///         covered by the deterministic real-vector tests.
contract FuzzTest is Test {
    uint256 constant Q = 8380417;
    uint8 constant OP_NTT = 3;
    uint8 constant OP_INTT = 4;
    uint8 constant OP_MUL = 5;

    MLDSAVerifier verifier;
    FuzzHarness harness;

    function setUp() public {
        verifier = new MLDSAVerifier();
        harness = new FuzzHarness();
    }

    // derive a deterministic in-range polynomial from a fuzz seed
    function _polyFromSeed(uint256 seed) internal pure returns (uint256[256] memory c, bytes memory enc) {
        enc = new bytes(768);
        for (uint256 i = 0; i < 256; i++) {
            uint256 v = uint256(keccak256(abi.encodePacked(seed, i))) % Q;
            c[i] = v;
            enc[i * 3] = bytes1(uint8(v >> 16));
            enc[i * 3 + 1] = bytes1(uint8(v >> 8));
            enc[i * 3 + 2] = bytes1(uint8(v));
        }
    }

    function _decode(bytes memory b) internal pure returns (uint256[256] memory p) {
        for (uint256 i = 0; i < 256; i++) {
            p[i] = (uint256(uint8(b[i * 3])) << 16) | (uint256(uint8(b[i * 3 + 1])) << 8) | uint256(uint8(b[i * 3 + 2]));
        }
    }

    /// INTT(NTT(p)) == p for arbitrary in-range polynomials.
    function testFuzz_NttInvNtt_RoundTrip(uint256 seed) public view {
        (, bytes memory enc) = _polyFromSeed(seed);
        bytes memory roundTrip = harness.exec(OP_INTT, harness.exec(OP_NTT, enc));
        assertEq(keccak256(roundTrip), keccak256(enc), "INTT(NTT(p)) != p");
    }

    /// Pointwise multiply matches mulmod for arbitrary inputs.
    function testFuzz_PointwiseMul(uint256 seedA, uint256 seedB) public view {
        (uint256[256] memory a, bytes memory ea) = _polyFromSeed(seedA);
        (uint256[256] memory b, bytes memory eb) = _polyFromSeed(seedB);
        uint256[256] memory r = _decode(harness.exec(OP_MUL, bytes.concat(ea, eb)));
        for (uint256 i = 0; i < 256; i++) {
            assertEq(r[i], mulmod(a[i], b[i], Q), "pointwise mul mismatch");
        }
    }

    /// All NTT outputs are reduced mod Q (never >= Q).
    function testFuzz_NttOutputInRange(uint256 seed) public view {
        (, bytes memory enc) = _polyFromSeed(seed);
        uint256[256] memory out = _decode(harness.exec(OP_NTT, enc));
        for (uint256 i = 0; i < 256; i++) {
            assertLt(out[i], Q, "NTT coeff out of range");
        }
    }

    /// verify() never reverts and returns false for wrong-length inputs.
    function testFuzz_Verify_GracefulOnMalformed(bytes calldata pk, bytes calldata sig) public view {
        // keep it on the cheap path: at least one length is wrong
        vm.assume(pk.length != 1952 || sig.length != 3309);
        bool ok = verifier.verify(pk, bytes32(uint256(123)), sig);
        assertFalse(ok, "malformed inputs must not verify");
    }

    /// Correct-length garbage must return false (not revert). A few explicit
    /// cases rather than fuzz, since each is a full ~163M-gas verification.
    function test_Verify_GarbageCorrectLength_ReturnsFalse() public view {
        bytes memory pk = new bytes(1952);
        bytes memory sig = new bytes(3309);
        for (uint256 i = 0; i < 1952; i++) {
            pk[i] = bytes1(uint8(i));
        }
        for (uint256 i = 0; i < 3309; i++) {
            sig[i] = bytes1(uint8(i * 7));
        }
        assertFalse(verifier.verify(pk, keccak256("m"), sig), "garbage must not verify");
    }
}
