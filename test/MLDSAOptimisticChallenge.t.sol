// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {MLDSAOptimistic} from "../src/MLDSAOptimistic.sol";

/// @dev Exposes the internal step executor so primitive re-execution can be
///      tested directly.
contract OptimisticHarness is MLDSAOptimistic {
    constructor(uint256 w, uint256 b) MLDSAOptimistic(w, b) {}

    function exec(uint8 opcode, bytes calldata input) external pure returns (bytes memory) {
        return executeStep(opcode, input);
    }
}

/// @title MLDSAOptimisticChallengeTest
/// @notice Proves the fraud-proof mechanism actually works after replacing the
///         _stepPolynomialOp stub: a prover who commits a wrong output for a
///         polynomial step (NTT, pointwise, etc.) is caught by challenge(), and
///         an honest prover is never penalized.
contract MLDSAOptimisticChallengeTest is Test {
    // opcodes (mirror MLDSAOptimistic's internal constants)
    uint8 constant OP_EXPANDA = 0;
    uint8 constant OP_SHAKE256_64 = 1;
    uint8 constant OP_SAMPLEINBALL = 2;
    uint8 constant OP_NTT = 3;
    uint8 constant OP_INTT = 4;
    uint8 constant OP_MUL = 5;
    uint8 constant OP_ADD = 6;
    uint8 constant OP_SUB = 7;
    uint8 constant OP_SCALE2D = 8;
    uint8 constant OP_USEHINT = 9;

    uint256 constant Q = 8380417;
    uint256 constant CHALLENGE_WINDOW = 300;
    uint256 constant MIN_BOND = 0.01 ether;

    OptimisticHarness opt;
    address submitter = makeAddr("submitter");
    address challenger = makeAddr("challenger");

    function setUp() public {
        opt = new OptimisticHarness(CHALLENGE_WINDOW, MIN_BOND);
        vm.deal(submitter, 10 ether);
    }

    // ─── helpers ────────────────────────────────────────

    function _poly(uint256[256] memory c) internal pure returns (bytes memory b) {
        b = new bytes(768);
        for (uint256 i = 0; i < 256; i++) {
            b[i * 3] = bytes1(uint8(c[i] >> 16));
            b[i * 3 + 1] = bytes1(uint8(c[i] >> 8));
            b[i * 3 + 2] = bytes1(uint8(c[i]));
        }
    }

    function _decode(bytes memory b, uint256 off) internal pure returns (uint256[256] memory p) {
        for (uint256 i = 0; i < 256; i++) {
            uint256 o = off + i * 3;
            p[i] = (uint256(uint8(b[o])) << 16) | (uint256(uint8(b[o + 1])) << 8) | uint256(uint8(b[o + 2]));
        }
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    // ─── primitive correctness ──────────────────────────

    function test_NTT_InvNTT_RoundTrip() public view {
        uint256[256] memory c;
        for (uint256 i = 0; i < 256; i++) {
            c[i] = (i * 7 + 1) % Q;
        }
        bytes memory p = _poly(c);

        bytes memory nttOut = opt.exec(OP_NTT, p);
        bytes memory back = opt.exec(OP_INTT, nttOut);

        assertEq(keccak256(back), keccak256(p), "INTT(NTT(p)) must equal p");
    }

    function test_Pointwise_Mul_Add_Sub() public view {
        uint256[256] memory a;
        uint256[256] memory b;
        for (uint256 i = 0; i < 256; i++) {
            a[i] = (i + 2) % Q;
            b[i] = (i + 5) % Q;
        }
        bytes memory ab = bytes.concat(_poly(a), _poly(b));

        uint256[256] memory mul = _decode(opt.exec(OP_MUL, ab), 0);
        uint256[256] memory add = _decode(opt.exec(OP_ADD, ab), 0);
        uint256[256] memory sub = _decode(opt.exec(OP_SUB, ab), 0);
        for (uint256 i = 0; i < 256; i++) {
            assertEq(mul[i], mulmod(a[i], b[i], Q), "mul");
            assertEq(add[i], addmod(a[i], b[i], Q), "add");
            assertEq(sub[i], addmod(a[i], Q - b[i], Q), "sub");
        }
    }

    function test_Scale2D() public view {
        uint256[256] memory a;
        for (uint256 i = 0; i < 256; i++) {
            a[i] = (i * 3) % 1024; // 10-bit t1 coeffs
        }
        uint256[256] memory r = _decode(opt.exec(OP_SCALE2D, _poly(a)), 0);
        for (uint256 i = 0; i < 256; i++) {
            assertEq(r[i], mulmod(a[i], uint256(1) << 13, Q), "scale2d");
        }
    }

    // ─── fraud proof: corrupted polynomial step IS caught ──────────────

    function _submitWithCorruptedStep(uint8 opcode, bytes memory input, bytes memory committedOutput)
        internal
        returns (bytes32 commitmentId, bytes32[] memory proof)
    {
        // honest sibling leaf (arbitrary)
        bytes32 sibling = keccak256("sibling-leaf");
        // disputed leaf commits the (possibly wrong) output the prover claims
        bytes32 disputed = keccak256(abi.encodePacked(uint32(0), opcode, input, committedOutput));
        bytes32 root = _hashPair(disputed, sibling);

        bytes memory pk = new bytes(1952);
        bytes memory sig = new bytes(3309);
        bytes32 message = bytes32(uint256(0xabc));

        vm.prank(submitter);
        opt.submitVerification{value: MIN_BOND}(pk, message, sig, root);

        bytes32 sigHash = keccak256(abi.encodePacked(pk, message, sig));
        commitmentId = keccak256(abi.encodePacked(sigHash, root, submitter, block.number));

        proof = new bytes32[](1);
        proof[0] = sibling;
    }

    function test_Challenge_CatchesCorruptedNTT() public {
        // honest input, but prover commits a WRONG NTT output
        uint256[256] memory c;
        for (uint256 i = 0; i < 256; i++) {
            c[i] = (i + 1) % Q;
        }
        bytes memory input = _poly(c);
        bytes memory correct = opt.exec(OP_NTT, input);
        bytes memory wrong = correct;
        wrong[0] = bytes1(uint8(wrong[0]) ^ 0xFF); // corrupt one byte

        (bytes32 id, bytes32[] memory proof) = _submitWithCorruptedStep(OP_NTT, input, wrong);

        uint256 balBefore = challenger.balance;
        vm.prank(challenger);
        opt.challenge(id, uint32(0), OP_NTT, input, wrong, proof);

        // challenger is paid the bond; commitment is rejected
        assertEq(challenger.balance, balBefore + MIN_BOND, "challenger rewarded");
        (,,,,, MLDSAOptimistic.VerificationStatus status) = opt.commitments(id);
        assertEq(uint256(status), uint256(MLDSAOptimistic.VerificationStatus.Rejected), "rejected");
    }

    function test_Challenge_CatchesCorruptedMul() public {
        uint256[256] memory a;
        uint256[256] memory b;
        for (uint256 i = 0; i < 256; i++) {
            a[i] = (i + 2) % Q;
            b[i] = (i + 9) % Q;
        }
        bytes memory input = bytes.concat(_poly(a), _poly(b));
        bytes memory wrong = opt.exec(OP_MUL, input);
        wrong[3] = bytes1(uint8(wrong[3]) ^ 0x01);

        (bytes32 id, bytes32[] memory proof) = _submitWithCorruptedStep(OP_MUL, input, wrong);

        vm.prank(challenger);
        opt.challenge(id, uint32(0), OP_MUL, input, wrong, proof);

        (,,,,, MLDSAOptimistic.VerificationStatus status) = opt.commitments(id);
        assertEq(uint256(status), uint256(MLDSAOptimistic.VerificationStatus.Rejected), "rejected");
    }

    // ─── fraud proof also covers the hash/sampling steps ───────────────

    function _expectCaught(uint8 opcode, bytes memory input) internal {
        bytes memory wrong = opt.exec(opcode, input);
        wrong[wrong.length - 1] = bytes1(uint8(wrong[wrong.length - 1]) ^ 0xFF);

        (bytes32 id, bytes32[] memory proof) = _submitWithCorruptedStep(opcode, input, wrong);

        vm.prank(challenger);
        opt.challenge(id, uint32(0), opcode, input, wrong, proof);

        (,,,,, MLDSAOptimistic.VerificationStatus status) = opt.commitments(id);
        assertEq(uint256(status), uint256(MLDSAOptimistic.VerificationStatus.Rejected), "must be rejected");
    }

    function test_Challenge_CatchesCorruptedExpandA() public {
        bytes memory seed = new bytes(34); // rho(32) || col || row
        seed[0] = 0xAB;
        _expectCaught(OP_EXPANDA, seed);
    }

    function test_Challenge_CatchesCorruptedShake256() public {
        bytes memory input = new bytes(100);
        input[0] = 0xCD;
        _expectCaught(OP_SHAKE256_64, input);
    }

    function test_Challenge_CatchesCorruptedSampleInBall() public {
        bytes memory cTilde = new bytes(48); // c_tilde
        cTilde[0] = 0xEF;
        _expectCaught(OP_SAMPLEINBALL, cTilde);
    }

    // ─── honest prover is NOT penalized ─────────────────

    function test_Challenge_HonestStepSurvives() public {
        uint256[256] memory c;
        for (uint256 i = 0; i < 256; i++) {
            c[i] = (i + 1) % Q;
        }
        bytes memory input = _poly(c);
        bytes memory correct = opt.exec(OP_NTT, input); // honest output

        (bytes32 id, bytes32[] memory proof) = _submitWithCorruptedStep(OP_NTT, input, correct);

        // Challenging a correct step must fail (the prover did nothing wrong)
        vm.prank(challenger);
        vm.expectRevert(MLDSAOptimistic.StepVerificationFailed.selector);
        opt.challenge(id, uint32(0), OP_NTT, input, correct, proof);

        // commitment remains pending
        (,,,,, MLDSAOptimistic.VerificationStatus status) = opt.commitments(id);
        assertEq(uint256(status), uint256(MLDSAOptimistic.VerificationStatus.Pending), "still pending");
    }

    // ─── a bogus Merkle proof is rejected ───────────────

    function test_Challenge_BadMerkleProof_Reverts() public {
        uint256[256] memory c;
        bytes memory input = _poly(c);
        bytes memory wrong = opt.exec(OP_NTT, input);
        wrong[0] = bytes1(uint8(wrong[0]) ^ 0xFF);

        (bytes32 id,) = _submitWithCorruptedStep(OP_NTT, input, wrong);

        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = keccak256("not-the-sibling");

        vm.prank(challenger);
        vm.expectRevert(MLDSAOptimistic.InvalidMerkleProof.selector);
        opt.challenge(id, uint32(0), OP_NTT, input, wrong, badProof);
    }
}
