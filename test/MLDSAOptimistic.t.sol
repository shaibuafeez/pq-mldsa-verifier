// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {MLDSAOptimistic} from "../src/MLDSAOptimistic.sol";

contract MLDSAOptimisticTest is Test {
    MLDSAOptimistic public optimistic;

    uint256 constant CHALLENGE_WINDOW = 300; // ~1 hour at 12s/block
    uint256 constant MIN_BOND = 0.01 ether;

    address submitter = makeAddr("submitter");
    address challenger = makeAddr("challenger");
    address nobody = makeAddr("nobody");

    bytes pk;
    bytes sig;
    bytes32 message;

    function setUp() public {
        optimistic = new MLDSAOptimistic(CHALLENGE_WINDOW, MIN_BOND);

        // Load real test vectors
        string memory pkHex = vm.readFile("test/vectors/pk.hex");
        string memory sigHex = vm.readFile("test/vectors/sig.hex");
        pk = vm.parseBytes(pkHex);
        sig = vm.parseBytes(sigHex);
        message = 0x9e4f18281574b474df452cbac5b93cba6a36544a4b4f7c385ac3a928c66a4c84;

        vm.deal(submitter, 10 ether);
        vm.deal(challenger, 10 ether);
    }

    // ─── Submit tests ───────────────────────────────────

    function test_submitVerification() public {
        bytes32 merkleRoot = keccak256("fake-merkle-root");

        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot, true);
    }

    function test_submitRevertsInsufficientBond() public {
        bytes32 merkleRoot = keccak256("fake-merkle-root");

        vm.prank(submitter);
        vm.expectRevert(MLDSAOptimistic.InsufficientBond.selector);
        optimistic.submitVerification{value: MIN_BOND - 1}(pk, message, sig, merkleRoot, true);
    }

    // ─── Submit input-validation guards ─────────────────

    function test_submitRevertsBadPublicKeyLength() public {
        bytes memory badPk = new bytes(100);
        vm.prank(submitter);
        vm.expectRevert(abi.encodeWithSelector(MLDSAOptimistic.InvalidPublicKeyLength.selector, uint256(100)));
        optimistic.submitVerification{value: MIN_BOND}(badPk, message, sig, keccak256("r"), true);
    }

    function test_submitRevertsBadSignatureLength() public {
        bytes memory badSig = new bytes(100);
        vm.prank(submitter);
        vm.expectRevert(abi.encodeWithSelector(MLDSAOptimistic.InvalidSignatureLength.selector, uint256(100)));
        optimistic.submitVerification{value: MIN_BOND}(pk, message, badSig, keccak256("r"), true);
    }

    function test_submitRevertsZeroMerkleRoot() public {
        vm.prank(submitter);
        vm.expectRevert(MLDSAOptimistic.ZeroMerkleRoot.selector);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, bytes32(0), true);
    }

    function test_submitRevertsAlreadyVerified() public {
        bytes32 merkleRoot = keccak256("fake-merkle-root");
        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot, true);

        bytes32 sigHash = keccak256(abi.encodePacked(pk, message, sig));
        bytes32 commitmentId = keccak256(
            abi.encodePacked(optimistic.headerHashFor(pk, message, sig, true), merkleRoot, submitter, block.number)
        );
        vm.roll(block.number + CHALLENGE_WINDOW + 1);
        optimistic.finalize(commitmentId);

        // Re-submitting the same (pk,msg,sig) after it's accepted must revert.
        vm.prank(submitter);
        vm.expectRevert(MLDSAOptimistic.AlreadyVerified.selector);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, keccak256("r2"), true);
    }

    // ─── Trace header: claimed-result gating ────────────

    function test_claimedResultFalse_NotVerifiable() public {
        bytes32 merkleRoot = keccak256("reject-trace");
        // Submit a trace that *claims* the signature is invalid.
        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot, false);

        bytes32 commitmentId = keccak256(
            abi.encodePacked(optimistic.headerHashFor(pk, message, sig, false), merkleRoot, submitter, block.number)
        );
        vm.roll(block.number + CHALLENGE_WINDOW + 1);
        optimistic.finalize(commitmentId);

        // Finalized, but a reject-claim must never make verify() return true.
        assertFalse(optimistic.verify(pk, message, sig), "reject-claim must not verify");
    }

    function test_headerBindsClaimedResult() public view {
        assertTrue(
            optimistic.headerHashFor(pk, message, sig, true) != optimistic.headerHashFor(pk, message, sig, false),
            "claimed result must change the header hash"
        );
    }

    // ─── Finalize tests ─────────────────────────────────

    function test_finalizeAfterWindow() public {
        bytes32 merkleRoot = keccak256("fake-merkle-root");

        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot, true);

        // Get the commitment ID
        bytes32 sigHash = keccak256(abi.encodePacked(pk, message, sig));
        bytes32 commitmentId = keccak256(
            abi.encodePacked(optimistic.headerHashFor(pk, message, sig, true), merkleRoot, submitter, block.number)
        );

        // Fast-forward past challenge window
        vm.roll(block.number + CHALLENGE_WINDOW + 1);

        uint256 submitterBalanceBefore = submitter.balance;

        // Anyone can finalize
        vm.prank(nobody);
        optimistic.finalize(commitmentId);

        // Bond returned to submitter
        assertEq(submitter.balance, submitterBalanceBefore + MIN_BOND);
    }

    function test_verifyReturnsTrueAfterFinalize() public {
        bytes32 merkleRoot = keccak256("fake-merkle-root");

        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot, true);

        bytes32 sigHash = keccak256(abi.encodePacked(pk, message, sig));
        bytes32 commitmentId = keccak256(
            abi.encodePacked(optimistic.headerHashFor(pk, message, sig, true), merkleRoot, submitter, block.number)
        );

        // Before finalize: verify returns false
        assertFalse(optimistic.verify(pk, message, sig));

        // Fast-forward and finalize
        vm.roll(block.number + CHALLENGE_WINDOW + 1);
        optimistic.finalize(commitmentId);

        // After finalize: verify returns true
        assertTrue(optimistic.verify(pk, message, sig));
    }

    function test_finalizeRevertsBeforeWindow() public {
        bytes32 merkleRoot = keccak256("fake-merkle-root");

        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot, true);

        bytes32 sigHash = keccak256(abi.encodePacked(pk, message, sig));
        bytes32 commitmentId = keccak256(
            abi.encodePacked(optimistic.headerHashFor(pk, message, sig, true), merkleRoot, submitter, block.number)
        );

        // Try to finalize immediately (within window)
        vm.expectRevert(MLDSAOptimistic.ChallengeWindowActive.selector);
        optimistic.finalize(commitmentId);
    }

    // ─── IMLDSAVerifier interface tests ─────────────────

    function test_verifyReturnsFalseWithoutCommitment() public view {
        assertFalse(optimistic.verify(pk, message, sig));
    }

    function test_verifyReturnsFalseForBadLength() public view {
        assertFalse(optimistic.verify(new bytes(100), message, sig), "bad pk length");
        assertFalse(optimistic.verify(pk, message, new bytes(100)), "bad sig length");
    }

    function test_verifyReturnsFalseForWrongMessage() public {
        bytes32 merkleRoot = keccak256("fake-merkle-root");

        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot, true);

        bytes32 sigHash = keccak256(abi.encodePacked(pk, message, sig));
        bytes32 commitmentId = keccak256(
            abi.encodePacked(optimistic.headerHashFor(pk, message, sig, true), merkleRoot, submitter, block.number)
        );

        vm.roll(block.number + CHALLENGE_WINDOW + 1);
        optimistic.finalize(commitmentId);

        // The original message verifies
        assertTrue(optimistic.verify(pk, message, sig));

        // A different message does not
        assertFalse(optimistic.verify(pk, bytes32(uint256(1)), sig));
    }

    // ─── Multiple commitments ───────────────────────────

    function test_multipleIndependentCommitments() public {
        bytes32 merkleRoot1 = keccak256("root-1");
        bytes32 merkleRoot2 = keccak256("root-2");
        bytes32 message2 = bytes32(uint256(999));

        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot1, true);

        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message2, sig, merkleRoot2, true);

        // Both should be pending (verify returns false for both)
        assertFalse(optimistic.verify(pk, message, sig));
        assertFalse(optimistic.verify(pk, message2, sig));
    }

    // ─── Gas measurement ────────────────────────────────

    function test_submitGas() public {
        bytes32 merkleRoot = keccak256("fake-merkle-root");

        uint256 gasBefore = gasleft();
        vm.prank(submitter);
        optimistic.submitVerification{value: MIN_BOND}(pk, message, sig, merkleRoot, true);
        uint256 gasUsed = gasBefore - gasleft();

        // Should be well under 1M gas
        assertLt(gasUsed, 1_000_000, "Submit should use < 1M gas");
    }
}
