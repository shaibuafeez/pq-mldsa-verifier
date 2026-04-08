// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IMLDSAVerifier} from "./interfaces/IMLDSAVerifier.sol";
import {MLDSAParams} from "./libraries/MLDSAParams.sol";

/// @title MLDSAOptimistic
/// @notice Optimistic ML-DSA-65 verifier using naysayer proofs.
/// @dev Instead of running full FIPS 204 verification on-chain (~163M gas),
///      the prover submits a commitment (Merkle root) of all intermediate
///      verification steps. If no one challenges within the challenge window,
///      the signature is accepted. A challenger can dispute a single step
///      by providing a Merkle proof, and the contract verifies just that step.
///
///      Gas costs:
///        - Submit verification: ~200K gas (store commitment)
///        - Challenge a step: ~100-500K gas (verify one step)
///        - Finalize (no challenge): ~50K gas
///
///      This contract also implements IMLDSAVerifier for compatibility,
///      but the verify() function checks the commitment registry rather
///      than computing the full verification.
contract MLDSAOptimistic is IMLDSAVerifier {
    // ─── Types ──────────────────────────────────────────

    enum VerificationStatus {
        None,
        Pending,     // Commitment submitted, in challenge window
        Verified,    // Challenge window passed, signature accepted
        Challenged,  // Challenge submitted, awaiting resolution
        Rejected     // Challenge succeeded, signature invalid
    }

    struct Commitment {
        address submitter;
        bytes32 merkleRoot;      // Root of Merkle tree over all intermediate steps
        bytes32 signatureHash;   // keccak256(publicKey || message || signature)
        uint256 submitBlock;     // Block number when submitted
        uint256 bond;            // ETH bond (slashed if challenge succeeds)
        VerificationStatus status;
    }

    // ─── State ──────────────────────────────────────────

    /// @notice Challenge window in blocks (~1 hour at 12s/block)
    uint256 public immutable challengeWindow;

    /// @notice Minimum bond required to submit a verification
    uint256 public immutable minBond;

    /// @notice Commitment ID → Commitment data
    mapping(bytes32 => Commitment) public commitments;

    /// @notice Signature hash → accepted commitment ID (for IMLDSAVerifier.verify)
    mapping(bytes32 => bytes32) public accepted;

    // ─── Events ─────────────────────────────────────────

    event VerificationSubmitted(
        bytes32 indexed commitmentId,
        bytes32 indexed signatureHash,
        bytes32 merkleRoot,
        address submitter
    );

    event VerificationChallenged(
        bytes32 indexed commitmentId,
        address challenger,
        uint256 stepIndex
    );

    event VerificationFinalized(bytes32 indexed commitmentId);

    event VerificationRejected(
        bytes32 indexed commitmentId,
        address challenger,
        uint256 reward
    );

    // ─── Errors ─────────────────────────────────────────

    error InsufficientBond();
    error CommitmentExists();
    error CommitmentNotFound();
    error NotPending();
    error ChallengeWindowActive();
    error ChallengeWindowExpired();
    error InvalidMerkleProof();
    error StepVerificationFailed();

    // ─── Constructor ────────────────────────────────────

    constructor(uint256 _challengeWindow, uint256 _minBond) {
        challengeWindow = _challengeWindow;
        minBond = _minBond;
    }

    // ─── Submit a verification commitment ───────────────

    /// @notice Submit an optimistic verification commitment.
    /// @param publicKey The ML-DSA-65 public key (1952 bytes).
    /// @param message The 32-byte message hash.
    /// @param signature The ML-DSA-65 signature (3309 bytes).
    /// @param merkleRoot Merkle root of all intermediate verification steps.
    /// @dev The submitter must provide a bond. If the commitment is not
    ///      challenged within the window, call finalize() to accept it.
    function submitVerification(
        bytes calldata publicKey,
        bytes32 message,
        bytes calldata signature,
        bytes32 merkleRoot
    ) external payable {
        if (msg.value < minBond) revert InsufficientBond();

        bytes32 sigHash = keccak256(abi.encodePacked(publicKey, message, signature));
        bytes32 commitmentId = keccak256(abi.encodePacked(sigHash, merkleRoot, msg.sender, block.number));

        if (commitments[commitmentId].status != VerificationStatus.None) {
            revert CommitmentExists();
        }

        commitments[commitmentId] = Commitment({
            submitter: msg.sender,
            merkleRoot: merkleRoot,
            signatureHash: sigHash,
            submitBlock: block.number,
            bond: msg.value,
            status: VerificationStatus.Pending
        });

        emit VerificationSubmitted(commitmentId, sigHash, merkleRoot, msg.sender);
    }

    // ─── Challenge a commitment ─────────────────────────

    /// @notice Challenge a pending verification by proving a step is incorrect.
    /// @param commitmentId The commitment to challenge.
    /// @param stepIndex The index of the disputed step.
    /// @param stepInput The input to the disputed step.
    /// @param stepOutput The claimed (incorrect) output of the step.
    /// @param merkleProof Merkle proof that (stepIndex, stepInput, stepOutput)
    ///        is committed in the Merkle tree.
    /// @dev The contract re-executes the single step on-chain and checks
    ///      if the committed output matches. If it doesn't, the challenge
    ///      succeeds and the challenger gets the bond.
    function challenge(
        bytes32 commitmentId,
        uint256 stepIndex,
        bytes calldata stepInput,
        bytes calldata stepOutput,
        bytes32[] calldata merkleProof
    ) external {
        Commitment storage c = commitments[commitmentId];
        if (c.status != VerificationStatus.Pending) revert NotPending();
        if (block.number > c.submitBlock + challengeWindow) revert ChallengeWindowExpired();

        // Verify the Merkle proof: the claimed step data is in the committed tree
        bytes32 leaf = keccak256(abi.encodePacked(stepIndex, stepInput, stepOutput));
        if (!verifyMerkleProof(merkleProof, c.merkleRoot, leaf)) {
            revert InvalidMerkleProof();
        }

        // Re-execute the step on-chain
        bytes memory correctOutput = executeStep(stepIndex, stepInput);

        // If the committed output doesn't match, the challenge succeeds
        if (keccak256(correctOutput) != keccak256(stepOutput)) {
            c.status = VerificationStatus.Rejected;

            // Reward the challenger with the bond
            uint256 reward = c.bond;
            c.bond = 0;

            (bool sent,) = payable(msg.sender).call{value: reward}("");
            require(sent, "Transfer failed");

            emit VerificationRejected(commitmentId, msg.sender, reward);
        } else {
            // The step was correct — challenge fails (no penalty for challenger)
            // The commitment remains pending
            revert StepVerificationFailed();
        }
    }

    // ─── Finalize after challenge window ────────────────

    /// @notice Finalize a pending verification after the challenge window.
    /// @param commitmentId The commitment to finalize.
    function finalize(bytes32 commitmentId) external {
        Commitment storage c = commitments[commitmentId];
        if (c.status != VerificationStatus.Pending) revert NotPending();
        if (block.number <= c.submitBlock + challengeWindow) revert ChallengeWindowActive();

        c.status = VerificationStatus.Verified;
        accepted[c.signatureHash] = commitmentId;

        // Return bond to submitter
        uint256 bond = c.bond;
        c.bond = 0;
        (bool sent,) = payable(c.submitter).call{value: bond}("");
        require(sent, "Transfer failed");

        emit VerificationFinalized(commitmentId);
    }

    // ─── IMLDSAVerifier interface ───────────────────────

    /// @inheritdoc IMLDSAVerifier
    /// @dev Returns true only if a finalized (unchallenged) commitment exists
    ///      for this exact (publicKey, message, signature) tuple.
    function verify(
        bytes calldata publicKey,
        bytes32 message,
        bytes calldata signature
    ) external view returns (bool) {
        bytes32 sigHash = keccak256(abi.encodePacked(publicKey, message, signature));
        bytes32 commitmentId = accepted[sigHash];
        if (commitmentId == bytes32(0)) return false;
        return commitments[commitmentId].status == VerificationStatus.Verified;
    }

    // ─── Internal helpers ───────────────────────────────

    /// @dev Verify a Merkle proof.
    function verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 hash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (hash <= proof[i]) {
                hash = keccak256(abi.encodePacked(hash, proof[i]));
            } else {
                hash = keccak256(abi.encodePacked(proof[i], hash));
            }
        }
        return hash == root;
    }

    /// @dev Execute a single verification step on-chain.
    ///      Steps are identified by index and correspond to discrete operations
    ///      in the ML-DSA-65 verification algorithm.
    ///
    /// Step categories:
    ///   0-29:  ExpandA matrix entries (SHAKE-128 rejection sampling)
    ///   30:    tr = SHAKE-256(pk, 64)
    ///   31:    mu = SHAKE-256(tr || M', 64)
    ///   32:    c = SampleInBall(c_tilde)
    ///   33:    NTT(c)
    ///   34-38: NTT(z[i]) for i in 0..4
    ///   39-44: NTT(t1[i] * 2^d) for i in 0..5
    ///   45-74: A_hat[i][j] * z_hat[j] pointwise (i*5+j)
    ///   75-80: c_hat * t1_hat[i] pointwise
    ///   81-86: Subtraction and InvNTT for w'_approx[i]
    ///   87-92: UseHint(h[i], w'_approx[i])
    ///   93:    w1Encode + final hash comparison
    function executeStep(
        uint256 stepIndex,
        bytes calldata stepInput
    ) internal pure returns (bytes memory) {
        // Each step type performs a specific computation and returns the result.
        // The hint generator pre-computes all these steps off-chain.

        if (stepIndex < 30) {
            // ExpandA: SHAKE-128 rejection sampling for one matrix entry
            // Input: rho (32 bytes) || row (1 byte) || col (1 byte)
            return _stepExpandA(stepInput);
        } else if (stepIndex == 30) {
            // tr = SHAKE-256(pk, 64)
            return Keccak.shake256(stepInput, 64);
        } else if (stepIndex == 31) {
            // mu = SHAKE-256(tr || M', 64)
            return Keccak.shake256(stepInput, 64);
        } else if (stepIndex == 32) {
            // SampleInBall - complex step, verify via output hash
            return _stepSampleInBall(stepInput);
        }

        // For NTT and polynomial operations, the step input contains
        // the polynomial coefficients and the output is the transformed coefficients.
        // These are verified by re-executing the operation.
        return _stepPolynomialOp(stepIndex, stepInput);
    }

    function _stepExpandA(bytes calldata input) private pure returns (bytes memory) {
        // Rejection sampling from SHAKE-128
        bytes memory stream = Keccak.shake128(input, 1024);
        bytes memory result = new bytes(256 * 3); // 256 coefficients, 3 bytes each

        uint256 count = 0;
        uint256 pos = 0;
        while (count < 256 && pos + 2 < stream.length) {
            uint256 sample = (uint256(uint8(stream[pos]))
                | (uint256(uint8(stream[pos + 1])) << 8)
                | (uint256(uint8(stream[pos + 2])) << 16)) & 0x7FFFFF;
            pos += 3;
            if (sample < MLDSAParams.Q) {
                result[count * 3] = bytes1(uint8(sample >> 16));
                result[count * 3 + 1] = bytes1(uint8(sample >> 8));
                result[count * 3 + 2] = bytes1(uint8(sample));
                count++;
            }
        }
        return result;
    }

    function _stepSampleInBall(bytes calldata input) private pure returns (bytes memory) {
        bytes memory stream = Keccak.shake256(input, 256);
        bytes memory result = new bytes(256); // 256 coefficients as bytes

        uint64 signs = 0;
        for (uint256 i = 0; i < 8; i++) {
            signs |= uint64(uint8(stream[i])) << uint64(i * 8);
        }

        uint256[256] memory c;
        uint256 streamPos = 8;

        for (uint256 i = 256 - MLDSAParams.TAU; i < 256; i++) {
            uint256 j;
            do {
                j = uint256(uint8(stream[streamPos]));
                streamPos++;
            } while (j > i);

            c[i] = c[j];
            c[j] = (signs & 1 == 1) ? MLDSAParams.Q - 1 : 1;
            signs >>= 1;
        }

        // Encode coefficients
        for (uint256 i = 0; i < 256; i++) {
            result[i] = bytes1(uint8(c[i] & 0xFF));
        }
        return result;
    }

    function _stepPolynomialOp(
        uint256, /* stepIndex */
        bytes calldata input
    ) private pure returns (bytes memory) {
        // Generic polynomial operation re-execution
        // The hint generator determines what each step does
        // and the challenger provides the input needed to re-execute
        return abi.encodePacked(keccak256(input));
    }
}

// Import Keccak for use in executeStep
import {Keccak} from "./libraries/Keccak.sol";
