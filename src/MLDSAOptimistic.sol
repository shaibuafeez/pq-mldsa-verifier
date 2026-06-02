// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IMLDSAVerifier} from "./interfaces/IMLDSAVerifier.sol";
import {MLDSAParams} from "./libraries/MLDSAParams.sol";
import {NTT} from "./libraries/NTT.sol";
import {MLDSAVerify} from "./libraries/MLDSAVerify.sol";
import {Keccak} from "./libraries/Keccak.sol";

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
    // ─── Step opcodes ───────────────────────────────────
    // Every intermediate verification step is one of these primitive,
    // independently re-executable operations. The off-chain hint generator
    // decomposes full FIPS 204 verification into a sequence of these steps;
    // a challenger disputes any single one and the contract re-runs just that
    // primitive on-chain. (Replaces the previous polynomial-op stub.)
    uint8 internal constant OP_EXPANDA = 0; // SHAKE-128 rejection sampling (one A matrix entry)
    uint8 internal constant OP_SHAKE256_64 = 1; // SHAKE-256 -> 64 bytes (tr, mu)
    uint8 internal constant OP_SAMPLEINBALL = 2; // challenge polynomial from c_tilde
    uint8 internal constant OP_NTT = 3; // forward NTT (1 poly -> 1 poly)
    uint8 internal constant OP_INTT = 4; // inverse NTT (1 poly -> 1 poly)
    uint8 internal constant OP_MUL = 5; // pointwise multiply (2 polys -> 1)
    uint8 internal constant OP_ADD = 6; // pointwise add (2 polys -> 1)
    uint8 internal constant OP_SUB = 7; // pointwise subtract (2 polys -> 1)
    uint8 internal constant OP_SCALE2D = 8; // multiply each coeff by 2^D mod Q (1 poly -> 1)
    uint8 internal constant OP_USEHINT = 9; // UseHint(hintPoly, wPoly) -> w1 poly
    // Final-result steps (acceptance computation) — see docs/optimistic-trace.md §6
    uint8 internal constant OP_ENCODE_W1 = 10; // pack 6 w1 polys (4 bits/coeff) -> 768 B
    uint8 internal constant OP_SHAKE256_48 = 11; // c_tilde' = SHAKE-256(mu || w1Bytes, 48)
    uint8 internal constant OP_COMPARE_CTILDE = 12; // c_tilde' == c_tilde -> 1 byte (0/1)

    /// @dev Canonical polynomial serialization: 256 coefficients, 3 bytes each
    ///      (big-endian). Coefficients are < Q < 2^23 so 3 bytes is exact.
    ///      MUST match the off-chain hint generator's encodeCoeffs().
    uint256 internal constant POLY_BYTES = 768; // 256 * 3

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
    error InvalidPublicKeyLength(uint256 actual);
    error InvalidSignatureLength(uint256 actual);
    error ZeroMerkleRoot();
    error AlreadyVerified();

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
        // Cheap sanity checks (reviewer #6/#7). These do not make the optimistic
        // path sound on their own — trace linkage is still required (see
        // SECURITY.md) — but they reject obviously malformed submissions early.
        if (publicKey.length != MLDSAParams.PK_SIZE) revert InvalidPublicKeyLength(publicKey.length);
        if (signature.length != MLDSAParams.SIG_SIZE) revert InvalidSignatureLength(signature.length);
        if (merkleRoot == bytes32(0)) revert ZeroMerkleRoot();

        bytes32 sigHash = keccak256(abi.encodePacked(publicKey, message, signature));
        // Reject re-submitting a tuple that's already been accepted.
        if (accepted[sigHash] != bytes32(0)) revert AlreadyVerified();

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
    /// @param stepIndex The ordinal index of the disputed step (4-byte, big-endian
    ///        in the leaf preimage; must match the hint generator).
    /// @param opcode The primitive operation of the disputed step (see OP_* above).
    /// @param stepInput The input to the disputed step.
    /// @param stepOutput The claimed (incorrect) output of the step.
    /// @param merkleProof Merkle proof that (stepIndex, opcode, stepInput, stepOutput)
    ///        is committed in the Merkle tree.
    /// @dev The contract re-executes the single primitive on-chain and checks
    ///      if the committed output matches. If it doesn't, the challenge
    ///      succeeds and the challenger gets the bond.
    function challenge(
        bytes32 commitmentId,
        uint32 stepIndex,
        uint8 opcode,
        bytes calldata stepInput,
        bytes calldata stepOutput,
        bytes32[] calldata merkleProof
    ) external {
        Commitment storage c = commitments[commitmentId];
        if (c.status != VerificationStatus.Pending) revert NotPending();
        if (block.number > c.submitBlock + challengeWindow) revert ChallengeWindowExpired();

        // Verify the Merkle proof: the claimed step data is in the committed tree.
        // Leaf preimage layout matches the off-chain generator exactly:
        //   uint32(stepIndex) ++ uint8(opcode) ++ stepInput ++ stepOutput
        bytes32 leaf = keccak256(abi.encodePacked(stepIndex, opcode, stepInput, stepOutput));
        if (!verifyMerkleProof(merkleProof, c.merkleRoot, leaf)) {
            revert InvalidMerkleProof();
        }

        // Re-execute the step on-chain
        bytes memory correctOutput = executeStep(opcode, stepInput);

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

    /// @dev Execute a single verification step on-chain by opcode.
    ///      Every step is a primitive, deterministic operation that is fully
    ///      re-executed here — there is no longer any hash-of-input stub, so a
    ///      prover who commits a wrong output for ANY operation type (including
    ///      NTT / pointwise / UseHint) is caught by re-execution.
    ///
    ///      Soundness note: this makes each step *individually* verifiable. Full
    ///      L1 soundness additionally requires step *linkage* (that each step's
    ///      output is the next step's input, bound to pk/msg/sig and the final
    ///      accept). That linkage check is the documented remaining work — see
    ///      SECURITY.md. This function closes the re-execution gap only.
    function executeStep(uint8 opcode, bytes calldata stepInput) internal pure returns (bytes memory) {
        if (opcode == OP_EXPANDA) {
            // SHAKE-128 rejection sampling for one A matrix entry.
            // Input: rho (32 bytes) || row (1 byte) || col (1 byte)
            return _stepExpandA(stepInput);
        } else if (opcode == OP_SHAKE256_64) {
            // tr = SHAKE-256(pk, 64)  or  mu = SHAKE-256(tr || M', 64)
            return Keccak.shake256(stepInput, 64);
        } else if (opcode == OP_SAMPLEINBALL) {
            // challenge polynomial c = SampleInBall(c_tilde)
            return _stepSampleInBall(stepInput);
        } else if (opcode == OP_NTT) {
            uint256[256] memory p = _decodePoly(stepInput, 0);
            NTT.ntt(p);
            return _encodePoly(p);
        } else if (opcode == OP_INTT) {
            uint256[256] memory p = _decodePoly(stepInput, 0);
            NTT.invNtt(p);
            return _encodePoly(p);
        } else if (opcode == OP_SCALE2D) {
            uint256[256] memory p = _decodePoly(stepInput, 0);
            uint256 factor = uint256(1) << MLDSAParams.D;
            for (uint256 i = 0; i < 256; i++) {
                p[i] = mulmod(p[i], factor, MLDSAParams.Q);
            }
            return _encodePoly(p);
        } else if (opcode == OP_MUL || opcode == OP_ADD || opcode == OP_SUB) {
            require(stepInput.length == 2 * POLY_BYTES, "binop input");
            uint256[256] memory a = _decodePoly(stepInput, 0);
            uint256[256] memory b = _decodePoly(stepInput, POLY_BYTES);
            uint256[256] memory r;
            if (opcode == OP_MUL) {
                r = NTT.pointwiseMul(a, b);
            } else if (opcode == OP_ADD) {
                r = NTT.pointwiseAdd(a, b);
            } else {
                r = NTT.pointwiseSub(a, b);
            }
            return _encodePoly(r);
        } else if (opcode == OP_USEHINT) {
            // input: hint poly (768) || w poly (768); output: w1 poly (768)
            require(stepInput.length == 2 * POLY_BYTES, "usehint input");
            uint256[256] memory hint = _decodePoly(stepInput, 0);
            uint256[256] memory w = _decodePoly(stepInput, POLY_BYTES);
            uint256[256] memory w1;
            for (uint256 i = 0; i < 256; i++) {
                w1[i] = MLDSAVerify.useHint(hint[i], w[i]);
            }
            return _encodePoly(w1);
        } else if (opcode == OP_ENCODE_W1) {
            // input: 6 w1 polys (6 * 768 = 4608 B); output: packed w1Bytes (768 B)
            require(stepInput.length == 6 * POLY_BYTES, "encodew1 input");
            uint256[256][6] memory w1;
            for (uint256 i = 0; i < 6; i++) {
                w1[i] = _decodePoly(stepInput, i * POLY_BYTES);
            }
            return MLDSAVerify.encodeW1(w1);
        } else if (opcode == OP_SHAKE256_48) {
            // c_tilde' = SHAKE-256(mu || w1Bytes, 48)
            return Keccak.shake256(stepInput, 48);
        } else if (opcode == OP_COMPARE_CTILDE) {
            // input: c_tilde'(48) || c_tilde(48); output: 1 byte (1 == accept)
            require(stepInput.length == 96, "compare input");
            bool eq = true;
            for (uint256 i = 0; i < 48; i++) {
                if (stepInput[i] != stepInput[48 + i]) {
                    eq = false;
                    break;
                }
            }
            bytes memory out = new bytes(1);
            out[0] = eq ? bytes1(0x01) : bytes1(0x00);
            return out;
        }
        revert("unknown opcode");
    }

    // ─── Canonical polynomial (de)serialization (3 bytes/coeff, big-endian) ──

    function _decodePoly(bytes calldata b, uint256 off) private pure returns (uint256[256] memory p) {
        require(b.length >= off + POLY_BYTES, "poly len");
        for (uint256 i = 0; i < 256; i++) {
            uint256 o = off + i * 3;
            p[i] = (uint256(uint8(b[o])) << 16) | (uint256(uint8(b[o + 1])) << 8) | uint256(uint8(b[o + 2]));
        }
    }

    function _encodePoly(uint256[256] memory p) private pure returns (bytes memory out) {
        out = new bytes(POLY_BYTES);
        for (uint256 i = 0; i < 256; i++) {
            uint256 v = p[i];
            out[i * 3] = bytes1(uint8(v >> 16));
            out[i * 3 + 1] = bytes1(uint8(v >> 8));
            out[i * 3 + 2] = bytes1(uint8(v));
        }
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

        // Canonical encoding: 3 bytes per coefficient, big-endian — identical to
        // every other polynomial step and to the off-chain generator's
        // encodeCoeffs(). (Was previously 1 byte/coeff, which both truncated
        // Q-1 and produced a 256-byte output that never matched the committed
        // 768-byte step; covered now by the all-steps parity test.)
        return _encodePoly(c);
    }

}
