// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {MLDSAParams} from "./MLDSAParams.sol";
import {NTT} from "./NTT.sol";
import {Keccak} from "./Keccak.sol";
import {MLDSADecode} from "./MLDSADecode.sol";

/// @title MLDSAVerify
/// @notice Core ML-DSA-65 verification algorithm per FIPS 204, Algorithm 8.
/// @dev Full on-chain verification. Gas-intensive but FIPS 204 compliant.
library MLDSAVerify {
    uint256 private constant Q = MLDSAParams.Q;

    /// @notice Verify an ML-DSA-65 signature.
    /// @param pk The 1952-byte public key.
    /// @param message The 32-byte message hash.
    /// @param sig The 3309-byte signature.
    /// @return True if the signature is valid.
    function verify(
        bytes calldata pk,
        bytes32 message,
        bytes calldata sig
    ) internal pure returns (bool) {
        // Step 1: Decode public key
        (bytes32 rho, uint256[256][6] memory t1) = MLDSADecode.decodePk(pk);

        // Step 2: Decode signature
        (bytes memory cTilde, int256[256][5] memory z, uint256[256][6] memory h, bool validHint) =
            MLDSADecode.decodeSig(sig);

        // Step 3: Check hint validity
        if (!validHint) return false;

        // Step 4: Check ||z||_inf < gamma1 - beta
        if (!checkNormBound(z)) return false;

        // Step 5: Check hint weight <= omega
        if (!checkHintWeight(h)) return false;

        // Step 6: Expand A from rho using SHAKE-128
        uint256[256][5][6] memory aHat = expandA(rho);

        // Step 7: tr = SHAKE-256(pk, 64)
        bytes memory tr = Keccak.shake256(abi.encodePacked(pk), 64);

        // Step 8: mu = SHAKE-256(tr || M', 64)
        // M' = 0x00 || 0x00 || message (empty context)
        bytes memory muInput = abi.encodePacked(tr, bytes1(0x00), bytes1(0x00), message);
        bytes memory mu = Keccak.shake256(muInput, 64);

        // Step 9: c = SampleInBall(c_tilde)
        uint256[256] memory c = sampleInBall(cTilde);

        // Step 10: c_hat = NTT(c)
        NTT.ntt(c);

        // Step 11-14: w'_approx = InvNTT(A_hat * NTT(z) - c_hat * NTT(t1 * 2^d))
        uint256[256][6] memory wApprox = computeWApprox(aHat, z, c, t1);

        // Step 15: w1' = UseHint(h, w'_approx)
        uint256[256][6] memory w1Prime = useHintVector(h, wApprox);

        // Step 16: Encode w1'
        bytes memory w1Bytes = encodeW1(w1Prime);

        // Step 17: c_tilde' = SHAKE-256(mu || w1_bytes, 48)
        bytes memory hashInput = abi.encodePacked(mu, w1Bytes);
        bytes memory cTildePrime = Keccak.shake256(hashInput, 48);

        // Step 18: Accept iff c_tilde == c_tilde'
        return keccak256(cTilde) == keccak256(cTildePrime);
    }

    /// @dev Check infinity norm of z vector < NORM_BOUND.
    function checkNormBound(int256[256][5] memory z) private pure returns (bool) {
        int256 bound = int256(MLDSAParams.NORM_BOUND);
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = 0; j < 256; j++) {
                int256 coeff = z[i][j];
                if (coeff >= bound || coeff <= -bound) return false;
            }
        }
        return true;
    }

    /// @dev Check total hint weight <= omega.
    function checkHintWeight(uint256[256][6] memory h) private pure returns (bool) {
        uint256 total = 0;
        for (uint256 i = 0; i < 6; i++) {
            for (uint256 j = 0; j < 256; j++) {
                total += h[i][j];
            }
        }
        return total <= MLDSAParams.OMEGA;
    }

    /// @dev ExpandA: generate K x L matrix in NTT domain using SHAKE-128.
    function expandA(bytes32 rho) private pure returns (uint256[256][5][6] memory aHat) {
        for (uint256 i = 0; i < 6; i++) {
            for (uint256 j = 0; j < 5; j++) {
                aHat[i][j] = rejNttPoly(rho, uint8(i), uint8(j));
            }
        }
    }

    /// @dev RejNTTPoly: sample a polynomial in NTT domain via SHAKE-128 rejection sampling.
    function rejNttPoly(bytes32 rho, uint8 row, uint8 col) private pure returns (uint256[256] memory coeffs) {
        // Seed: rho || col || row (column before row per FIPS 204)
        bytes memory seed = abi.encodePacked(rho, col, row);
        // We need enough SHAKE-128 output for rejection sampling
        // Each coefficient needs ~3 bytes, with ~0.1% rejection rate
        // 256 * 3 * 1.01 ≈ 776 bytes. Use 1024 for safety.
        bytes memory stream = Keccak.shake128(seed, 1024);

        uint256 count = 0;
        uint256 pos = 0;

        while (count < 256 && pos + 2 < stream.length) {
            uint256 b0 = uint256(uint8(stream[pos]));
            uint256 b1 = uint256(uint8(stream[pos + 1]));
            uint256 b2 = uint256(uint8(stream[pos + 2]));
            pos += 3;

            uint256 sample = (b0 | (b1 << 8) | (b2 << 16)) & 0x7FFFFF; // 23 bits
            if (sample < Q) {
                coeffs[count] = sample;
                count++;
            }
        }

        // If we didn't get enough (extremely unlikely), squeeze more
        // In practice, 1024 bytes gives ~341 samples with ~0.1% rejection
        require(count == 256, "RejNTTPoly: insufficient samples");
    }

    /// @dev SampleInBall: generate challenge polynomial with tau nonzero +/-1 coefficients.
    function sampleInBall(bytes memory cTilde) private pure returns (uint256[256] memory c) {
        // Use SHAKE-256 to generate random bytes
        // Need 8 bytes for signs + up to ~100 bytes for indices (with rejection)
        bytes memory stream = Keccak.shake256(cTilde, 256);

        // First 8 bytes: sign bits
        uint64 signs = 0;
        for (uint256 i = 0; i < 8; i++) {
            signs |= uint64(uint8(stream[i])) << uint64(i * 8);
        }

        uint256 streamPos = 8;

        // Fisher-Yates shuffle for tau = 49 nonzero positions
        for (uint256 i = 256 - MLDSAParams.TAU; i < 256; i++) {
            // Rejection sample j in [0, i]
            uint256 j;
            do {
                require(streamPos < stream.length, "SampleInBall: need more bytes");
                j = uint256(uint8(stream[streamPos]));
                streamPos++;
            } while (j > i);

            c[i] = c[j];

            // +1 or -1 based on sign bit
            if (signs & 1 == 1) {
                c[j] = Q - 1; // -1 mod Q
            } else {
                c[j] = 1;
            }
            signs >>= 1;
        }
    }

    /// @dev Compute w'_approx = InvNTT(A_hat * NTT(z) - c_hat * NTT(t1 * 2^d)).
    function computeWApprox(
        uint256[256][5][6] memory aHat,
        int256[256][5] memory z,
        uint256[256] memory cHat, // already in NTT domain
        uint256[256][6] memory t1
    ) private pure returns (uint256[256][6] memory wApprox) {
        // Convert z to unsigned mod Q and compute NTT
        uint256[256][5] memory zHat;
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = 0; j < 256; j++) {
                int256 val = z[i][j];
                zHat[i][j] = val >= 0 ? uint256(val) : uint256(int256(Q) + val);
            }
            NTT.ntt(zHat[i]);
        }

        // Compute NTT(t1 * 2^d)
        uint256[256][6] memory t1Hat;
        for (uint256 i = 0; i < 6; i++) {
            for (uint256 j = 0; j < 256; j++) {
                t1Hat[i][j] = mulmod(t1[i][j], uint256(1) << MLDSAParams.D, Q);
            }
            NTT.ntt(t1Hat[i]);
        }

        // For each row i: wApprox[i] = InvNTT( sum_j(A_hat[i][j] * z_hat[j]) - c_hat * t1_hat[i] )
        for (uint256 i = 0; i < 6; i++) {
            uint256[256] memory acc;

            // Matrix-vector multiply: A_hat[i] * z_hat
            for (uint256 j = 0; j < 5; j++) {
                uint256[256] memory product = NTT.pointwiseMul(aHat[i][j], zHat[j]);
                acc = NTT.pointwiseAdd(acc, product);
            }

            // Subtract c_hat * t1_hat[i]
            uint256[256] memory ct1 = NTT.pointwiseMul(cHat, t1Hat[i]);
            wApprox[i] = NTT.pointwiseSub(acc, ct1);

            // Inverse NTT
            NTT.invNtt(wApprox[i]);
        }
    }

    /// @dev Decompose: r = r1 * alpha + r0 mod Q, with r0 centered.
    function decompose(uint256 r) internal pure returns (uint256 r1, int256 r0) {
        uint256 rPos = r % Q;

        // Centered mod alpha
        int256 r0Signed = int256(rPos % MLDSAParams.ALPHA);
        if (uint256(r0Signed) > MLDSAParams.ALPHA / 2) {
            r0Signed -= int256(MLDSAParams.ALPHA);
        }

        // Special boundary case
        if (int256(rPos) - r0Signed == int256(Q) - 1) {
            r1 = 0;
            r0 = r0Signed - 1;
        } else {
            r1 = uint256(int256(rPos) - r0Signed) / MLDSAParams.ALPHA;
            r0 = r0Signed;
        }
    }

    /// @dev UseHint for a single coefficient.
    function useHint(uint256 hint, uint256 r) internal pure returns (uint256) {
        (uint256 r1, int256 r0) = decompose(r);

        if (hint == 1) {
            if (r0 > 0) {
                return (r1 + 1) % MLDSAParams.M_HIGHBITS;
            } else {
                return (r1 + MLDSAParams.M_HIGHBITS - 1) % MLDSAParams.M_HIGHBITS;
            }
        }
        return r1;
    }

    /// @dev Apply UseHint to entire vector of K polynomials.
    function useHintVector(
        uint256[256][6] memory h,
        uint256[256][6] memory w
    ) private pure returns (uint256[256][6] memory w1) {
        for (uint256 i = 0; i < 6; i++) {
            for (uint256 j = 0; j < 256; j++) {
                w1[i][j] = useHint(h[i][j], w[i][j]);
            }
        }
    }

    /// @dev Encode w1 vector: 4 bits per coefficient, K polynomials.
    function encodeW1(uint256[256][6] memory w1) private pure returns (bytes memory) {
        // K * 128 bytes = 768 bytes
        bytes memory result = new bytes(768);
        uint256 idx = 0;

        for (uint256 poly = 0; poly < 6; poly++) {
            for (uint256 j = 0; j < 256; j += 2) {
                result[idx] = bytes1(uint8(w1[poly][j] | (w1[poly][j + 1] << 4)));
                idx++;
            }
        }

        return result;
    }
}
