// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {MLDSAParams} from "./MLDSAParams.sol";

/// @title MLDSADecode
/// @notice Decoding functions for ML-DSA-65 public keys and signatures per FIPS 204.
/// @dev All bit-unpacking uses little-endian byte ordering.
library MLDSADecode {
    /// @notice Decode a public key into rho and t1 polynomials.
    /// @param pk The 1952-byte public key.
    /// @return rho 32-byte seed for matrix A.
    /// @return t1 K=6 polynomials, each 256 coefficients in [0, 1023] (10 bits each).
    function decodePk(bytes calldata pk) internal pure returns (bytes32 rho, uint256[256][6] memory t1) {
        require(pk.length == MLDSAParams.PK_SIZE, "Invalid pk length");

        // First 32 bytes are rho
        rho = bytes32(pk[0:32]);

        // Remaining 1920 bytes: K=6 polynomials at 320 bytes each (10 bits/coeff)
        for (uint256 poly = 0; poly < 6; poly++) {
            uint256 baseOffset = 32 + poly * 320;
            t1[poly] = unpackPoly10(pk[baseOffset:baseOffset + 320]);
        }
    }

    /// @notice Decode a signature into c_tilde, z polynomials, and hint h.
    /// @param sig The 3309-byte signature.
    /// @return cTilde 48-byte commitment hash.
    /// @return z L=5 polynomials with coefficients in [-(gamma1-1), gamma1].
    /// @return h K=6 hint polynomials with coefficients in {0, 1}.
    /// @return valid True if hint encoding is well-formed.
    function decodeSig(bytes calldata sig)
        internal
        pure
        returns (bytes memory cTilde, int256[256][5] memory z, uint256[256][6] memory h, bool valid)
    {
        require(sig.length == MLDSAParams.SIG_SIZE, "Invalid sig length");

        // First 48 bytes: c_tilde
        cTilde = new bytes(48);
        for (uint256 i = 0; i < 48; i++) {
            cTilde[i] = sig[i];
        }

        // Next 3200 bytes: L=5 z polynomials at 640 bytes each (20 bits/coeff)
        for (uint256 poly = 0; poly < 5; poly++) {
            uint256 baseOffset = 48 + poly * 640;
            z[poly] = unpackPolyZ(sig[baseOffset:baseOffset + 640]);
        }

        // Last 61 bytes: hint encoding
        uint256 hintOffset = 48 + 5 * 640; // = 3248
        (h, valid) = unpackHint(sig[hintOffset:hintOffset + 61]);
    }

    /// @notice Unpack a polynomial with 10 bits per coefficient (for t1).
    /// @dev Little-endian bit packing. Output coefficients in [0, 1023].
    function unpackPoly10(bytes calldata data) internal pure returns (uint256[256] memory coeffs) {
        // 256 coefficients * 10 bits = 2560 bits = 320 bytes
        // Process 4 coefficients from 5 bytes at a time (40 bits = 4 * 10)
        for (uint256 i = 0; i < 64; i++) {
            uint256 base = i * 5;
            uint256 b0 = uint256(uint8(data[base]));
            uint256 b1 = uint256(uint8(data[base + 1]));
            uint256 b2 = uint256(uint8(data[base + 2]));
            uint256 b3 = uint256(uint8(data[base + 3]));
            uint256 b4 = uint256(uint8(data[base + 4]));

            uint256 ci = i * 4;
            coeffs[ci] = (b0 | (b1 << 8)) & 0x3FF;
            coeffs[ci + 1] = ((b1 >> 2) | (b2 << 6)) & 0x3FF;
            coeffs[ci + 2] = ((b2 >> 4) | (b3 << 4)) & 0x3FF;
            coeffs[ci + 3] = ((b3 >> 6) | (b4 << 2)) & 0x3FF;
        }
    }

    /// @notice Unpack a z polynomial with 20 bits per coefficient.
    /// @dev Encoded as gamma1 - z_coeff. Output: signed coefficients in [-(gamma1-1), gamma1].
    function unpackPolyZ(bytes calldata data) internal pure returns (int256[256] memory coeffs) {
        // 256 coefficients * 20 bits = 5120 bits = 640 bytes
        // Process 2 coefficients from 5 bytes at a time (40 bits = 2 * 20)
        for (uint256 i = 0; i < 128; i++) {
            uint256 base = i * 5;
            uint256 b0 = uint256(uint8(data[base]));
            uint256 b1 = uint256(uint8(data[base + 1]));
            uint256 b2 = uint256(uint8(data[base + 2]));
            uint256 b3 = uint256(uint8(data[base + 3]));
            uint256 b4 = uint256(uint8(data[base + 4]));

            uint256 ci = i * 2;
            uint256 v0 = (b0 | (b1 << 8) | (b2 << 16)) & 0xFFFFF;
            uint256 v1 = ((b2 >> 4) | (b3 << 4) | (b4 << 12)) & 0xFFFFF;

            // Recover signed: coefficient = gamma1 - encoded_value
            coeffs[ci] = int256(MLDSAParams.GAMMA1) - int256(v0);
            coeffs[ci + 1] = int256(MLDSAParams.GAMMA1) - int256(v1);
        }
    }

    /// @notice Unpack hint encoding (61 bytes = omega + K).
    /// @dev Returns K=6 polynomials with {0,1} coefficients and validity flag.
    function unpackHint(bytes calldata data) internal pure returns (uint256[256][6] memory h, bool valid) {
        valid = true;
        uint256 prevOffset = 0;

        for (uint256 poly = 0; poly < 6; poly++) {
            uint256 offset = uint256(uint8(data[55 + poly])); // offsets start at index omega=55

            // Validate monotonicity
            if (offset < prevOffset) {
                valid = false;
                return (h, valid);
            }
            // Validate bound
            if (offset > 55) {
                valid = false;
                return (h, valid);
            }

            // Set hint positions for this polynomial
            for (uint256 j = prevOffset; j < offset; j++) {
                uint256 pos = uint256(uint8(data[j]));

                // Validate strictly increasing within polynomial
                if (j > prevOffset) {
                    uint256 prevPos = uint256(uint8(data[j - 1]));
                    if (pos <= prevPos) {
                        valid = false;
                        return (h, valid);
                    }
                }

                h[poly][pos] = 1;
            }

            prevOffset = offset;
        }

        // Validate unused positions are zero
        for (uint256 j = prevOffset; j < 55; j++) {
            if (uint8(data[j]) != 0) {
                valid = false;
                return (h, valid);
            }
        }
    }
}
