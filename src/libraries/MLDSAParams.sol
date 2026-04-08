// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title MLDSAParams
/// @notice ML-DSA-65 (FIPS 204) parameter constants.
library MLDSAParams {
    // --- Core Parameters ---
    uint256 internal constant Q = 8380417; // Prime modulus = 2^23 - 2^13 + 1
    uint256 internal constant N = 256; // Polynomial degree
    uint256 internal constant K = 6; // Matrix rows / public key vector length
    uint256 internal constant L = 5; // Matrix columns / secret key vector length
    uint256 internal constant D = 13; // Dropped bits from t

    // --- Security Parameters ---
    uint256 internal constant TAU = 49; // Challenge Hamming weight
    uint256 internal constant ETA = 4; // Secret key coefficient bound
    uint256 internal constant GAMMA1 = 524288; // 2^19, mask coefficient range
    uint256 internal constant GAMMA2 = 261888; // (Q-1)/32, low-order rounding range
    uint256 internal constant BETA = 196; // TAU * ETA, rejection bound
    uint256 internal constant OMEGA = 55; // Max hint ones

    // --- Derived Constants ---
    uint256 internal constant ALPHA = 523776; // 2 * GAMMA2
    uint256 internal constant M_HIGHBITS = 16; // (Q-1) / ALPHA, number of high-bits levels
    uint256 internal constant NORM_BOUND = 524092; // GAMMA1 - BETA, infinity norm check bound
    uint256 internal constant Q_HALF = 4190208; // (Q-1)/2, for centered representation
    uint256 internal constant N_INV = 8347681; // 256^{-1} mod Q, for InvNTT scaling

    // --- Size Constants (bytes) ---
    uint256 internal constant PK_SIZE = 1952; // Public key: 32 + 320*K
    uint256 internal constant SIG_SIZE = 3309; // Signature: 48 + 640*L + 55 + K
    uint256 internal constant C_TILDE_BYTES = 48; // Commitment hash length
    uint256 internal constant RHO_BYTES = 32; // Seed for matrix A
    uint256 internal constant TR_BYTES = 64; // Public key hash length
    uint256 internal constant MU_BYTES = 64; // Message representative length

    // --- Encoding Sizes ---
    uint256 internal constant T1_PACKED_BYTES = 320; // Per polynomial: 256 * 10 / 8
    uint256 internal constant Z_PACKED_BYTES = 640; // Per polynomial: 256 * 20 / 8
    uint256 internal constant H_PACKED_BYTES = 61; // OMEGA + K
    uint256 internal constant W1_PACKED_BYTES = 128; // Per polynomial: 256 * 4 / 8

    // --- NTT Constants ---
    uint256 internal constant ZETA = 1753; // Primitive 512th root of unity mod Q
}
