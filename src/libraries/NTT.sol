// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title NTT
/// @notice Number Theoretic Transform for ML-DSA-65 over Z_q[X]/(X^256+1).
/// @dev Implements Cooley-Tukey (forward) and Gentleman-Sande (inverse) butterflies
///      per FIPS 204, Algorithms 35-36. Uses zeta = 1753 (primitive 512th root of unity).
///      Zetas stored as packed bytes constant (3 bytes per value, big-endian).
library NTT {
    uint256 internal constant Q = 8380417;
    uint256 internal constant N_INV = 8347681; // 256^{-1} mod Q

    /// @dev Load zeta at index k from packed constant. Each zeta is 3 bytes big-endian.
    function zeta(uint256 k) private pure returns (uint256) {
        // We store all 256 zetas inline to avoid SLOAD costs
        // Using a lookup function with switch cases for the most critical values
        // would be cleaner, but assembly from packed bytes is more gas-efficient.
        bytes memory z = ZETAS_PACKED;
        uint256 offset = k * 3;
        return (uint256(uint8(z[offset])) << 16) | (uint256(uint8(z[offset + 1])) << 8) | uint256(uint8(z[offset + 2]));
    }

    /// @notice Forward NTT (Cooley-Tukey butterfly).
    /// @dev Transforms polynomial from standard to NTT domain. Modifies `f` in place.
    function ntt(uint256[256] memory f) internal pure {
        uint256 k = 0;
        for (uint256 len = 128; len >= 1; len >>= 1) {
            for (uint256 start = 0; start < 256; start += 2 * len) {
                k++;
                uint256 z = zeta(k);
                for (uint256 j = start; j < start + len; j++) {
                    uint256 t = mulmod(z, f[j + len], Q);
                    uint256 fj = f[j];
                    f[j + len] = addmod(fj, Q - t, Q);
                    f[j] = addmod(fj, t, Q);
                }
            }
        }
    }

    /// @notice Inverse NTT (Gentleman-Sande butterfly).
    /// @dev Transforms polynomial from NTT to standard domain.
    ///      Includes final scaling by N^{-1} mod Q. Modifies `f` in place.
    function invNtt(uint256[256] memory f) internal pure {
        uint256 k = 256;
        for (uint256 len = 1; len <= 128; len <<= 1) {
            for (uint256 start = 0; start < 256; start += 2 * len) {
                k--;
                uint256 z = Q - zeta(k); // negated
                for (uint256 j = start; j < start + len; j++) {
                    uint256 t = f[j];
                    f[j] = addmod(t, f[j + len], Q);
                    f[j + len] = mulmod(z, addmod(t, Q - f[j + len], Q), Q);
                }
            }
        }
        // Scale by N^{-1} mod Q
        for (uint256 i = 0; i < 256; i++) {
            f[i] = mulmod(f[i], N_INV, Q);
        }
    }

    /// @notice Pointwise multiplication of two polynomials in NTT domain.
    function pointwiseMul(uint256[256] memory a, uint256[256] memory b) internal pure returns (uint256[256] memory c) {
        for (uint256 i = 0; i < 256; i++) {
            c[i] = mulmod(a[i], b[i], Q);
        }
    }

    /// @notice Pointwise addition of two polynomials.
    function pointwiseAdd(uint256[256] memory a, uint256[256] memory b) internal pure returns (uint256[256] memory c) {
        for (uint256 i = 0; i < 256; i++) {
            c[i] = addmod(a[i], b[i], Q);
        }
    }

    /// @notice Pointwise subtraction: a - b mod Q.
    function pointwiseSub(uint256[256] memory a, uint256[256] memory b) internal pure returns (uint256[256] memory c) {
        for (uint256 i = 0; i < 256; i++) {
            c[i] = addmod(a[i], Q - b[i], Q);
        }
    }

    // -----------------------------------------------------------------------
    // Packed zetas: 256 values * 3 bytes each = 768 bytes, big-endian.
    // ZETAS[i] = 1753^BitRev8(i) mod Q. Index 0 (=1) unused by NTT.
    // Generated programmatically and verified against FIPS 204 reference.
    // -----------------------------------------------------------------------
    bytes private constant ZETAS_PACKED =
        hex"000001495e023975673965694f062b53df734fe0334f066b76b1ae360dd528edb0207fe439728370894a0881926d3dc84c729441e0b428a3d266528a4a18a77940340a52ee6b7d814e9f1d1a28772571df1649ee7611bd492bb72af69722d8d536f72a30911e29d13f49267350685f2010a23887f711b2c30603a40e2bed10b72c4a5f351f9d15428cd43177f420e612341c1d1ad87373668149553f3952f662564a65ad05439a1c53aa5f30b622087f383b0e6d2c83da1c496e330e2b1c5b702ee3f1137eb957a9303ac6ef3fd54c4eb2ea503ee17bb1752648b41ef2561d90a245a6d42ae59b52589c6ef1f53f7288175102075d591187ba52aca9773e9e0296d82592ec4cff12404ce84aa5821e54e64f16c11a7e7903978f4e481731b8595884cc1b48275b63d05d787a35225e400c7e6c09d15bd5326bc4d3258ecb2e534c097a6c3b88206d285c2ca4f8337caa14b2a055853628f18655795d4af670234a8675e82678de6605528c7adf590f6e175bf3da459b7e628b345dbecb1a9e7b0006d96257c5574b3c69a8ef28983864b5fe7ef8f52a4e78120a230154a809b7ff435e87437ff85cd5b44dc04e4728af7f735d0c8d0d0f66d55a6d8061ab98185d96437f314682986629604bd57928de06465d8d49b0e309b4347c0db35a68b0409ba964d3d521762a658591246e3948c39b7bc7594f5859392db223092312eb67454df230c31c28542413232e7faf802dbfcb022a0b7e832c26587a6b3375095b766be1cc5e061e78e00d628c373da6044ae53c1f1d686330bb7361b85ea06c671ac7201fc65ba4ff60d77208f2016de024080e6d56038e6956881e6d3e2603bd6a9dfa07c0176dbfd474d0bd63e1e35195737ab60d2867ba2decd458018c3f4cf50b7009427e233cbd372733336739571a4b5d1969261ef20611c14e4c76c83cf42f7fb19a6af66c2e16693352d6034760085260741e782f63166f0a1107c0f1776d0b0d1ff03458240223d468c5595e88852faa3223fc655e694251e0ed65adb32ca5e679e1fe7b406435e1dd433aac464ade1cfe1473f1ce10170e74b6d7";
}
