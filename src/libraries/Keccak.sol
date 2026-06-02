// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title Keccak
/// @notice Keccak-f[1600] sponge construction for SHAKE-128 and SHAKE-256.
/// @dev The EVM keccak256 precompile uses the same permutation but with different
///      padding and fixed output. We need SHAKE for variable-length output with
///      domain separator 0x1F. This implements the full 24-round permutation.
library Keccak {
    // Round constants for Keccak-f[1600] (iota step)
    uint64 private constant RC0 = 0x0000000000000001;
    uint64 private constant RC1 = 0x0000000000008082;
    uint64 private constant RC2 = 0x800000000000808A;
    uint64 private constant RC3 = 0x8000000080008000;
    uint64 private constant RC4 = 0x000000000000808B;
    uint64 private constant RC5 = 0x0000000080000001;
    uint64 private constant RC6 = 0x8000000080008081;
    uint64 private constant RC7 = 0x8000000000008009;
    uint64 private constant RC8 = 0x000000000000008A;
    uint64 private constant RC9 = 0x0000000000000088;
    uint64 private constant RC10 = 0x0000000080008009;
    uint64 private constant RC11 = 0x000000008000000A;
    uint64 private constant RC12 = 0x000000008000808B;
    uint64 private constant RC13 = 0x800000000000008B;
    uint64 private constant RC14 = 0x8000000000008089;
    uint64 private constant RC15 = 0x8000000000008003;
    uint64 private constant RC16 = 0x8000000000008002;
    uint64 private constant RC17 = 0x8000000000000080;
    uint64 private constant RC18 = 0x000000000000800A;
    uint64 private constant RC19 = 0x800000008000000A;
    uint64 private constant RC20 = 0x8000000080008081;
    uint64 private constant RC21 = 0x8000000000008080;
    uint64 private constant RC22 = 0x0000000080000001;
    uint64 private constant RC23 = 0x8000000080008008;

    /// @notice SHAKE-128: absorb input and squeeze output bytes.
    /// @param input The data to absorb.
    /// @param outputLen Number of bytes to squeeze.
    /// @return output The squeezed bytes.
    function shake128(bytes memory input, uint256 outputLen) internal pure returns (bytes memory output) {
        return sponge(input, outputLen, 168); // rate = 168 bytes for SHAKE-128
    }

    /// @notice SHAKE-256: absorb input and squeeze output bytes.
    /// @param input The data to absorb.
    /// @param outputLen Number of bytes to squeeze.
    /// @return output The squeezed bytes.
    function shake256(bytes memory input, uint256 outputLen) internal pure returns (bytes memory output) {
        return sponge(input, outputLen, 136); // rate = 136 bytes for SHAKE-256
    }

    /// @notice Core sponge construction.
    /// @param input Data to absorb.
    /// @param outputLen Bytes to squeeze.
    /// @param rate Rate in bytes (168 for SHAKE-128, 136 for SHAKE-256).
    function sponge(bytes memory input, uint256 outputLen, uint256 rate) internal pure returns (bytes memory output) {
        uint64[25] memory state;
        output = new bytes(outputLen);

        // --- Absorb phase ---
        uint256 inputLen = input.length;
        uint256 blockCount = inputLen / rate;

        // Absorb full blocks
        for (uint256 block_ = 0; block_ < blockCount; block_++) {
            absorbBlock(state, input, block_ * rate, rate);
            keccakF(state);
        }

        // Absorb final block with SHAKE padding (0x1F...0x80)
        uint256 remaining = inputLen - blockCount * rate;
        bytes memory padded = new bytes(rate);

        // Copy remaining input bytes
        for (uint256 i = 0; i < remaining; i++) {
            padded[i] = input[blockCount * rate + i];
        }

        // SHAKE domain separator: 0x1F at position after last input byte
        padded[remaining] = bytes1(0x1F);

        // Padding terminator: 0x80 at last byte of rate block
        padded[rate - 1] = padded[rate - 1] | bytes1(0x80);

        absorbBlock(state, padded, 0, rate);
        keccakF(state);

        // --- Squeeze phase ---
        uint256 squeezed = 0;
        while (squeezed < outputLen) {
            uint256 toSqueeze = outputLen - squeezed;
            if (toSqueeze > rate) {
                toSqueeze = rate;
            }
            squeezeBlock(state, output, squeezed, toSqueeze);
            squeezed += toSqueeze;
            if (squeezed < outputLen) {
                keccakF(state);
            }
        }
    }

    /// @dev XOR a block of data into the state (absorb).
    function absorbBlock(uint64[25] memory state, bytes memory data, uint256 offset, uint256 len) private pure {
        uint256 laneCount = len / 8;
        for (uint256 i = 0; i < laneCount; i++) {
            uint64 lane = toLane(data, offset + i * 8);
            state[i] ^= lane;
        }
    }

    /// @dev Extract bytes from state (squeeze).
    function squeezeBlock(uint64[25] memory state, bytes memory output, uint256 offset, uint256 len) private pure {
        uint256 fullLanes = len / 8;
        for (uint256 i = 0; i < fullLanes; i++) {
            fromLane(state[i], output, offset + i * 8);
        }
        // Handle partial lane
        uint256 remaining = len - fullLanes * 8;
        if (remaining > 0) {
            uint64 lane = state[fullLanes];
            for (uint256 j = 0; j < remaining; j++) {
                output[offset + fullLanes * 8 + j] = bytes1(uint8(lane >> (j * 8)));
            }
        }
    }

    /// @dev Convert 8 bytes (little-endian) to a uint64 lane.
    function toLane(bytes memory data, uint256 offset) private pure returns (uint64 lane) {
        for (uint256 i = 0; i < 8; i++) {
            lane |= uint64(uint8(data[offset + i])) << uint64(i * 8);
        }
    }

    /// @dev Write a uint64 lane as 8 bytes (little-endian).
    function fromLane(uint64 lane, bytes memory output, uint256 offset) private pure returns (uint64) {
        for (uint256 i = 0; i < 8; i++) {
            output[offset + i] = bytes1(uint8(lane >> (i * 8)));
        }
        return lane;
    }

    /// @dev Rotate left a 64-bit value.
    function rotl64(uint64 x, uint256 n) private pure returns (uint64) {
        return (x << uint64(n)) | (x >> uint64(64 - n));
    }

    /// @notice Keccak-f[1600] permutation (24 rounds).
    /// @dev Operates on 25 uint64 lanes (5x5 state matrix, column-major: state[x + 5*y]).
    function keccakF(uint64[25] memory s) internal pure {
        // Unrolled 24 rounds for gas efficiency
        for (uint256 round = 0; round < 24; round++) {
            // --- theta ---
            uint64 c0 = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
            uint64 c1 = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
            uint64 c2 = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
            uint64 c3 = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
            uint64 c4 = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];

            uint64 d0 = c4 ^ rotl64(c1, 1);
            uint64 d1 = c0 ^ rotl64(c2, 1);
            uint64 d2 = c1 ^ rotl64(c3, 1);
            uint64 d3 = c2 ^ rotl64(c4, 1);
            uint64 d4 = c3 ^ rotl64(c0, 1);

            s[0] ^= d0;
            s[5] ^= d0;
            s[10] ^= d0;
            s[15] ^= d0;
            s[20] ^= d0;
            s[1] ^= d1;
            s[6] ^= d1;
            s[11] ^= d1;
            s[16] ^= d1;
            s[21] ^= d1;
            s[2] ^= d2;
            s[7] ^= d2;
            s[12] ^= d2;
            s[17] ^= d2;
            s[22] ^= d2;
            s[3] ^= d3;
            s[8] ^= d3;
            s[13] ^= d3;
            s[18] ^= d3;
            s[23] ^= d3;
            s[4] ^= d4;
            s[9] ^= d4;
            s[14] ^= d4;
            s[19] ^= d4;
            s[24] ^= d4;

            // --- rho + pi ---
            uint64 t = s[1];
            uint64 tmp;

            // Unrolled rho+pi: move s[pi(x,y)] = rotl(s[x+5y], rho_offset)
            // pi mapping: (x,y) -> (y, 2x+3y mod 5), traversal order from spec
            tmp = s[10];
            s[10] = rotl64(t, 1);
            t = tmp;
            tmp = s[7];
            s[7] = rotl64(t, 3);
            t = tmp;
            tmp = s[11];
            s[11] = rotl64(t, 6);
            t = tmp;
            tmp = s[17];
            s[17] = rotl64(t, 10);
            t = tmp;
            tmp = s[18];
            s[18] = rotl64(t, 15);
            t = tmp;
            tmp = s[3];
            s[3] = rotl64(t, 21);
            t = tmp;
            tmp = s[5];
            s[5] = rotl64(t, 28);
            t = tmp;
            tmp = s[16];
            s[16] = rotl64(t, 36);
            t = tmp;
            tmp = s[8];
            s[8] = rotl64(t, 45);
            t = tmp;
            tmp = s[21];
            s[21] = rotl64(t, 55);
            t = tmp;
            tmp = s[24];
            s[24] = rotl64(t, 2);
            t = tmp;
            tmp = s[4];
            s[4] = rotl64(t, 14);
            t = tmp;
            tmp = s[15];
            s[15] = rotl64(t, 27);
            t = tmp;
            tmp = s[23];
            s[23] = rotl64(t, 41);
            t = tmp;
            tmp = s[19];
            s[19] = rotl64(t, 56);
            t = tmp;
            tmp = s[13];
            s[13] = rotl64(t, 8);
            t = tmp;
            tmp = s[12];
            s[12] = rotl64(t, 25);
            t = tmp;
            tmp = s[2];
            s[2] = rotl64(t, 43);
            t = tmp;
            tmp = s[20];
            s[20] = rotl64(t, 62);
            t = tmp;
            tmp = s[14];
            s[14] = rotl64(t, 18);
            t = tmp;
            tmp = s[22];
            s[22] = rotl64(t, 39);
            t = tmp;
            tmp = s[9];
            s[9] = rotl64(t, 61);
            t = tmp;
            tmp = s[6];
            s[6] = rotl64(t, 20);
            t = tmp;
            s[1] = rotl64(t, 44);

            // --- chi ---
            for (uint256 y = 0; y < 25; y += 5) {
                uint64 a0 = s[y];
                uint64 a1 = s[y + 1];
                uint64 a2 = s[y + 2];
                uint64 a3 = s[y + 3];
                uint64 a4 = s[y + 4];
                s[y] = a0 ^ ((~a1) & a2);
                s[y + 1] = a1 ^ ((~a2) & a3);
                s[y + 2] = a2 ^ ((~a3) & a4);
                s[y + 3] = a3 ^ ((~a4) & a0);
                s[y + 4] = a4 ^ ((~a0) & a1);
            }

            // --- iota ---
            if (round == 0) s[0] ^= RC0;
            else if (round == 1) s[0] ^= RC1;
            else if (round == 2) s[0] ^= RC2;
            else if (round == 3) s[0] ^= RC3;
            else if (round == 4) s[0] ^= RC4;
            else if (round == 5) s[0] ^= RC5;
            else if (round == 6) s[0] ^= RC6;
            else if (round == 7) s[0] ^= RC7;
            else if (round == 8) s[0] ^= RC8;
            else if (round == 9) s[0] ^= RC9;
            else if (round == 10) s[0] ^= RC10;
            else if (round == 11) s[0] ^= RC11;
            else if (round == 12) s[0] ^= RC12;
            else if (round == 13) s[0] ^= RC13;
            else if (round == 14) s[0] ^= RC14;
            else if (round == 15) s[0] ^= RC15;
            else if (round == 16) s[0] ^= RC16;
            else if (round == 17) s[0] ^= RC17;
            else if (round == 18) s[0] ^= RC18;
            else if (round == 19) s[0] ^= RC19;
            else if (round == 20) s[0] ^= RC20;
            else if (round == 21) s[0] ^= RC21;
            else if (round == 22) s[0] ^= RC22;
            else s[0] ^= RC23;
        }
    }
}
