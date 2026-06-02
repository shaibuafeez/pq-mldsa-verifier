import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { keccak_256 } from '@noble/hashes/sha3';
import { shake128, shake256 } from '@noble/hashes/sha3';
import { buildMerkleTree, type MerkleTree } from './merkle';
import { ntt, invNtt, pointwiseMul, pointwiseAdd, pointwiseSub, scale2d, useHint, encodeW1 } from './poly';

const Q = 8380417;
const K = 6;
const L = 5;
const TAU = 49;
const GAMMA1 = 524288; // 2^19
const D = 13;
const OMEGA = 55;
const ALPHA = 523776; // 2 * GAMMA2
const M_HIGHBITS = 16;

// Step opcodes — must match MLDSAOptimistic.sol's OP_* constants.
export const OP = {
  EXPANDA: 0,
  SHAKE256_64: 1,
  SAMPLEINBALL: 2,
  NTT: 3,
  INTT: 4,
  MUL: 5,
  ADD: 6,
  SUB: 7,
  SCALE2D: 8,
  USEHINT: 9,
  ENCODE_W1: 10,
  SHAKE256_48: 11,
  COMPARE_CTILDE: 12,
} as const;

/** A single step in the verification process. */
export interface VerificationStep {
  index: number;
  opcode: number;
  description: string;
  input: Uint8Array;
  output: Uint8Array;
}

/** Complete hint data for optimistic verification. */
export interface HintData {
  publicKey: Uint8Array;
  message: Uint8Array;
  signature: Uint8Array;
  steps: VerificationStep[];
  merkleTree: MerkleTree;
  merkleRoot: Uint8Array;
  isValid: boolean;
}

/** Encode a uint32 as 4 bytes big-endian. */
function encodeU32(n: number): Uint8Array {
  return new Uint8Array([(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}

/** Encode an array of coefficients as bytes (3 bytes per coeff, big-endian). */
function encodeCoeffs(coeffs: number[]): Uint8Array {
  const result = new Uint8Array(coeffs.length * 3);
  for (let i = 0; i < coeffs.length; i++) {
    const v = ((coeffs[i] % Q) + Q) % Q;
    result[i * 3] = (v >> 16) & 0xff;
    result[i * 3 + 1] = (v >> 8) & 0xff;
    result[i * 3 + 2] = v & 0xff;
  }
  return result;
}

/** Concatenate byte arrays. */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/** Decode one z polynomial (20-bit signed, 640 bytes) to unsigned mod Q.
 *  Mirrors MLDSADecode.unpackPolyZ + the z->unsigned conversion in computeWApprox. */
function decodeZPoly(sig: Uint8Array, base: number): number[] {
  const out = new Array(256).fill(0);
  for (let i = 0; i < 128; i++) {
    const o = base + i * 5;
    const b0 = sig[o], b1 = sig[o + 1], b2 = sig[o + 2], b3 = sig[o + 3], b4 = sig[o + 4];
    const v0 = (b0 | (b1 << 8) | (b2 << 16)) & 0xfffff;
    const v1 = ((b2 >> 4) | (b3 << 4) | (b4 << 12)) & 0xfffff;
    const c0 = GAMMA1 - v0;
    const c1 = GAMMA1 - v1;
    out[i * 2] = ((c0 % Q) + Q) % Q;
    out[i * 2 + 1] = ((c1 % Q) + Q) % Q;
  }
  return out;
}

/** Decode hint (61 bytes) to K polynomials of {0,1}. Mirrors MLDSADecode.unpackHint. */
function decodeHint(sig: Uint8Array, base: number): number[][] {
  const h: number[][] = Array.from({ length: K }, () => new Array(256).fill(0));
  let prevOffset = 0;
  for (let poly = 0; poly < K; poly++) {
    const offset = sig[base + OMEGA + poly];
    for (let j = prevOffset; j < offset; j++) {
      h[poly][sig[base + j]] = 1;
    }
    prevOffset = offset;
  }
  return h;
}

/**
 * Generate all intermediate verification steps for an ML-DSA-65 signature.
 *
 * This runs the full FIPS 204 verification algorithm step by step,
 * capturing each intermediate result. The steps are used to build
 * a Merkle tree for optimistic on-chain verification.
 */
export function generateHints(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): HintData {
  const steps: VerificationStep[] = [];
  let stepIndex = 0;

  // --- Step 0: Verify the signature is valid using noble ---
  const isValid = ml_dsa65.verify(signature, message, publicKey);

  // --- Decode public key ---
  const rho = publicKey.slice(0, 32);
  const t1Packed = publicKey.slice(32);

  // Decode t1 (K=6 polynomials, 10 bits per coeff, 320 bytes each)
  const t1: number[][] = [];
  for (let p = 0; p < K; p++) {
    const poly = new Array(256).fill(0);
    const base = p * 320;
    for (let i = 0; i < 64; i++) {
      const b0 = t1Packed[base + i * 5];
      const b1 = t1Packed[base + i * 5 + 1];
      const b2 = t1Packed[base + i * 5 + 2];
      const b3 = t1Packed[base + i * 5 + 3];
      const b4 = t1Packed[base + i * 5 + 4];
      poly[i * 4] = (b0 | (b1 << 8)) & 0x3ff;
      poly[i * 4 + 1] = ((b1 >> 2) | (b2 << 6)) & 0x3ff;
      poly[i * 4 + 2] = ((b2 >> 4) | (b3 << 4)) & 0x3ff;
      poly[i * 4 + 3] = ((b3 >> 6) | (b4 << 2)) & 0x3ff;
    }
    t1.push(poly);
  }

  // --- Steps 0-29: ExpandA (SHAKE-128 rejection sampling) ---
  // A is sampled directly in the NTT domain; keep the matrix for the
  // polynomial steps below.
  const aHat: number[][][] = Array.from({ length: K }, () => [] as number[][]);
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < L; j++) {
      const seed = concat(rho, new Uint8Array([j, i])); // col before row
      const stream = shake128(seed, { dkLen: 1024 });

      const coeffs: number[] = [];
      let pos = 0;
      while (coeffs.length < 256) {
        const sample =
          (stream[pos] | (stream[pos + 1] << 8) | (stream[pos + 2] << 16)) & 0x7fffff;
        pos += 3;
        if (sample < Q) {
          coeffs.push(sample);
        }
      }

      aHat[i][j] = coeffs;
      const output = encodeCoeffs(coeffs);
      steps.push({
        index: stepIndex,
        opcode: OP.EXPANDA,
        description: `ExpandA[${i}][${j}]`,
        input: seed,
        output,
      });
      stepIndex++;
    }
  }

  // --- Step 30: tr = SHAKE-256(pk, 64) ---
  const tr = shake256(publicKey, { dkLen: 64 });
  steps.push({
    index: stepIndex++,
    opcode: OP.SHAKE256_64,
    description: 'tr = SHAKE-256(pk, 64)',
    input: publicKey,
    output: tr,
  });

  // --- Step 31: mu = SHAKE-256(tr || M', 64) ---
  // M' = 0x00 || 0x00 || message (empty context for direct verification)
  const mPrime = concat(new Uint8Array([0x00, 0x00]), message);
  const muInput = concat(tr, mPrime);
  const mu = shake256(muInput, { dkLen: 64 });
  steps.push({
    index: stepIndex++,
    opcode: OP.SHAKE256_64,
    description: 'mu = SHAKE-256(tr || M\', 64)',
    input: muInput,
    output: mu,
  });

  // --- Step 32: SampleInBall(c_tilde) ---
  const cTilde = signature.slice(0, 48);
  const challengeStream = shake256(cTilde, { dkLen: 256 });

  let signs = 0n;
  for (let i = 0; i < 8; i++) {
    signs |= BigInt(challengeStream[i]) << BigInt(i * 8);
  }

  const c = new Array(256).fill(0);
  let streamPos = 8;
  for (let i = 256 - TAU; i < 256; i++) {
    let j: number;
    do {
      j = challengeStream[streamPos++];
    } while (j > i);
    c[i] = c[j];
    c[j] = (signs & 1n) === 1n ? Q - 1 : 1;
    signs >>= 1n;
  }

  steps.push({
    index: stepIndex++,
    opcode: OP.SAMPLEINBALL,
    description: 'SampleInBall(c_tilde)',
    input: cTilde,
    output: encodeCoeffs(c),
  });

  // --- Steps 33+: polynomial pipeline, decomposed into primitive ops ---
  // Each step is one re-executable primitive that MLDSAOptimistic.executeStep
  // reproduces exactly (enforced by test/OptimisticHintParity.t.sol). Together
  // they cover the entire w'_approx computation and UseHint — no stub, no gap.

  const pushUnary = (opcode: number, desc: string, input: number[], output: number[]) => {
    steps.push({
      index: stepIndex++,
      opcode,
      description: desc,
      input: encodeCoeffs(input),
      output: encodeCoeffs(output),
    });
  };
  const pushBinary = (opcode: number, desc: string, a: number[], b: number[], output: number[]) => {
    steps.push({
      index: stepIndex++,
      opcode,
      description: desc,
      input: concat(encodeCoeffs(a), encodeCoeffs(b)),
      output: encodeCoeffs(output),
    });
  };

  // cHat = NTT(c)
  const cHat = c.slice();
  ntt(cHat);
  pushUnary(OP.NTT, 'NTT(c)', c, cHat);

  // Decode and transform z: zHat[j] = NTT(z[j] mod Q)
  const zHat: number[][] = [];
  for (let j = 0; j < L; j++) {
    const zUnsigned = decodeZPoly(signature, 48 + j * 640);
    const zh = zUnsigned.slice();
    ntt(zh);
    pushUnary(OP.NTT, `NTT(z[${j}])`, zUnsigned, zh);
    zHat.push(zh);
  }

  // t1Hat[i] = NTT(t1[i] * 2^d)
  const t1Hat: number[][] = [];
  for (let i = 0; i < K; i++) {
    const scaled = scale2d(t1[i]);
    pushUnary(OP.SCALE2D, `t1[${i}] * 2^d`, t1[i], scaled);
    const th = scaled.slice();
    ntt(th);
    pushUnary(OP.NTT, `NTT(t1[${i}] * 2^d)`, scaled, th);
    t1Hat.push(th);
  }

  // Decode hint
  const h = decodeHint(signature, 3248);

  // For each row: wApprox[i] = InvNTT( sum_j A_hat[i][j]*z_hat[j] - c_hat*t1_hat[i] )
  const w1All: number[][] = [];
  for (let i = 0; i < K; i++) {
    let acc = new Array(256).fill(0);
    for (let j = 0; j < L; j++) {
      const product = pointwiseMul(aHat[i][j], zHat[j]);
      pushBinary(OP.MUL, `A[${i}][${j}] * z_hat[${j}]`, aHat[i][j], zHat[j], product);
      const newAcc = pointwiseAdd(acc, product);
      pushBinary(OP.ADD, `acc[${i}] += product[${j}]`, acc, product, newAcc);
      acc = newAcc;
    }
    const ct1 = pointwiseMul(cHat, t1Hat[i]);
    pushBinary(OP.MUL, `c_hat * t1_hat[${i}]`, cHat, t1Hat[i], ct1);

    const wApprox = pointwiseSub(acc, ct1);
    pushBinary(OP.SUB, `w_approx_ntt[${i}]`, acc, ct1, wApprox);

    invNtt(wApprox);
    pushUnary(OP.INTT, `InvNTT(w_approx[${i}])`, pointwiseSub(acc, ct1), wApprox);

    const w1 = wApprox.map((r, k) => useHint(h[i][k], r));
    pushBinary(OP.USEHINT, `UseHint(h[${i}], w_approx[${i}])`, h[i], wApprox, w1);
    w1All.push(w1);
  }

  // --- Final-result steps: encode w1, hash to c_tilde', compare ---
  const w1Bytes = encodeW1(w1All);
  steps.push({
    index: stepIndex++,
    opcode: OP.ENCODE_W1,
    description: 'EncodeW1',
    input: concat(...w1All.map(encodeCoeffs)),
    output: w1Bytes,
  });

  const cTildePrimeInput = concat(mu, w1Bytes);
  const cTildePrime = shake256(cTildePrimeInput, { dkLen: 48 });
  steps.push({
    index: stepIndex++,
    opcode: OP.SHAKE256_48,
    description: "c_tilde' = SHAKE-256(mu || w1Bytes, 48)",
    input: cTildePrimeInput,
    output: cTildePrime,
  });

  let ctEqual = 1;
  for (let i = 0; i < 48; i++) {
    if (cTildePrime[i] !== cTilde[i]) { ctEqual = 0; break; }
  }
  steps.push({
    index: stepIndex++,
    opcode: OP.COMPARE_CTILDE,
    description: 'COMPARE c_tilde',
    input: concat(cTildePrime, cTilde),
    output: new Uint8Array([ctEqual]),
  });

  // Build Merkle tree from all steps
  const leaves = steps.map((step) =>
    concat(encodeU32(step.index), new Uint8Array([step.opcode]), step.input, step.output),
  );

  const merkleTree = buildMerkleTree(leaves);

  return {
    publicKey,
    message,
    signature,
    steps,
    merkleTree,
    merkleRoot: merkleTree.root,
    isValid,
  };
}
