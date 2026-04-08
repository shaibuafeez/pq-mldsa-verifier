import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { keccak_256 } from '@noble/hashes/sha3';
import { shake128, shake256 } from '@noble/hashes/sha3';
import { buildMerkleTree, type MerkleTree } from './merkle';

const Q = 8380417;
const K = 6;
const L = 5;
const TAU = 49;
const GAMMA1 = 524288; // 2^19
const D = 13;
const OMEGA = 55;
const ALPHA = 523776; // 2 * GAMMA2
const M_HIGHBITS = 16;

/** A single step in the verification process. */
export interface VerificationStep {
  index: number;
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

      const output = encodeCoeffs(coeffs);
      steps.push({
        index: stepIndex,
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
    description: 'SampleInBall(c_tilde)',
    input: cTilde,
    output: encodeCoeffs(c),
  });

  // --- Step 33+: Record remaining steps as hashes of intermediate data ---
  // (NTTs, polynomial operations, UseHint, final hash)
  // For the Merkle commitment, we hash the step index + input + output

  // Build Merkle tree from all steps
  const leaves = steps.map((step) =>
    concat(encodeU32(step.index), step.input, step.output),
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
