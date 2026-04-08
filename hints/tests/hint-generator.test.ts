import { describe, expect, it } from 'bun:test';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { generateHints } from '../src/hint-generator';
import { getMerkleProof, verifyMerkleProof } from '../src/merkle';

describe('generateHints', () => {
  // Generate a fresh keypair and signature for testing
  const { publicKey, secretKey } = ml_dsa65.keygen();
  const message = new Uint8Array(32);
  message[0] = 0xab;
  message[31] = 0xcd;
  const signature = ml_dsa65.sign(message, secretKey);

  it('produces hints for a valid signature', () => {
    const hints = generateHints(publicKey, message, signature);
    expect(hints.isValid).toBe(true);
    expect(hints.merkleRoot.length).toBe(32);
    expect(hints.steps.length).toBeGreaterThan(30);
  });

  it('has correct step count (30 ExpandA + tr + mu + SampleInBall = 33)', () => {
    const hints = generateHints(publicKey, message, signature);
    expect(hints.steps.length).toBe(33);
  });

  it('produces deterministic merkle root', () => {
    const h1 = generateHints(publicKey, message, signature);
    const h2 = generateHints(publicKey, message, signature);
    expect(Array.from(h1.merkleRoot)).toEqual(Array.from(h2.merkleRoot));
  });

  it('ExpandA steps have correct description format', () => {
    const hints = generateHints(publicKey, message, signature);
    expect(hints.steps[0].description).toBe('ExpandA[0][0]');
    expect(hints.steps[29].description).toBe('ExpandA[5][4]');
  });

  it('each ExpandA step output is 768 bytes (256 coefficients * 3 bytes)', () => {
    const hints = generateHints(publicKey, message, signature);
    for (let i = 0; i < 30; i++) {
      expect(hints.steps[i].output.length).toBe(768);
    }
  });

  it('tr step output is 64 bytes', () => {
    const hints = generateHints(publicKey, message, signature);
    expect(hints.steps[30].output.length).toBe(64);
  });

  it('mu step output is 64 bytes', () => {
    const hints = generateHints(publicKey, message, signature);
    expect(hints.steps[31].output.length).toBe(64);
  });

  it('SampleInBall output is 768 bytes (256 coefficients * 3 bytes)', () => {
    const hints = generateHints(publicKey, message, signature);
    expect(hints.steps[32].output.length).toBe(768);
  });

  it('merkle proof verifies for each step', () => {
    const hints = generateHints(publicKey, message, signature);

    for (let i = 0; i < hints.steps.length; i++) {
      const proof = getMerkleProof(hints.merkleTree, i);
      // Build the leaf the same way as the tree
      const step = hints.steps[i];
      const leafData = new Uint8Array([
        (step.index >> 24) & 0xff,
        (step.index >> 16) & 0xff,
        (step.index >> 8) & 0xff,
        step.index & 0xff,
        ...step.input,
        ...step.output,
      ]);
      const valid = verifyMerkleProof(hints.merkleRoot, leafData, proof);
      expect(valid).toBe(true);
    }
  });

  it('detects invalid signature', () => {
    const badSig = new Uint8Array(signature);
    badSig[0] ^= 0xff;
    const hints = generateHints(publicKey, message, badSig);
    expect(hints.isValid).toBe(false);
  });

  it('public key and signature sizes are correct', () => {
    expect(publicKey.length).toBe(1952);
    expect(signature.length).toBe(3309);
  });
});
