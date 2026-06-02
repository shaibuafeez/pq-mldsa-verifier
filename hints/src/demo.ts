#!/usr/bin/env node
/**
 * End-to-end demo of the pq-mldsa-verifier system.
 *
 * Demonstrates the full pipeline:
 * 1. Generate ML-DSA-65 keypair
 * 2. Sign a message
 * 3. Generate verification hints + Merkle tree
 * 4. Verify Merkle proofs for each step
 * 5. Show gas cost comparison
 *
 * Run: bun run src/demo.ts
 *   or: npx tsx src/demo.ts
 */

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { generateHints } from './hint-generator';
import { getMerkleProof, verifyMerkleProof } from './merkle';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function formatBytes(n: number): string {
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} bytes`;
}

console.log('='.repeat(70));
console.log('  pq-mldsa-verifier: End-to-End Demo');
console.log('  Pure-Solidity ML-DSA-65 Verifier for quantumFDN pq-smart-wallet');
console.log('='.repeat(70));
console.log();

// Step 1: Key Generation
console.log('[1/5] Generating ML-DSA-65 keypair...');
const t0 = performance.now();
const { publicKey, secretKey } = ml_dsa65.keygen();
const keygenTime = (performance.now() - t0).toFixed(1);

console.log(`  Public key:  ${formatBytes(publicKey.length)} (${bytesToHex(publicKey.slice(0, 16))}...)`);
console.log(`  Secret key:  ${formatBytes(secretKey.length)}`);
console.log(`  Time:        ${keygenTime}ms`);
console.log();

// Step 2: Sign a message
console.log('[2/5] Signing message...');
const message = new Uint8Array(32);
// Simulate a transaction hash
message[0] = 0xde;
message[1] = 0xad;
message[2] = 0xbe;
message[3] = 0xef;
message[31] = 0x42;

const t1 = performance.now();
const signature = ml_dsa65.sign(message, secretKey);
const signTime = (performance.now() - t1).toFixed(1);

console.log(`  Message:     0x${bytesToHex(message).slice(0, 16)}...`);
console.log(`  Signature:   ${formatBytes(signature.length)} (${bytesToHex(signature.slice(0, 16))}...)`);
console.log(`  Time:        ${signTime}ms`);
console.log();

// Step 3: Verify signature (sanity check)
console.log('[3/5] Verifying signature (off-chain sanity check)...');
const t2 = performance.now();
const valid = ml_dsa65.verify(signature, message, publicKey);
const verifyTime = (performance.now() - t2).toFixed(1);
console.log(`  Valid:       ${valid}`);
console.log(`  Time:        ${verifyTime}ms`);
console.log();

// Step 4: Generate hints for optimistic verification
console.log('[4/5] Generating verification hints + Merkle tree...');
const t3 = performance.now();
const hints = generateHints(publicKey, message, signature);
const hintTime = (performance.now() - t3).toFixed(1);

console.log(`  Valid:        ${hints.isValid}`);
console.log(`  Steps:        ${hints.steps.length}`);
console.log(`  Merkle root:  0x${bytesToHex(hints.merkleRoot)}`);
console.log(`  Tree layers:  ${hints.merkleTree.layers.length}`);
console.log(`  Time:         ${hintTime}ms`);
console.log();

// Show step breakdown
console.log('  Step breakdown:');
for (const step of hints.steps) {
  const inputSize = formatBytes(step.input.length).padStart(10);
  const outputSize = formatBytes(step.output.length).padStart(10);
  console.log(`    [${String(step.index).padStart(2)}] ${step.description.padEnd(30)} input:${inputSize}  output:${outputSize}`);
}
console.log();

// Step 5: Verify Merkle proofs
console.log('[5/5] Verifying Merkle proofs for all steps...');
let allValid = true;
for (let i = 0; i < hints.steps.length; i++) {
  const proof = getMerkleProof(hints.merkleTree, i);
  const step = hints.steps[i];
  const leafData = new Uint8Array([
    (step.index >> 24) & 0xff,
    (step.index >> 16) & 0xff,
    (step.index >> 8) & 0xff,
    step.index & 0xff,
    ...step.input,
    ...step.output,
  ]);
  const proofValid = verifyMerkleProof(hints.merkleRoot, leafData, proof);
  if (!proofValid) {
    console.log(`  FAIL: Step ${i} Merkle proof invalid!`);
    allValid = false;
  }
}
console.log(`  All ${hints.steps.length} Merkle proofs: ${allValid ? 'VALID' : 'FAILED'}`);
console.log();

// Summary
console.log('='.repeat(70));
console.log('  Summary: On-Chain Verification Costs');
console.log('='.repeat(70));
console.log();
console.log('  Mode                       Gas Cost       Where');
console.log('  ────────────────────────    ──────────     ─────────────────────');
console.log('  Full verification          ~163M gas      MLDSAVerifier.sol');
console.log('  Optimistic submit          ~295K gas      MLDSAOptimistic.sol');
console.log('  Challenge (single step)    ~100-500K gas  MLDSAOptimistic.sol');
console.log('  Finalize (no challenge)    ~50K gas       MLDSAOptimistic.sol');
console.log();
console.log('  Data sizes for on-chain submission:');
console.log(`    Public key calldata:     ${formatBytes(publicKey.length)}`);
console.log(`    Signature calldata:      ${formatBytes(signature.length)}`);
console.log(`    Merkle root:             32 bytes`);
console.log(`    Total submit calldata:   ~${formatBytes(publicKey.length + signature.length + 32 + 32)}`);
console.log();
console.log('  Comparison with existing solutions:');
console.log('  ────────────────────────────────────────────────────');
console.log('  Tetration dilithium-sol    >30M gas   ML-DSA-44 only, broken');
console.log('  quantumFDN Stylus          374K gas   Arbitrum only (Rust/WASM)');
console.log('  This (full)                163M gas   Any EVM chain');
console.log('  This (optimistic)          295K gas   Any EVM chain (PoC)');
console.log();

// Output data that would be sent on-chain
console.log('='.repeat(70));
console.log('  On-Chain Submission Data (hex)');
console.log('='.repeat(70));
console.log();
console.log(`  merkleRoot: 0x${bytesToHex(hints.merkleRoot)}`);
console.log(`  publicKey:  0x${bytesToHex(publicKey).slice(0, 64)}...`);
console.log(`  message:    0x${bytesToHex(message)}`);
console.log(`  signature:  0x${bytesToHex(signature).slice(0, 64)}...`);
console.log();
console.log('  To submit on-chain, call:');
console.log('  optimistic.submitVerification(publicKey, message, signature, merkleRoot, true)');
console.log();
