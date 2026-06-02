// Generates a cross-language parity fixture: runs the hint generator on the
// repo's real ML-DSA-65 test vector and writes every polynomial step
// (opcode, input, output) to test/vectors/optimistic-steps.json. The Foundry
// test OptimisticHintParity.t.sol re-executes each step on-chain and asserts
// the output matches byte-for-byte — proving the TS generator and the Solidity
// executeStep() agree.
//
// Run: bun run src/gen-fixture.ts   (from the hints/ directory)

import { readFileSync, writeFileSync } from 'node:fs';
import { generateHints } from './hint-generator';

function parseHex(s: string): Uint8Array {
  const h = s.trim().replace(/^0x/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function toHex(b: Uint8Array): string {
  return '0x' + Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

const pk = parseHex(readFileSync('../test/vectors/pk.hex', 'utf8'));
const sig = parseHex(readFileSync('../test/vectors/sig.hex', 'utf8'));
const message = parseHex('9e4f18281574b474df452cbac5b93cba6a36544a4b4f7c385ac3a928c66a4c84');

const hints = generateHints(pk, message, sig);

// Polynomial steps only (opcode >= 3); the hashing steps already have coverage.
const poly = hints.steps.filter((s) => s.opcode >= 3);

const fixture = {
  count: poly.length,
  opcodes: poly.map((s) => s.opcode),
  inputs: poly.map((s) => toHex(s.input)),
  outputs: poly.map((s) => toHex(s.output)),
};

writeFileSync('../test/vectors/optimistic-steps.json', JSON.stringify(fixture));
console.log(`wrote ${poly.length} polynomial steps to test/vectors/optimistic-steps.json`);
