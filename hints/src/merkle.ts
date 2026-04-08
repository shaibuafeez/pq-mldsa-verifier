import { keccak_256 } from '@noble/hashes/sha3';

export interface MerkleTree {
  root: Uint8Array;
  leaves: Uint8Array[];
  layers: Uint8Array[][];
}

/** Concatenate two byte arrays. */
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

/** Compare two byte arrays lexicographically. */
function compare(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

/** Hash two nodes in sorted order (for consistent proofs). */
function hashPair(a: Uint8Array, b: Uint8Array): Uint8Array {
  return compare(a, b) <= 0 ? keccak_256(concat(a, b)) : keccak_256(concat(b, a));
}

/** Build a Merkle tree from leaf data. */
export function buildMerkleTree(leaves: Uint8Array[]): MerkleTree {
  if (leaves.length === 0) {
    return { root: new Uint8Array(32), leaves: [], layers: [] };
  }

  // Hash leaves
  const hashedLeaves = leaves.map((l) => keccak_256(l));
  const layers: Uint8Array[][] = [hashedLeaves];

  let current = hashedLeaves;
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(hashPair(current[i], current[i + 1]));
      } else {
        next.push(current[i]); // Odd element promoted
      }
    }
    layers.push(next);
    current = next;
  }

  return {
    root: current[0],
    leaves: hashedLeaves,
    layers,
  };
}

/** Get a Merkle proof for a leaf at a given index. */
export function getMerkleProof(tree: MerkleTree, index: number): Uint8Array[] {
  const proof: Uint8Array[] = [];
  let idx = index;

  for (let layer = 0; layer < tree.layers.length - 1; layer++) {
    const current = tree.layers[layer];
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;

    if (siblingIdx < current.length) {
      proof.push(current[siblingIdx]);
    }

    idx = Math.floor(idx / 2);
  }

  return proof;
}

/** Verify a Merkle proof. */
export function verifyMerkleProof(
  root: Uint8Array,
  leaf: Uint8Array,
  proof: Uint8Array[],
): boolean {
  let hash = keccak_256(leaf);
  for (const sibling of proof) {
    hash = hashPair(hash, sibling);
  }
  return arraysEqual(hash, root);
}

function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
