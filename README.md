# pq-mldsa-verifier

![Solidity](https://img.shields.io/badge/Solidity-%3E%3D0.8.21-363636?logo=solidity)
![FIPS 204](https://img.shields.io/badge/FIPS_204-ML--DSA--65-2563eb)
![Post-Quantum](https://img.shields.io/badge/post--quantum-NIST_Level_3-16a34a)
![Tests](https://img.shields.io/badge/tests-58_passing-16a34a)
![License](https://img.shields.io/badge/license-MIT-gray)

**Pure-Solidity on-chain verification of ML-DSA-65 (FIPS 204) post-quantum digital signatures.**

Prepare your smart contracts for the post-quantum era — no precompiles, no WASM, no chain lock-in. Just Solidity.

> **Warning**: This is experimental cryptographic software. It has not been audited. Do not use in production without independent security review.

> **Live on Base Sepolia:** the full verifier is deployed at
> [`0xe42C6eF5b71834930faC33780bE730F7112a3a6B`](https://sepolia.basescan.org/address/0xe42C6eF5b71834930faC33780bE730F7112a3a6B)
> and verifies a real ML-DSA-65 signature on-chain (returns `true` for the
> @noble vector, `false` for a wrong message). See [`DEPLOYMENTS.md`](DEPLOYMENTS.md).

## The Problem

Every Ethereum wallet today signs with ECDSA. A sufficiently powerful quantum computer breaks ECDSA completely. [NIST standardized ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final) in August 2024 as the post-quantum replacement.

[quantumFDN](https://github.com/multivmlabs) built the only production post-quantum smart contract wallet — but it has two hard constraints:

1. **Chain-locked.** Their ML-DSA-65 verifier runs in Rust on Arbitrum Stylus (WASM). It cannot deploy to Ethereum, Base, Optimism, Polygon, or any other EVM chain.

2. **No L1 path.** Full ML-DSA-65 verification costs ~163M gas — ~4.5x beyond Ethereum's ~36M block gas limit. Even if you ported the math, you couldn't execute it in a single L1 transaction.

Every non-Arbitrum chain is locked out of post-quantum wallet security.

## The Solution

Two contracts. One interface. Zero changes to their wallet.

```solidity
// That's it. Same interface, any EVM chain.
bool valid = verifier.verify(publicKey, messageHash, signature);
```

| Mode | Contract | Gas | Runs On |
|------|----------|-----|---------|
| **Full verification** | `MLDSAVerifier.sol` | ~163M | L2s with high gas limits, off-chain, testing. **Production-ready, fully tested.** |
| **Optimistic verification** | `MLDSAOptimistic.sol` | ~200K submit | Cheaper path for L1. **PoC** — every step is now re-executable on-chain and challengeable (see below), but full L1 soundness still needs step-*linkage* binding. Not production-ready. |

Both implement quantumFDN's exact [`IMLDSAVerifier`](src/interfaces/IMLDSAVerifier.sol) interface. Their `PQValidatorModule.sol` calls our contract with zero code changes — swap the address, done.

This is **proven, not asserted**: [`test/integration/PQWalletIntegration.t.sol`](test/integration/PQWalletIntegration.t.sol) drives the *unmodified* upstream `PQValidatorModule` against this verifier and validates a real ML-DSA-65 UserOp end-to-end — using the same `@noble`-generated vectors that `pq-smart-wallet` ships. The wallet's own suite can only `vm.mockCall` the verifier to return `true` (its production verifier is Arbitrum Stylus/WASM and can't run in the EVM); this is the first test that runs the validator pipeline against on-chain ML-DSA math. Drop this verifier in and the wallet runs on any EVM chain.

## Quick Start

```bash
# Clone
git clone https://github.com/shaibuafeez/pq-mldsa-verifier.git
cd pq-mldsa-verifier

# Build & test (46 Solidity + 12 TS tests: unit, fraud proofs, TS⟷Solidity parity, real wallet integration)
forge build && forge test -vv

# Run the end-to-end demo (keygen → sign → hints → Merkle proofs)
cd hints && bun install && bun run demo
```

**5-line integration:**

```solidity
import {IMLDSAVerifier} from "pq-mldsa-verifier/interfaces/IMLDSAVerifier.sol";

contract MyWallet {
    IMLDSAVerifier immutable verifier;

    function validateSignature(bytes calldata pk, bytes32 msg, bytes calldata sig) external view {
        require(verifier.verify(pk, msg, sig), "invalid PQ signature");
    }
}
```

## Gas Benchmarks

| Operation | Gas | Equivalent To |
|-----------|-----|---------------|
| Full ML-DSA-65 verification | **162,917,043** | ~54,000 `ecrecover()` calls |
| Optimistic submit (bond + commitment) | **~200,000** | ~67 `ecrecover()` calls |
| Challenge one step | **100,000 - 500,000** | Single SHAKE re-execution |
| Finalize (no challenge) | **~50,000** | Cheaper than a Uniswap swap |

### Competitive Landscape

| Project | Gas | Algorithm | Chains | Status |
|---------|-----|-----------|--------|--------|
| Tetration `dilithium-solidity` | >30M | ML-DSA-44 only | EVM | Broken SHAKE, abandoned since 2023 |
| quantumFDN Stylus verifier | 374K | ML-DSA-65 | Arbitrum only | Production |
| **This (full)** | **163M** | **ML-DSA-65** | **Any EVM** | 58 tests, cross-validated, live on Base Sepolia |
| **This (optimistic)** | **~200K submit** | **ML-DSA-65** | **Any EVM** | PoC — per-step re-execution proven; linkage pending |

## Architecture

```
 Off-Chain (TypeScript)                     On-Chain (Solidity)
┌───────────────────────┐              ┌───────────────────────────────┐
│                       │              │                               │
│  hint-generator       │   submit()   │  MLDSAVerifier.sol            │
│  ├── ExpandA (30x)    │─────────────>│  ├── IMLDSAVerifier           │
│  ├── SHAKE-256 (tr)   │  merkle root │  ├── MLDSAVerify.sol          │
│  ├── SHAKE-256 (mu)   │              │  │   ├── NTT.sol              │
│  ├── SampleInBall     │              │  │   ├── Keccak.sol           │
│  └── Merkle tree      │              │  │   ├── MLDSADecode.sol      │
│                       │              │  │   └── MLDSAParams.sol      │
│  135 verification      │              │  │                             │
│  steps captured       │              │  MLDSAOptimistic.sol          │
│                       │              │  ├── submit + ETH bond        │
└───────────────────────┘              │  ├── challenge window (N blks)│
                                       │  ├── single-step re-execute   │
                                       │  └── finalize or slash        │
                                       │                               │
                                       └───────────────────────────────┘
```

```
src/
├── MLDSAVerifier.sol            # Main entry — verify(pk, msg, sig) → bool
├── MLDSAOptimistic.sol          # Optimistic — submit/challenge/finalize
├── interfaces/
│   └── IMLDSAVerifier.sol       # Interface (identical to quantumFDN's)
└── libraries/
    ├── MLDSAVerify.sol          # FIPS 204 Algorithm 8 — full verification logic
    ├── NTT.sol                  # Number Theoretic Transform (forward + inverse)
    ├── Keccak.sol               # Keccak-f[1600] → SHAKE-128/256 from scratch
    ├── MLDSADecode.sol          # Public key & signature bit-unpacking
    └── MLDSAParams.sol          # All ML-DSA-65 constants

hints/
├── src/
│   ├── hint-generator.ts        # Captures all 135 steps (33 hash/sampling + 102 polynomial)
│   ├── merkle.ts                # Merkle tree for dispute resolution
│   └── demo.ts                  # End-to-end demo script
└── tests/
    └── hint-generator.test.ts   # 12 tests — proofs, determinism, parity, step validation
```

## How Optimistic Verification Works

Full ML-DSA-65 verification has 33+ discrete steps (matrix expansion, hashing, polynomial transforms). Instead of running all of them on-chain:

```
SUBMIT      Prover runs full verification off-chain.
            Commits Merkle root of all intermediate step results.
            Posts ETH bond.                                          ~200K gas

CHALLENGE   Anyone can dispute ONE step during the challenge window.
            Provides: step index + opcode + input + output + Merkle proof.
            Contract re-executes that single primitive on-chain.
            Output mismatch → challenge succeeds.                 100-500K gas

FINALIZE    No valid challenge after N blocks?
            Signature accepted. Bond returned to prover.              ~50K gas

     OR

SLASH       Challenge proved a wrong step?
            Signature rejected. Challenger takes the bond.
```

Honest prover: never challenged. Dishonest prover: caught and slashed. Same security model as optimistic rollups.

**What's proven today (and what isn't).** Every step is a primitive, deterministic
operation — ExpandA, SHAKE-256, SampleInBall, NTT, InvNTT, pointwise mul/add/sub,
scale-by-2^d, UseHint — and the contract re-executes *all* of them on-chain (the
previous polynomial-step stub is gone). The off-chain generator emits the full
135-step sequence, and a cross-language parity test re-runs every one of the 102
polynomial steps on-chain and asserts byte-for-byte agreement
([`test/OptimisticHintParity.t.sol`](test/OptimisticHintParity.t.sol)). Fraud
proofs are demonstrated end-to-end: a corrupted step is caught and the bond
slashed; an honest step cannot be challenged
([`test/MLDSAOptimisticChallenge.t.sol`](test/MLDSAOptimisticChallenge.t.sol)).

The remaining gap before this is L1-sound: **step linkage.** Each step is
individually verifiable, but the protocol does not yet enforce that step N's
output is step N+1's input, nor bind the step sequence to (pk, message,
signature) and the final accept. Until that linkage check exists, a malicious
prover could commit individually-correct steps that don't compose into the real
verification. This is the documented next milestone — see
[`SECURITY.md`](SECURITY.md). Use the **full** verifier for anything real today.

## Test Results

```
58 tests across 7 suites — 0 failures

┌──────────────────────────────┬────────┬────────┬─────────┐
│ Test Suite                   │ Passed │ Failed │ Skipped │
├──────────────────────────────┼────────┼────────┼─────────┤
│ MLDSAVerifierTest            │ 18     │ 0      │ 0       │
│ MLDSAOptimisticTest          │ 9      │ 0      │ 0       │
│ MLDSAOptimisticChallengeTest │ 7      │ 0      │ 0       │  ← fraud proofs
│ OptimisticHintParityTest     │ 1      │ 0      │ 0       │  ← TS⟷Solidity parity (102 steps)
│ PQWalletIntegrationTest      │ 6      │ 0      │ 0       │  ← real wallet module, no mocks
│ FuzzTest                     │ 5      │ 0      │ 0       │  ← NTT/pointwise invariants, graceful failure
│ Hint Generator (TS)          │ 12     │ 0      │ 0       │
└──────────────────────────────┴────────┴────────┴─────────┘
```

| Category | What's Verified |
|----------|-----------------|
| **Real signature** | `@noble/post-quantum` ML-DSA-65 signature verifies on-chain at 162.9M gas. Wrong message returns false. Tampered signature returns false. Never reverts. |
| **Cross-implementation** | Uses quantumFDN's exact `js-noble-vectors.json` — the same test vector their Rust Stylus verifier is tested against. Three implementations, one vector, all pass. |
| **SHAKE-128/256** | Matches NIST known-answer vectors. Empty input: `SHAKE-256("") = 0x46b9dd2b...`. Deterministic. Multi-block squeeze. |
| **NTT** | Forward/inverse round-trip with sparse and full 256-coefficient polynomials. |
| **Optimistic flow** | Submit, challenge window, finalize, bond return, insufficient bond revert, independent multi-commitment. |
| **Merkle proofs** | All 135 steps produce valid proofs. Deterministic roots across runs. |

## How ML-DSA-65 Works

<details>
<summary>Click to expand — lattice cryptography primer</summary>

ML-DSA (formerly Dilithium) is a lattice-based digital signature scheme standardized as [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

**Signing** (off-chain): The signer uses a secret key to produce a signature over a message. The signature contains a masked vector `z` and hints `h` that help the verifier recover intermediate values.

**Verification** (on-chain, what this project implements):

1. **Decode** public key (rho + t1) and signature (c_tilde + z + h)
2. **ExpandA** — reconstruct the 6x5 public matrix from seed `rho` via SHAKE-128
3. **SampleInBall** — derive challenge polynomial `c` from `c_tilde` via SHAKE-256
4. **Matrix multiply** — compute `w'_approx = InvNTT(A * NTT(z) - c * NTT(t1 * 2^d))`
5. **UseHint** — apply hints to recover high-order bits `w1`
6. **Final hash** — check `SHAKE-256(mu || w1Encode(w1))` matches `c_tilde`

All arithmetic happens in the polynomial ring `Z_q[X]/(X^256 + 1)` with `q = 8,380,417`.

### Parameters (ML-DSA-65, NIST Level 3)

| Parameter | Value | Role |
|-----------|-------|------|
| q | 8,380,417 | Prime modulus |
| n | 256 | Ring dimension |
| K, L | 6, 5 | Matrix dimensions |
| tau | 49 | Challenge weight |
| gamma1 | 2^19 | Signature range |
| gamma2 | 261,888 | Decomposition parameter |
| Public key | 1,952 bytes | rho (32B) + t1 (1920B) |
| Signature | 3,309 bytes | c_tilde (48B) + z (3200B) + h (61B) |

</details>

## Why SHAKE From Scratch?

The EVM's `keccak256` opcode computes Keccak-256: fixed 32-byte output, `0x01` padding. ML-DSA requires SHAKE-128 and SHAKE-256: variable-length output, `0x1F` padding, different rates.

Since the EVM doesn't expose the raw Keccak-f[1600] permutation, we implement all 24 rounds (theta, rho, pi, chi, iota) from scratch in Solidity. This is ~80% of the gas cost. A future EVM SHAKE precompile would drop full verification from 163M to ~30M gas; a *full* ML-DSA precompile — proposed in [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051) — targets ~3,000 gas, at which point this Solidity implementation becomes the portable fallback/reference for chains that haven't adopted it.

## Cross-Implementation Compatibility

```
@noble/post-quantum (JavaScript)  ──  generates signature
quantumFDN Stylus (Rust ml-dsa)   ──  verifies ✓
This project (Solidity)           ──  verifies ✓
```

One test vector. Three languages. Three implementations. All agree.

## Hint Generator

The `hints/` TypeScript package generates intermediate data for optimistic verification:

```typescript
import { generateHints } from 'pq-mldsa-hints';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const { publicKey, secretKey } = ml_dsa65.keygen();
const signature = ml_dsa65.sign(message, secretKey);
const hints = generateHints(publicKey, message, signature);

// hints.merkleRoot  → bytes32 to submit on-chain
// hints.steps       → 135 steps (33 hash/sampling + 102 polynomial primitives)
// hints.isValid     → signature validity check
```

All 135 steps are emitted, each a single primitive that `MLDSAOptimistic.executeStep`
re-executes on-chain (parity enforced by `test/OptimisticHintParity.t.sol`):

| Steps | Opcode | Operation | Input | Output |
|-------|--------|-----------|-------|--------|
| 0-29 | EXPANDA | ExpandA matrix entries (SHAKE-128) | rho + indices (34 B) | 256 coeffs (768 B) |
| 30-31 | SHAKE256_64 | `tr`, then `mu = SHAKE-256(tr \|\| M')` | pk / tr+message | 64 B |
| 32 | SAMPLEINBALL | `SampleInBall(c_tilde)` | c_tilde (48 B) | 256 coeffs (768 B) |
| 33–92… | NTT / SCALE2D | `NTT(c)`, `NTT(z[j])`, `NTT(t1[i]·2^d)` | 1 poly (768 B) | 1 poly (768 B) |
| …  | MUL / ADD / SUB | `A·z` products + accumulation, `c·t1`, subtraction | 2 polys (1536 B) | 1 poly (768 B) |
| … | INTT | `InvNTT(w_approx[i])` | 1 poly (768 B) | 1 poly (768 B) |
| …134 | USEHINT | `UseHint(h[i], w_approx[i])` | hint + w (1536 B) | w1 poly (768 B) |

## Goals

- [x] Pure Solidity ML-DSA-65 verification — no assembly, no precompiles, fully auditable
- [x] Drop-in compatibility with quantumFDN's `IMLDSAVerifier` interface
- [x] Pass quantumFDN's cross-implementation test vector
- [x] SHAKE-128/256 matching NIST known-answer vectors
- [x] Optimistic verification scaffold with naysayer proofs (PoC)
- [x] Off-chain hint generator with Merkle commitment
- [x] On-chain re-execution of **all** step primitives (NTT, pointwise, UseHint) — no stub
- [x] Off-chain generator emits the full 135-step sequence; cross-language parity test
- [x] Foundry deployment script + live Base Sepolia deployment ([`DEPLOYMENTS.md`](DEPLOYMENTS.md))
- [ ] **Step-linkage binding** for full optimistic L1 soundness (the real remaining work)
- [ ] Gas optimization pass (assembly for inner loops, precomputed tables)
- [ ] Support ML-DSA-44 and ML-DSA-87 parameter sets
- [ ] Formal verification of critical arithmetic (NTT, modular reduction)

## Limitations

| What | Impact | Workaround |
|------|--------|------------|
| Full verify > 30M gas limit | Cannot run on Ethereum L1 in a single tx | Use optimistic mode on L1; full mode works on L2 |
| Optimistic step *linkage* not enforced | Steps are individually re-executable, but not yet chained/bound to inputs — so optimistic mode is PoC, not L1-sound | Use full verifier for production; linkage binding is the next milestone (SECURITY.md) |
| SHAKE is 80% of gas | Inherent to EVM lacking SHAKE opcode | EVM SHAKE precompile, or full ML-DSA precompile ([EIP-8051](https://eips.ethereum.org/EIPS/eip-8051)) |
| Challenge window latency | ~1 hour before signature accepted on L1 | Acceptable for L1; use full verifier on L2 for instant finality |
| Unaudited | Not production-safe | Independent security review needed before mainnet |

## Security

This library implements cryptographic signature verification. Incorrect implementations can have catastrophic consequences.

**What we've done:**
- Tested against NIST known-answer vectors for SHAKE-128/256
- Cross-validated with quantumFDN's production test vector (JavaScript + Rust + Solidity)
- NTT round-trip + pointwise-correctness fuzzing (256 runs each) and graceful-failure fuzzing — see `test/Fuzz.t.sol`
- Fraud-proof tests: corrupted steps are caught, honest steps cannot be challenged
- Graceful failure: invalid inputs return `false`, never revert
- Threat model documented in [`SECURITY.md`](SECURITY.md)

**What's needed before production:**
- Independent security audit (the pure-Solidity Keccak/NTT/FIPS-204 arithmetic are the priority targets)
- Step-linkage binding before the optimistic path is L1-sound
- Formal verification of modular arithmetic

If you find a vulnerability, please report it responsibly by opening a private security advisory on this repository.

## Contributing

Contributions welcome. The highest-impact areas right now:

1. **Step-linkage binding** — make optimistic mode L1-sound by enforcing step wiring and binding to (pk, message, signature). See [`SECURITY.md`](SECURITY.md).
2. **Gas optimization** — assembly for hot loops in NTT and Keccak
3. **Additional parameter sets** — ML-DSA-44 (Level 2) and ML-DSA-87 (Level 5)
4. **EIP-8051 reference** — keep this implementation aligned as the pure-Solidity fallback/cross-check for the proposed ML-DSA precompile

```bash
# Run tests
forge test -vv

# Run with gas report
forge test --gas-report

# Run hint generator tests
cd hints && bun test
```

## License

MIT

## Acknowledgments

- [quantumFDN / MultiVM Labs](https://github.com/multivmlabs) — post-quantum smart contract wallet, `IMLDSAVerifier` interface, cross-implementation test vectors
- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) by Paul Miller — reference ML-DSA implementation
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA standard specification
- [poqeth](https://eprint.iacr.org/2024/247) — naysayer proof concept (AsiaCCS 2025)
- [dilithium-py](https://github.com/GiacomoPope/dilithium-py) — reference Python implementation used for cross-checking
