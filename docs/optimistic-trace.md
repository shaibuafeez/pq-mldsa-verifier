# Optimistic Verification — Trace Soundness Design (TRACE_V1)

> Status: **design**. This specifies what turns `MLDSAOptimistic` from a
> per-step-re-execution PoC into a sound optimistic verifier. Sections marked
> **[implemented]** are live; **[planned]** are not yet built. Until every
> "must" below is implemented, use the full `MLDSAVerifier` for anything real.

## 1. Threat model recap

The contract accepts a signature as valid if a submitted commitment is not
successfully challenged within the window. Soundness therefore means:

> A commitment can be finalized **iff** it corresponds to an honest, complete
> execution of FIPS-204 ML-DSA-65 verification on the committed
> `(publicKey, message, signature)` that ends in `accept`.

Today the contract proves each *step* is individually correct (re-execution +
cross-language parity). It does **not** prove:

1. the steps are the *right* steps, in the right order;
2. each step's input is a previous step's output (no substitution);
3. the first steps consume the actual `(pk, message, signature)`;
4. the last step is the `c_tilde` comparison and its result is `accept`;
5. all rejection preconditions (lengths, hint validity, norm bound, hint weight)
   are enforced.

This document closes 1–5.

## 2. What an honest trace is

The full verifier (`MLDSAVerify.verify`) is a fixed dataflow graph. A *trace* is
the linearization of that graph into `N` primitive steps, each:

```
step i = (opcode, inputs[], output)
```

where every element of `inputs[]` is either:
- a **public input slice** (a region of pk / message / signature), or
- the **output of an earlier step** `j < i`.

The trace is *valid* iff (a) every step re-executes to its claimed output,
(b) the wiring matches the canonical ML-DSA-65 graph for the committed
parameter set, and (c) the final step asserts `accept`.

## 3. Trace header & public-input binding  [planned — reviewer #2/#3]

`submitVerification` commits a **header** alongside the Merkle root. The
commitment id and the accepted-tuple key bind to it:

```
TraceHeader {
  bytes4   version;        // "TRACE_V1"
  uint16   paramSet;       // 65  (ML-DSA-65)
  bytes32  publicKeyHash;  // keccak256(publicKey)
  bytes32  message;        // 32-byte message
  bytes32  signatureHash;  // keccak256(signature)
  uint32   stepCount;      // exact expected trace length for this paramSet
  bool     claimedResult;  // must be true to be finalizable
}

headerHash = keccak256(abi.encode(TRACE_HEADER_DOMAIN, header))
commitmentId = keccak256(headerHash, merkleRoot, submitter, block.number)
```

Rules:
- `paramSet` fixes `stepCount` (a constant per parameter set). A trace of the
  wrong length is rejected at submit.
- `verify(pk, msg, sig)` recomputes `publicKeyHash`/`signatureHash` and only
  returns true if a **finalized** commitment exists whose header matches **and**
  `claimedResult == true`.
- `claimedResult == false` traces may exist (an honest "this signature is
  invalid" proof) but never make `verify` return true.

## 4. Versioned, domain-separated, position-aware leaves  [planned — reviewer #5/#6]

Each leaf binds the step *and its wiring*, not just raw data:

```
leaf_i = keccak256(
  MLDSA_TRACE_LEAF_V1,   // domain tag
  headerHash,            // ties every leaf to these public inputs
  uint32 stepIndex,
  uint8  opcode,
  keccak256(input),      // inputHash
  keccak256(output),     // outputHash
  encode(dependencyIndexes)  // which earlier steps (or public-input slices) feed this step
)
```

Node hashing is domain-separated and **position-aware** (no sorted pairs):

```
node = keccak256(MLDSA_TRACE_NODE_V1, left, right)
```

Position-aware proofs commit to *exact ordering*, so a challenger can prove
"step `i` claims dependency `j`" unambiguously. (Sorted-pair trees prove
membership, not position — insufficient for an execution trace.)

## 5. Linkage enforcement  [planned — reviewer #1, the core]

A new challenge type, `challengeLinkage(i, j, ...)`, lets a challenger prove a
*wiring* fault without re-running crypto:

- **Dependency mismatch:** step `i` claims its `k`-th input is step `j`'s output,
  but `inputHash_i[k] != outputHash_j`. Provide both leaves + proofs → slash.
- **Public-input mismatch:** step `i` claims to consume a slice of pk/msg/sig,
  but the committed `inputHash` ≠ `keccak256(that slice of the header's
  pk/msg/sig)` → slash. (Requires the disputed public bytes; cheap.)
- **Wrong graph:** step `i`'s `(opcode, dependencyIndexes)` does not match the
  canonical graph entry for index `i` at this `paramSet` → slash. The canonical
  graph is a contract constant (or derivable), so this is a pure comparison.
- **Bad length / missing final:** `stepCount` ≠ canonical, or the final step is
  not `COMPARE_CTILDE`, or its output ≠ `accept` → cannot finalize.

Existing `challenge(...)` (step re-execution) handles *computation* faults;
`challengeLinkage(...)` handles *wiring* faults. Both must be unwinnable against
an honest trace and winnable against any dishonest one.

## 6. Final-result steps  [implemented — see §8]

The trace must end in the acceptance computation, so disputes can reach it:

| opcode | operation | input | output |
|--------|-----------|-------|--------|
| `ENCODE_W1` | pack the 6 `w1` polynomials (4 bits/coeff) | 6 × w1 poly (4608 B) | `w1Bytes` (768 B) |
| `SHAKE256_48` | `c_tilde' = SHAKE-256(mu \|\| w1Bytes, 48)` | mu(64) ‖ w1Bytes(768) | 48 B |
| `COMPARE_CTILDE` | `c_tilde' == c_tilde` | c_tilde'(48) ‖ c_tilde(48) | 1 B (0/1) |

The committed final leaf is `COMPARE_CTILDE`; `claimedResult` must equal its
output. Without these, the trace proves primitives but never *acceptance*.

## 7. Decode & precondition coverage  [planned — reviewer #4]

The full verifier rejects before doing math; the optimistic trace needs
traceable equivalents, each a challengeable step/assertion:

- public-key decode correctness (rho/t1 slices vs pk bytes)
- signature decode correctness (c_tilde/z/h slices vs sig bytes)
- `validHint == true` (well-formed hint encoding)
- `hintWeight <= OMEGA (55)`
- `||z||_inf < GAMMA1 - BETA`
- packed-value bounds (10-bit t1, 20-bit z)

A trace that skips a required precondition fails the "wrong graph" linkage check
(§5): the canonical graph includes these assertion steps at fixed indices.

## 8. Implementation status

- [x] Per-step re-execution of all primitives (no stub) — `executeStep`
- [x] Cross-language parity over **all** emitted steps — `OptimisticHintParity.t.sol`
- [x] Fraud tests for every step type (incl. ExpandA/SHAKE/SampleInBall)
- [x] Submit-time input validation (lengths, nonzero root, no double-accept)
- [x] Final-result opcodes `ENCODE_W1` / `SHAKE256_48` / `COMPARE_CTILDE`
- [ ] Trace header + public-input binding (§3)
- [ ] Versioned domain-separated position-aware leaves (§4)
- [ ] Linkage challenge `challengeLinkage` (§5)
- [ ] Decode/precondition trace coverage (§7)
- [ ] `finalize` gated on `claimedResult == accept` and canonical `stepCount`

Until the unchecked boxes land, `MLDSAOptimistic` is **PoC** and must not gate
real value. The full `MLDSAVerifier` is unaffected by any of this.
```
