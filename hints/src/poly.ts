// Polynomial primitives for ML-DSA-65, ported byte-for-byte from the on-chain
// libraries (src/libraries/NTT.sol and MLDSAVerify.sol) so that the hint
// generator's step outputs are reproduced exactly by the contract's
// executeStep(). Parity is enforced by a Foundry cross-test
// (test/OptimisticHintParity.t.sol) that re-executes a generated fixture.
//
// Coefficients are kept as JS numbers: products are < Q^2 ≈ 7.02e13, well within
// Number.MAX_SAFE_INTEGER (9.007e15), so no BigInt is needed.

export const Q = 8380417;
export const N_INV = 8347681; // 256^{-1} mod Q
export const D = 13;
const ALPHA = 523776; // 2 * GAMMA2
const M_HIGHBITS = 16;

// Same packed zetas as src/libraries/NTT.sol (3 bytes/value, big-endian).
const ZETAS_HEX =
  '000001495e023975673965694f062b53df734fe0334f066b76b1ae360dd528edb0207fe439728370894a0881926d3dc84c729441e0b428a3d266528a4a18a77940340a52ee6b7d814e9f1d1a28772571df1649ee7611bd492bb72af69722d8d536f72a30911e29d13f49267350685f2010a23887f711b2c30603a40e2bed10b72c4a5f351f9d15428cd43177f420e612341c1d1ad87373668149553f3952f662564a65ad05439a1c53aa5f30b622087f383b0e6d2c83da1c496e330e2b1c5b702ee3f1137eb957a9303ac6ef3fd54c4eb2ea503ee17bb1752648b41ef2561d90a245a6d42ae59b52589c6ef1f53f7288175102075d591187ba52aca9773e9e0296d82592ec4cff12404ce84aa5821e54e64f16c11a7e7903978f4e481731b8595884cc1b48275b63d05d787a35225e400c7e6c09d15bd5326bc4d3258ecb2e534c097a6c3b88206d285c2ca4f8337caa14b2a055853628f18655795d4af670234a8675e82678de6605528c7adf590f6e175bf3da459b7e628b345dbecb1a9e7b0006d96257c5574b3c69a8ef28983864b5fe7ef8f52a4e78120a230154a809b7ff435e87437ff85cd5b44dc04e4728af7f735d0c8d0d0f66d55a6d8061ab98185d96437f314682986629604bd57928de06465d8d49b0e309b4347c0db35a68b0409ba964d3d521762a658591246e3948c39b7bc7594f5859392db223092312eb67454df230c31c28542413232e7faf802dbfcb022a0b7e832c26587a6b3375095b766be1cc5e061e78e00d628c373da6044ae53c1f1d686330bb7361b85ea06c671ac7201fc65ba4ff60d77208f2016de024080e6d56038e6956881e6d3e2603bd6a9dfa07c0176dbfd474d0bd63e1e35195737ab60d2867ba2decd458018c3f4cf50b7009427e233cbd372733336739571a4b5d1969261ef20611c14e4c76c83cf42f7fb19a6af66c2e16693352d6034760085260741e782f63166f0a1107c0f1776d0b0d1ff03458240223d468c5595e88852faa3223fc655e694251e0ed65adb32ca5e679e1fe7b406435e1dd433aac464ade1cfe1473f1ce10170e74b6d7';

function loadZetas(): number[] {
  const z: number[] = [];
  for (let k = 0; k < 256; k++) {
    const o = k * 6;
    z.push(parseInt(ZETAS_HEX.slice(o, o + 6), 16));
  }
  return z;
}
const ZETAS = loadZetas();

const mod = (x: number) => ((x % Q) + Q) % Q;
const mulmod = (a: number, b: number) => mod(a * b);

/** Forward NTT (Cooley-Tukey), in place — mirrors NTT.ntt. */
export function ntt(f: number[]): void {
  let k = 0;
  for (let len = 128; len >= 1; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      k++;
      const z = ZETAS[k];
      for (let j = start; j < start + len; j++) {
        const t = mulmod(z, f[j + len]);
        const fj = f[j];
        f[j + len] = mod(fj - t);
        f[j] = mod(fj + t);
      }
    }
  }
}

/** Inverse NTT (Gentleman-Sande) with N^{-1} scaling, in place — mirrors NTT.invNtt. */
export function invNtt(f: number[]): void {
  let k = 256;
  for (let len = 1; len <= 128; len <<= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      k--;
      const z = Q - ZETAS[k];
      for (let j = start; j < start + len; j++) {
        const t = f[j];
        f[j] = mod(t + f[j + len]);
        f[j + len] = mulmod(z, mod(t - f[j + len]));
      }
    }
  }
  for (let i = 0; i < 256; i++) f[i] = mulmod(f[i], N_INV);
}

export function pointwiseMul(a: number[], b: number[]): number[] {
  const c = new Array(256);
  for (let i = 0; i < 256; i++) c[i] = mulmod(a[i], b[i]);
  return c;
}

export function pointwiseAdd(a: number[], b: number[]): number[] {
  const c = new Array(256);
  for (let i = 0; i < 256; i++) c[i] = mod(a[i] + b[i]);
  return c;
}

export function pointwiseSub(a: number[], b: number[]): number[] {
  const c = new Array(256);
  for (let i = 0; i < 256; i++) c[i] = mod(a[i] - b[i]);
  return c;
}

export function scale2d(a: number[]): number[] {
  const c = new Array(256);
  const factor = 1 << D;
  for (let i = 0; i < 256; i++) c[i] = mulmod(a[i], factor);
  return c;
}

/** decompose — mirrors MLDSAVerify.decompose. */
function decompose(r: number): { r1: number; r0: number } {
  const rPos = mod(r);
  let r0 = rPos % ALPHA;
  if (r0 > ALPHA / 2) r0 -= ALPHA;
  if (rPos - r0 === Q - 1) {
    return { r1: 0, r0: r0 - 1 };
  }
  return { r1: (rPos - r0) / ALPHA, r0 };
}

/** encodeW1 — mirrors MLDSAVerify.encodeW1 (4 bits/coeff, K=6 polys -> 768 bytes). */
export function encodeW1(w1: number[][]): Uint8Array {
  const out = new Uint8Array(768);
  let idx = 0;
  for (let poly = 0; poly < 6; poly++) {
    for (let j = 0; j < 256; j += 2) {
      out[idx++] = (w1[poly][j] | (w1[poly][j + 1] << 4)) & 0xff;
    }
  }
  return out;
}

/** useHint — mirrors MLDSAVerify.useHint. */
export function useHint(hint: number, r: number): number {
  const { r1, r0 } = decompose(r);
  if (hint === 1) {
    if (r0 > 0) return (r1 + 1) % M_HIGHBITS;
    return (r1 + M_HIGHBITS - 1) % M_HIGHBITS;
  }
  return r1;
}
