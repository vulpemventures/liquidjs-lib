'use strict';
// SHA-256 for JavaScript Mak's edition.
//
// Originally written in 2014-2016 by Dmitry Chestnykh.
// Public domain, no warranty.
// https://github.com/Killfrra/bitcoin-sha256-js
// SHA-256 constants

const K = new Int32Array([
  0x428a2f98,
  0x71374491,
  0xb5c0fbcf,
  0xe9b5dba5,
  0x3956c25b,
  0x59f111f1,
  0x923f82a4,
  0xab1c5ed5,
  0xd807aa98,
  0x12835b01,
  0x243185be,
  0x550c7dc3,
  0x72be5d74,
  0x80deb1fe,
  0x9bdc06a7,
  0xc19bf174,
  0xe49b69c1,
  0xefbe4786,
  0x0fc19dc6,
  0x240ca1cc,
  0x2de92c6f,
  0x4a7484aa,
  0x5cb0a9dc,
  0x76f988da,
  0x983e5152,
  0xa831c66d,
  0xb00327c8,
  0xbf597fc7,
  0xc6e00bf3,
  0xd5a79147,
  0x06ca6351,
  0x14292967,
  0x27b70a85,
  0x2e1b2138,
  0x4d2c6dfc,
  0x53380d13,
  0x650a7354,
  0x766a0abb,
  0x81c2c92e,
  0x92722c85,
  0xa2bfe8a1,
  0xa81a664b,
  0xc24b8b70,
  0xc76c51a3,
  0xd192e819,
  0xd6990624,
  0xf40e3585,
  0x106aa070,
  0x19a4c116,
  0x1e376c08,
  0x2748774c,
  0x34b0bcb5,
  0x391c0cb3,
  0x4ed8aa4a,
  0x5b9cca4f,
  0x682e6ff3,
  0x748f82ee,
  0x78a5636f,
  0x84c87814,
  0x8cc70208,
  0x90befffa,
  0xa4506ceb,
  0xbef9a3f7,
  0xc67178f2,
]);
const initialState = new Int32Array([
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19,
]);

const w = new Int32Array(64);

function hashBlock(state: Int32Array, data: Int32Array, out: Int32Array): void {
  let u, i, j, t1, t2;
  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  let f = state[5];
  let g = state[6];
  let h = state[7];
  for (i = 0; i < 16; i++) w[i] = data[i];
  for (i = 16; i < 64; i++) {
    u = w[i - 2];
    t1 =
      ((u >>> 17) | (u << (32 - 17))) ^
      ((u >>> 19) | (u << (32 - 19))) ^
      (u >>> 10);
    u = w[i - 15];
    t2 =
      ((u >>> 7) | (u << (32 - 7))) ^
      ((u >>> 18) | (u << (32 - 18))) ^
      (u >>> 3);
    w[i] = ((t1 + w[i - 7]) | 0) + ((t2 + w[i - 16]) | 0);
  }
  for (i = 0; i < 64; i++) {
    t1 =
      ((((((e >>> 6) | (e << (32 - 6))) ^
        ((e >>> 11) | (e << (32 - 11))) ^
        ((e >>> 25) | (e << (32 - 25)))) +
        ((e & f) ^ (~e & g))) |
        0) +
        ((h + ((K[i] + w[i]) | 0)) | 0)) |
      0;
    t2 =
      ((((a >>> 2) | (a << (32 - 2))) ^
        ((a >>> 13) | (a << (32 - 13))) ^
        ((a >>> 22) | (a << (32 - 22)))) +
        ((a & b) ^ (a & c) ^ (b & c))) |
      0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) | 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) | 0;
  }
  out[0] = state[0] + a;
  out[1] = state[1] + b;
  out[2] = state[2] + c;
  out[3] = state[3] + d;
  out[4] = state[4] + e;
  out[5] = state[5] + f;
  out[6] = state[6] + g;
  out[7] = state[7] + h;
}

const midstate = new Int32Array(8);
const half = new Int32Array(16);
half[4] = 0x80000000;
half[15] = 640;

const hash1 = new Int32Array(16);
hash1[8] = 0x80000000;
hash1[15] = 256;

export function sha256d_init(data: Int32Array): void {
  half[0] = data[16];
  half[1] = data[17];
  half[2] = data[18];
  hashBlock(initialState, data.slice(0, 16), midstate);
}

const result = new Int32Array(8);

export function sha256d(nonce: number): Int32Array {
  half[3] = nonce;
  hashBlock(midstate, half, hash1);
  hashBlock(initialState, hash1, result);
  return result;
}

export function sha256Midstate(data: Int32Array): Int32Array {
  sha256d_init(data);
  return midstate;
}
