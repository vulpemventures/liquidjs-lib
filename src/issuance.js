'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const bufferutils_1 = require('./bufferutils');
const bcrypto = require('./crypto');
const sha256d_1 = require('./sha256d');
// export function assetToHex
/**
 * Generate the entropy.
 * @param outPoint the prevout point used to compute the entropy.
 * @param contractHash the 32 bytes contract hash.
 */
function generateEntropy(outPoint, contractHash = Buffer.alloc(32)) {
  if (outPoint.txHash.length !== 32) {
    throw new Error('Invalid txHash length');
  }
  const tBuffer = Buffer.allocUnsafe(36);
  const s = new bufferutils_1.BufferWriter(tBuffer, 0);
  s.writeSlice(outPoint.txHash);
  s.writeInt32(outPoint.vout);
  const prevoutHash = bcrypto.hash256(s.buffer);
  const concatened = Buffer.concat([prevoutHash, contractHash]);
  return sha256d_1.sha256Midstate(concatened);
}
exports.generateEntropy = generateEntropy;
/**
 * calculate the asset tag from a given entropy.
 * @param entropy the entropy used to compute the asset tag.
 */
function calculateAsset(entropy) {
  const kZero = Buffer.alloc(32);
  return sha256d_1.sha256Midstate(Buffer.concat([entropy, kZero]));
}
exports.calculateAsset = calculateAsset;
/**
 * Compute the reissuance token.
 * @param entropy the entropy used to compute the reissuance token.
 * @param confidential true if confidential.
 */
function calculateReissuanceToken(entropy, confidential = false) {
  const k = confidential
    ? Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000002',
        'hex',
      )
    : Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000001',
        'hex',
      );
  return sha256d_1.sha256Midstate(Buffer.concat([entropy, k]));
}
exports.calculateReissuanceToken = calculateReissuanceToken;
