'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const bufferutils_1 = require('./bufferutils');
const crypto_1 = require('./crypto');
const bcrypto = require('./crypto');
// export function assetToHex
/**
 * Generate the entropy.
 * @param outPoint the prevout point used to compute the entropy.
 * @param contractHash the 32 bytes contract hash.
 */
function generateEntropy(outPoint, contractHash = Buffer.alloc(32)) {
  console.log('prevout', outPoint);
  if (outPoint.txHash.length !== 64) {
    throw new Error('Invalid txHash length');
  }
  const tBuffer = Buffer.allocUnsafe(36);
  const s = new bufferutils_1.BufferWriter(tBuffer, 0);
  s.writeSlice(Buffer.from(outPoint.txHash, 'hex').reverse());
  s.writeUInt32(outPoint.vout);
  return bcrypto.sha256(
    Buffer.concat([bcrypto.hash256(tBuffer), contractHash]),
  );
}
exports.generateEntropy = generateEntropy;
/**
 * calculate the asset tag from a given entropy.
 * @param entropy the entropy used to compute the asset tag.
 */
function calculateAsset(entropy) {
  const kZero = Buffer.alloc(32);
  const assetBuffer = crypto_1.sha256(Buffer.concat([entropy, kZero]));
  const assetHex = assetBuffer.toString('hex');
  return assetHex;
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
  return crypto_1.sha256(Buffer.concat([entropy, k]));
}
exports.calculateReissuanceToken = calculateReissuanceToken;
