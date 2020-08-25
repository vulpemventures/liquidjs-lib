import { BufferWriter } from './bufferutils';
import * as bcrypto from './crypto';
import { sha256Midstate } from './sha256d';

export interface IssuanceContract {
  name: string;
  ticker: string;
  version: number;
  precision: number;
}

export interface OutPoint {
  txHash: Buffer;
  vout: number;
}
// export function assetToHex

/**
 * Generate the entropy.
 * @param outPoint the prevout point used to compute the entropy.
 * @param contractHash the 32 bytes contract hash.
 */
export function generateEntropy(
  outPoint: OutPoint,
  contractHash: Buffer = Buffer.alloc(32),
): Buffer {
  if (outPoint.txHash.length !== 32) {
    throw new Error('Invalid txHash length');
  }

  const tBuffer: Buffer = Buffer.allocUnsafe(36);
  const s: BufferWriter = new BufferWriter(tBuffer, 0);
  s.writeSlice(outPoint.txHash);
  s.writeInt32(outPoint.vout);
  const prevoutHash = bcrypto.hash256(s.buffer);
  const concatened = Buffer.concat([prevoutHash, contractHash]);
  return sha256Midstate(concatened);
}

/**
 * calculate the asset tag from a given entropy.
 * @param entropy the entropy used to compute the asset tag.
 */
export function calculateAsset(entropy: Buffer): Buffer {
  const kZero = Buffer.alloc(32);
  return sha256Midstate(Buffer.concat([entropy, kZero]));
}

/**
 * Compute the reissuance token.
 * @param entropy the entropy used to compute the reissuance token.
 * @param confidential true if confidential.
 */
export function calculateReissuanceToken(
  entropy: Buffer,
  confidential: boolean = false,
): Buffer {
  const k = confidential
    ? Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000002',
        'hex',
      )
    : Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000001',
        'hex',
      );

  return sha256Midstate(Buffer.concat([entropy, k]));
}
