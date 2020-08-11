import { sha256 } from './crypto';

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

function numToBuffer(num: number): Buffer {
  const b = new ArrayBuffer(4);
  new DataView(b).setUint32(0, num);
  return Buffer.from(new Uint8Array(b));
}

/**
 * Generate the entropy.
 * @param outPoint the prevout point used to compute the entropy.
 * @param contractHash the 32 bytes contract hash.
 */
export function generateEntropy(outPoint: OutPoint, contractHash: Buffer = Buffer.alloc(32)): Buffer {
  if (outPoint.txHash.length !== 32) {
    throw new Error('Invalid txHash length');
  }

  const serializedOutPoint = Buffer.concat([outPoint.txHash, numToBuffer(outPoint.vout)]);
  return sha256(Buffer.concat([
    sha256(serializedOutPoint),
    sha256(contractHash),
  ]));
}

/**
 * calculate the asset tag from a given entropy.
 * @param entropy the entropy used to compute the asset tag.
 */
export function calculateAsset(entropy: Buffer): Buffer {
  const kZero = Buffer.alloc(32);
  return sha256(Buffer.concat([entropy, kZero]));
}

/**
 * Compute the reissuance token.
 * @param entropy the entropy used to compute the reissuance token.
 * @param confidential true if confidential.
 */
export function calculateReissuanceToken(entropy: Buffer, confidential: boolean = false): Buffer {
  const k = confidential ?
    Buffer.from('0000000000000000000000000000000000000000000000000000000000000002', 'hex')
    : Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');

  return sha256(Buffer.concat([entropy, k]));
}
