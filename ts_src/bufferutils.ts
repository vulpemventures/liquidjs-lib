import * as types from './types';

const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');

const CONFIDENTIAL_COMMITMENT = 33; // default size of confidential commitments (i.e. asset, value, nonce)
const CONFIDENTIAL_VALUE = 9; // explicit size of confidential values

// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint(value: number, max: number): void {
  if (typeof value !== 'number')
    throw new Error('cannot write a non-number as a number');
  if (value < 0)
    throw new Error('specified a negative value for writing an unsigned value');
  if (value > max) throw new Error('RangeError: value out of range');
  if (Math.floor(value) !== value)
    throw new Error('value has a fractional component');
}

export function readUInt64LE(buffer: Buffer, offset: number): number {
  const a = buffer.readUInt32LE(offset);
  let b = buffer.readUInt32LE(offset + 4);
  b *= 0x100000000;

  verifuint(b + a, 0x001fffffffffffff);
  return b + a;
}

export function writeUInt64LE(
  buffer: Buffer,
  value: number,
  offset: number,
): number {
  verifuint(value, 0x001fffffffffffff);

  buffer.writeInt32LE(value & -1, offset);
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
  return offset + 8;
}

export function reverseBuffer(buffer: Buffer): Buffer {
  if (buffer.length < 1) return buffer;
  let j = buffer.length - 1;
  let tmp = 0;
  for (let i = 0; i < buffer.length / 2; i++) {
    tmp = buffer[i];
    buffer[i] = buffer[j];
    buffer[j] = tmp;
    j--;
  }
  return buffer;
}

/**
 * Helper class for serialization of bitcoin data types into a pre-allocated buffer.
 */
export class BufferWriter {
  constructor(public buffer: Buffer, public offset: number = 0) {
    typeforce(types.tuple(types.Buffer, types.UInt32), [buffer, offset]);
  }

  writeUInt8(i: number): void {
    this.offset = this.buffer.writeUInt8(i, this.offset);
  }

  writeInt32(i: number): void {
    this.offset = this.buffer.writeInt32LE(i, this.offset);
  }

  writeUInt32(i: number): void {
    this.offset = this.buffer.writeUInt32LE(i, this.offset);
  }

  writeUInt64(i: number): void {
    this.offset = writeUInt64LE(this.buffer, i, this.offset);
  }

  writeVarInt(i: number): void {
    varuint.encode(i, this.buffer, this.offset);
    this.offset += varuint.encode.bytes;
  }

  writeSlice(slice: Buffer): void {
    if (this.buffer.length < this.offset + slice.length) {
      throw new Error('Cannot write slice out of bounds');
    }
    this.offset += slice.copy(this.buffer, this.offset);
  }

  writeVarSlice(slice: Buffer): void {
    this.writeVarInt(slice.length);
    this.writeSlice(slice);
  }

  writeVector(vector: Buffer[]): void {
    this.writeVarInt(vector.length);
    vector.forEach((buf: Buffer) => this.writeVarSlice(buf));
  }

  writeConfidentialInFields(input: any): void {
    this.writeVarSlice(input.issuanceRangeProof);
    this.writeVarSlice(input.inflationRangeProof);
    this.writeVector(input.witness);
    this.writeVector(input.peginWitness);
  }

  writeConfidentialOutFields(output: any): void {
    this.writeVarSlice(output.surjectionProof);
    this.writeVarSlice(output.rangeProof);
  }
}

/**
 * Helper class for reading of bitcoin data types from a buffer.
 */
export class BufferReader {
  constructor(public buffer: Buffer, public offset: number = 0) {
    typeforce(types.tuple(types.Buffer, types.UInt32), [buffer, offset]);
  }

  readUInt8(): number {
    const result = this.buffer.readUInt8(this.offset);
    this.offset++;
    return result;
  }

  readInt32(): number {
    const result = this.buffer.readInt32LE(this.offset);
    this.offset += 4;
    return result;
  }

  readUInt32(): number {
    const result = this.buffer.readUInt32LE(this.offset);
    this.offset += 4;
    return result;
  }

  readUInt64(): number {
    const result = readUInt64LE(this.buffer, this.offset);
    this.offset += 8;
    return result;
  }

  readVarInt(): number {
    const vi = varuint.decode(this.buffer, this.offset);
    this.offset += varuint.decode.bytes;
    return vi;
  }

  readSlice(n: number): Buffer {
    if (this.buffer.length < this.offset + n) {
      throw new Error('Cannot read slice out of bounds');
    }
    const result = this.buffer.slice(this.offset, this.offset + n);
    this.offset += n;
    return result;
  }

  readVarSlice(): Buffer {
    return this.readSlice(this.readVarInt());
  }

  readVector(): Buffer[] {
    const count = this.readVarInt();
    const vector: Buffer[] = [];
    for (let i = 0; i < count; i++) vector.push(this.readVarSlice());
    return vector;
  }

  // CConfidentialAsset size 33, prefixA 10, prefixB 11
  readConfidentialAsset(): Buffer {
    const version = this.readUInt8();
    const versionBuffer = this.buffer.slice(this.offset - 1, this.offset);
    if (version === 1 || version === 0xff)
      return Buffer.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    else if (version === 10 || version === 11)
      return Buffer.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    return versionBuffer;
  }

  // CConfidentialNonce size 33, prefixA 2, prefixB 3
  readConfidentialNonce(): Buffer {
    const version = this.readUInt8();
    const versionBuffer = this.buffer.slice(this.offset - 1, this.offset);
    if (version === 1 || version === 0xff)
      return Buffer.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    else if (version === 2 || version === 3)
      return Buffer.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    return versionBuffer;
  }

  // CConfidentialValue size 9, prefixA 8, prefixB 9
  readConfidentialValue(): Buffer {
    const version = this.readUInt8();
    const versionBuffer = this.buffer.slice(this.offset - 1, this.offset);

    if (version === 1 || version === 0xff)
      return Buffer.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_VALUE - 1),
      ]);
    else if (version === 8 || version === 9)
      return Buffer.concat([
        versionBuffer,
        this.readSlice(CONFIDENTIAL_COMMITMENT - 1),
      ]);
    return versionBuffer;
  }

  readConfidentialInFields(): any {
    const issuanceRangeProof = this.readVarSlice();
    const inflationRangeProof = this.readVarSlice();
    const witness = this.readVector();
    const peginWitness = this.readVector();
    return {
      issuanceRangeProof,
      inflationRangeProof,
      witness,
      peginWitness,
    };
  }

  readConfidentialOutFields(): any {
    const surjectionProof = this.readVarSlice();
    const rangeProof = this.readVarSlice();
    return { surjectionProof, rangeProof };
  }

  readIssuance(): {
    assetBlindingNonce: Buffer;
    assetEntropy: Buffer;
    assetAmount: Buffer;
    tokenAmount: Buffer;
  } {
    const issuanceNonce = this.readSlice(32);
    const issuanceEntropy = this.readSlice(32);

    const amount = this.readConfidentialValue();
    const inflation = this.readConfidentialValue();

    return {
      assetBlindingNonce: issuanceNonce,
      assetEntropy: issuanceEntropy,
      assetAmount: amount,
      tokenAmount: inflation,
    };
  }
}
