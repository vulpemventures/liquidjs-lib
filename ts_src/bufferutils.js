"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const types = require("./types");
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');
const CONFIDENTIAL_COMMITMENT = 33; // default size of confidential commitments (i.e. asset, value, nonce)
const CONFIDENTIAL_VALUE = 9; // explicit size of confidential values
// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint(value, max) {
    if (typeof value !== 'number')
        throw new Error('cannot write a non-number as a number');
    if (value < 0)
        throw new Error('specified a negative value for writing an unsigned value');
    if (value > max)
        throw new Error('RangeError: value out of range');
    if (Math.floor(value) !== value)
        throw new Error('value has a fractional component');
}
function readUInt64LE(buffer, offset) {
    const a = buffer.readUInt32LE(offset);
    let b = buffer.readUInt32LE(offset + 4);
    b *= 0x100000000;
    verifuint(b + a, 0x001fffffffffffff);
    return b + a;
}
exports.readUInt64LE = readUInt64LE;
function writeUInt64LE(buffer, value, offset) {
    verifuint(value, 0x001fffffffffffff);
    buffer.writeInt32LE(value & -1, offset);
    buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4);
    return offset + 8;
}
exports.writeUInt64LE = writeUInt64LE;
function reverseBuffer(buffer) {
    if (buffer.length < 1)
        return buffer;
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
exports.reverseBuffer = reverseBuffer;
/**
 * Helper class for serialization of bitcoin data types into a pre-allocated buffer.
 */
class BufferWriter {
    constructor(buffer, offset = 0) {
        this.buffer = buffer;
        this.offset = offset;
        typeforce(types.tuple(types.Buffer, types.UInt32), [buffer, offset]);
    }
    writeUInt8(i) {
        this.offset = this.buffer.writeUInt8(i, this.offset);
    }
    writeInt32(i) {
        this.offset = this.buffer.writeInt32LE(i, this.offset);
    }
    writeUInt32(i) {
        this.offset = this.buffer.writeUInt32LE(i, this.offset);
    }
    writeUInt64(i) {
        this.offset = writeUInt64LE(this.buffer, i, this.offset);
    }
    writeVarInt(i) {
        varuint.encode(i, this.buffer, this.offset);
        this.offset += varuint.encode.bytes;
    }
    writeSlice(slice) {
        if (this.buffer.length < this.offset + slice.length) {
            throw new Error('Cannot write slice out of bounds');
        }
        this.offset += slice.copy(this.buffer, this.offset);
    }
    writeVarSlice(slice) {
        this.writeVarInt(slice.length);
        this.writeSlice(slice);
    }
    writeVector(vector) {
        this.writeVarInt(vector.length);
        vector.forEach((buf) => this.writeVarSlice(buf));
    }
    writeConfidentialInFields(input) {
        this.writeVarSlice(input.issuanceRangeProof);
        this.writeVarSlice(input.inflationRangeProof);
        this.writeVarInt(input.witness.length);
        for (const it of input.witness)
            this.writeVarSlice(it);
        this.writeVarInt(input.peginWitness.length);
        for (const it of input.peginWitness)
            this.writeVarSlice(it);
    }
    writeConfidentialOutFields(output) {
        this.writeVarSlice(output.surjectionProof);
        this.writeVarSlice(output.rangeProof);
    }
}
exports.BufferWriter = BufferWriter;
/**
 * Helper class for reading of bitcoin data types from a buffer.
 */
class BufferReader {
    constructor(buffer, offset = 0) {
        this.buffer = buffer;
        this.offset = offset;
        typeforce(types.tuple(types.Buffer, types.UInt32), [buffer, offset]);
    }
    readUInt8() {
        const result = this.buffer.readUInt8(this.offset);
        this.offset++;
        return result;
    }
    readInt32() {
        const result = this.buffer.readInt32LE(this.offset);
        this.offset += 4;
        return result;
    }
    readUInt32() {
        const result = this.buffer.readUInt32LE(this.offset);
        this.offset += 4;
        return result;
    }
    readUInt64() {
        const result = readUInt64LE(this.buffer, this.offset);
        this.offset += 8;
        return result;
    }
    readVarInt() {
        const vi = varuint.decode(this.buffer, this.offset);
        this.offset += varuint.decode.bytes;
        return vi;
    }
    readSlice(n) {
        if (this.buffer.length < this.offset + n) {
            throw new Error('Cannot read slice out of bounds');
        }
        const result = this.buffer.slice(this.offset, this.offset + n);
        this.offset += n;
        return result;
    }
    readVarSlice() {
        return this.readSlice(this.readVarInt());
    }
    readVector() {
        const count = this.readVarInt();
        const vector = [];
        for (let i = 0; i < count; i++)
            vector.push(this.readVarSlice());
        return vector;
    }
    // CConfidentialAsset size 33, prefixA 10, prefixB 11
    readConfidentialAsset() {
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
    readConfidentialNonce() {
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
    readConfidentialValue() {
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
    readConfidentialInFields() {
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
    readConfidentialOutFields() {
        const surjectionProof = this.readVarSlice();
        const rangeProof = this.readVarSlice();
        return { surjectionProof, rangeProof };
    }
    readIssuance() {
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
exports.BufferReader = BufferReader;
