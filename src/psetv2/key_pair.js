'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.KeyPair = exports.Key = exports.ErrEmptyKey = void 0;
const bufferutils_1 = require('../bufferutils');
exports.ErrEmptyKey = new Error('no more key pairs');
class Key {
  constructor(keyType, keyData) {
    this.keyType = keyType;
    this.keyData = keyData || Buffer.from([]);
  }
  static fromBuffer(r) {
    const value = r.readVarSlice();
    if (value.length === 0) {
      throw exports.ErrEmptyKey;
    }
    if (value.length > 10000) {
      throw new Error('invalid key size');
    }
    return new Key(value[0], value.slice(1));
  }
  toBuffer() {
    const buf = Buffer.concat([Buffer.of(this.keyType), this.keyData]);
    const size = bufferutils_1.varuint.encodingLength(buf.length) + buf.length;
    const w = bufferutils_1.BufferWriter.withCapacity(size);
    w.writeVarSlice(buf);
    return w.buffer;
  }
}
exports.Key = Key;
class KeyPair {
  constructor(key, value) {
    this.key = key;
    this.value = value || Buffer.from([]);
  }
  static fromBuffer(r) {
    const key = Key.fromBuffer(r);
    const value = r.readVarSlice();
    return new KeyPair(key, value);
  }
  toBuffer() {
    const keyBuf = this.key.toBuffer();
    const size =
      keyBuf.length +
      bufferutils_1.varuint.encodingLength(this.value.length) +
      this.value.length;
    const w = bufferutils_1.BufferWriter.withCapacity(size);
    w.writeSlice(keyBuf);
    w.writeVarSlice(this.value);
    return w.buffer;
  }
}
exports.KeyPair = KeyPair;
