'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.AssetHash = void 0;
class AssetHash {
  constructor(prefix, value) {
    this.prefix = prefix;
    this.value = value;
  }
  static fromHex(hex) {
    const bytes = Buffer.from(hex, 'hex');
    if (bytes.length === 32) {
      return this.fromBytes(bytes.reverse());
    }
    return this.fromBytes(bytes);
  }
  static fromBytes(bytes) {
    if (bytes.length === 32) {
      return new AssetHash(AssetHash.UNCONFIDENTIAL_PREFIX, bytes);
    }
    const prefix = bytes.length > 0 ? bytes[0] : 0;
    const value = bytes.length > 1 ? bytes.slice(1) : Buffer.alloc(0);
    if (
      prefix !== AssetHash.UNCONFIDENTIAL_PREFIX &&
      !AssetHash.CONFIDENTIAL_PREFIXES.includes(prefix)
    ) {
      throw new Error('Invalid asset prefix');
    }
    if (prefix === AssetHash.UNCONFIDENTIAL_PREFIX && value.length !== 32) {
      throw new Error('Invalid unconfidential asset length');
    }
    if (
      AssetHash.CONFIDENTIAL_PREFIXES.includes(prefix) &&
      value.length !== 32
    ) {
      throw new Error('Invalid confidential asset length');
    }
    return new AssetHash(prefix, value);
  }
  get hex() {
    if (this.prefix === AssetHash.UNCONFIDENTIAL_PREFIX) {
      return reverseWithoutMutate(this.value).toString('hex');
    }
    return Buffer.concat([Buffer.of(this.prefix), this.value]).toString('hex');
  }
  get bytes() {
    return Buffer.concat([Buffer.of(this.prefix), this.value]);
  }
  get bytesWithoutPrefix() {
    return this.value;
  }
  get isConfidential() {
    return this.prefix !== AssetHash.UNCONFIDENTIAL_PREFIX;
  }
}
exports.AssetHash = AssetHash;
AssetHash.UNCONFIDENTIAL_PREFIX = 0x01;
AssetHash.CONFIDENTIAL_PREFIXES = [0x0a, 0x0b];
function reverseWithoutMutate(buf) {
  return Buffer.from(buf).reverse();
}
