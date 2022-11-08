'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.ElementsValue = void 0;
const bufferutils_1 = require('./bufferutils');
class ElementsValue {
  constructor(prefix, value) {
    this.prefix = prefix;
    this.value = value;
  }
  static fromNumber(num) {
    if (num < 0) {
      throw new Error('Invalid negative number');
    }
    const value = Buffer.allocUnsafe(8);
    (0, bufferutils_1.writeUInt64LE)(value, num, 0);
    return new ElementsValue(this.UNCONFIDENTIAL_PREFIX, value.reverse());
  }
  static fromHex(hex) {
    const bytes = Buffer.from(hex, 'hex');
    return this.fromBytes(bytes);
  }
  static fromBytes(bytes) {
    if (bytes.length === 8) {
      return new ElementsValue(ElementsValue.UNCONFIDENTIAL_PREFIX, bytes);
    }
    const prefix = bytes.length > 0 ? bytes[0] : 0;
    const value = bytes.length > 1 ? bytes.slice(1) : Buffer.alloc(0);
    if (
      prefix !== ElementsValue.UNCONFIDENTIAL_PREFIX &&
      !ElementsValue.CONFIDENTIAL_PREFIXES.includes(prefix)
    ) {
      throw new Error('Invalid value prefix');
    }
    if (prefix === ElementsValue.UNCONFIDENTIAL_PREFIX && value.length !== 8) {
      throw new Error('Invalid unconfidential value length');
    }
    if (
      ElementsValue.CONFIDENTIAL_PREFIXES.includes(prefix) &&
      value.length !== 32
    ) {
      throw new Error('Invalid confidential value length');
    }
    return new ElementsValue(prefix, value);
  }
  get hex() {
    return Buffer.concat([Buffer.of(this.prefix), this.value]).toString('hex');
  }
  get bytes() {
    return Buffer.concat([Buffer.of(this.prefix), this.value]);
  }
  get number() {
    if (this.prefix !== ElementsValue.UNCONFIDENTIAL_PREFIX) {
      throw new Error('Invalid value prefix');
    }
    return (0, bufferutils_1.readUInt64LE)(reverseWithoutMutate(this.value), 0);
  }
  get isConfidential() {
    return this.prefix !== ElementsValue.UNCONFIDENTIAL_PREFIX;
  }
}
exports.ElementsValue = ElementsValue;
ElementsValue.UNCONFIDENTIAL_PREFIX = 0x01;
ElementsValue.CONFIDENTIAL_PREFIXES = [0x08, 0x09];
function reverseWithoutMutate(buf) {
  return Buffer.from(buf).reverse();
}
