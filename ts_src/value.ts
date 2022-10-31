import { readUInt64LE, writeUInt64LE } from './bufferutils';

export class ElementsValue {
  static UNCONFIDENTIAL_PREFIX = 0x01;
  static CONFIDENTIAL_PREFIXES = [0x08, 0x09];

  private prefix: number;
  private value: Buffer;

  private constructor(prefix: number, value: Buffer) {
    this.prefix = prefix;
    this.value = value;
  }

  static fromNumber(num: number): ElementsValue {
    if (num < 0) {
      throw new Error('Invalid negative number');
    }
    const value = Buffer.allocUnsafe(8);
    writeUInt64LE(value, num, 0);
    return new ElementsValue(this.UNCONFIDENTIAL_PREFIX, value.reverse());
  }

  static fromHex(hex: string): ElementsValue {
    const bytes = Buffer.from(hex, 'hex');
    return this.fromBytes(bytes);
  }

  static fromBytes(bytes: Buffer): ElementsValue {
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

  get hex(): string {
    return Buffer.concat([Buffer.of(this.prefix), this.value]).toString('hex');
  }

  get bytes(): Buffer {
    return Buffer.concat([Buffer.of(this.prefix), this.value]);
  }

  get number(): number {
    if (this.prefix !== ElementsValue.UNCONFIDENTIAL_PREFIX) {
      throw new Error('Invalid value prefix');
    }
    return readUInt64LE(reverseWithoutMutate(this.value), 0);
  }

  isConfidential(): boolean {
    if (this.bytes[0] === ElementsValue.UNCONFIDENTIAL_PREFIX) return false;
    return true;
  }
}

function reverseWithoutMutate(buf: Buffer): Buffer {
  return Buffer.from(buf).reverse();
}
