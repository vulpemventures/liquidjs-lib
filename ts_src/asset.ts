export class AssetHash {
  static UNCONFIDENTIAL_PREFIX = 0x01;
  static CONFIDENTIAL_PREFIXES = [0x0a, 0x0b];

  private prefix: number;
  private value: Buffer;

  private constructor(prefix: number, value: Buffer) {
    this.prefix = prefix;
    this.value = value;
  }

  static fromHex(hex: string): AssetHash {
    const bytes = Buffer.from(hex, 'hex');
    if (bytes.length === 32) {
      return this.fromBytes(bytes.reverse());
    }
    return this.fromBytes(bytes);
  }

  static fromBytes(bytes: Buffer): AssetHash {
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

  get hex(): string {
    if (this.prefix === AssetHash.UNCONFIDENTIAL_PREFIX) {
      return reverseWithoutMutate(this.value).toString('hex');
    }
    return Buffer.concat([Buffer.of(this.prefix), this.value]).toString('hex');
  }

  get bytes(): Buffer {
    return Buffer.concat([Buffer.of(this.prefix), this.value]);
  }

  get bytesWithoutPrefix(): Buffer {
    return this.value;
  }

  isConfidential(): boolean {
    return !(this.prefix === AssetHash.UNCONFIDENTIAL_PREFIX)
  }
}

function reverseWithoutMutate(buf: Buffer): Buffer {
  return Buffer.from(buf).reverse();
}
