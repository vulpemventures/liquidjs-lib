export class AssetHash {
  static CONFIDENTIAL_ASSET_PREFIX = Buffer.of(0x0a);
  static UNCONFIDENTIAL_ASSET_PREFIX = Buffer.of(0x01);

  private prefix: Buffer;
  private value: Buffer;

  constructor(prefix: Buffer, value: Buffer) {
    this.prefix = prefix;
    this.value = value;
  }

  static fromHex(hex: string, isConfidential: boolean): AssetHash {
    const prefix = isConfidential
      ? AssetHash.CONFIDENTIAL_ASSET_PREFIX
      : AssetHash.UNCONFIDENTIAL_ASSET_PREFIX;
    const value = Buffer.from(hex, 'hex').reverse();
    return new AssetHash(prefix, value);
  }

  static fromBytes(bytes: Buffer): AssetHash {
    if (bytes.length !== 1 + 32) {
      throw new Error('Invalid asset hash length');
    }

    const prefix = bytes.slice(0, 1);
    const value = bytes.slice(1);
    return new AssetHash(prefix, value);
  }

  get hex(): string {
    return reverseWithoutMutate(this.value).toString('hex');
  }

  get bytes(): Buffer {
    return Buffer.concat([this.prefix, this.value]);
  }
}

function reverseWithoutMutate(buf: Buffer): Buffer {
  return buf.slice().reverse();
}
