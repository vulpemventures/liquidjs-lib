import { BufferReader, BufferWriter, varuint } from '../bufferutils';

export class Key {
  static fromBuffer(r: BufferReader): Key {
    const value = r.readVarSlice();
    if (value.length === 0) {
      throw new Error('no more key pairs');
    }
    if (value.length > 10000) {
      throw new Error('invalid key size');
    }
    return new Key(value[0], value.slice(1));
  }

  keyType: number;
  keyData: Buffer;

  constructor(keyType: number, keyData?: Buffer) {
    this.keyType = keyType;
    this.keyData = keyData || Buffer.from([]);
  }

  toBuffer(): Buffer {
    const buf = Buffer.concat([Buffer.of(this.keyType), this.keyData]);
    const size = buf.length + 1;
    const w = BufferWriter.withCapacity(size);
    w.writeVarSlice(buf);
    return w.buffer;
  }
}

export class KeyPair {
  static fromBuffer(r: BufferReader): KeyPair {
    const key = Key.fromBuffer(r);
    const value = r.readVarSlice();
    return new KeyPair(key, value);
  }

  key: Key;
  value: Buffer;

  constructor(key: Key, value?: Buffer) {
    this.key = key;
    this.value = value || Buffer.from([]);
  }

  toBuffer(): Buffer {
    const keyBuf = this.key.toBuffer();
    const size =
      keyBuf.length +
      varuint.encodingLength(this.value.length) +
      this.value.length;
    const w = BufferWriter.withCapacity(size);
    w.writeSlice(keyBuf);
    w.writeVarSlice(this.value);
    return w.buffer;
  }
}
