import { BufferReader, BufferWriter, varuint } from '../bufferutils';
import { KeyPair } from './key_pair';
import { magicPrefix } from './pset';

export class ProprietaryData {
  static fromKeyPair(keyPair: KeyPair): ProprietaryData {
    if (keyPair.key.keyType !== 0xfc) {
      throw new Error('invalid proprietary data key type');
    }
    const r = new BufferReader(keyPair.key.keyData);
    const kpSize = keyPair.key.keyData.length;
    let readBytes = r.offset;

    const identifier = r.readVarSlice();
    if (identifier.length === 0) {
      throw new Error('invalid proprietary data identifier');
    }
    const subType = r.readUInt8();

    readBytes = r.offset - readBytes;
    const remainingBytes = kpSize - readBytes;
    let keyData = Buffer.from([]);
    if (remainingBytes > 0) {
      keyData = r.readSlice(remainingBytes);
    }

    return new ProprietaryData(identifier, subType, keyData, keyPair.value);
  }

  static proprietaryKey(subType: number, keyData?: Buffer): Buffer {
    const size = keySize(keyData);
    const buf = Buffer.allocUnsafe(size);
    const w = new BufferWriter(buf);
    w.writeVarSlice(magicPrefix);
    w.writeSlice(Buffer.from([subType]));
    if (keyData! && keyData!.length > 0) {
      w.writeSlice(keyData);
    }
    return buf;
  }

  identifier: Buffer;
  subType: number;
  keyData: Buffer;
  value: Buffer;

  constructor(id: Buffer, subType: number, keyData: Buffer, value: Buffer) {
    this.identifier = id;
    this.subType = subType;
    this.keyData = keyData;
    this.value = value;
  }
}

function keySize(keyData?: Buffer): number {
  const keyDataSize = keyData ? keyData.length : 0;
  return (
    varuint.encodingLength(magicPrefix.length) +
    magicPrefix.length +
    1 +
    keyDataSize
  );
}
