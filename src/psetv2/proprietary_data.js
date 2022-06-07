'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.ProprietaryData = void 0;
const bufferutils_1 = require('../bufferutils');
const pset_1 = require('./pset');
class ProprietaryData {
  constructor(id, subType, keyData, value) {
    this.identifier = id;
    this.subType = subType;
    this.keyData = keyData;
    this.value = value;
  }
  static fromKeyPair(keyPair) {
    if (keyPair.key.keyType !== 0xfc) {
      throw new Error('invalid proprietary data key type');
    }
    const r = new bufferutils_1.BufferReader(keyPair.key.keyData);
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
  static proprietaryKey(subType, keyData) {
    const size = keySize(keyData);
    const buf = Buffer.allocUnsafe(size);
    const w = new bufferutils_1.BufferWriter(buf);
    w.writeVarSlice(pset_1.magicPrefix);
    w.writeSlice(Buffer.from([subType]));
    if (keyData && keyData.length > 0) {
      w.writeSlice(keyData);
    }
    return buf;
  }
}
exports.ProprietaryData = ProprietaryData;
function keySize(keyData) {
  const keyDataSize = keyData ? keyData.length : 0;
  return (
    bufferutils_1.varuint.encodingLength(pset_1.magicPrefix.length) +
    pset_1.magicPrefix.length +
    1 +
    keyDataSize
  );
}
