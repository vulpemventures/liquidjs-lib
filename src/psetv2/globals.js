'use strict';
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.PsetGlobal = exports.GlobalDuplicateFieldError = void 0;
const fields_1 = require('./fields');
const key_pair_1 = require('./key_pair');
const proprietary_data_1 = require('./proprietary_data');
const varuint_bitcoin_1 = __importDefault(require('varuint-bitcoin'));
const bitset_1 = __importDefault(require('bitset'));
const bufferutils_1 = require('../bufferutils');
const pset_1 = require('./pset');
const bip32_1 = require('./bip32');
const pubKeyLength = 78;
class GlobalDuplicateFieldError extends Error {
  constructor(message) {
    if (message) {
      message = 'Duplicated global ' + message;
    }
    super(message);
  }
}
exports.GlobalDuplicateFieldError = GlobalDuplicateFieldError;
class PsetGlobal {
  constructor(txVersion, inputCount, outputCount, version, fallbackLocktime) {
    this.txVersion = txVersion || 0;
    this.inputCount = inputCount || 0;
    this.outputCount = outputCount || 0;
    this.version = version || 0;
    this.fallbackLocktime = fallbackLocktime;
  }
  static fromBuffer(r) {
    let kp;
    const global = new PsetGlobal();
    while (true) {
      try {
        kp = key_pair_1.KeyPair.fromBuffer(r);
      } catch (e) {
        if (e instanceof Error && e === key_pair_1.ErrEmptyKey) {
          global.sanityCheck();
          return global;
        }
        throw e;
      }
      switch (kp.key.keyType) {
        case fields_1.GlobalTypes.XPUB:
          if (
            kp.key.keyData.length !== pubKeyLength + 1 &&
            ![2, 3].includes(kp.key.keyData[46])
          ) {
            throw new Error('Invalid xpub length');
          }
          const extendedKey = kp.key.keyData.slice(1);
          const { masterFingerprint, path: derivationPath } = (0,
          bip32_1.decodeBip32Derivation)(kp.value);
          if (!global.xpubs) {
            global.xpubs = [];
          }
          global.xpubs.push({ extendedKey, masterFingerprint, derivationPath });
          break;
        case fields_1.GlobalTypes.TX_VERSION:
          if (global.txVersion > 0) {
            throw new GlobalDuplicateFieldError('tx version');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid global tx version length');
          }
          global.txVersion = kp.value.readUInt32LE();
          break;
        case fields_1.GlobalTypes.FALLBACK_LOCKTIME:
          if (global.fallbackLocktime > 0) {
            throw new GlobalDuplicateFieldError('fallback locktime');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid global fallback locktime length');
          }
          global.fallbackLocktime = kp.value.readUInt32LE();
          break;
        case fields_1.GlobalTypes.INPUT_COUNT:
          if (global.inputCount > 0) {
            throw new GlobalDuplicateFieldError('input count');
          }
          global.inputCount = varuint_bitcoin_1.default.decode(kp.value);
          break;
        case fields_1.GlobalTypes.OUTPUT_COUNT:
          if (global.outputCount > 0) {
            throw new GlobalDuplicateFieldError('output count');
          }
          global.outputCount = varuint_bitcoin_1.default.decode(kp.value);
          break;
        case fields_1.GlobalTypes.TX_MODIFIABLE:
          if (global.txModifiable) {
            throw new GlobalDuplicateFieldError('tx modifiable');
          }
          if (kp.value.length !== 1) {
            throw new Error('Invalid global tx modifiable length');
          }
          global.txModifiable = new bitset_1.default(kp.value[0]);
          break;
        case fields_1.GlobalTypes.VERSION:
          if (global.version > 0) {
            throw new GlobalDuplicateFieldError('version');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid global version length');
          }
          global.version = kp.value.readUInt32LE();
          break;
        case fields_1.GlobalTypes.PROPRIETARY:
          const data = proprietary_data_1.ProprietaryData.fromKeyPair(kp);
          if (pset_1.magicPrefix.compare(data.identifier) === 0) {
            switch (data.subType) {
              case fields_1.GlobalProprietaryTypes.SCALAR:
                if (data.keyData.length !== 32) {
                  throw new Error('Invalid global scalar length');
                }
                if (!global.scalars) {
                  global.scalars = [];
                }
                global.scalars.push(data.keyData);
                break;
              case fields_1.GlobalProprietaryTypes.TX_MODIFIABLE:
                if (global.modifiable) {
                  throw new GlobalDuplicateFieldError('pset modifiable');
                }
                if (kp.value.length !== 1) {
                  throw new Error('Invalid global pset modifiable length');
                }
                global.modifiable = new bitset_1.default(kp.value[0]);
                break;
              default:
                if (!global.proprietaryData) {
                  global.proprietaryData = [];
                }
                global.proprietaryData.push(data);
            }
          }
          break;
        default:
          if (!global.unknowns) {
            global.unknowns = [];
          }
          global.unknowns.push(kp);
          break;
      }
    }
  }
  sanityCheck() {
    if (this.txVersion < 2) {
      throw new Error('Global tx version must be at least 2');
    }
    if (this.txVersion !== 2) {
      throw new Error('Global version must be exactly 2');
    }
    if (this.txModifiable && parseInt(this.txModifiable.toString(), 2) > 7) {
      throw new Error('Invalid global tx modifiable value');
    }
    if (this.modifiable && parseInt(this.modifiable.toString(), 2) !== 0) {
      throw new Error('Invalid global pset modifiable value');
    }
    if (
      this.xpubs &&
      this.xpubs.some((xpub, i) => {
        if (i === this.xpubs.length - 1) {
          return false;
        }
        const next = this.xpubs.slice(i + 1);
        return next.some(
          (nextXpub) => xpub.extendedKey.compare(nextXpub.extendedKey) === 0,
        );
      })
    ) {
      throw new GlobalDuplicateFieldError('xpub');
    }
    if (
      this.scalars &&
      this.scalars.some((scalar, i) => {
        if (i === this.scalars.length - 1) {
          return false;
        }
        const next = this.scalars.slice(i + 1);
        return next.some((nextScalar) => scalar.compare(nextScalar) === 0);
      })
    ) {
      throw new GlobalDuplicateFieldError('scalar');
    }
    return this;
  }
  toBuffer() {
    const keyPairs = this.getKeyPairs();
    const kpBuf = keyPairs.map((kp) => kp.toBuffer());
    let size = 0;
    kpBuf.forEach((buf) => {
      size += buf.length;
    });
    const w = bufferutils_1.BufferWriter.withCapacity(size);
    kpBuf.forEach((buf) => w.writeSlice(buf));
    return w.buffer;
  }
  getKeyPairs() {
    const keyPairs = [];
    if (this.xpubs && this.xpubs.length > 0) {
      this.xpubs.forEach(
        ({ extendedKey, masterFingerprint, derivationPath }) => {
          const keyData = Buffer.concat([
            Buffer.of(extendedKey.length),
            extendedKey,
          ]);
          const key = new key_pair_1.Key(fields_1.GlobalTypes.XPUB, keyData);
          const value = (0, bip32_1.encodeBIP32Derivation)(
            masterFingerprint,
            derivationPath,
          );
          keyPairs.push(new key_pair_1.KeyPair(key, value));
        },
      );
    }
    const txVersion = Buffer.allocUnsafe(4);
    txVersion.writeUInt32LE(this.txVersion, 0);
    const txVersionKey = new key_pair_1.Key(fields_1.GlobalTypes.TX_VERSION);
    keyPairs.push(new key_pair_1.KeyPair(txVersionKey, txVersion));
    if (this.fallbackLocktime !== undefined) {
      const fallbackLocktime = Buffer.allocUnsafe(4);
      fallbackLocktime.writeUInt32LE(this.fallbackLocktime, 0);
      const fallbackLocktimeKey = new key_pair_1.Key(
        fields_1.GlobalTypes.FALLBACK_LOCKTIME,
      );
      keyPairs.push(
        new key_pair_1.KeyPair(fallbackLocktimeKey, fallbackLocktime),
      );
    }
    const inputCount = Buffer.allocUnsafe(
      varuint_bitcoin_1.default.encodingLength(this.inputCount),
    );
    varuint_bitcoin_1.default.encode(this.inputCount, inputCount, 0);
    const inputCountKey = new key_pair_1.Key(fields_1.GlobalTypes.INPUT_COUNT);
    keyPairs.push(new key_pair_1.KeyPair(inputCountKey, inputCount));
    const outputCount = Buffer.allocUnsafe(
      varuint_bitcoin_1.default.encodingLength(this.outputCount),
    );
    varuint_bitcoin_1.default.encode(this.outputCount, outputCount, 0);
    const outputCountKey = new key_pair_1.Key(
      fields_1.GlobalTypes.OUTPUT_COUNT,
    );
    keyPairs.push(new key_pair_1.KeyPair(outputCountKey, outputCount));
    if (this.txModifiable) {
      const txModifiable = Buffer.allocUnsafe(1);
      txModifiable.writeUInt8(Number(this.txModifiable.toString(10)), 0);
      const txModifiableKey = new key_pair_1.Key(
        fields_1.GlobalTypes.TX_MODIFIABLE,
      );
      keyPairs.push(new key_pair_1.KeyPair(txModifiableKey, txModifiable));
    }
    if (this.scalars && this.scalars.length > 0) {
      this.scalars.forEach((scalar) => {
        const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
          fields_1.GlobalProprietaryTypes.SCALAR,
          scalar,
        );
        const scalarKey = new key_pair_1.Key(
          fields_1.GlobalTypes.PROPRIETARY,
          keyData,
        );
        keyPairs.push(new key_pair_1.KeyPair(scalarKey));
      });
    }
    if (this.modifiable && parseInt(this.modifiable.toString(), 2) > 0) {
      const modifiable = Buffer.allocUnsafe(1);
      modifiable.writeUInt8(Number(this.modifiable.toString(2)), 0);
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.GlobalProprietaryTypes.TX_MODIFIABLE,
      );
      const modifiableKey = new key_pair_1.Key(
        fields_1.GlobalTypes.PROPRIETARY,
        keyData,
      );
      keyPairs.push(new key_pair_1.KeyPair(modifiableKey, modifiable));
    }
    const version = Buffer.allocUnsafe(4);
    version.writeUInt32LE(this.version, 0);
    const versionKey = new key_pair_1.Key(fields_1.GlobalTypes.VERSION);
    keyPairs.push(new key_pair_1.KeyPair(versionKey, version));
    if (this.proprietaryData && this.proprietaryData.length > 0) {
      this.proprietaryData.forEach((data) => {
        const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
          data.subType,
          data.keyData,
        );
        const key = new key_pair_1.Key(
          fields_1.GlobalTypes.PROPRIETARY,
          keyData,
        );
        keyPairs.push(new key_pair_1.KeyPair(key, data.value));
      });
    }
    keyPairs.concat(this.unknowns || []);
    return keyPairs;
  }
}
exports.PsetGlobal = PsetGlobal;
