import { GlobalProprietaryTypes, GlobalTypes } from './fields';
import { ErrEmptyKey, Key, KeyPair } from './key_pair';
import { ProprietaryData } from './proprietary_data';
import varuint from 'varuint-bitcoin';
import BitSet from 'bitset';
import { BufferReader, BufferWriter } from '../bufferutils';
import { magicPrefix } from './pset';
import { decodeBip32Derivation, encodeBIP32Derivation } from './bip32';
import { Xpub } from './interfaces';

const pubKeyLength = 78;

export class GlobalDuplicateFieldError extends Error {
  constructor(message?: string) {
    if (message) {
      message = 'Duplicated global ' + message;
    }
    super(message);
  }
}

export class Global {
  static fromBuffer(r: BufferReader): Global {
    let kp: KeyPair;
    const global = new Global();
    while (true) {
      try {
        kp = KeyPair.fromBuffer(r);
      } catch (e) {
        if (e instanceof Error && e === ErrEmptyKey) {
          global.sanityCheck();
          return global;
        }
        throw e;
      }

      switch (kp.key.keyType) {
        case GlobalTypes.XPUB:
          if (
            kp.key.keyData.length !== pubKeyLength + 1 &&
            ![2, 3].includes(kp.key.keyData[46])
          ) {
            throw new Error('Invalid xpub length');
          }
          const extendedKey = kp.key.keyData.slice(1);
          const {
            masterFingerprint,
            path: derivationPath,
          } = decodeBip32Derivation(kp.value);
          if (!global.xpubs) {
            global.xpubs = [];
          }
          global.xpubs.push({ extendedKey, masterFingerprint, derivationPath });
          break;
        case GlobalTypes.TX_VERSION:
          if (global.txVersion > 0) {
            throw new GlobalDuplicateFieldError('tx version');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid global tx version length');
          }
          global.txVersion = kp.value.readUInt32LE();
          break;
        case GlobalTypes.FALLBACK_LOCKTIME:
          if (global.fallbackLocktime! > 0) {
            throw new GlobalDuplicateFieldError('fallback locktime');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid global fallback locktime length');
          }
          global.fallbackLocktime = kp.value.readUInt32LE();
          break;
        case GlobalTypes.INPUT_COUNT:
          if (global.inputCount > 0) {
            throw new GlobalDuplicateFieldError('input count');
          }
          global.inputCount = varuint.decode(kp.value);
          break;
        case GlobalTypes.OUTPUT_COUNT:
          if (global.outputCount > 0) {
            throw new GlobalDuplicateFieldError('output count');
          }
          global.outputCount = varuint.decode(kp.value);
          break;
        case GlobalTypes.TX_MODIFIABLE:
          if (global.txModifiable!) {
            throw new GlobalDuplicateFieldError('tx modifiable');
          }
          if (kp.value.length !== 1) {
            throw new Error('Invalid global tx modifiable length');
          }
          global.txModifiable = new BitSet(kp.value[0]);
          break;
        case GlobalTypes.VERSION:
          if (global.version > 0) {
            throw new GlobalDuplicateFieldError('version');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid global version length');
          }
          global.version = kp.value.readUInt32LE();
          break;
        case GlobalTypes.PROPRIETARY:
          const data = ProprietaryData.fromKeyPair(kp);
          if (magicPrefix.compare(data.identifier) === 0) {
            switch (data.subType) {
              case GlobalProprietaryTypes.SCALAR:
                if (data.keyData.length !== 32) {
                  throw new Error('Invalid global scalar length');
                }
                if (!global.scalars) {
                  global.scalars = [];
                }
                global.scalars!.push(data.keyData);
                break;
              case GlobalProprietaryTypes.TX_MODIFIABLE:
                if (global.modifiable!) {
                  throw new GlobalDuplicateFieldError('pset modifiable');
                }
                if (kp.value.length !== 1) {
                  throw new Error('Invalid global pset modifiable length');
                }
                global.modifiable = new BitSet(kp.value[0]);
                break;
              default:
                if (!global.proprietaryData) {
                  global.proprietaryData = [];
                }
                global.proprietaryData!.push(data);
            }
          }
          break;
        default:
          if (!global.unknowns) {
            global.unknowns = [];
          }
          global.unknowns!.push(kp);
          break;
      }
    }
  }

  xpubs?: Xpub[];
  txVersion: number;
  inputCount: number;
  outputCount: number;
  txModifiable?: BitSet;
  version: number;
  fallbackLocktime?: number;
  scalars?: Buffer[];
  modifiable?: BitSet;
  proprietaryData?: ProprietaryData[];
  unknowns?: KeyPair[];

  constructor(
    txVersion?: number,
    inputCount?: number,
    outputCount?: number,
    version?: number,
    fallbackLocktime?: number,
  ) {
    this.txVersion = txVersion || 0;
    this.inputCount = inputCount || 0;
    this.outputCount = outputCount || 0;
    this.version = version || 0;
    this.fallbackLocktime = fallbackLocktime;
  }

  sanityCheck(): this {
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
        if (i === this.xpubs!.length - 1) {
          return false;
        }
        const next = this.xpubs!.slice(i + 1);
        return next.some(
          nextXpub => xpub.extendedKey.compare(nextXpub.extendedKey) === 0,
        );
      })
    ) {
      throw new GlobalDuplicateFieldError('xpub');
    }
    if (
      this.scalars &&
      this.scalars.some((scalar, i) => {
        if (i === this.scalars!.length - 1) {
          return false;
        }
        const next = this.scalars!.slice(i + 1);
        return next.some(nextScalar => scalar.compare(nextScalar) === 0);
      })
    ) {
      throw new GlobalDuplicateFieldError('scalar');
    }
    return this;
  }

  toBuffer(): Buffer {
    const keyPairs = this.getKeyPairs();
    const kpBuf = keyPairs.map(kp => kp.toBuffer());
    let size = 0;
    kpBuf.forEach(buf => {
      size += buf.length;
    });
    const w = BufferWriter.withCapacity(size);
    kpBuf.forEach(buf => w.writeSlice(buf));
    return w.buffer;
  }

  private getKeyPairs(): KeyPair[] {
    const keyPairs = [] as KeyPair[];

    if (this.xpubs! && this.xpubs.length > 0) {
      this.xpubs!.forEach(
        ({ extendedKey, masterFingerprint, derivationPath }) => {
          const keyData = Buffer.concat([
            Buffer.of(extendedKey.length),
            extendedKey,
          ]);
          const key = new Key(GlobalTypes.XPUB, keyData);
          const value = encodeBIP32Derivation(
            masterFingerprint,
            derivationPath,
          );
          keyPairs.push(new KeyPair(key, value));
        },
      );
    }

    const txVersion = Buffer.allocUnsafe(4);
    txVersion.writeUInt32LE(this.txVersion, 0);
    const txVersionKey = new Key(GlobalTypes.TX_VERSION);
    keyPairs.push(new KeyPair(txVersionKey, txVersion));

    if (this.fallbackLocktime !== undefined) {
      const fallbackLocktime = Buffer.allocUnsafe(4);
      fallbackLocktime.writeUInt32LE(this.fallbackLocktime, 0);
      const fallbackLocktimeKey = new Key(GlobalTypes.FALLBACK_LOCKTIME);
      keyPairs.push(new KeyPair(fallbackLocktimeKey, fallbackLocktime));
    }

    const inputCount = Buffer.allocUnsafe(
      varuint.encodingLength(this.inputCount),
    );
    varuint.encode(this.inputCount, inputCount, 0);
    const inputCountKey = new Key(GlobalTypes.INPUT_COUNT);
    keyPairs.push(new KeyPair(inputCountKey, inputCount));

    const outputCount = Buffer.allocUnsafe(
      varuint.encodingLength(this.outputCount),
    );
    varuint.encode(this.outputCount, outputCount, 0);
    const outputCountKey = new Key(GlobalTypes.OUTPUT_COUNT);
    keyPairs.push(new KeyPair(outputCountKey, outputCount));

    if (this.txModifiable!) {
      const txModifiable = Buffer.allocUnsafe(1);
      txModifiable.writeUInt8(Number(this.txModifiable!.toString(10)), 0);
      const txModifiableKey = new Key(GlobalTypes.TX_MODIFIABLE);
      keyPairs.push(new KeyPair(txModifiableKey, txModifiable));
    }

    if (this.scalars! && this.scalars!.length > 0) {
      this.scalars.forEach(scalar => {
        const keyData = ProprietaryData.proprietaryKey(
          GlobalProprietaryTypes.SCALAR,
          scalar,
        );
        const scalarKey = new Key(GlobalTypes.PROPRIETARY, keyData);
        keyPairs.push(new KeyPair(scalarKey));
      });
    }

    if (this.modifiable! && parseInt(this.modifiable.toString(), 2) > 0) {
      const modifiable = Buffer.allocUnsafe(1);
      modifiable.writeUInt8(Number(this.modifiable.toString(2)), 0);
      const keyData = ProprietaryData.proprietaryKey(
        GlobalProprietaryTypes.TX_MODIFIABLE,
      );
      const modifiableKey = new Key(GlobalTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(modifiableKey, modifiable));
    }

    const version = Buffer.allocUnsafe(4);
    version.writeUInt32LE(this.version, 0);
    const versionKey = new Key(GlobalTypes.VERSION);
    keyPairs.push(new KeyPair(versionKey, version));

    if (this.proprietaryData! && this.proprietaryData!.length > 0) {
      this.proprietaryData.forEach(data => {
        const keyData = ProprietaryData.proprietaryKey(
          data.subType,
          data.keyData,
        );
        const key = new Key(GlobalTypes.PROPRIETARY, keyData);
        keyPairs.push(new KeyPair(key, data.value));
      });
    }

    keyPairs.concat(this.unknowns || []);

    return keyPairs;
  }
}
