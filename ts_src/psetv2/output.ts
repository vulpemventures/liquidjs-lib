import {
  BufferReader,
  BufferWriter,
  readUInt64LE,
  writeUInt64LE,
} from '../bufferutils';
import { decodeBip32Derivation, encodeBIP32Derivation } from './bip32';
import { OutputProprietaryTypes, OutputTypes } from './fields';
import { Bip32Derivation } from './interfaces';
import { Key, KeyPair } from './key_pair';
import { ProprietaryData } from './proprietary_data';
import { magicPrefix } from './pset';

export class Output {
  static fromBuffer(r: BufferReader): Output {
    let kp: KeyPair;
    const output = new Output();
    while (true) {
      try {
        kp = KeyPair.fromBuffer(r);
      } catch (e) {
        if ((e as Error).message === 'no more key pairs') {
          output.sanityCheck();
          return output;
        }
        throw e;
      }

      switch (kp.key.keyType) {
        case OutputTypes.REDEEM_SCRIPT:
          if (output.redeemScript!.length > 0) {
            throw new Error('duplicated output key REDEEM_SCRIPT');
          }
          output.redeemScript = kp.value;
          break;
        case OutputTypes.WITNESS_SCRIPT:
          if (output.witnessScript!.length > 0) {
            throw new Error('duplicated output key WITNESS_SCRIPT');
          }
          output.witnessScript = kp.value;
          break;
        case OutputTypes.BIP32_DERIVATION:
          const pubkey = kp.key.keyData;
          if (pubkey.length !== 33) {
            throw new Error('invalid output bip32 pubkey length');
          }
          if (!output.bip32Derivation) {
            output.bip32Derivation = [];
          }
          if (output.bip32Derivation!.find(d => d.pubkey.equals(pubkey))) {
            throw new Error('duplicated output bip32 derivation');
          }
          const { masterFingerprint, path } = decodeBip32Derivation(kp.value);
          output.bip32Derivation!.push({ pubkey, masterFingerprint, path });
          break;
        case OutputTypes.AMOUNT:
          if (output.value > 0) {
            throw new Error('duplicated output key AMOUNT');
          }
          if (kp.value.length !== 8) {
            throw new Error('invalid output amount length');
          }
          output.value = readUInt64LE(kp.value, 0);
          break;
        case OutputTypes.SCRIPT:
          if (output.script! && output.script!.length > 0) {
            throw new Error('duplicated output key SCRIPT');
          }
          output.script = kp.value;
          break;
        case OutputTypes.PROPRIETARY:
          const data = ProprietaryData.fromKeyPair(kp);
          if (Buffer.compare(data.identifier, magicPrefix) === 0) {
            switch (data.subType) {
              case OutputProprietaryTypes.VALUE_COMMITMENT:
                if (
                  output.valueCommitment! &&
                  output.valueCommitment!.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key VALUE_COMMITMENT',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error('invalid output value commitment length');
                }
                output.valueCommitment = kp.value;
                break;
              case OutputProprietaryTypes.ASSET:
                if (output.asset.length > 0) {
                  throw new Error('duplicated output proprietary key ASSET');
                }
                if (kp.value.length !== 32) {
                  throw new Error('invalid output asset length');
                }
                output.asset = kp.value;
                break;
              case OutputProprietaryTypes.ASSET_COMMITMENT:
                if (
                  output.assetCommitment! &&
                  output.assetCommitment!.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key ASSET_COMMITMENT',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error('invalid output asset length');
                }
                output.assetCommitment = kp.value;
                break;
              case OutputProprietaryTypes.VALUE_RANGEPROOF:
                if (
                  output.valueRangeproof! &&
                  output.valueRangeproof!.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key VALUE_RANGEPROOF',
                  );
                }
                output.valueRangeproof = kp.value;
                break;
              case OutputProprietaryTypes.ASSET_SURJECTION_PROOF:
                if (
                  output.assetSurjectionProof! &&
                  output.assetSurjectionProof!.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key ASSET_SURJECTION_PROOF',
                  );
                }
                output.assetSurjectionProof = kp.value;
                break;
              case OutputProprietaryTypes.BLINDING_PUBKEY:
                if (
                  output.blindingPubkey! &&
                  output.blindingPubkey!.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key BLINDING_PUBKEY',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error('invalid output blinding pubkey length');
                }
                output.blindingPubkey = kp.value;
                break;
              case OutputProprietaryTypes.ECDH_PUBKEY:
                if (output.ecdhPubkey! && output.ecdhPubkey!.length > 0) {
                  throw new Error(
                    'duplicated ooutput proprietary key ECDH_PUBKEY',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error('invalid output ecdh pubkey length');
                }
                output.ecdhPubkey = kp.value;
                break;
              case OutputProprietaryTypes.BLINDER_INDEX:
                if (output.blinderIndex !== undefined) {
                  throw new Error(
                    'duplicated output proprietary key ECDH_PUBKEY',
                  );
                }
                if (kp.value.length !== 4) {
                  throw new Error('invalid output blidner index length');
                }
                output.blinderIndex = kp.value.readUInt32LE();
                break;
              case OutputProprietaryTypes.BLIND_VALUE_PROOF:
                if (
                  output.blindValueProof! &&
                  output.blindValueProof!.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key BLIND_VALUE_PROOF',
                  );
                }
                output.blindValueProof = kp.value;
                break;
              case OutputProprietaryTypes.BLIND_ASSET_PROOF:
                if (
                  output.blindAssetProof! &&
                  output.blindAssetProof!.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key BLIND_ASSET_PROOF',
                  );
                }
                output.blindAssetProof = kp.value;
                break;
              default:
                if (!output.proprietaryData) {
                  output.proprietaryData = [];
                }
                output.proprietaryData!.push(data);
            }
          }
          break;
        default:
          if (!output.unknowns) {
            output.unknowns = [];
          }
          output.unknowns!.push(kp);
          break;
      }
    }
  }

  redeemScript?: Buffer;
  witnessScript?: Buffer;
  bip32Derivation?: Bip32Derivation[];
  value: number;
  script?: Buffer;
  valueCommitment?: Buffer;
  asset: Buffer;
  assetCommitment?: Buffer;
  valueRangeproof?: Buffer;
  assetSurjectionProof?: Buffer;
  blindingPubkey?: Buffer;
  ecdhPubkey?: Buffer;
  blinderIndex?: number;
  blindValueProof?: Buffer;
  blindAssetProof?: Buffer;
  proprietaryData?: ProprietaryData[];
  unknowns?: KeyPair[];

  constructor(value?: number, asset?: Buffer, script?: Buffer) {
    this.value = value || 0;
    this.asset = asset || Buffer.from([]);
    this.script = script;
  }

  sanityCheck(): void {
    if (this.asset.length === 0) {
      throw new Error('missing output asset');
    }
    if (this.asset.length !== 32) {
      throw new Error('invalid output asset length');
    }
    if (
      this.isBlinded() &&
      this.isPartiallyBlinded() &&
      !this.isFullyBlinded()
    ) {
      throw new Error(
        'output is partially blinded while it must be either unblinded or fully blinded',
      );
    }
    if (this.isFullyBlinded() && this.blinderIndex! > 0) {
      throw new Error('blinder index must be unset for fully blinded output');
    }
  }

  isBlinded(): boolean {
    return this.blindingPubkey! && this.blindingPubkey!.length > 0;
  }

  isPartiallyBlinded(): boolean {
    return (
      this.isBlinded() &&
      ((this.valueCommitment! && this.valueCommitment!.length > 0) ||
        (this.assetCommitment! && this.assetCommitment!.length > 0) ||
        (this.valueRangeproof! && this.valueRangeproof!.length > 0) ||
        (this.assetSurjectionProof! && this.assetSurjectionProof!.length > 0) ||
        (this.ecdhPubkey! && this.ecdhPubkey!.length > 0))
    );
  }

  isFullyBlinded(): boolean {
    return (
      this.isBlinded() &&
      (this.valueCommitment! &&
        this.valueCommitment!.length > 0 &&
        (this.assetCommitment! && this.assetCommitment!.length > 0) &&
        (this.valueRangeproof! && this.valueRangeproof!.length > 0) &&
        (this.assetSurjectionProof! && this.assetSurjectionProof!.length) > 0 &&
        (this.ecdhPubkey! && this.ecdhPubkey!.length > 0))
    );
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

    if (this.redeemScript! && this.redeemScript!.length > 0) {
      const key = new Key(OutputTypes.REDEEM_SCRIPT);
      keyPairs.push(new KeyPair(key, this.redeemScript!));
    }

    if (this.witnessScript! && this.witnessScript!.length > 0) {
      const key = new Key(OutputTypes.WITNESS_SCRIPT);
      keyPairs.push(new KeyPair(key, this.witnessScript!));
    }

    if (this.bip32Derivation! && this.bip32Derivation!.length > 0) {
      this.bip32Derivation!.forEach(({ pubkey, masterFingerprint, path }) => {
        const key = new Key(OutputTypes.BIP32_DERIVATION, pubkey);
        const value = encodeBIP32Derivation(masterFingerprint, path);
        keyPairs.push(new KeyPair(key, value));
      });
    }

    if (this.script!) {
      const key = new Key(OutputTypes.SCRIPT);
      keyPairs.push(new KeyPair(key, this.script!));
    }

    if (this.valueCommitment! && this.valueCommitment!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.VALUE_COMMITMENT,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.valueCommitment!));
    }

    const amountKey = new Key(OutputTypes.AMOUNT);
    const amount = Buffer.allocUnsafe(8);
    writeUInt64LE(amount, this.value, 0);
    keyPairs.push(new KeyPair(amountKey, amount));

    if (this.assetCommitment! && this.assetCommitment!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.ASSET_COMMITMENT,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.assetCommitment!));
    }

    if (this.asset.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.ASSET,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.asset));
    }

    if (this.valueRangeproof! && this.valueRangeproof!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.VALUE_RANGEPROOF,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.valueRangeproof!));
    }

    if (this.assetSurjectionProof! && this.assetSurjectionProof!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.ASSET_SURJECTION_PROOF,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.assetSurjectionProof!));
    }

    if (this.blindingPubkey! && this.blindingPubkey!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.BLINDING_PUBKEY,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.blindingPubkey!));
    }

    if (this.ecdhPubkey! && this.ecdhPubkey!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.ECDH_PUBKEY,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.ecdhPubkey!));
    }

    const proprietaryKeyData = ProprietaryData.proprietaryKey(
      OutputProprietaryTypes.BLINDER_INDEX,
    );
    const blinderIndexKey = new Key(
      OutputTypes.PROPRIETARY,
      proprietaryKeyData,
    );
    const blinderIndex = Buffer.allocUnsafe(4);
    let bi = 0;
    if (this.blinderIndex! > 0) {
      bi = this.blinderIndex!;
    }
    blinderIndex.writeUInt32LE(bi);
    keyPairs.push(new KeyPair(blinderIndexKey, blinderIndex));

    if (this.blindValueProof! && this.blindValueProof!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.BLIND_VALUE_PROOF,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.blindValueProof!));
    }

    if (this.blindAssetProof! && this.blindAssetProof!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        OutputProprietaryTypes.BLIND_ASSET_PROOF,
      );
      const key = new Key(OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.blindAssetProof!));
    }

    if (this.proprietaryData! && this.proprietaryData!.length > 0) {
      this.proprietaryData.forEach(data => {
        const keyData = ProprietaryData.proprietaryKey(
          data.subType,
          data.keyData,
        );
        const key = new Key(OutputTypes.PROPRIETARY, keyData);
        keyPairs.push(new KeyPair(key, data.value));
      });
    }

    keyPairs.concat(this.unknowns || []);

    return keyPairs;
  }
}
