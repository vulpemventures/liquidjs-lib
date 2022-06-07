'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.Output = void 0;
const bufferutils_1 = require('../bufferutils');
const bip32_1 = require('./bip32');
const fields_1 = require('./fields');
const key_pair_1 = require('./key_pair');
const proprietary_data_1 = require('./proprietary_data');
const pset_1 = require('./pset');
class Output {
  constructor(value, asset, script) {
    this.value = value || 0;
    this.asset = asset || Buffer.from([]);
    this.script = script;
  }
  static fromBuffer(r) {
    let kp;
    let output = new Output();
    while (true) {
      try {
        kp = key_pair_1.KeyPair.fromBuffer(r);
      } catch (e) {
        if (e.message === 'no more key pairs') {
          output.sanityCheck();
          return output;
        }
        throw e;
      }
      switch (kp.key.keyType) {
        case fields_1.OutputTypes.REDEEM_SCRIPT:
          if (output.redeemScript.length > 0) {
            throw new Error('duplicated output key REDEEM_SCRIPT');
          }
          output.redeemScript = kp.value;
          break;
        case fields_1.OutputTypes.WITNESS_SCRIPT:
          if (output.witnessScript.length > 0) {
            throw new Error('duplicated output key WITNESS_SCRIPT');
          }
          output.witnessScript = kp.value;
          break;
        case fields_1.OutputTypes.BIP32_DERIVATION:
          let pubkey = kp.key.keyData;
          if (pubkey.length !== 33) {
            throw new Error('invalid output bip32 pubkey length');
          }
          if (!output.bip32Derivation) {
            output.bip32Derivation = [];
          }
          if (output.bip32Derivation.find(d => d.pubkey.equals(pubkey))) {
            throw new Error('duplicated output bip32 derivation');
          }
          let { masterFingerprint, path } = (0, bip32_1.decodeBip32Derivation)(
            kp.value,
          );
          output.bip32Derivation.push({ pubkey, masterFingerprint, path });
          break;
        case fields_1.OutputTypes.AMOUNT:
          if (output.value > 0) {
            throw new Error('duplicated output key AMOUNT');
          }
          if (kp.value.length !== 8) {
            throw new Error('invalid output amount length');
          }
          output.value = (0, bufferutils_1.readUInt64LE)(kp.value, 0);
          break;
        case fields_1.OutputTypes.SCRIPT:
          if (output.script && output.script.length > 0) {
            throw new Error('duplicated output key SCRIPT');
          }
          output.script = kp.value;
          break;
        case fields_1.OutputTypes.PROPRIETARY:
          let data = proprietary_data_1.ProprietaryData.fromKeyPair(kp);
          if (Buffer.compare(data.identifier, pset_1.magicPrefix) === 0) {
            switch (data.subType) {
              case fields_1.OutputProprietaryTypes.VALUE_COMMITMENT:
                if (
                  output.valueCommitment &&
                  output.valueCommitment.length > 0
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
              case fields_1.OutputProprietaryTypes.ASSET:
                if (output.asset.length > 0) {
                  throw new Error('duplicated output proprietary key ASSET');
                }
                if (kp.value.length !== 32) {
                  throw new Error('invalid output asset length');
                }
                output.asset = kp.value;
                break;
              case fields_1.OutputProprietaryTypes.ASSET_COMMITMENT:
                if (
                  output.assetCommitment &&
                  output.assetCommitment.length > 0
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
              case fields_1.OutputProprietaryTypes.VALUE_RANGEPROOF:
                if (
                  output.valueRangeproof &&
                  output.valueRangeproof.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key VALUE_RANGEPROOF',
                  );
                }
                output.valueRangeproof = kp.value;
                break;
              case fields_1.OutputProprietaryTypes.ASSET_SURJECTION_PROOF:
                if (
                  output.assetSurjectionProof &&
                  output.assetSurjectionProof.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key ASSET_SURJECTION_PROOF',
                  );
                }
                output.assetSurjectionProof = kp.value;
                break;
              case fields_1.OutputProprietaryTypes.BLINDING_PUBKEY:
                if (output.blindingPubkey && output.blindingPubkey.length > 0) {
                  throw new Error(
                    'duplicated output proprietary key BLINDING_PUBKEY',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error('invalid output blinding pubkey length');
                }
                output.blindingPubkey = kp.value;
                break;
              case fields_1.OutputProprietaryTypes.ECDH_PUBKEY:
                if (output.ecdhPubkey && output.ecdhPubkey.length > 0) {
                  throw new Error(
                    'duplicated ooutput proprietary key ECDH_PUBKEY',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error('invalid output ecdh pubkey length');
                }
                output.ecdhPubkey = kp.value;
                break;
              case fields_1.OutputProprietaryTypes.BLINDER_INDEX:
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
              case fields_1.OutputProprietaryTypes.BLIND_VALUE_PROOF:
                if (
                  output.blindValueProof &&
                  output.blindValueProof.length > 0
                ) {
                  throw new Error(
                    'duplicated output proprietary key BLIND_VALUE_PROOF',
                  );
                }
                output.blindValueProof = kp.value;
                break;
              case fields_1.OutputProprietaryTypes.BLIND_ASSET_PROOF:
                if (
                  output.blindAssetProof &&
                  output.blindAssetProof.length > 0
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
                output.proprietaryData.push(data);
            }
          }
          break;
        default:
          if (!output.unknowns) {
            output.unknowns = [];
          }
          output.unknowns.push(kp);
          break;
      }
    }
  }
  sanityCheck() {
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
    if (this.isFullyBlinded() && this.blinderIndex > 0) {
      throw new Error('blinder index must be unset for fully blinded output');
    }
  }
  isBlinded() {
    return this.blindingPubkey && this.blindingPubkey.length > 0;
  }
  isPartiallyBlinded() {
    return (
      this.isBlinded() &&
      ((this.valueCommitment && this.valueCommitment.length > 0) ||
        (this.assetCommitment && this.assetCommitment.length > 0) ||
        (this.valueRangeproof && this.valueRangeproof.length > 0) ||
        (this.assetSurjectionProof && this.assetSurjectionProof.length > 0) ||
        (this.ecdhPubkey && this.ecdhPubkey.length > 0))
    );
  }
  isFullyBlinded() {
    return (
      this.isBlinded() &&
      (this.valueCommitment &&
        this.valueCommitment.length > 0 &&
        (this.assetCommitment && this.assetCommitment.length > 0) &&
        (this.valueRangeproof && this.valueRangeproof.length > 0) &&
        (this.assetSurjectionProof && this.assetSurjectionProof.length) > 0 &&
        (this.ecdhPubkey && this.ecdhPubkey.length > 0))
    );
  }
  toBuffer() {
    const keyPairs = this.getKeyPairs();
    const kpBuf = keyPairs.map(kp => kp.toBuffer());
    let size = 0;
    kpBuf.forEach(buf => {
      size += buf.length;
    });
    const w = bufferutils_1.BufferWriter.withCapacity(size);
    kpBuf.forEach(buf => w.writeSlice(buf));
    return w.buffer;
  }
  getKeyPairs() {
    var keyPairs = [];
    if (this.redeemScript && this.redeemScript.length > 0) {
      let key = new key_pair_1.Key(fields_1.OutputTypes.REDEEM_SCRIPT);
      keyPairs.push(new key_pair_1.KeyPair(key, this.redeemScript));
    }
    if (this.witnessScript && this.witnessScript.length > 0) {
      let key = new key_pair_1.Key(fields_1.OutputTypes.WITNESS_SCRIPT);
      keyPairs.push(new key_pair_1.KeyPair(key, this.witnessScript));
    }
    if (this.bip32Derivation && this.bip32Derivation.length > 0) {
      this.bip32Derivation.forEach(({ pubkey, masterFingerprint, path }) => {
        let key = new key_pair_1.Key(
          fields_1.OutputTypes.BIP32_DERIVATION,
          pubkey,
        );
        let value = (0, bip32_1.encodeBIP32Derivation)(masterFingerprint, path);
        keyPairs.push(new key_pair_1.KeyPair(key, value));
      });
    }
    if (this.script) {
      let key = new key_pair_1.Key(fields_1.OutputTypes.SCRIPT);
      keyPairs.push(new key_pair_1.KeyPair(key, this.script));
    }
    if (this.valueCommitment && this.valueCommitment.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.VALUE_COMMITMENT,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.valueCommitment));
    }
    let key = new key_pair_1.Key(fields_1.OutputTypes.AMOUNT);
    let value = Buffer.allocUnsafe(8);
    (0, bufferutils_1.writeUInt64LE)(value, this.value, 0);
    keyPairs.push(new key_pair_1.KeyPair(key, value));
    if (this.assetCommitment && this.assetCommitment.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.ASSET_COMMITMENT,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.assetCommitment));
    }
    if (this.asset.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.ASSET,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.asset));
    }
    if (this.valueRangeproof && this.valueRangeproof.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.VALUE_RANGEPROOF,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.valueRangeproof));
    }
    if (this.assetSurjectionProof && this.assetSurjectionProof.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.ASSET_SURJECTION_PROOF,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.assetSurjectionProof));
    }
    if (this.blindingPubkey && this.blindingPubkey.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.BLINDING_PUBKEY,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.blindingPubkey));
    }
    if (this.ecdhPubkey && this.ecdhPubkey.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.ECDH_PUBKEY,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.ecdhPubkey));
    }
    let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
      fields_1.OutputProprietaryTypes.BLINDER_INDEX,
    );
    key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
    value = Buffer.allocUnsafe(4);
    let bi = 0;
    if (this.blinderIndex > 0) {
      bi = this.blinderIndex;
    }
    value.writeUInt32LE(bi);
    keyPairs.push(new key_pair_1.KeyPair(key, value));
    if (this.blindValueProof && this.blindValueProof.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.BLIND_VALUE_PROOF,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.blindValueProof));
    }
    if (this.blindAssetProof && this.blindAssetProof.length > 0) {
      let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.OutputProprietaryTypes.BLIND_ASSET_PROOF,
      );
      let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.blindAssetProof));
    }
    if (this.proprietaryData && this.proprietaryData.length > 0) {
      this.proprietaryData.forEach(data => {
        let keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
          data.subType,
          data.keyData,
        );
        let key = new key_pair_1.Key(fields_1.OutputTypes.PROPRIETARY, keyData);
        keyPairs.push(new key_pair_1.KeyPair(key, data.value));
      });
    }
    keyPairs.concat(this.unknowns || []);
    return keyPairs;
  }
}
exports.Output = Output;
