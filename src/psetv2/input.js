'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function() {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function(o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function(o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.Input = void 0;
const bufferutils_1 = require('../bufferutils');
const issuance_1 = require('../issuance');
const transaction_1 = require('../transaction');
const bip32_1 = require('./bip32');
const fields_1 = require('./fields');
const key_pair_1 = require('./key_pair');
const proprietary_data_1 = require('./proprietary_data');
const pset_1 = require('./pset');
const bscript = __importStar(require('../script'));
const utils_1 = require('./utils');
class Input {
  constructor(previousTxid, previousTxIndex, sequence) {
    this.previousTxid = previousTxid || Buffer.from([]);
    this.previousTxIndex = previousTxIndex >= 0 ? previousTxIndex : -1;
    this.sequence = sequence || -1;
  }
  static fromBuffer(r) {
    let kp;
    const input = new Input();
    while (true) {
      try {
        kp = key_pair_1.KeyPair.fromBuffer(r);
      } catch (e) {
        if (e instanceof Error && e === key_pair_1.ErrEmptyKey) {
          input.sanityCheck();
          return input;
        }
        throw e;
      }
      switch (kp.key.keyType) {
        case fields_1.InputTypes.NON_WITNESS_UTXO:
          if (input.nonWitnessUtxo) {
            throw new Error('duplicated input key NON_WITNESS_UTXO');
          }
          input.nonWitnessUtxo = transaction_1.Transaction.fromBuffer(kp.value);
          break;
        case fields_1.InputTypes.WITNESS_UTXO:
          if (input.witnessUtxo) {
            throw new Error('duplicated input key WITNESS_UTXO');
          }
          input.witnessUtxo = deserializeOutput(kp.value);
          break;
        case fields_1.InputTypes.PARTIAL_SIG:
          if (!input.partialSigs) {
            input.partialSigs = [];
          }
          const pk = kp.key.keyData;
          if (pk.length !== 33) {
            throw new Error("invalid partial sig's pubkey length");
          }
          if (input.partialSigs.find(ps => ps.pubkey.equals(pubkey))) {
            throw new Error('duplicated input signature');
          }
          const signature = kp.value;
          bscript.signature.decode(signature);
          input.partialSigs.push({ pubkey: pk, signature });
          break;
        case fields_1.InputTypes.SIGHASH_TYPE:
          if (input.sighashType > 0) {
            throw new Error('duplicated input key SIGHASH_TYPE');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input sighash type length');
          }
          input.sighashType = kp.value.readUInt32LE();
          break;
        case fields_1.InputTypes.REDEEM_SCRIPT:
          if (input.redeemScript.length > 0) {
            throw new Error('duplicated input key REDEEM_SCRIPT');
          }
          input.redeemScript = kp.value;
          break;
        case fields_1.InputTypes.WITNESS_SCRIPT:
          if (input.witnessScript.length > 0) {
            throw new Error('duplicated input key WITNESS_SCRIPT');
          }
          input.witnessScript = kp.value;
          break;
        case fields_1.InputTypes.BIP32_DERIVATION:
          const pubkey = kp.key.keyData;
          if (pubkey.length !== 33) {
            throw new Error('invalid input bip32 derivation pubkey length');
          }
          if (!input.bip32Derivation) {
            input.bip32Derivation = [];
          }
          if (input.bip32Derivation.find(d => d.pubkey.equals(pubkey))) {
            throw new Error('duplicated input bip32 derivation');
          }
          const { masterFingerprint, path } = (0,
          bip32_1.decodeBip32Derivation)(kp.value);
          input.bip32Derivation.push({ pubkey, masterFingerprint, path });
          break;
        case fields_1.InputTypes.FINAL_SCRIPTSIG:
          if (input.finalScriptSig.length > 0) {
            throw new Error('duplicated input key FINAL_SCRIPTSIG');
          }
          input.finalScriptSig = kp.value;
          break;
        case fields_1.InputTypes.FINAL_SCRIPTWITNESS:
          if (input.finalScriptWitness.length > 0) {
            throw new Error('duplicated input key FINAL_SCRIPTWITNESS');
          }
          input.finalScriptWitness = kp.value;
          break;
        case fields_1.InputTypes.RIPEMD_160:
          const ripemd160Key = kp.key.keyData.toString('hex');
          if (ripemd160Key.length !== 20) {
            throw new Error('invalid length for key of ripemd160 preimages');
          }
          if (!input.ripemd160Preimages) {
            input.ripemd160Preimages = {};
          }
          input.ripemd160Preimages[ripemd160Key] = kp.value;
          break;
        case fields_1.InputTypes.SHA_256:
          const sha256Key = kp.key.keyData.toString('hex');
          if (sha256Key.length !== 32) {
            throw new Error('invalid length for key of sha256 preimages');
          }
          if (!input.sha256Preimages) {
            input.sha256Preimages = {};
          }
          input.sha256Preimages[sha256Key] = kp.value;
          break;
        case fields_1.InputTypes.HASH_160:
          const hash160Key = kp.key.keyData.toString('hex');
          if (hash160Key.length !== 20) {
            throw new Error('invalid length for key of hash160 preimages');
          }
          if (!input.hash160Preimages) {
            input.hash160Preimages = {};
          }
          input.hash160Preimages[hash160Key] = kp.value;
          break;
        case fields_1.InputTypes.HASH_256:
          const hash256Key = kp.key.keyData.toString('hex');
          if (hash256Key.length !== 32) {
            throw new Error('invalid length for key of hash256 preimages');
          }
          if (!input.hash256Preimages) {
            input.hash256Preimages = {};
          }
          input.hash256Preimages[hash256Key] = kp.value;
          break;
        case fields_1.InputTypes.PREVIOUS_TXID:
          if (input.previousTxid.length > 0) {
            throw new Error('duplicated input key PREVIOUS_TXID');
          }
          if (kp.value.length !== 32) {
            throw new Error('invalid input previous txid length');
          }
          input.previousTxid = kp.value;
          break;
        case fields_1.InputTypes.PREVIOUS_TXINDEX:
          if (input.previousTxIndex > 0) {
            throw new Error('duplicated input key PREVIOUS_TXINDEX');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input previous tx index length');
          }
          input.previousTxIndex = kp.value.readUInt32LE();
          break;
        case fields_1.InputTypes.SEQUENCE:
          if (input.sequence > 0) {
            throw new Error('duplicated input key SEQUENCE');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input sequence length');
          }
          input.sequence = kp.value.readUInt32LE();
          break;
        case fields_1.InputTypes.REQUIRED_TIME_LOCKTIME:
          if (input.requiredTimeLocktime > 0) {
            throw new Error('duplicated input key REQUIRED_TIME_LOCKTIME');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input time-based locktime length');
          }
          input.requiredTimeLocktime = kp.value.readUInt32LE();
          break;
        case fields_1.InputTypes.REQUIRED_HEIGHT_LOCKTIME:
          if (input.requiredHeightLocktime > 0) {
            throw new Error('duplicated input key REQUIRED_HEIGHT_LOCKTIME');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input height-based locktime length');
          }
          input.requiredHeightLocktime = kp.value.readUInt32LE();
          break;
        case fields_1.InputTypes.TAP_KEY_SIG:
          if (input.tapKeySig && input.tapKeySig.length > 0) {
            throw new Error('duplicated input key TAP_KEY_SIG');
          }
          if (kp.value.length !== 64 && kp.value.length !== 65) {
            throw new Error('invalid input taproot key signature length');
          }
          input.tapKeySig = kp.value;
          break;
        case fields_1.InputTypes.TAP_SCRIPT_SIG:
          if (!input.tapScriptSig) {
            input.tapScriptSig = [];
          }
          if (kp.key.keyData.length !== 64) {
            throw new Error('invalid input TAP_SCRIPT_SIG key data length');
          }
          const tapPubkey = kp.key.keyData.slice(0, 32);
          const leafHash = kp.key.keyData.slice(32);
          if (input.tapScriptSig.find(ps => ps.pubkey.equals(tapPubkey))) {
            throw new Error('duplicated input key TAP_SCRIPT_SIG');
          }
          if (kp.value.length !== 64 && kp.value.length !== 65) {
            throw new Error('invalid input taproot key signature length');
          }
          input.tapScriptSig.push({
            pubkey: tapPubkey,
            leafHash,
            signature: kp.value,
          });
          break;
        case fields_1.InputTypes.TAP_LEAF_SCRIPT:
          if (!input.tapLeafScript) {
            input.tapLeafScript = [];
          }
          if ((kp.key.keyData.length - 1) % 32 !== 0) {
            throw new Error('invalid input TAP_LEAF_SCRIPT key data length');
          }
          const controlBlock = kp.key.keyData;
          const leafVersion = kp.value.slice(-1)[0];
          if ((controlBlock[0] & 0xfe) !== leafVersion) {
            throw new Error('invalid input taproot leaf script version');
          }
          input.tapLeafScript.push({
            controlBlock,
            leafVersion,
            script: kp.value,
          });
          break;
        case fields_1.InputTypes.TAP_BIP32_DERIVATION:
          const tapKey = kp.key.keyData;
          if (tapKey.length !== 33) {
            throw new Error('invalid input bip32 derivation pubkey length');
          }
          if (!input.tapBip32Derivation) {
            input.tapBip32Derivation = [];
          }
          const tapBip32Pubkey = kp.key.keyData;
          if (
            input.tapBip32Derivation.find(d => d.pubkey.equals(tapBip32Pubkey))
          ) {
            throw new Error('duplicated input taproot bip32 derivation');
          }
          const nHashes = bufferutils_1.varuint.decode(kp.value);
          const nHashesLen = bufferutils_1.varuint.encodingLength(nHashes);
          const bip32Deriv = (0, bip32_1.decodeBip32Derivation)(
            kp.value.slice(nHashesLen + nHashes * 32),
          );
          const leafHashes = new Array(nHashes);
          for (
            let i = 0, _offset = nHashesLen;
            i < nHashes;
            i++, _offset += 32
          ) {
            leafHashes[i] = kp.value.slice(_offset, _offset + 32);
          }
          input.tapBip32Derivation.push({
            pubkey: tapBip32Pubkey,
            masterFingerprint: bip32Deriv.masterFingerprint,
            path: bip32Deriv.path,
            leafHashes,
          });
          break;
        case fields_1.InputTypes.TAP_INTERNAL_KEY:
          if (input.tapInternalKey && input.tapInternalKey.length > 0) {
            throw new Error('duplicated input key TAP_INTERNAL_KEY');
          }
          if (kp.value.length !== 32) {
            throw new Error('invalid input taproot internal key length');
          }
          input.tapInternalKey = kp.value;
          break;
        case fields_1.InputTypes.TAP_MERKLE_ROOT:
          if (input.tapMerkleRoot && input.tapMerkleRoot.length > 0) {
            throw new Error('duplicated input key TAP_MERKLE_ROOT');
          }
          if (kp.value.length !== 32) {
            throw new Error('invalid input taproot merkle root length');
          }
          input.tapMerkleRoot = kp.value;
          break;
        case fields_1.InputTypes.PROPRIETARY:
          const data = proprietary_data_1.ProprietaryData.fromKeyPair(kp);
          if (Buffer.compare(data.identifier, pset_1.magicPrefix) === 0) {
            switch (data.subType) {
              case fields_1.InputProprietaryTypes.ISSUANCE_VALUE:
                if (input.issuanceValue > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_VALUE',
                  );
                }
                if (kp.value.length !== 8) {
                  throw new Error('invalid input issuance value length');
                }
                input.issuanceValue = (0, bufferutils_1.readUInt64LE)(
                  kp.value,
                  0,
                );
                break;
              case fields_1.InputProprietaryTypes.ISSUANCE_VALUE_COMMITMENT:
                if (input.issuanceValueCommitment.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_VALUE_COMMITMENT',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error(
                    'invalid input issuance value commitment length',
                  );
                }
                input.issuanceValueCommitment = kp.value;
                break;
              case fields_1.InputProprietaryTypes.ISSUANCE_VALUE_RANGEPROOF:
                if (input.issuanceValueRangeproof.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_VALUE_RANGEPROOF',
                  );
                }
                input.issuanceValueRangeproof = kp.value;
                break;
              case fields_1.InputProprietaryTypes
                .ISSUANCE_INFLATION_KEYS_RANGEPROOF:
                if (input.issuanceInflationKeysRangeproof.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_INFLATION_KEYS_RANGEPROOF',
                  );
                }
                input.issuanceInflationKeysRangeproof = kp.value;
                break;
              case fields_1.InputProprietaryTypes.PEGIN_TX:
                if (input.peginTx) {
                  throw new Error('duplicated input proprietary key PEGIN_TX');
                }
                input.peginTx = transaction_1.Transaction.fromBuffer(kp.value);
                break;
              case fields_1.InputProprietaryTypes.PEGIN_TXOUT_PROOF:
                if (input.peginTxoutProof.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_TXOUT_PROOF',
                  );
                }
                input.peginTxoutProof = kp.value;
                break;
              case fields_1.InputProprietaryTypes.PEGIN_GENESIS_HASH:
                if (input.peginGenesisHash.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_GENESIS_HASH',
                  );
                }
                if (kp.value.length !== 32) {
                  throw new Error('invalid input pegin genesis hash length');
                }
                input.peginGenesisHash = kp.value;
                break;
              case fields_1.InputProprietaryTypes.PEGIN_CLAIM_SCRIPT:
                if (input.peginClaimScript.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_CLAIM_SCRIPT',
                  );
                }
                input.peginClaimScript = kp.value;
                break;
              case fields_1.InputProprietaryTypes.PEGIN_VALUE:
                if (input.peginValue > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_VALUE',
                  );
                }
                if (kp.value.length !== 8) {
                  throw new Error('invalid input pegin value length');
                }
                input.peginValue = (0, bufferutils_1.readUInt64LE)(kp.value, 0);
                break;
              case fields_1.InputProprietaryTypes.PEGIN_WITNESS:
                if (input.peginWitness.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_WITNESS',
                  );
                }
                input.peginWitness = kp.value;
                break;
              case fields_1.InputProprietaryTypes.ISSUANCE_INFLATION_KEYS:
                if (input.issuanceInflationKeys > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_INFLATION_KEYS',
                  );
                }
                if (kp.value.length !== 8) {
                  throw new Error(
                    'invalid input issuance inflation keys length',
                  );
                }
                input.issuanceInflationKeys = (0, bufferutils_1.readUInt64LE)(
                  kp.value,
                  0,
                );
                break;
              case fields_1.InputProprietaryTypes
                .ISSUANCE_INFLATION_KEYS_COMMITMENT:
                if (input.issuanceInflationKeysCommitment.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_INFLATION_KEYS_COMMITMENT',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error(
                    'invalid input issuance inflation keys commitment length',
                  );
                }
                input.issuanceInflationKeysCommitment = kp.value;
                break;
              case fields_1.InputProprietaryTypes.ISSUANCE_BLINDING_NONCE:
                if (input.issuanceBlindingNonce.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_BLINDING_NONCE',
                  );
                }
                if (kp.value.length !== 32) {
                  throw new Error(
                    'invalid input issuance blinding nonce length',
                  );
                }
                input.issuanceBlindingNonce = kp.value;
                break;
              case fields_1.InputProprietaryTypes.ISSUANCE_ASSET_ENTROPY:
                if (input.issuanceAssetEntropy.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_ASSET_ENTROPY',
                  );
                }
                if (kp.value.length !== 32) {
                  throw new Error(
                    'invalid input issuance asset entropy length',
                  );
                }
                input.issuanceAssetEntropy = kp.value;
                break;
              case fields_1.InputProprietaryTypes.UTXO_RANGEPROOF:
                if (input.utxoRangeProof.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key UTXO_RANGEPROOF',
                  );
                }
                input.utxoRangeProof = kp.value;
                break;
              case fields_1.InputProprietaryTypes.ISSUANCE_BLIND_VALUE_PROOF:
                if (input.issuanceBlindValueProof.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_BLIND_VALUE_PROOF',
                  );
                }
                input.issuanceBlindValueProof = kp.value;
                break;
              case fields_1.InputProprietaryTypes
                .ISSUANCE_BLIND_INFLATION_KEYS_PROOF:
                if (input.issuanceBlindInflationKeysProof.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_BLIND_INFLATION_KEYS_PROOF',
                  );
                }
                input.issuanceBlindInflationKeysProof = kp.value;
                break;
              default:
                if (!input.proprietaryData) {
                  input.proprietaryData = [];
                }
                input.proprietaryData.push(data);
            }
          }
          break;
        default:
          if (!input.unknowns) {
            input.unknowns = [];
          }
          input.unknowns.push(kp);
      }
    }
  }
  sanityCheck() {
    if (this.previousTxid.length !== 32) {
      throw new Error('input previous txid is missing or has invalid length');
    }
    if (this.previousTxIndex < 0) {
      throw new Error('Missing input previous tx index');
    }
    if (this.sequence < 0) {
      throw new Error('missing input sequence');
    }
    if (
      !this.witnessUtxo &&
      this.witnessScript &&
      this.witnessScript.length > 0
    ) {
      throw new Error(
        'input witness script cannot be set if witness utxo is unset',
      );
    }
    if (
      !this.witnessUtxo &&
      this.finalScriptWitness &&
      this.finalScriptWitness.length > 0
    ) {
      throw new Error(
        'input final script witness cannot be set if witness utxo is unset',
      );
    }
    const issuanceValueCommitmentSet =
      this.issuanceValueCommitment && this.issuanceValueCommitment.length > 0;
    const issuanceValueRangeproofSet =
      this.issuanceValueRangeproof && this.issuanceValueRangeproof.length > 0;
    if (issuanceValueCommitmentSet !== issuanceValueRangeproofSet) {
      throw new Error(
        'input issuance value commitment and range proof must be both either set or unset',
      );
    }
    const issuanceInflationKeysCommitmentSet =
      this.issuanceInflationKeysCommitment &&
      this.issuanceInflationKeysCommitment.length > 0;
    const issuanceInflationKeysRangeproofSet =
      this.issuanceInflationKeysRangeproof &&
      this.issuanceInflationKeysRangeproof.length > 0;
    if (
      issuanceInflationKeysCommitmentSet !== issuanceInflationKeysRangeproofSet
    ) {
      throw new Error(
        'input issuance inflation keys commitment and range proof must be both either set or unset',
      );
    }
    return this;
  }
  hasIssuance() {
    return this.issuanceValue > 0 || this.issuanceInflationKeys > 0;
  }
  hasIssuanceBlinded() {
    return this.issuanceValueCommitment.length > 0;
  }
  hasReissuance() {
    if (!this.issuanceBlindingNonce) {
      return false;
    }
    return !this.issuanceBlindingNonce.equals(transaction_1.ZERO);
  }
  isFinalized() {
    return (
      (this.finalScriptSig && this.finalScriptSig.length > 0) ||
      (this.finalScriptWitness && this.finalScriptWitness.length > 0)
    );
  }
  isTaproot() {
    return (
      (this.tapInternalKey && this.tapInternalKey.length > 0) ||
      (this.tapMerkleRoot && this.tapMerkleRoot.length > 0) ||
      (this.tapLeafScript && this.tapLeafScript.length > 0) ||
      (this.tapBip32Derivation && this.tapBip32Derivation.length > 0) ||
      (this.witnessUtxo && (0, utils_1.isP2TR)(this.witnessUtxo.script))
    );
  }
  getIssuanceAssetHash() {
    if (!this.hasIssuance()) {
      return undefined;
    }
    if (!this.issuanceAssetEntropy) {
      throw new Error('missing issuance asset entropy');
    }
    let entropy = this.issuanceAssetEntropy;
    if (!this.hasReissuance()) {
      entropy = (0, issuance_1.generateEntropy)(
        { txHash: this.previousTxid, vout: this.previousTxIndex },
        this.issuanceAssetEntropy,
      );
    }
    return (0, issuance_1.calculateAsset)(entropy);
  }
  getIssuanceInflationKeysHash(blindedIssuance) {
    if (!this.hasIssuance()) {
      return undefined;
    }
    if (!this.issuanceAssetEntropy) {
      throw new Error('missing issuance asset entropy');
    }
    let entropy = this.issuanceAssetEntropy;
    if (!this.hasReissuance()) {
      entropy = (0, issuance_1.generateEntropy)(
        { txHash: this.previousTxid, vout: this.previousTxIndex },
        this.issuanceAssetEntropy,
      );
    }
    return (0, issuance_1.calculateReissuanceToken)(entropy, blindedIssuance);
  }
  getUtxo() {
    if (!this.witnessUtxo && !this.nonWitnessUtxo) {
      return undefined;
    }
    if (!this.nonWitnessUtxo) {
      return this.witnessUtxo;
    }
    return this.nonWitnessUtxo.outs[this.previousTxIndex];
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
    const keyPairs = [];
    if (this.nonWitnessUtxo) {
      const key = new key_pair_1.Key(fields_1.InputTypes.NON_WITNESS_UTXO);
      const value = this.nonWitnessUtxo.toBuffer();
      keyPairs.push(new key_pair_1.KeyPair(key, value));
    }
    if (this.witnessUtxo) {
      const key = new key_pair_1.Key(fields_1.InputTypes.WITNESS_UTXO);
      const value = serializeOutput(this.witnessUtxo);
      keyPairs.push(new key_pair_1.KeyPair(key, value));
    }
    if (this.partialSigs && this.partialSigs.length > 0) {
      this.partialSigs.forEach(({ pubkey, signature }) => {
        const key = new key_pair_1.Key(fields_1.InputTypes.PARTIAL_SIG, pubkey);
        keyPairs.push(new key_pair_1.KeyPair(key, signature));
      });
    }
    if (this.sighashType > 0) {
      const key = new key_pair_1.Key(fields_1.InputTypes.SIGHASH_TYPE);
      const value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.sighashType);
      keyPairs.push(new key_pair_1.KeyPair(key, value));
    }
    if (this.redeemScript && this.redeemScript.length > 0) {
      const key = new key_pair_1.Key(fields_1.InputTypes.REDEEM_SCRIPT);
      keyPairs.push(new key_pair_1.KeyPair(key, this.redeemScript));
    }
    if (this.witnessScript && this.witnessScript.length > 0) {
      const key = new key_pair_1.Key(fields_1.InputTypes.WITNESS_SCRIPT);
      keyPairs.push(new key_pair_1.KeyPair(key, this.witnessScript));
    }
    if (this.bip32Derivation && this.bip32Derivation.length > 0) {
      this.bip32Derivation.forEach(({ pubkey, masterFingerprint, path }) => {
        const key = new key_pair_1.Key(
          fields_1.InputTypes.BIP32_DERIVATION,
          pubkey,
        );
        const value = (0, bip32_1.encodeBIP32Derivation)(
          masterFingerprint,
          path,
        );
        keyPairs.push(new key_pair_1.KeyPair(key, value));
      });
    }
    if (this.finalScriptSig && this.finalScriptSig.length > 0) {
      const key = new key_pair_1.Key(fields_1.InputTypes.FINAL_SCRIPTSIG);
      keyPairs.push(new key_pair_1.KeyPair(key, this.finalScriptSig));
    }
    if (this.finalScriptWitness && this.finalScriptWitness.length > 0) {
      const key = new key_pair_1.Key(fields_1.InputTypes.FINAL_SCRIPTWITNESS);
      keyPairs.push(new key_pair_1.KeyPair(key, this.finalScriptWitness));
    }
    if (
      this.ripemd160Preimages &&
      Object.keys(this.ripemd160Preimages).length > 0
    ) {
      Object.entries(this.ripemd160Preimages).forEach(([k, v]) => {
        const key = new key_pair_1.Key(
          fields_1.InputTypes.RIPEMD_160,
          Buffer.from(k, 'hex'),
        );
        keyPairs.push(new key_pair_1.KeyPair(key, v));
      });
    }
    if (this.sha256Preimages && Object.keys(this.sha256Preimages).length > 0) {
      Object.entries(this.sha256Preimages).forEach(([k, v]) => {
        const key = new key_pair_1.Key(
          fields_1.InputTypes.SHA_256,
          Buffer.from(k, 'hex'),
        );
        keyPairs.push(new key_pair_1.KeyPair(key, v));
      });
    }
    if (
      this.hash160Preimages &&
      Object.keys(this.hash160Preimages).length > 0
    ) {
      Object.entries(this.hash160Preimages).forEach(([k, v]) => {
        const key = new key_pair_1.Key(
          fields_1.InputTypes.HASH_160,
          Buffer.from(k, 'hex'),
        );
        keyPairs.push(new key_pair_1.KeyPair(key, v));
      });
    }
    if (
      this.hash256Preimages &&
      Object.keys(this.hash256Preimages).length > 0
    ) {
      Object.entries(this.hash256Preimages).forEach(([k, v]) => {
        const key = new key_pair_1.Key(
          fields_1.InputTypes.HASH_256,
          Buffer.from(k, 'hex'),
        );
        keyPairs.push(new key_pair_1.KeyPair(key, v));
      });
    }
    const preivousTxidKey = new key_pair_1.Key(
      fields_1.InputTypes.PREVIOUS_TXID,
    );
    keyPairs.push(new key_pair_1.KeyPair(preivousTxidKey, this.previousTxid));
    const prevTxIndexKey = new key_pair_1.Key(
      fields_1.InputTypes.PREVIOUS_TXINDEX,
    );
    const prevTxIndex = Buffer.allocUnsafe(4);
    prevTxIndex.writeUInt32LE(this.previousTxIndex);
    keyPairs.push(new key_pair_1.KeyPair(prevTxIndexKey, prevTxIndex));
    const sequenceKey = new key_pair_1.Key(fields_1.InputTypes.SEQUENCE);
    const sequence = Buffer.allocUnsafe(4);
    sequence.writeUInt32LE(this.sequence);
    keyPairs.push(new key_pair_1.KeyPair(sequenceKey, sequence));
    if (this.requiredTimeLocktime > 0) {
      const key = new key_pair_1.Key(
        fields_1.InputTypes.REQUIRED_TIME_LOCKTIME,
      );
      const value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.requiredTimeLocktime);
      keyPairs.push(new key_pair_1.KeyPair(key, value));
    }
    if (this.requiredHeightLocktime > 0) {
      const key = new key_pair_1.Key(
        fields_1.InputTypes.REQUIRED_HEIGHT_LOCKTIME,
      );
      const value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.requiredHeightLocktime);
      keyPairs.push(new key_pair_1.KeyPair(key, value));
    }
    if (this.tapKeySig && this.tapKeySig.length > 0) {
      const key = new key_pair_1.Key(fields_1.InputTypes.TAP_KEY_SIG);
      keyPairs.push(new key_pair_1.KeyPair(key, this.tapKeySig));
    }
    if (this.tapScriptSig && this.tapScriptSig.length > 0) {
      this.tapScriptSig.forEach(({ pubkey, signature, leafHash }) => {
        const keyData = Buffer.concat([pubkey, leafHash]);
        const key = new key_pair_1.Key(
          fields_1.InputTypes.TAP_SCRIPT_SIG,
          keyData,
        );
        keyPairs.push(new key_pair_1.KeyPair(key, signature));
      });
    }
    if (this.tapLeafScript && this.tapLeafScript.length > 0) {
      this.tapLeafScript.forEach(({ leafVersion, script, controlBlock }) => {
        const key = new key_pair_1.Key(
          fields_1.InputTypes.TAP_LEAF_SCRIPT,
          controlBlock,
        );
        const value = Buffer.concat([script, Buffer.of(leafVersion)]);
        keyPairs.push(new key_pair_1.KeyPair(key, value));
      });
    }
    if (this.tapBip32Derivation && this.tapBip32Derivation.length > 0) {
      this.tapBip32Derivation.forEach(
        ({ pubkey, masterFingerprint, path, leafHashes }) => {
          const key = new key_pair_1.Key(
            fields_1.InputTypes.TAP_BIP32_DERIVATION,
            pubkey,
          );
          const nHashesLen = bufferutils_1.varuint.encodingLength(
            leafHashes.length,
          );
          const nHashesBuf = Buffer.allocUnsafe(nHashesLen);
          bufferutils_1.varuint.encode(leafHashes.length, nHashesBuf);
          const value = Buffer.concat([
            nHashesBuf,
            ...leafHashes,
            (0, bip32_1.encodeBIP32Derivation)(masterFingerprint, path),
          ]);
          keyPairs.push(new key_pair_1.KeyPair(key, value));
        },
      );
    }
    if (this.tapInternalKey && this.tapInternalKey.length > 0) {
      const key = new key_pair_1.Key(fields_1.InputTypes.TAP_INTERNAL_KEY);
      keyPairs.push(new key_pair_1.KeyPair(key, this.tapInternalKey));
    }
    if (this.tapMerkleRoot && this.tapMerkleRoot.length > 0) {
      const key = new key_pair_1.Key(fields_1.InputTypes.TAP_MERKLE_ROOT);
      keyPairs.push(new key_pair_1.KeyPair(key, this.tapMerkleRoot));
    }
    if (this.issuanceValue > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_VALUE,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      const value = Buffer.allocUnsafe(8);
      (0, bufferutils_1.writeUInt64LE)(value, this.issuanceValue, 0);
      keyPairs.push(new key_pair_1.KeyPair(key, value));
    }
    if (
      this.issuanceValueCommitment &&
      this.issuanceValueCommitment.length > 0
    ) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_VALUE_COMMITMENT,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.issuanceValueCommitment));
    }
    if (
      this.issuanceValueRangeproof &&
      this.issuanceValueRangeproof.length > 0
    ) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_VALUE_RANGEPROOF,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.issuanceValueRangeproof));
    }
    if (
      this.issuanceInflationKeysRangeproof &&
      this.issuanceInflationKeysRangeproof.length > 0
    ) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_RANGEPROOF,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(
        new key_pair_1.KeyPair(key, this.issuanceInflationKeysRangeproof),
      );
    }
    if (this.peginTx) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.PEGIN_TX,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.peginTx.toBuffer()));
    }
    if (this.peginTxoutProof && this.peginTxoutProof.length > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.PEGIN_TXOUT_PROOF,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.peginTxoutProof));
    }
    if (this.peginGenesisHash && this.peginGenesisHash.length > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.PEGIN_GENESIS_HASH,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.peginGenesisHash));
    }
    if (this.peginClaimScript && this.peginClaimScript.length > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.PEGIN_CLAIM_SCRIPT,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.peginClaimScript));
    }
    if (this.peginValue > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.PEGIN_VALUE,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      const value = Buffer.allocUnsafe(8);
      (0, bufferutils_1.writeUInt64LE)(value, this.peginValue, 0);
      keyPairs.push(new key_pair_1.KeyPair(key, value));
    }
    if (this.peginWitness && this.peginWitness.length > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.PEGIN_WITNESS,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.peginWitness));
    }
    if (this.issuanceInflationKeys > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_INFLATION_KEYS,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      const value = Buffer.allocUnsafe(8);
      (0, bufferutils_1.writeUInt64LE)(value, this.issuanceInflationKeys, 0);
      keyPairs.push(new key_pair_1.KeyPair(key, value));
    }
    if (
      this.issuanceInflationKeysCommitment &&
      this.issuanceInflationKeysCommitment.length > 0
    ) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_COMMITMENT,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(
        new key_pair_1.KeyPair(key, this.issuanceInflationKeysCommitment),
      );
    }
    if (this.issuanceBlindingNonce && this.issuanceBlindingNonce.length > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_BLINDING_NONCE,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.issuanceBlindingNonce));
    }
    if (this.issuanceAssetEntropy && this.issuanceAssetEntropy.length > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_ASSET_ENTROPY,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.issuanceAssetEntropy));
    }
    if (this.utxoRangeProof && this.utxoRangeProof.length > 0) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.UTXO_RANGEPROOF,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.utxoRangeProof));
    }
    if (
      this.issuanceBlindValueProof &&
      this.issuanceBlindValueProof.length > 0
    ) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_BLIND_VALUE_PROOF,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new key_pair_1.KeyPair(key, this.issuanceBlindValueProof));
    }
    if (
      this.issuanceBlindInflationKeysProof &&
      this.issuanceBlindInflationKeysProof.length > 0
    ) {
      const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
        fields_1.InputProprietaryTypes.ISSUANCE_BLIND_INFLATION_KEYS_PROOF,
      );
      const key = new key_pair_1.Key(fields_1.InputTypes.PROPRIETARY, keyData);
      keyPairs.push(
        new key_pair_1.KeyPair(key, this.issuanceBlindInflationKeysProof),
      );
    }
    if (this.proprietaryData && this.proprietaryData.length > 0) {
      this.proprietaryData.forEach(data => {
        const keyData = proprietary_data_1.ProprietaryData.proprietaryKey(
          data.subType,
          data.keyData,
        );
        const key = new key_pair_1.Key(
          fields_1.InputTypes.PROPRIETARY,
          keyData,
        );
        keyPairs.push(new key_pair_1.KeyPair(key, data.value));
      });
    }
    keyPairs.concat(this.unknowns || []);
    return keyPairs;
  }
}
exports.Input = Input;
function serializeOutput(out) {
  let size =
    out.asset.length +
    out.value.length +
    bufferutils_1.varuint.encodingLength(out.script.length) +
    out.script.length +
    out.nonce.length;
  if (out.nonce.length > 1) {
    size +=
      out.surjectionProof.length +
      bufferutils_1.varuint.encodingLength(out.surjectionProof.length);
    size +=
      out.rangeProof.length +
      bufferutils_1.varuint.encodingLength(out.rangeProof.length);
  }
  const buf = Buffer.allocUnsafe(size);
  const w = new bufferutils_1.BufferWriter(buf, 0);
  w.writeSlice(out.asset);
  w.writeSlice(out.value);
  w.writeSlice(out.nonce);
  w.writeVarSlice(out.script);
  if (out.nonce.length > 1) {
    w.writeVarSlice(out.surjectionProof);
    w.writeVarSlice(out.rangeProof);
  }
  return buf;
}
function deserializeOutput(buf) {
  if (buf.length < 45) {
    throw new Error('invalid input witness utxo length');
  }
  const r = new bufferutils_1.BufferReader(buf);
  const asset = r.readSlice(33);
  const value = r.readConfidentialValue();
  const nonce = r.readConfidentialNonce();
  const script = r.readVarSlice();
  let surjectionProof;
  let rangeProof;
  if (nonce.length > 1) {
    surjectionProof = r.readVarSlice();
    rangeProof = r.readVarSlice();
  }
  return { asset, value, nonce, script, surjectionProof, rangeProof };
}
