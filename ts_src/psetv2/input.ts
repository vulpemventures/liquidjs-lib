import {
  BufferReader,
  BufferWriter,
  readUInt64LE,
  varuint,
  writeUInt64LE,
} from '../bufferutils';
import {
  calculateAsset,
  calculateReissuanceToken,
  generateEntropy,
} from '../issuance';
import { Output, Transaction, ZERO } from '../transaction';
import { decodeBip32Derivation, encodeBIP32Derivation } from './bip32';
import { InputProprietaryTypes, InputTypes } from './fields';
import { Bip32Derivation, PartialSig } from './interfaces';
import { Key, KeyPair } from './key_pair';
import { ProprietaryData } from './proprietary_data';
import { magicPrefix } from './pset';
import * as bscript from '../script';

export class Input {
  static fromBuffer(r: BufferReader): Input {
    let kp: KeyPair;
    let input = new Input();
    while (true) {
      try {
        kp = KeyPair.fromBuffer(r);
      } catch (e) {
        if ((e as Error).message === 'no more key pairs') {
          input.sanityCheck();
          return input;
        }
        throw e;
      }

      switch (kp.key.keyType) {
        case InputTypes.NON_WITNESS_UTXO:
          if (input.nonWitnessUtxo!) {
            throw new Error('duplicated input key NON_WITNESS_UTXO');
          }
          input.nonWitnessUtxo = Transaction.fromBuffer(kp.value);
          break;
        case InputTypes.WITNESS_UTXO:
          if (input.witnessUtxo!) {
            throw new Error('duplicated input key WITNESS_UTXO');
          }
          input.witnessUtxo = deserializeOutput(kp.value);
          break;
        case InputTypes.PARTIAL_SIG:
          if (!input.partialSigs) {
            input.partialSigs = [];
          }
          var pubkey = kp.key.keyData;
          if (pubkey.length !== 33) {
            throw new Error("invalid partial sig's pubkey length");
          }
          if (input.partialSigs!.find(ps => ps.pubkey.equals(pubkey))) {
            throw new Error('duplicated input signature');
          }
          let signature = kp.value;
          bscript.signature.decode(signature);
          input.partialSigs!.push({ pubkey, signature });
          break;
        case InputTypes.SIGHASH_TYPE:
          if (input.sighashType! > 0) {
            throw new Error('duplicated input key SIGHASH_TYPE');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input sighash type length');
          }
          input.sighashType = kp.value.readUInt32LE();
          break;
        case InputTypes.REDEEM_SCRIPT:
          if (input.redeemScript!.length > 0) {
            throw new Error('duplicated input key REDEEM_SCRIPT');
          }
          input.redeemScript = kp.value;
          break;
        case InputTypes.WITNESS_SCRIPT:
          if (input.witnessScript!.length > 0) {
            throw new Error('duplicated input key WITNESS_SCRIPT');
          }
          input.witnessScript = kp.value;
          break;
        case InputTypes.BIP32_DERIVATION:
          var pubkey = kp.key.keyData;
          if (pubkey!.length !== 33) {
            throw new Error('invalid input bip32 derivation pubkey length');
          }
          if (!input.bip32Derivation) {
            input.bip32Derivation = [];
          }
          if (input.bip32Derivation!.find(d => d.pubkey.equals(pubkey))) {
            throw new Error('duplicated input bip32 derivation');
          }
          let { masterFingerprint, path } = decodeBip32Derivation(kp.value);
          input.bip32Derivation!.push({ pubkey, masterFingerprint, path });
          break;
        case InputTypes.FINAL_SCRIPTSIG:
          if (input.finalScriptSig!.length > 0) {
            throw new Error('duplicated input key FINAL_SCRIPTSIG');
          }
          input.finalScriptSig = kp.value;
          break;
        case InputTypes.FINAL_SCRIPTWITNESS:
          if (input.finalScriptWitness!.length > 0) {
            throw new Error('duplicated input key FINAL_SCRIPTWITNESS');
          }
          input.finalScriptWitness = kp.value;
          break;
        case InputTypes.RIPEMD_160:
          var key = kp.key.keyData.toString('hex');
          if (key.length !== 20) {
            throw new Error('invalid length for key of ripemd160 preimages');
          }
          if (!input.ripemd160Preimages) {
            input.ripemd160Preimages = {};
          }
          input.ripemd160Preimages[key] = kp.value;
          break;
        case InputTypes.SHA_256:
          var key = kp.key.keyData.toString('hex');
          if (key.length !== 32) {
            throw new Error('invalid length for key of sha256 preimages');
          }
          if (!input.sha256Preimages) {
            input.sha256Preimages = {};
          }
          input.sha256Preimages[key] = kp.value;
          break;
        case InputTypes.HASH_160:
          var key = kp.key.keyData.toString('hex');
          if (key.length !== 20) {
            throw new Error('invalid length for key of hash160 preimages');
          }
          if (!input.hash160Preimages) {
            input.hash160Preimages = {};
          }
          input.hash160Preimages[key] = kp.value;
          break;
        case InputTypes.HASH_256:
          var key = kp.key.keyData.toString('hex');
          if (key.length !== 32) {
            throw new Error('invalid length for key of hash256 preimages');
          }
          if (!input.hash256Preimages) {
            input.hash256Preimages = {};
          }
          input.hash256Preimages[key] = kp.value;
          break;
        case InputTypes.PREVIOUS_TXID:
          if (input.previousTxid!.length > 0) {
            throw new Error('duplicated input key PREVIOUS_TXID');
          }
          if (kp.value.length !== 32) {
            throw new Error('invalid input previous txid length');
          }
          input.previousTxid = kp.value;
          break;
        case InputTypes.PREVIOUS_TXINDEX:
          if (input.previousTxIndex! > 0) {
            throw new Error('duplicated input key PREVIOUS_TXINDEX');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input previous tx index length');
          }
          input.previousTxIndex = kp.value.readUInt32LE();
          break;
        case InputTypes.SEQUENCE:
          if (input.sequence! > 0) {
            throw new Error('duplicated input key SEQUENCE');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input sequence length');
          }
          input.sequence = kp.value.readUInt32LE();
          break;
        case InputTypes.REQUIRED_TIME_LOCKTIME:
          if (input.requiredTimeLocktime! > 0) {
            throw new Error('duplicated input key REQUIRED_TIME_LOCKTIME');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input time-based locktime length');
          }
          input.requiredTimeLocktime = kp.value.readUInt32LE();
          break;
        case InputTypes.REQUIRED_HEIGHT_LOCKTIME:
          if (input.requiredHeightLocktime! > 0) {
            throw new Error('duplicated input key REQUIRED_HEIGHT_LOCKTIME');
          }
          if (kp.value.length !== 4) {
            throw new Error('invalid input height-based locktime length');
          }
          input.requiredHeightLocktime = kp.value.readUInt32LE();
          break;
        case InputTypes.PROPRIETARY:
          let data = ProprietaryData.fromKeyPair(kp);
          if (Buffer.compare(data.identifier, magicPrefix) === 0) {
            switch (data.subType) {
              case InputProprietaryTypes.ISSUANCE_VALUE:
                if (input.issuanceValue! > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_VALUE',
                  );
                }
                if (kp.value.length !== 8) {
                  throw new Error('invalid input issuance value length');
                }
                input.issuanceValue = readUInt64LE(kp.value, 0);
                break;
              case InputProprietaryTypes.ISSUANCE_VALUE_COMMITMENT:
                if (input.issuanceValueCommitment!.length > 0) {
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
              case InputProprietaryTypes.ISSUANCE_VALUE_RANGEPROOF:
                if (input.issuanceValueRangeproof!.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_VALUE_RANGEPROOF',
                  );
                }
                input.issuanceValueRangeproof = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_RANGEPROOF:
                if (input.issuanceInflationKeysRangeproof!.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_INFLATION_KEYS_RANGEPROOF',
                  );
                }
                input.issuanceInflationKeysRangeproof = kp.value;
                break;
              case InputProprietaryTypes.PEGIN_TX:
                if (input.peginTx!) {
                  throw new Error('duplicated input proprietary key PEGIN_TX');
                }
                input.peginTx = Transaction.fromBuffer(kp.value);
                break;
              case InputProprietaryTypes.PEGIN_TXOUT_PROOF:
                if (input.peginTxoutProof!.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_TXOUT_PROOF',
                  );
                }
                input.peginTxoutProof = kp.value;
                break;
              case InputProprietaryTypes.PEGIN_GENESIS_HASH:
                if (input.peginGenesisHash!.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_GENESIS_HASH',
                  );
                }
                if (kp.value.length !== 32) {
                  throw new Error('invalid input pegin genesis hash length');
                }
                input.peginGenesisHash = kp.value;
                break;
              case InputProprietaryTypes.PEGIN_CLAIM_SCRIPT:
                if (input.peginClaimScript!.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_CLAIM_SCRIPT',
                  );
                }
                input.peginClaimScript = kp.value;
                break;
              case InputProprietaryTypes.PEGIN_VALUE:
                if (input.peginValue! > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_VALUE',
                  );
                }
                if (kp.value.length !== 8) {
                  throw new Error('invalid input pegin value length');
                }
                input.peginValue = readUInt64LE(kp.value, 0);
                break;
              case InputProprietaryTypes.PEGIN_WITNESS:
                if (input.peginWitness!.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key PEGIN_WITNESS',
                  );
                }
                input.peginWitness = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_INFLATION_KEYS:
                if (input.issuanceInflationKeys! > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_INFLATION_KEYS',
                  );
                }
                if (kp.value.length !== 8) {
                  throw new Error(
                    'invalid input issuance inflation keys length',
                  );
                }
                input.issuanceInflationKeys = readUInt64LE(kp.value, 0);
                break;
              case InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_COMMITMENT:
                if (input.issuanceInflationKeysCommitment!.length > 0) {
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
              case InputProprietaryTypes.ISSUANCE_BLINDING_NONCE:
                if (input.issuanceBlindingNonce!.length > 0) {
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
              case InputProprietaryTypes.ISSUANCE_ASSET_ENTROPY:
                if (input.issuanceAssetEntropy!.length > 0) {
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
              case InputProprietaryTypes.UTXO_RANGEPROOF:
                if (input.utxoRangeProof!.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key UTXO_RANGEPROOF',
                  );
                }
                input.utxoRangeProof = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_BLIND_VALUE_PROOF:
                if (input.issuanceBlindValueProof!.length > 0) {
                  throw new Error(
                    'duplicated input proprietary key ISSUANCE_BLIND_VALUE_PROOF',
                  );
                }
                input.issuanceBlindValueProof = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_BLIND_INFLATION_KEYS_PROOF:
                if (input.issuanceBlindInflationKeysProof!.length > 0) {
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
                input.proprietaryData!.push(data);
            }
          }
          break;
        default:
          if (!input.unknowns) {
            input.unknowns = [];
          }
          input.unknowns!.push(kp);
      }
    }
  }

  nonWitnessUtxo?: Transaction;
  witnessUtxo?: Output;
  partialSigs?: PartialSig[];
  sighashType?: number;
  redeemScript?: Buffer;
  witnessScript?: Buffer;
  bip32Derivation?: Bip32Derivation[];
  finalScriptSig?: Buffer;
  finalScriptWitness?: Buffer;
  ripemd160Preimages?: Record<string, Buffer>;
  sha256Preimages?: Record<string, Buffer>;
  hash160Preimages?: Record<string, Buffer>;
  hash256Preimages?: Record<string, Buffer>;
  previousTxid: Buffer;
  previousTxIndex: number;
  sequence: number;
  requiredTimeLocktime?: number;
  requiredHeightLocktime?: number;
  issuanceValue?: number;
  issuanceValueCommitment?: Buffer;
  issuanceValueRangeproof?: Buffer;
  issuanceInflationKeysRangeproof?: Buffer;
  peginTx?: Transaction;
  peginTxoutProof?: Buffer;
  peginGenesisHash?: Buffer;
  peginClaimScript?: Buffer;
  peginValue?: number;
  peginWitness?: Buffer;
  issuanceInflationKeys?: number;
  issuanceInflationKeysCommitment?: Buffer;
  issuanceBlindingNonce?: Buffer;
  issuanceAssetEntropy?: Buffer;
  utxoRangeProof?: Buffer;
  issuanceBlindValueProof?: Buffer;
  issuanceBlindInflationKeysProof?: Buffer;
  proprietaryData?: ProprietaryData[];
  unknowns?: KeyPair[];

  constructor(
    previousTxid?: Buffer,
    previousTxIndex?: number,
    sequence?: number,
  ) {
    this.previousTxid = previousTxid || Buffer.from([]);
    this.previousTxIndex = previousTxIndex! >= 0 ? previousTxIndex! : -1;
    this.sequence = sequence || -1;
  }

  sanityCheck(): void {
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
      this.witnessScript! &&
      this.witnessScript!.length > 0
    ) {
      throw new Error(
        'input witness script cannot be set if witness utxo is unset',
      );
    }
    if (
      !this.witnessUtxo &&
      this.finalScriptWitness! &&
      this.finalScriptWitness!.length > 0
    ) {
      throw new Error(
        'input final script witness cannot be set if witness utxo is unset',
      );
    }
    let issuanceValueCommitmentSet =
      this.issuanceValueCommitment! && this.issuanceValueCommitment!.length > 0;
    let issuanceValueRangeproofSet =
      this.issuanceValueRangeproof! && this.issuanceValueRangeproof!.length > 0;
    if (issuanceValueCommitmentSet != issuanceValueRangeproofSet) {
      throw new Error(
        'input issuance value commitment and range proof must be both either set or unset',
      );
    }
    let issuanceInflationKeysCommitmentSet =
      this.issuanceInflationKeysCommitment! &&
      this.issuanceInflationKeysCommitment!.length > 0;
    let issuanceInflationKeysRangeproofSet =
      this.issuanceInflationKeysRangeproof! &&
      this.issuanceInflationKeysRangeproof!.length > 0;
    if (
      issuanceInflationKeysCommitmentSet != issuanceInflationKeysRangeproofSet
    ) {
      throw new Error(
        'input issuance inflation keys commitment and range proof must be both either set or unset',
      );
    }
  }

  hasIssuance(): boolean {
    return this.issuanceValue! > 0 || this.issuanceInflationKeys! > 0;
  }

  hasIssuanceBlinded(): boolean {
    return this.issuanceValueCommitment!.length > 0;
  }

  hasReissuance(): boolean {
    if (!this.issuanceBlindingNonce) {
      return false;
    }
    return !this.issuanceBlindingNonce!.equals(ZERO);
  }

  isFinalized(): boolean {
    return (
      (this.finalScriptSig! && this.finalScriptSig!.length > 0) ||
      (this.finalScriptWitness! && this.finalScriptWitness!.length > 0)
    );
  }

  getIssuanceAssetHash(): Buffer | undefined {
    if (!this.hasIssuance()) {
      return undefined;
    }

    if (!this.issuanceAssetEntropy) {
      throw new Error('missing issuance asset entropy');
    }

    let entropy = this.issuanceAssetEntropy!;
    if (!this.hasReissuance()) {
      entropy = generateEntropy(
        { txHash: this.previousTxid, vout: this.previousTxIndex },
        this.issuanceAssetEntropy!,
      );
    }
    return calculateAsset(entropy);
  }

  getIssuanceInflationKeysHash(blindedIssuance: boolean): Buffer | undefined {
    if (!this.hasIssuance()) {
      return undefined;
    }

    if (!this.issuanceAssetEntropy) {
      throw new Error('missing issuance asset entropy');
    }

    let entropy = this.issuanceAssetEntropy!;
    if (!this.hasReissuance()) {
      entropy = generateEntropy(
        { txHash: this.previousTxid, vout: this.previousTxIndex },
        this.issuanceAssetEntropy!,
      );
    }
    return calculateReissuanceToken(entropy, blindedIssuance);
  }

  getUtxo(): Output | undefined {
    if (!this.witnessUtxo && !this.nonWitnessUtxo) {
      return undefined;
    }

    if (!this.nonWitnessUtxo) {
      return this.witnessUtxo;
    }
    return this.nonWitnessUtxo!.outs[this.previousTxIndex];
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
    var keyPairs = [] as KeyPair[];

    if (this.nonWitnessUtxo!) {
      let key = new Key(InputTypes.NON_WITNESS_UTXO);
      let value = this.nonWitnessUtxo!.toBuffer();
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.witnessUtxo!) {
      let key = new Key(InputTypes.WITNESS_UTXO);
      let value = serializeOutput(this.witnessUtxo!);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.partialSigs! && this.partialSigs!.length > 0) {
      this.partialSigs!.forEach(({ pubkey, signature }) => {
        let key = new Key(InputTypes.PARTIAL_SIG, pubkey);
        keyPairs.push(new KeyPair(key, signature));
      });
    }

    if (this.sighashType! > 0) {
      let key = new Key(InputTypes.SIGHASH_TYPE);
      let value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.sighashType!);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.redeemScript! && this.redeemScript!.length > 0) {
      let key = new Key(InputTypes.REDEEM_SCRIPT);
      keyPairs.push(new KeyPair(key, this.redeemScript!));
    }

    if (this.witnessScript! && this.witnessScript!.length > 0) {
      let key = new Key(InputTypes.WITNESS_SCRIPT);
      keyPairs.push(new KeyPair(key, this.witnessScript!));
    }

    if (this.bip32Derivation! && this.bip32Derivation!.length > 0) {
      this.bip32Derivation!.forEach(({ pubkey, masterFingerprint, path }) => {
        let key = new Key(InputTypes.BIP32_DERIVATION, pubkey);
        let value = encodeBIP32Derivation(masterFingerprint, path);
        keyPairs.push(new KeyPair(key, value));
      });
    }

    if (this.finalScriptSig! && this.finalScriptSig!.length > 0) {
      let key = new Key(InputTypes.FINAL_SCRIPTSIG);
      keyPairs.push(new KeyPair(key, this.finalScriptSig!));
    }

    if (this.finalScriptWitness! && this.finalScriptWitness!.length > 0) {
      let key = new Key(InputTypes.FINAL_SCRIPTWITNESS);
      keyPairs.push(new KeyPair(key, this.finalScriptWitness!));
    }

    if (
      this.ripemd160Preimages! &&
      Object.keys(this.ripemd160Preimages!).length > 0
    ) {
      Object.entries(this.ripemd160Preimages!).forEach(([k, v]) => {
        let key = new Key(InputTypes.RIPEMD_160, Buffer.from(k, 'hex'));
        keyPairs.push(new KeyPair(key, v));
      });
    }

    if (
      this.sha256Preimages! &&
      Object.keys(this.sha256Preimages!).length > 0
    ) {
      Object.entries(this.sha256Preimages!).forEach(([k, v]) => {
        let key = new Key(InputTypes.SHA_256, Buffer.from(k, 'hex'));
        keyPairs.push(new KeyPair(key, v));
      });
    }

    if (
      this.hash160Preimages! &&
      Object.keys(this.hash160Preimages!).length > 0
    ) {
      Object.entries(this.hash160Preimages!).forEach(([k, v]) => {
        let key = new Key(InputTypes.HASH_160, Buffer.from(k, 'hex'));
        keyPairs.push(new KeyPair(key, v));
      });
    }

    if (
      this.hash256Preimages! &&
      Object.keys(this.hash256Preimages!).length > 0
    ) {
      Object.entries(this.hash256Preimages!).forEach(([k, v]) => {
        let key = new Key(InputTypes.HASH_256, Buffer.from(k, 'hex'));
        keyPairs.push(new KeyPair(key, v));
      });
    }

    let preivousTxidKey = new Key(InputTypes.PREVIOUS_TXID);
    keyPairs.push(new KeyPair(preivousTxidKey, this.previousTxid));

    let prevTxIndexKey = new Key(InputTypes.PREVIOUS_TXINDEX);
    let prevTxIndex = Buffer.allocUnsafe(4);
    prevTxIndex.writeUInt32LE(this.previousTxIndex);
    keyPairs.push(new KeyPair(prevTxIndexKey, prevTxIndex));

    let sequenceKey = new Key(InputTypes.SEQUENCE);
    let sequence = Buffer.allocUnsafe(4);
    sequence.writeUInt32LE(this.sequence);
    keyPairs.push(new KeyPair(sequenceKey, sequence));

    if (this.requiredTimeLocktime! > 0) {
      let key = new Key(InputTypes.REQUIRED_TIME_LOCKTIME);
      let value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.requiredTimeLocktime!);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.requiredHeightLocktime! > 0) {
      let key = new Key(InputTypes.REQUIRED_HEIGHT_LOCKTIME);
      let value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.requiredHeightLocktime!);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.issuanceValue! > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_VALUE,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      let value = Buffer.allocUnsafe(8);
      writeUInt64LE(value, this.issuanceValue!, 0);
      keyPairs.push(new KeyPair(key, value));
    }

    if (
      this.issuanceValueCommitment! &&
      this.issuanceValueCommitment!.length > 0
    ) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_VALUE_COMMITMENT,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceValueCommitment!));
    }

    if (
      this.issuanceValueRangeproof! &&
      this.issuanceValueRangeproof!.length > 0
    ) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_VALUE_RANGEPROOF,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceValueRangeproof!));
    }

    if (
      this.issuanceInflationKeysRangeproof! &&
      this.issuanceInflationKeysRangeproof!.length > 0
    ) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_RANGEPROOF,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceInflationKeysRangeproof!));
    }

    if (this.peginTx!) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_TX,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginTx!.toBuffer()));
    }

    if (this.peginTxoutProof! && this.peginTxoutProof!.length > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_TXOUT_PROOF,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginTxoutProof!));
    }

    if (this.peginGenesisHash! && this.peginGenesisHash!.length > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_GENESIS_HASH,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginGenesisHash!));
    }

    if (this.peginClaimScript! && this.peginClaimScript!.length > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_CLAIM_SCRIPT,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginClaimScript!));
    }

    if (this.peginValue! > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_VALUE,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      let value = Buffer.allocUnsafe(8);
      writeUInt64LE(value, this.peginValue!, 0);
      keyPairs.push(new KeyPair(key, value!));
    }

    if (this.peginWitness! && this.peginWitness!.length > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_WITNESS,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginWitness!));
    }

    if (this.issuanceInflationKeys! > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_INFLATION_KEYS,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      let value = Buffer.allocUnsafe(8);
      writeUInt64LE(value, this.issuanceInflationKeys!, 0);
      keyPairs.push(new KeyPair(key, value!));
    }

    if (
      this.issuanceInflationKeysCommitment! &&
      this.issuanceInflationKeysCommitment!.length > 0
    ) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_COMMITMENT,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceInflationKeysCommitment!));
    }

    if (this.issuanceBlindingNonce! && this.issuanceBlindingNonce!.length > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_BLINDING_NONCE,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceBlindingNonce!));
    }

    if (this.issuanceAssetEntropy! && this.issuanceAssetEntropy!.length > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_ASSET_ENTROPY,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceAssetEntropy!));
    }

    if (this.utxoRangeProof! && this.utxoRangeProof!.length > 0) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.UTXO_RANGEPROOF,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.utxoRangeProof!));
    }

    if (
      this.issuanceBlindValueProof! &&
      this.issuanceBlindValueProof!.length > 0
    ) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_BLIND_VALUE_PROOF,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceBlindValueProof!));
    }

    if (
      this.issuanceBlindInflationKeysProof! &&
      this.issuanceBlindInflationKeysProof!.length > 0
    ) {
      let keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_BLIND_INFLATION_KEYS_PROOF,
      );
      let key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceBlindInflationKeysProof!));
    }

    if (this.proprietaryData! && this.proprietaryData!.length > 0) {
      this.proprietaryData.forEach(data => {
        let keyData = ProprietaryData.proprietaryKey(
          data.subType,
          data.keyData,
        );
        let key = new Key(InputTypes.PROPRIETARY, keyData);
        keyPairs.push(new KeyPair(key, data.value));
      });
    }

    keyPairs.concat(this.unknowns || []);

    return keyPairs;
  }
}

function serializeOutput(out: Output): Buffer {
  let size =
    out.asset.length +
    out.value.length +
    varuint.encodingLength(out.script.length) +
    out.script.length +
    out.nonce.length;
  if (out.nonce.length > 1) {
    size +=
      out.surjectionProof!.length +
      varuint.encodingLength(out.surjectionProof!.length);
    size +=
      out.rangeProof!.length + varuint.encodingLength(out.rangeProof!.length);
  }
  let buf = Buffer.allocUnsafe(size);
  let w = new BufferWriter(buf, 0);

  w.writeSlice(out.asset);
  w.writeSlice(out.value);
  w.writeSlice(out.nonce);
  w.writeVarSlice(out.script);
  if (out.nonce.length > 1) {
    w.writeVarSlice(out.surjectionProof!);
    w.writeVarSlice(out.rangeProof!);
  }
  return buf;
}

function deserializeOutput(buf: Buffer): Output {
  if (buf.length < 45) {
    throw new Error('invalid input witness utxo length');
  }

  let r = new BufferReader(buf);
  let asset = r.readSlice(33);
  let value = r.readConfidentialValue();
  let nonce = r.readConfidentialNonce();
  let script = r.readVarSlice();
  let surjectionProof: Buffer | undefined;
  let rangeProof: Buffer | undefined;
  if (nonce.length > 1) {
    surjectionProof = r.readVarSlice();
    rangeProof = r.readVarSlice();
  }
  return { asset, value, nonce, script, surjectionProof, rangeProof };
}
