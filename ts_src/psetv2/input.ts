import { Transaction as BitcoinTransaction } from 'bitcoinjs-lib';
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
import {
  Bip32Derivation,
  PartialSig,
  TapBip32Derivation,
  TapInternalKey,
  TapKeySig,
  TapLeafScript,
  TapMerkleRoot,
  TapScriptSig,
} from './interfaces';
import { ErrEmptyKey, Key, KeyPair } from './key_pair';
import { ProprietaryData } from './proprietary_data';
import { magicPrefix } from './pset';
import * as bscript from '../script';
import { isP2TR } from './utils';
import { AssetHash } from '../asset';
import { ElementsValue } from '../value';

export class InputDuplicateFieldError extends Error {
  constructor(message?: string) {
    if (message) {
      message = 'Duplicated input ' + message;
    }
    super(message);
  }
}

export class PsetInput {
  static fromBuffer(r: BufferReader): PsetInput {
    let kp: KeyPair;
    const input = new PsetInput();
    while (true) {
      try {
        kp = KeyPair.fromBuffer(r);
      } catch (e) {
        if (e instanceof Error && e === ErrEmptyKey) {
          input.sanityCheck();
          return input;
        }
        throw e;
      }

      switch (kp.key.keyType) {
        case InputTypes.NON_WITNESS_UTXO:
          if (input.nonWitnessUtxo!) {
            throw new InputDuplicateFieldError('non-witness utxo');
          }
          input.nonWitnessUtxo = Transaction.fromBuffer(kp.value);
          break;
        case InputTypes.WITNESS_UTXO:
          if (input.witnessUtxo!) {
            throw new InputDuplicateFieldError('witness utxo');
          }
          input.witnessUtxo = deserializeOutput(kp.value);
          break;
        case InputTypes.PARTIAL_SIG:
          if (!input.partialSigs) {
            input.partialSigs = [];
          }
          const pk = kp.key.keyData;
          if (pk.length !== 33) {
            throw new Error(`Invalid partial sig's pubkey length`);
          }
          if (input.partialSigs!.find((ps) => ps.pubkey.equals(pk))) {
            throw new InputDuplicateFieldError('partial sig');
          }
          const signature = kp.value;
          bscript.signature.decode(signature);
          input.partialSigs!.push({ pubkey: pk, signature });
          break;
        case InputTypes.SIGHASH_TYPE:
          if (input.sighashType !== undefined) {
            throw new InputDuplicateFieldError('sighash type');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid input sighash type length');
          }
          input.sighashType = kp.value.readUInt32LE();
          break;
        case InputTypes.REDEEM_SCRIPT:
          if (input.redeemScript && input.redeemScript.length > 0) {
            throw new InputDuplicateFieldError('redeem script');
          }
          input.redeemScript = kp.value;
          break;
        case InputTypes.WITNESS_SCRIPT:
          if (input.witnessScript && input.witnessScript.length > 0) {
            throw new InputDuplicateFieldError('witness script');
          }
          input.witnessScript = kp.value;
          break;
        case InputTypes.BIP32_DERIVATION:
          const pubkey = kp.key.keyData;
          if (pubkey!.length !== 33) {
            throw new Error('Invalid input bip32 derivation pubkey length');
          }
          if (!input.bip32Derivation) {
            input.bip32Derivation = [];
          }
          if (input.bip32Derivation!.find((d) => d.pubkey.equals(pubkey))) {
            throw new InputDuplicateFieldError('bip32 derivation');
          }
          const { masterFingerprint, path } = decodeBip32Derivation(kp.value);
          input.bip32Derivation!.push({ pubkey, masterFingerprint, path });
          break;
        case InputTypes.FINAL_SCRIPTSIG:
          if (input.finalScriptSig && input.finalScriptSig.length > 0) {
            throw new InputDuplicateFieldError('final scriptsig');
          }
          input.finalScriptSig = kp.value;
          break;
        case InputTypes.FINAL_SCRIPTWITNESS:
          if (input.finalScriptWitness && input.finalScriptWitness.length > 0) {
            throw new InputDuplicateFieldError('final script witness');
          }
          input.finalScriptWitness = kp.value;
          break;
        case InputTypes.RIPEMD_160:
          const ripemd160Key = kp.key.keyData.toString('hex');
          if (ripemd160Key.length !== 20) {
            throw new Error('Invalid length for key of ripemd160 preimages');
          }
          if (!input.ripemd160Preimages) {
            input.ripemd160Preimages = {};
          }
          input.ripemd160Preimages[ripemd160Key] = kp.value;
          break;
        case InputTypes.SHA_256:
          const sha256Key = kp.key.keyData.toString('hex');
          if (sha256Key.length !== 32) {
            throw new Error('Invalid length for key of sha256 preimages');
          }
          if (!input.sha256Preimages) {
            input.sha256Preimages = {};
          }
          input.sha256Preimages[sha256Key] = kp.value;
          break;
        case InputTypes.HASH_160:
          const hash160Key = kp.key.keyData.toString('hex');
          if (hash160Key.length !== 20) {
            throw new Error('Invalid length for key of hash160 preimages');
          }
          if (!input.hash160Preimages) {
            input.hash160Preimages = {};
          }
          input.hash160Preimages[hash160Key] = kp.value;
          break;
        case InputTypes.HASH_256:
          const hash256Key = kp.key.keyData.toString('hex');
          if (hash256Key.length !== 32) {
            throw new Error('Invalid length for key of hash256 preimages');
          }
          if (!input.hash256Preimages) {
            input.hash256Preimages = {};
          }
          input.hash256Preimages[hash256Key] = kp.value;
          break;
        case InputTypes.PREVIOUS_TXID:
          if (input.previousTxid && input.previousTxid.length > 0) {
            throw new InputDuplicateFieldError('previous txid');
          }
          if (kp.value.length !== 32) {
            throw new Error('Invalid input previous txid length');
          }
          input.previousTxid = kp.value;
          break;
        case InputTypes.PREVIOUS_TXINDEX:
          if (input.previousTxIndex! > 0) {
            throw new InputDuplicateFieldError('previous txindex');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid input previous tx index length');
          }
          input.previousTxIndex = kp.value.readUInt32LE();
          break;
        case InputTypes.SEQUENCE:
          if (input.sequence !== undefined) {
            throw new InputDuplicateFieldError('sequence');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid input sequence length');
          }
          input.sequence = kp.value.readUInt32LE();
          break;
        case InputTypes.REQUIRED_TIME_LOCKTIME:
          if (input.requiredTimeLocktime! > 0) {
            throw new InputDuplicateFieldError('time locktime');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid input time-based locktime length');
          }
          input.requiredTimeLocktime = kp.value.readUInt32LE();
          break;
        case InputTypes.REQUIRED_HEIGHT_LOCKTIME:
          if (input.requiredHeightLocktime! > 0) {
            throw new InputDuplicateFieldError('height locktime');
          }
          if (kp.value.length !== 4) {
            throw new Error('Invalid input height-based locktime length');
          }
          input.requiredHeightLocktime = kp.value.readUInt32LE();
          break;
        case InputTypes.TAP_KEY_SIG:
          if (input.tapKeySig! && input.tapKeySig!.length > 0) {
            throw new InputDuplicateFieldError('taproot keysig');
          }
          if (kp.value.length !== 64 && kp.value.length !== 65) {
            throw new Error('Invalid input taproot key signature length');
          }
          input.tapKeySig = kp.value;
          break;
        case InputTypes.TAP_SCRIPT_SIG:
          if (!input.tapScriptSig) {
            input.tapScriptSig = [];
          }
          if (kp.key.keyData.length !== 64) {
            throw new Error('Invalid input TAP_SCRIPT_SIG key data length');
          }
          const tapPubkey = kp.key.keyData.slice(0, 32);
          const leafHash = kp.key.keyData.slice(32);

          if (input.tapScriptSig.find((ps) => ps.pubkey.equals(tapPubkey))!) {
            throw new InputDuplicateFieldError('taproot scriptsig');
          }
          if (kp.value.length !== 64 && kp.value.length !== 65) {
            throw new Error('Invalid input taproot key signature length');
          }
          input.tapScriptSig!.push({
            pubkey: tapPubkey,
            leafHash,
            signature: kp.value,
          });
          break;
        case InputTypes.TAP_LEAF_SCRIPT:
          if (!input.tapLeafScript) {
            input.tapLeafScript = [];
          }
          if ((kp.key.keyData.length - 1) % 32 !== 0) {
            throw new Error('Invalid input TAP_LEAF_SCRIPT key data length');
          }

          const controlBlock = kp.key.keyData;
          const leafVersion = kp.value.slice(-1)[0];
          if ((controlBlock[0] & 0xfe) !== leafVersion) {
            throw new Error('Invalid input taproot leaf script version');
          }
          input.tapLeafScript!.push({
            controlBlock,
            leafVersion,
            script: kp.value.slice(0, -1),
          });
          break;
        case InputTypes.TAP_BIP32_DERIVATION:
          const tapKey = kp.key.keyData;
          if (tapKey!.length !== 33) {
            throw new Error('Invalid input bip32 derivation pubkey length');
          }
          if (!input.tapBip32Derivation) {
            input.tapBip32Derivation = [];
          }
          const tapBip32Pubkey = kp.key.keyData;
          if (
            input.tapBip32Derivation!.find((d) =>
              d.pubkey.equals(tapBip32Pubkey),
            )
          ) {
            throw new InputDuplicateFieldError('taproot bip32 derivation');
          }
          const nHashes = varuint.decode(kp.value);
          const nHashesLen = varuint.encodingLength(nHashes);
          const bip32Deriv = decodeBip32Derivation(
            kp.value.slice(nHashesLen + nHashes * 32),
          );
          const leafHashes: Buffer[] = new Array(nHashes);
          for (
            let i = 0, _offset = nHashesLen;
            i < nHashes;
            i++, _offset += 32
          ) {
            leafHashes[i] = kp.value.slice(_offset, _offset + 32);
          }
          input.tapBip32Derivation!.push({
            pubkey: tapBip32Pubkey,
            masterFingerprint: bip32Deriv.masterFingerprint,
            path: bip32Deriv.path,
            leafHashes,
          });
          break;
        case InputTypes.TAP_INTERNAL_KEY:
          if (input.tapInternalKey && input.tapInternalKey.length > 0) {
            throw new InputDuplicateFieldError('taproot internal key');
          }
          if (kp.value.length !== 32) {
            throw new Error('Invalid input taproot internal key length');
          }
          input.tapInternalKey = kp.value;
          break;
        case InputTypes.TAP_MERKLE_ROOT:
          if (input.tapMerkleRoot && input.tapMerkleRoot.length > 0) {
            throw new InputDuplicateFieldError('taproot merkle root');
          }
          if (kp.value.length !== 32) {
            throw new Error('Invalid input taproot merkle root length');
          }
          input.tapMerkleRoot = kp.value;
          break;
        case InputTypes.PROPRIETARY:
          const data = ProprietaryData.fromKeyPair(kp);
          if (Buffer.compare(data.identifier, magicPrefix) === 0) {
            switch (data.subType) {
              case InputProprietaryTypes.ISSUANCE_VALUE:
                if (input.issuanceValue! > 0) {
                  throw new InputDuplicateFieldError('issuance value');
                }
                if (kp.value.length !== 8) {
                  throw new Error('Invalid input issuance value length');
                }
                input.issuanceValue = readUInt64LE(kp.value, 0);
                break;
              case InputProprietaryTypes.ISSUANCE_VALUE_COMMITMENT:
                if (
                  input.issuanceValueCommitment &&
                  input.issuanceValueCommitment!.length > 0
                ) {
                  throw new InputDuplicateFieldError(
                    'issuance value commitment',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error(
                    'Invalid input issuance value commitment length',
                  );
                }
                input.issuanceValueCommitment = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_VALUE_RANGEPROOF:
                if (
                  input.issuanceValueRangeproof &&
                  input.issuanceValueRangeproof!.length > 0
                ) {
                  throw new InputDuplicateFieldError(
                    'issuance value range proof',
                  );
                }
                input.issuanceValueRangeproof = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_RANGEPROOF:
                if (
                  input.issuanceInflationKeysRangeproof &&
                  input.issuanceInflationKeysRangeproof!.length > 0
                ) {
                  throw new InputDuplicateFieldError(
                    'issuance inflation keys range proof',
                  );
                }
                input.issuanceInflationKeysRangeproof = kp.value;
                break;
              case InputProprietaryTypes.PEGIN_TX:
                if (input.peginTx !== undefined) {
                  throw new InputDuplicateFieldError('pegin tx');
                }
                try {
                  input.peginTx = BitcoinTransaction.fromBuffer(kp.value);
                } catch (ignore) {
                  throw new Error('Invalid input pegin tx');
                }
                break;
              case InputProprietaryTypes.PEGIN_TXOUT_PROOF:
                if (
                  input.peginTxoutProof &&
                  input.peginTxoutProof!.length > 0
                ) {
                  throw new InputDuplicateFieldError('pegin txout proof');
                }
                input.peginTxoutProof = kp.value;
                break;
              case InputProprietaryTypes.PEGIN_GENESIS_HASH:
                if (
                  input.peginGenesisHash &&
                  input.peginGenesisHash!.length > 0
                ) {
                  throw new InputDuplicateFieldError('pegin genesis hash');
                }
                if (kp.value.length !== 32) {
                  throw new Error('Invalid input pegin genesis hash length');
                }
                input.peginGenesisHash = kp.value;
                break;
              case InputProprietaryTypes.PEGIN_CLAIM_SCRIPT:
                if (
                  input.peginClaimScript &&
                  input.peginClaimScript!.length > 0
                ) {
                  throw new InputDuplicateFieldError('pegin claim script');
                }
                input.peginClaimScript = kp.value;
                break;
              case InputProprietaryTypes.PEGIN_VALUE:
                if (input.peginValue! > 0) {
                  throw new InputDuplicateFieldError('pegin value');
                }
                if (kp.value.length !== 8) {
                  throw new Error('Invalid input pegin value length');
                }
                input.peginValue = readUInt64LE(kp.value, 0);
                break;
              case InputProprietaryTypes.PEGIN_WITNESS:
                if (input.peginWitness && input.peginWitness!.length > 0) {
                  throw new InputDuplicateFieldError('pegin witness');
                }
                const pwr = new BufferReader(kp.value);
                try {
                  input.peginWitness = pwr.readVector();
                } catch (ignore) {
                  throw new Error('Invalid input pegin witness');
                }
                break;
              case InputProprietaryTypes.ISSUANCE_INFLATION_KEYS:
                if (input.issuanceInflationKeys! > 0) {
                  throw new InputDuplicateFieldError('issuance inflation keys');
                }
                if (kp.value.length !== 8) {
                  throw new Error(
                    'Invalid input issuance inflation keys length',
                  );
                }
                input.issuanceInflationKeys = readUInt64LE(kp.value, 0);
                break;
              case InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_COMMITMENT:
                if (
                  input.issuanceInflationKeysCommitment &&
                  input.issuanceInflationKeysCommitment!.length > 0
                ) {
                  throw new InputDuplicateFieldError(
                    'issuance inflation keys commitment',
                  );
                }
                if (kp.value.length !== 33) {
                  throw new Error(
                    'Invalid input issuance inflation keys commitment length',
                  );
                }
                input.issuanceInflationKeysCommitment = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_BLINDING_NONCE:
                if (
                  input.issuanceBlindingNonce &&
                  input.issuanceBlindingNonce!.length > 0
                ) {
                  throw new InputDuplicateFieldError('issuance blinding nonce');
                }
                if (kp.value.length !== 32) {
                  throw new Error(
                    'Invalid input issuance blinding nonce length',
                  );
                }
                input.issuanceBlindingNonce = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_ASSET_ENTROPY:
                if (
                  input.issuanceAssetEntropy &&
                  input.issuanceAssetEntropy!.length > 0
                ) {
                  throw new InputDuplicateFieldError('issuance asset entropy');
                }
                if (kp.value.length !== 32) {
                  throw new Error(
                    'Invalid input issuance asset entropy length',
                  );
                }
                input.issuanceAssetEntropy = kp.value;
                break;
              case InputProprietaryTypes.UTXO_RANGEPROOF:
                if (input.utxoRangeProof && input.utxoRangeProof!.length > 0) {
                  throw new InputDuplicateFieldError('utxo range proof');
                }
                input.utxoRangeProof = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_BLIND_VALUE_PROOF:
                if (
                  input.issuanceBlindValueProof &&
                  input.issuanceBlindValueProof!.length > 0
                ) {
                  throw new InputDuplicateFieldError(
                    'issuance blind value proof',
                  );
                }
                input.issuanceBlindValueProof = kp.value;
                break;
              case InputProprietaryTypes.ISSUANCE_BLIND_INFLATION_KEYS_PROOF:
                if (
                  input.issuanceBlindInflationKeysProof &&
                  input.issuanceBlindInflationKeysProof!.length > 0
                ) {
                  throw new InputDuplicateFieldError(
                    'issuance blind inflation keys proof',
                  );
                }
                input.issuanceBlindInflationKeysProof = kp.value;
                break;
              case InputProprietaryTypes.EXPLICIT_VALUE:
                if (input.explicitValue !== undefined) {
                  throw new InputDuplicateFieldError('explicit value');
                }
                if (kp.value.length !== 8) {
                  throw new Error('Invalid input explicit value length');
                }
                input.explicitValue = readUInt64LE(kp.value, 0);
                break;
              case InputProprietaryTypes.VALUE_PROOF:
                if (
                  input.explicitValueProof &&
                  input.explicitValueProof.length > 0
                ) {
                  throw new InputDuplicateFieldError('explicit value proof');
                }
                input.explicitValueProof = kp.value;
                break;
              case InputProprietaryTypes.EXPLICIT_ASSET:
                if (input.explicitAsset && input.explicitAsset.length > 0) {
                  throw new InputDuplicateFieldError('explicit asset');
                }
                input.explicitAsset = kp.value;
                break;
              case InputProprietaryTypes.ASSET_PROOF:
                if (
                  input.explicitAssetProof &&
                  input.explicitAssetProof.length > 0
                ) {
                  throw new InputDuplicateFieldError('explicit asset proof');
                }
                input.explicitAssetProof = kp.value;
                break;
              case InputProprietaryTypes.BLINDED_ISSUANCE:
                if (input.blindedIssuance !== undefined) {
                  throw new InputDuplicateFieldError('blinded issuance');
                }
                if (kp.value.length !== 1) {
                  throw new Error('invalid blinded issuance length');
                }
                input.blindedIssuance = kp.value.equals(Buffer.of(0x01))
                  ? true
                  : false;
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
  sequence?: number;
  requiredTimeLocktime?: number;
  requiredHeightLocktime?: number;
  tapKeySig?: TapKeySig;
  tapScriptSig?: TapScriptSig[];
  tapLeafScript?: TapLeafScript[];
  tapBip32Derivation?: TapBip32Derivation[];
  tapInternalKey?: TapInternalKey;
  tapMerkleRoot?: TapMerkleRoot;
  issuanceValue?: number;
  issuanceValueCommitment?: Buffer;
  issuanceValueRangeproof?: Buffer;
  issuanceInflationKeysRangeproof?: Buffer;
  peginTx?: BitcoinTransaction;
  peginTxoutProof?: Buffer;
  peginGenesisHash?: Buffer;
  peginClaimScript?: Buffer;
  peginValue?: number;
  peginWitness?: Buffer[];
  issuanceInflationKeys?: number;
  issuanceInflationKeysCommitment?: Buffer;
  issuanceBlindingNonce?: Buffer;
  issuanceAssetEntropy?: Buffer;
  utxoRangeProof?: Buffer;
  issuanceBlindValueProof?: Buffer;
  issuanceBlindInflationKeysProof?: Buffer;
  explicitValue?: number;
  explicitValueProof?: Buffer;
  explicitAsset?: Buffer;
  explicitAssetProof?: Buffer;
  blindedIssuance?: boolean;
  proprietaryData?: ProprietaryData[];
  unknowns?: KeyPair[];

  constructor(
    previousTxid?: Buffer,
    previousTxIndex?: number,
    sequence?: number,
  ) {
    this.previousTxid = previousTxid || Buffer.from([]);
    this.previousTxIndex = previousTxIndex || 0;
    this.sequence = sequence;
  }

  sanityCheck(): this {
    if (this.previousTxid.length === 0) {
      throw new Error('Missing input previous txid');
    }
    if (this.previousTxIndex < 0) {
      throw new Error('Missing input previous tx index');
    }

    if (
      !this.witnessUtxo &&
      this.witnessScript! &&
      this.witnessScript!.length > 0
    ) {
      throw new Error(
        'Input witness script cannot be set if witness utxo is unset',
      );
    }
    if (
      !this.witnessUtxo &&
      this.finalScriptWitness! &&
      this.finalScriptWitness!.length > 0
    ) {
      throw new Error(
        'Input final script witness cannot be set if witness utxo is unset',
      );
    }
    const issuanceValueCommitSet =
      this.issuanceValueCommitment && this.issuanceValueCommitment.length > 0;
    const issuanceBlindValueProofSet =
      this.issuanceBlindValueProof && this.issuanceBlindValueProof.length > 0;
    if (
      this.issuanceValue! &&
      issuanceValueCommitSet !== issuanceBlindValueProofSet
    ) {
      throw new Error('Missing input issuance value commitment or blind proof');
    }
    const issuanceInflationKeysCommitSet =
      this.issuanceInflationKeysCommitment &&
      this.issuanceInflationKeysCommitment.length > 0;
    const issuanceBlindInflationKeysProofSet =
      this.issuanceBlindInflationKeysProof &&
      this.issuanceBlindInflationKeysProof.length > 0;
    if (
      this.issuanceInflationKeys! &&
      issuanceInflationKeysCommitSet !== issuanceBlindInflationKeysProofSet
    ) {
      throw new Error(
        'Missing input issuance inflation keys commitment or blind proof',
      );
    }

    if (this.sighashType !== undefined && this.sighashType < 0) {
      throw new Error('Invalid sighash type');
    }

    if (this.explicitValue && !this.explicitValueProof) {
      throw new Error(
        'Explicit value proof is required if explicit value is set',
      );
    }

    if (this.explicitValueProof && !this.explicitValue) {
      throw new Error('Explicit value is required if value proof is set');
    }

    if (this.explicitAsset && !this.explicitAssetProof) {
      throw new Error('Explicit asset proof is required if explicit asset set');
    }

    if (this.explicitAssetProof && !this.explicitAsset) {
      throw new Error('Explicit asset is required if asset proof is set');
    }

    if (this.explicitAsset) {
      const asset = AssetHash.fromBytes(this.explicitAsset);
      if (asset.isConfidential()) {
        throw new Error(`Explicit asset should be unconfidential`);
      }
    }

    const utxo = this.getUtxo();
    if (utxo && this.explicitAsset) {
      if (!AssetHash.fromBytes(utxo.asset).isConfidential()) {
        throw new Error(
          'Explicit asset must be undefined if previous utxo is unconfidential',
        );
      }
    }

    if (utxo && this.explicitValue !== undefined) {
      if (!ElementsValue.fromBytes(utxo.value).isConfidential()) {
        throw new Error(
          'Explicit value must be undefined if previout utxo is unconfidential',
        );
      }
    }

    return this;
  }

  hasIssuance(): boolean {
    if (!this.issuanceBlindingNonce) return false;
    return this.issuanceBlindingNonce.equals(ZERO);
  }

  hasIssuanceBlinded(): boolean {
    return this.issuanceValueCommitment!.length > 0;
  }

  hasReissuance(): boolean {
    if (!this.issuanceBlindingNonce) return false;
    return !this.issuanceBlindingNonce.equals(ZERO);
  }

  isFinalized(): boolean {
    return (
      (this.finalScriptSig! && this.finalScriptSig!.length > 0) ||
      (this.finalScriptWitness! && this.finalScriptWitness!.length > 0)
    );
  }

  isTaproot(): boolean {
    return (
      (this.tapInternalKey! && this.tapInternalKey.length > 0) ||
      (this.tapMerkleRoot! && this.tapMerkleRoot.length > 0) ||
      (this.tapLeafScript! && this.tapLeafScript.length > 0) ||
      (this.tapBip32Derivation! && this.tapBip32Derivation!.length > 0) ||
      (this.witnessUtxo! && isP2TR(this.witnessUtxo!.script))
    );
  }

  getIssuanceAssetHash(): Buffer | undefined {
    if (!this.hasIssuance() && !this.hasReissuance()) {
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
    if (!this.hasIssuance() && !this.hasReissuance()) {
      return undefined;
    }

    if (!this.issuanceAssetEntropy) {
      throw new Error('missing issuance asset entropy');
    }

    let entropy = this.issuanceAssetEntropy!;
    if (this.hasIssuance()) {
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
      const utxo = this.witnessUtxo!;
      if (!this.utxoRangeProof)
        throw new Error('missing utxoRangeProof (getUtxo)');
      utxo.rangeProof = this.utxoRangeProof;
      return utxo;
    }
    return this.nonWitnessUtxo!.outs[this.previousTxIndex];
  }

  toBuffer(): Buffer {
    const keyPairs = this.getKeyPairs();
    const kpBuf = keyPairs.map((kp) => kp.toBuffer());
    let size = 0;
    kpBuf.forEach((buf) => {
      size += buf.length;
    });
    const w = BufferWriter.withCapacity(size);
    kpBuf.forEach((buf) => w.writeSlice(buf));
    return w.buffer;
  }

  private getKeyPairs(): KeyPair[] {
    const keyPairs = [] as KeyPair[];

    if (this.nonWitnessUtxo!) {
      const key = new Key(InputTypes.NON_WITNESS_UTXO);
      const value = this.nonWitnessUtxo!.toBuffer();
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.witnessUtxo!) {
      const key = new Key(InputTypes.WITNESS_UTXO);
      const value = serializeOutput(this.witnessUtxo!);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.partialSigs! && this.partialSigs!.length > 0) {
      this.partialSigs!.forEach(({ pubkey, signature }) => {
        const key = new Key(InputTypes.PARTIAL_SIG, pubkey);
        keyPairs.push(new KeyPair(key, signature));
      });
    }

    if (this.sighashType !== undefined) {
      const key = new Key(InputTypes.SIGHASH_TYPE);
      const value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.sighashType!);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.redeemScript! && this.redeemScript!.length > 0) {
      const key = new Key(InputTypes.REDEEM_SCRIPT);
      keyPairs.push(new KeyPair(key, this.redeemScript!));
    }

    if (this.witnessScript! && this.witnessScript!.length > 0) {
      const key = new Key(InputTypes.WITNESS_SCRIPT);
      keyPairs.push(new KeyPair(key, this.witnessScript!));
    }

    if (this.bip32Derivation! && this.bip32Derivation!.length > 0) {
      this.bip32Derivation!.forEach(({ pubkey, masterFingerprint, path }) => {
        const key = new Key(InputTypes.BIP32_DERIVATION, pubkey);
        const value = encodeBIP32Derivation(masterFingerprint, path);
        keyPairs.push(new KeyPair(key, value));
      });
    }

    if (this.finalScriptSig! && this.finalScriptSig!.length > 0) {
      const key = new Key(InputTypes.FINAL_SCRIPTSIG);
      keyPairs.push(new KeyPair(key, this.finalScriptSig!));
    }

    if (this.finalScriptWitness! && this.finalScriptWitness!.length > 0) {
      const key = new Key(InputTypes.FINAL_SCRIPTWITNESS);
      keyPairs.push(new KeyPair(key, this.finalScriptWitness!));
    }

    if (
      this.ripemd160Preimages! &&
      Object.keys(this.ripemd160Preimages!).length > 0
    ) {
      Object.entries(this.ripemd160Preimages!).forEach(([k, v]) => {
        const key = new Key(InputTypes.RIPEMD_160, Buffer.from(k, 'hex'));
        keyPairs.push(new KeyPair(key, v));
      });
    }

    if (
      this.sha256Preimages! &&
      Object.keys(this.sha256Preimages!).length > 0
    ) {
      Object.entries(this.sha256Preimages!).forEach(([k, v]) => {
        const key = new Key(InputTypes.SHA_256, Buffer.from(k, 'hex'));
        keyPairs.push(new KeyPair(key, v));
      });
    }

    if (
      this.hash160Preimages! &&
      Object.keys(this.hash160Preimages!).length > 0
    ) {
      Object.entries(this.hash160Preimages!).forEach(([k, v]) => {
        const key = new Key(InputTypes.HASH_160, Buffer.from(k, 'hex'));
        keyPairs.push(new KeyPair(key, v));
      });
    }

    if (
      this.hash256Preimages! &&
      Object.keys(this.hash256Preimages!).length > 0
    ) {
      Object.entries(this.hash256Preimages!).forEach(([k, v]) => {
        const key = new Key(InputTypes.HASH_256, Buffer.from(k, 'hex'));
        keyPairs.push(new KeyPair(key, v));
      });
    }

    const preivousTxidKey = new Key(InputTypes.PREVIOUS_TXID);
    keyPairs.push(new KeyPair(preivousTxidKey, this.previousTxid));

    const prevTxIndexKey = new Key(InputTypes.PREVIOUS_TXINDEX);
    const prevTxIndex = Buffer.allocUnsafe(4);
    prevTxIndex.writeUInt32LE(this.previousTxIndex);
    keyPairs.push(new KeyPair(prevTxIndexKey, prevTxIndex));

    if (this.sequence! > 0) {
      const sequenceKey = new Key(InputTypes.SEQUENCE);
      const sequence = Buffer.allocUnsafe(4);
      sequence.writeUInt32LE(this.sequence!);
      keyPairs.push(new KeyPair(sequenceKey, sequence));
    }

    if (this.requiredTimeLocktime! > 0) {
      const key = new Key(InputTypes.REQUIRED_TIME_LOCKTIME);
      const value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.requiredTimeLocktime!);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.requiredHeightLocktime! > 0) {
      const key = new Key(InputTypes.REQUIRED_HEIGHT_LOCKTIME);
      const value = Buffer.allocUnsafe(4);
      value.writeUInt32LE(this.requiredHeightLocktime!);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.tapKeySig! && this.tapKeySig.length > 0) {
      const key = new Key(InputTypes.TAP_KEY_SIG);
      keyPairs.push(new KeyPair(key, this.tapKeySig!));
    }

    if (this.tapScriptSig! && this.tapScriptSig!.length > 0) {
      this.tapScriptSig.forEach(({ pubkey, signature, leafHash }) => {
        const keyData = Buffer.concat([pubkey, leafHash]);
        const key = new Key(InputTypes.TAP_SCRIPT_SIG, keyData);
        keyPairs.push(new KeyPair(key, signature));
      });
    }

    if (this.tapLeafScript! && this.tapLeafScript.length > 0) {
      this.tapLeafScript.forEach(({ leafVersion, script, controlBlock }) => {
        const key = new Key(InputTypes.TAP_LEAF_SCRIPT, controlBlock);
        const value = Buffer.concat([script, Buffer.of(leafVersion)]);
        keyPairs.push(new KeyPair(key, value));
      });
    }

    if (this.tapBip32Derivation! && this.tapBip32Derivation!.length > 0) {
      this.tapBip32Derivation!.forEach(
        ({ pubkey, masterFingerprint, path, leafHashes }) => {
          const key = new Key(InputTypes.TAP_BIP32_DERIVATION, pubkey);
          const nHashesLen = varuint.encodingLength(leafHashes.length);
          const nHashesBuf = Buffer.allocUnsafe(nHashesLen);
          varuint.encode(leafHashes.length, nHashesBuf);
          const value = Buffer.concat([
            nHashesBuf,
            ...leafHashes,
            encodeBIP32Derivation(masterFingerprint, path),
          ]);
          keyPairs.push(new KeyPair(key, value));
        },
      );
    }

    if (this.tapInternalKey! && this.tapInternalKey!.length > 0) {
      const key = new Key(InputTypes.TAP_INTERNAL_KEY);
      keyPairs.push(new KeyPair(key, this.tapInternalKey!));
    }

    if (this.tapMerkleRoot! && this.tapMerkleRoot!.length > 0) {
      const key = new Key(InputTypes.TAP_MERKLE_ROOT);
      keyPairs.push(new KeyPair(key, this.tapMerkleRoot));
    }

    if (this.issuanceValue! > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_VALUE,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      const value = Buffer.allocUnsafe(8);
      writeUInt64LE(value, this.issuanceValue!, 0);
      keyPairs.push(new KeyPair(key, value));
    }

    if (
      this.issuanceValueCommitment! &&
      this.issuanceValueCommitment!.length > 0
    ) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_VALUE_COMMITMENT,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceValueCommitment!));
    }

    if (
      this.issuanceValueRangeproof! &&
      this.issuanceValueRangeproof!.length > 0
    ) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_VALUE_RANGEPROOF,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceValueRangeproof!));
    }

    if (
      this.issuanceInflationKeysRangeproof! &&
      this.issuanceInflationKeysRangeproof!.length > 0
    ) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_RANGEPROOF,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceInflationKeysRangeproof!));
    }

    if (this.peginTx!) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_TX,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginTx!.toBuffer()));
    }

    if (this.peginTxoutProof! && this.peginTxoutProof!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_TXOUT_PROOF,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginTxoutProof!));
    }

    if (this.peginGenesisHash! && this.peginGenesisHash!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_GENESIS_HASH,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginGenesisHash!));
    }

    if (this.peginClaimScript! && this.peginClaimScript!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_CLAIM_SCRIPT,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.peginClaimScript!));
    }

    if (this.peginValue! > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_VALUE,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      const value = Buffer.allocUnsafe(8);
      writeUInt64LE(value, this.peginValue!, 0);
      keyPairs.push(new KeyPair(key, value!));
    }

    if (this.peginWitness! && this.peginWitness!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.PEGIN_WITNESS,
      );
      const w = new BufferWriter(Buffer.allocUnsafe(0));
      w.writeVector(this.peginWitness!);
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, w.buffer));
    }

    if (this.issuanceInflationKeys! > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_INFLATION_KEYS,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      const value = Buffer.allocUnsafe(8);
      writeUInt64LE(value, this.issuanceInflationKeys!, 0);
      keyPairs.push(new KeyPair(key, value!));
    }

    if (
      this.issuanceInflationKeysCommitment! &&
      this.issuanceInflationKeysCommitment!.length > 0
    ) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_INFLATION_KEYS_COMMITMENT,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceInflationKeysCommitment!));
    }

    if (this.issuanceBlindingNonce! && this.issuanceBlindingNonce!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_BLINDING_NONCE,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceBlindingNonce!));
    }

    if (this.issuanceAssetEntropy! && this.issuanceAssetEntropy!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_ASSET_ENTROPY,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceAssetEntropy!));
    }

    if (this.utxoRangeProof! && this.utxoRangeProof!.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.UTXO_RANGEPROOF,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.utxoRangeProof!));
    }

    if (
      this.issuanceBlindValueProof! &&
      this.issuanceBlindValueProof!.length > 0
    ) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_BLIND_VALUE_PROOF,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceBlindValueProof!));
    }

    if (
      this.issuanceBlindInflationKeysProof! &&
      this.issuanceBlindInflationKeysProof!.length > 0
    ) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ISSUANCE_BLIND_INFLATION_KEYS_PROOF,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.issuanceBlindInflationKeysProof!));
    }

    if (this.explicitValue && this.explicitValue >= 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.EXPLICIT_VALUE,
      );

      const key = new Key(InputTypes.PROPRIETARY, keyData);
      const value = Buffer.allocUnsafe(8);
      writeUInt64LE(value, this.explicitValue, 0);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.explicitValueProof && this.explicitValueProof.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.VALUE_PROOF,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.explicitValueProof));
    }

    if (this.explicitAsset && this.explicitAsset.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.EXPLICIT_ASSET,
      );

      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.explicitAsset));
    }

    if (this.explicitAssetProof && this.explicitAssetProof.length > 0) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.ASSET_PROOF,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      keyPairs.push(new KeyPair(key, this.explicitAssetProof));
    }

    if (this.blindedIssuance !== undefined) {
      const keyData = ProprietaryData.proprietaryKey(
        InputProprietaryTypes.BLINDED_ISSUANCE,
      );
      const key = new Key(InputTypes.PROPRIETARY, keyData);
      const value = Buffer.of(this.blindedIssuance ? 0x01 : 0x00);
      keyPairs.push(new KeyPair(key, value));
    }

    if (this.proprietaryData! && this.proprietaryData!.length > 0) {
      this.proprietaryData.forEach((data) => {
        const keyData = ProprietaryData.proprietaryKey(
          data.subType,
          data.keyData,
        );
        const key = new Key(InputTypes.PROPRIETARY, keyData);
        keyPairs.push(new KeyPair(key, data.value));
      });
    }

    keyPairs.concat(this.unknowns || []);

    return keyPairs;
  }
}

function serializeOutput(out: Output): Buffer {
  const size =
    out.asset.length +
    out.value.length +
    varuint.encodingLength(out.script.length) +
    out.script.length +
    out.nonce.length;
  const buf = Buffer.allocUnsafe(size);
  const w = new BufferWriter(buf, 0);

  w.writeSlice(out.asset);
  w.writeSlice(out.value);
  w.writeSlice(out.nonce);
  w.writeVarSlice(out.script);
  return buf;
}

function deserializeOutput(buf: Buffer): Output {
  if (buf.length < 45) {
    throw new Error('Invalid input witness utxo length');
  }

  const r = new BufferReader(buf);
  const asset = r.readSlice(33);
  const value = r.readConfidentialValue();
  const nonce = r.readConfidentialNonce();
  const script = r.readVarSlice();
  return { asset, value, nonce, script };
}
