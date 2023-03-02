'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function (o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
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
exports.Transaction = exports.ZERO = void 0;
const bufferutils_1 = require('./bufferutils');
const bcrypto = __importStar(require('./crypto'));
const bscript = __importStar(require('./script'));
const script_1 = require('./script');
const types = __importStar(require('./types'));
const { typeforce } = types;
const EMPTY_BUFFER = Buffer.allocUnsafe(0);
const EMPTY_WITNESS = [];
exports.ZERO = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const ONE = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const WITNESS_SCALE_FACTOR = 4;
const OUTPOINT_ISSUANCE_FLAG = (1 << 31) >>> 0;
const OUTPOINT_PEGIN_FLAG = (1 << 30) >>> 0;
const OUTPOINT_INDEX_MASK = 0x3fffffff;
const MINUS_1 = 4294967295;
const VALUE_UINT64_MAX = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT = {
  script: EMPTY_BUFFER,
  asset: exports.ZERO,
  nonce: exports.ZERO,
  valueBuffer: VALUE_UINT64_MAX,
};
class Transaction {
  constructor() {
    this.version = 1;
    this.locktime = 0;
    this.flag = 0;
    this.ins = [];
    this.outs = [];
  }
  static fromBuffer(buffer, _NO_STRICT) {
    const bufferReader = new bufferutils_1.BufferReader(buffer);
    const tx = new Transaction();
    tx.version = bufferReader.readInt32();
    tx.flag = bufferReader.readUInt8();
    let hasWitnesses = false;
    if (tx.flag & Transaction.ADVANCED_TRANSACTION_FLAG) {
      hasWitnesses = true;
    }
    const vinLen = bufferReader.readVarInt();
    for (let i = 0; i < vinLen; ++i) {
      const inHash = bufferReader.readSlice(32);
      let inIndex = bufferReader.readUInt32();
      const inScript = bufferReader.readVarSlice();
      const inSequence = bufferReader.readUInt32();
      let inIsPegin = false;
      let inIssuance;
      if (inIndex !== MINUS_1) {
        if (inIndex & OUTPOINT_ISSUANCE_FLAG) {
          inIssuance = bufferReader.readIssuance();
        }
        if (inIndex & OUTPOINT_PEGIN_FLAG) {
          inIsPegin = true;
        }
        inIndex &= OUTPOINT_INDEX_MASK;
      }
      tx.ins.push({
        hash: inHash,
        index: inIndex,
        script: inScript,
        sequence: inSequence,
        witness: EMPTY_WITNESS,
        isPegin: inIsPegin,
        issuance: inIssuance,
        peginWitness: EMPTY_WITNESS,
        issuanceRangeProof: EMPTY_BUFFER,
        inflationRangeProof: EMPTY_BUFFER,
      });
    }
    const voutLen = bufferReader.readVarInt();
    for (let i = 0; i < voutLen; ++i) {
      const asset = bufferReader.readConfidentialAsset();
      const value = bufferReader.readConfidentialValue();
      const nonce = bufferReader.readConfidentialNonce();
      const script = bufferReader.readVarSlice();
      tx.outs.push({
        asset,
        value,
        nonce,
        script,
        rangeProof: EMPTY_BUFFER,
        surjectionProof: EMPTY_BUFFER,
      });
    }
    tx.locktime = bufferReader.readUInt32();
    if (hasWitnesses) {
      for (let i = 0; i < vinLen; ++i) {
        const {
          witness,
          peginWitness,
          issuanceRangeProof,
          inflationRangeProof,
        } = bufferReader.readConfidentialInFields();
        tx.ins[i].witness = witness;
        tx.ins[i].peginWitness = peginWitness;
        tx.ins[i].issuanceRangeProof = issuanceRangeProof;
        tx.ins[i].inflationRangeProof = inflationRangeProof;
      }
      for (let i = 0; i < voutLen; ++i) {
        const { rangeProof, surjectionProof } =
          bufferReader.readConfidentialOutFields();
        tx.outs[i].rangeProof = rangeProof;
        tx.outs[i].surjectionProof = surjectionProof;
      }
    }
    if (_NO_STRICT) return tx;
    if (bufferReader.offset !== buffer.length)
      throw new Error('Transaction has unexpected data');
    return tx;
  }
  static fromHex(hex) {
    return Transaction.fromBuffer(Buffer.from(hex, 'hex'), false);
  }
  static isCoinbaseHash(buffer) {
    typeforce(types.Hash256bit, buffer);
    for (let i = 0; i < 32; ++i) {
      if (buffer[i] !== 0) return false;
    }
    return true;
  }
  isCoinbase() {
    return (
      this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
    );
  }
  // A quick and reliable way to validate that all the buffers are of correct type and length
  validateIssuance(assetBlindingNonce, assetEntropy, assetAmount, tokenAmount) {
    typeforce(types.Hash256bit, assetBlindingNonce);
    typeforce(types.Hash256bit, assetEntropy);
    typeforce(
      types.oneOf(
        types.ConfidentialValue,
        types.ConfidentialCommitment,
        types.BufferOne,
      ),
      assetAmount,
    );
    typeforce(
      types.oneOf(
        types.ConfidentialValue,
        types.ConfidentialCommitment,
        types.BufferOne,
      ),
      tokenAmount,
    );
    return true;
  }
  addInput(hash, index, sequence, scriptSig, issuance) {
    typeforce(
      types.tuple(
        types.Hash256bit,
        types.UInt32,
        types.maybe(types.UInt32),
        types.maybe(types.Buffer),
        types.maybe(types.Object),
      ),
      arguments,
    );
    let isPegin = false;
    if (index !== MINUS_1) {
      if (index & OUTPOINT_ISSUANCE_FLAG) {
        if (!issuance) {
          throw new Error(
            'Issuance flag has been set but the Issuance object is not defined or invalid',
          );
        } else
          this.validateIssuance(
            issuance.assetBlindingNonce,
            issuance.assetEntropy,
            issuance.assetAmount,
            issuance.tokenAmount,
          );
      }
      if (index & OUTPOINT_PEGIN_FLAG) {
        isPegin = true;
      }
      index &= OUTPOINT_INDEX_MASK;
    }
    // Add the input and return the input's index
    return (
      this.ins.push({
        hash,
        index,
        isPegin,
        issuance,
        script: scriptSig || EMPTY_BUFFER,
        witness: EMPTY_WITNESS,
        peginWitness: EMPTY_WITNESS,
        issuanceRangeProof: EMPTY_BUFFER,
        inflationRangeProof: EMPTY_BUFFER,
        sequence: sequence || Transaction.DEFAULT_SEQUENCE,
      }) - 1
    );
  }
  addOutput(scriptPubKey, value, asset, nonce, rangeProof, surjectionProof) {
    typeforce(
      types.tuple(
        types.Buffer,
        types.oneOf(types.ConfidentialValue, types.ConfidentialCommitment),
        types.AssetBufferWithFlag,
        types.oneOf(types.ConfidentialCommitment, types.BufferOne),
        types.maybe(types.Buffer),
        types.maybe(types.Buffer),
      ),
      arguments,
    );
    // Add the output and return the output's index
    return (
      this.outs.push({
        script: scriptPubKey,
        value,
        asset,
        nonce: nonce || EMPTY_BUFFER,
        rangeProof: rangeProof || EMPTY_BUFFER,
        surjectionProof: surjectionProof || EMPTY_BUFFER,
      }) - 1
    );
  }
  hasWitnesses() {
    return (
      this.flag === 1 ||
      this.ins.some((x) => {
        return x.witness.length !== 0;
      }) ||
      this.outs.some((x) => {
        return x.rangeProof.length !== 0 && x.surjectionProof.length !== 0;
      })
    );
  }
  weight() {
    const base = this.__byteLength(false);
    const total = this.__byteLength(true);
    return base * (WITNESS_SCALE_FACTOR - 1) + total;
  }
  virtualSize() {
    const vsize =
      (this.weight() + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    return Math.floor(vsize);
  }
  byteLength(_ALLOW_WITNESS) {
    return this.__byteLength(_ALLOW_WITNESS || true);
  }
  clone() {
    const newTx = new Transaction();
    newTx.version = this.version;
    newTx.locktime = this.locktime;
    newTx.flag = this.flag;
    newTx.ins = this.ins.map((txIn) => {
      return {
        hash: txIn.hash,
        index: txIn.index,
        script: txIn.script,
        sequence: txIn.sequence,
        witness: txIn.witness,
        isPegin: txIn.isPegin,
        issuance: txIn.issuance,
        peginWitness: txIn.peginWitness,
        issuanceRangeProof: txIn.issuanceRangeProof,
        inflationRangeProof: txIn.inflationRangeProof,
      };
    });
    newTx.outs = this.outs.map((txOut) => {
      return {
        script: txOut.script,
        value: txOut.value,
        asset: txOut.asset,
        nonce: txOut.nonce,
        rangeProof: txOut.rangeProof,
        surjectionProof: txOut.surjectionProof,
      };
    });
    return newTx;
  }
  /**
   * Hash transaction for signing a specific input.
   *
   * Bitcoin uses a different hash for each signed transaction input.
   * This method copies the transaction, makes the necessary changes based on the
   * hashType, and then hashes the result.
   * This hash can then be used to sign the provided transaction input.
   */
  hashForSignature(inIndex, prevOutScript, hashType) {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number),
      arguments,
    );
    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length) return ONE;
    // ignore OP_CODESEPARATOR
    const ourScript = bscript.compile(
      bscript.decompile(prevOutScript).filter((x) => {
        return x !== script_1.OPS.OP_CODESEPARATOR;
      }),
    );
    const txTmp = this.clone();
    // SIGHASH_NONE: ignore all outputs? (wildcard payee)
    if ((hashType & 0x1f) === Transaction.SIGHASH_NONE) {
      txTmp.outs = [];
      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, i) => {
        if (i === inIndex) return;
        input.sequence = 0;
      });
      // SIGHASH_SINGLE: ignore all outputs, except at the same index?
    } else if ((hashType & 0x1f) === Transaction.SIGHASH_SINGLE) {
      // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L60
      if (inIndex >= this.outs.length) return ONE;
      // truncate outputs after
      txTmp.outs.length = inIndex + 1;
      // "blank" outputs before
      for (let i = 0; i < inIndex; i++) {
        txTmp.outs[i] = BLANK_OUTPUT;
      }
      // ignore sequence numbers (except at inIndex)
      txTmp.ins.forEach((input, y) => {
        if (y === inIndex) return;
        input.sequence = 0;
      });
    }
    // SIGHASH_ANYONECANPAY: ignore inputs entirely?
    if (hashType & Transaction.SIGHASH_ANYONECANPAY) {
      txTmp.ins = [txTmp.ins[inIndex]];
      txTmp.ins[0].script = ourScript;
      // SIGHASH_ALL: only ignore input scripts
    } else {
      // "blank" others input scripts
      txTmp.ins.forEach((input) => {
        input.script = EMPTY_BUFFER;
      });
      txTmp.ins[inIndex].script = ourScript;
    }
    // serialize and hash
    const buffer = Buffer.allocUnsafe(txTmp.__byteLength(false, true) + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false, true, true);
    return bcrypto.hash256(buffer);
  }
  // differs from bitcoin core
  // https://github.com/ElementsProject/elements/blob/84b3f7b0045b50a585d60e56e77e8914b6cf6040/doc/taproot-sighash.mediawiki
  hashForWitnessV1(
    inIndex,
    prevOutScripts,
    prevoutAssetsValues,
    hashType,
    genesisBlockHash,
    leafHash,
    annex,
  ) {
    typeforce(
      types.tuple(
        types.UInt32,
        typeforce.arrayOf(types.Buffer),
        typeforce.arrayOf(types.Object),
        types.UInt32,
      ),
      arguments,
    );
    if (prevOutScripts.length !== this.ins.length) {
      throw new Error('Must supply prevout script and value for all inputs');
    }
    const outputType =
      hashType === Transaction.SIGHASH_DEFAULT
        ? Transaction.SIGHASH_ALL
        : hashType & Transaction.SIGHASH_OUTPUT_MASK;
    const inputType = hashType & Transaction.SIGHASH_INPUT_MASK;
    const isAnyoneCanPay = inputType === Transaction.SIGHASH_ANYONECANPAY;
    const isNone = outputType === Transaction.SIGHASH_NONE;
    const isSingle = outputType === Transaction.SIGHASH_SINGLE;
    let hashPrevouts = EMPTY_BUFFER;
    let hashSequences = EMPTY_BUFFER;
    let hashOutputs = EMPTY_BUFFER;
    let hashIssuances = EMPTY_BUFFER;
    let hashScriptPubKeys = EMPTY_BUFFER;
    // elements new hashes for witness  v1
    let hashOutpointsFlags = EMPTY_BUFFER;
    let hashIssuancesProofs = EMPTY_BUFFER;
    let hashOutputsWitnesses = EMPTY_BUFFER;
    let hashSpentAssetsAmounts = EMPTY_BUFFER;
    if (!isAnyoneCanPay) {
      hashPrevouts = getPrevoutsSHA256(this.ins);
      hashOutpointsFlags = getOutpointFlagsSHA256(this.ins);
      hashSpentAssetsAmounts = getSpentAssetsAmountsSHA256(prevoutAssetsValues);
      hashIssuancesProofs = getIssuanceProofsSHA256(this.ins);
      hashScriptPubKeys = getPrevoutScriptsSHA256(prevOutScripts);
      hashSequences = getSequenceSHA256(this.ins);
      hashIssuances = getIssuanceSHA256(this.ins);
    }
    if (!(isNone || isSingle)) {
      hashOutputs = getOutputsSHA256(this.outs);
      hashOutputsWitnesses = getOutputWitnessesSHA256(this.outs);
    } else if (isSingle && inIndex < this.outs.length) {
      const output = this.outs[inIndex];
      hashOutputs = getOutputsSHA256([output]);
      hashOutputsWitnesses = getOutputWitnessesSHA256([output]);
    }
    // key-path spent or a tapscript (annex is for future update)
    const spendType = (leafHash ? 2 : 0) + (annex ? 1 : 0);
    // Length calculation from:
    // https://github.com/ElementsProject/elements/blob/84b3f7b0045b50a585d60e56e77e8914b6cf6040/doc/taproot-sighash.mediawiki
    const inputPartSize = isAnyoneCanPay
      ? 1 +
        32 +
        4 +
        prevoutAssetsValues[inIndex].asset.length +
        prevoutAssetsValues[inIndex].value.length +
        (0, bufferutils_1.varSliceSize)(prevOutScripts[inIndex]) +
        4 +
        (this.ins[inIndex].issuance ? getIssuanceSize(this.ins[inIndex]) : 1)
      : 4;
    const fullMsgSize = 32 * 2 + 1 + 4 + 4 + 1 + inputPartSize;
    const sigMsgSize =
      fullMsgSize +
      (!isAnyoneCanPay ? 7 * 32 : 0) +
      (!(isNone || isSingle) ? 32 + 32 : 0) +
      (annex ? 32 : 0) +
      (isSingle ? 32 + 32 : 0) +
      (leafHash ? 37 : 0);
    const sigMsgWriter = bufferutils_1.BufferWriter.withCapacity(sigMsgSize);
    // this is "blockchain rationale", only used in elements
    // it prevents signatures to be reused accross different Elements instance
    sigMsgWriter.writeSlice(genesisBlockHash);
    sigMsgWriter.writeSlice(genesisBlockHash);
    sigMsgWriter.writeUInt8(hashType);
    // Transaction
    sigMsgWriter.writeInt32(this.version);
    sigMsgWriter.writeUInt32(this.locktime);
    if (!isAnyoneCanPay) {
      sigMsgWriter.writeSlice(hashOutpointsFlags);
      sigMsgWriter.writeSlice(hashPrevouts);
      sigMsgWriter.writeSlice(hashSpentAssetsAmounts);
      sigMsgWriter.writeSlice(hashScriptPubKeys);
      sigMsgWriter.writeSlice(hashSequences);
      sigMsgWriter.writeSlice(hashIssuances);
      sigMsgWriter.writeSlice(hashIssuancesProofs);
    }
    if (!(isNone || isSingle)) {
      sigMsgWriter.writeSlice(hashOutputs);
      sigMsgWriter.writeSlice(hashOutputsWitnesses);
    }
    // Input
    sigMsgWriter.writeUInt8(spendType);
    if (isAnyoneCanPay) {
      const input = this.ins[inIndex];
      sigMsgWriter.writeUInt8(getInputFlag(input));
      sigMsgWriter.writeSlice(input.hash);
      sigMsgWriter.writeUInt32(input.index);
      sigMsgWriter.writeSlice(prevoutAssetsValues[inIndex].asset);
      sigMsgWriter.writeSlice(prevoutAssetsValues[inIndex].value);
      sigMsgWriter.writeVarSlice(prevOutScripts[inIndex]);
      sigMsgWriter.writeUInt32(input.sequence);
      if (input.issuance) {
        sigMsgWriter.writeSlice(input.issuance.assetBlindingNonce);
        sigMsgWriter.writeSlice(input.issuance.assetEntropy);
        sigMsgWriter.writeSlice(input.issuance.assetAmount);
        sigMsgWriter.writeSlice(input.issuance.tokenAmount);
        const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
          (0, bufferutils_1.varSliceSize)(input.issuanceRangeProof) +
            (0, bufferutils_1.varSliceSize)(input.inflationRangeProof),
        );
        bufferWriter.writeVarSlice(input.issuanceRangeProof || Buffer.of(0x00));
        bufferWriter.writeVarSlice(
          input.inflationRangeProof || Buffer.of(0x00),
        );
        const hashIssuance = bcrypto.sha256(bufferWriter.end());
        sigMsgWriter.writeSlice(hashIssuance);
      } else {
        sigMsgWriter.writeSlice(Buffer.of(0x00));
      }
    } else {
      sigMsgWriter.writeUInt32(inIndex);
    }
    if (annex) {
      const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
        (0, bufferutils_1.varSliceSize)(annex),
      );
      bufferWriter.writeVarSlice(annex);
      sigMsgWriter.writeSlice(bcrypto.sha256(bufferWriter.end()));
    }
    if (isSingle) {
      sigMsgWriter.writeSlice(hashOutputs);
      sigMsgWriter.writeSlice(hashOutputsWitnesses);
    }
    // BIP342 extension
    if (leafHash) {
      sigMsgWriter.writeSlice(leafHash);
      sigMsgWriter.writeUInt8(0);
      sigMsgWriter.writeUInt32(0xffffffff);
    }
    return bcrypto.taggedHash('TapSighash/elements', sigMsgWriter.end());
  }
  hashForWitnessV0(inIndex, prevOutScript, value, hashType) {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, types.Buffer, types.UInt32),
      arguments,
    );
    let hashOutputs = exports.ZERO;
    let hashPrevouts = exports.ZERO;
    let hashSequence = exports.ZERO;
    let hashIssuances = exports.ZERO;
    // Inputs
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      const prevoutsHashWriter = bufferutils_1.BufferWriter.withCapacity(
        (32 + 4) * this.ins.length,
      );
      this.ins.forEach((txIn) => {
        prevoutsHashWriter.writeSlice(txIn.hash);
        prevoutsHashWriter.writeUInt32(txIn.index);
      });
      hashPrevouts = bcrypto.hash256(prevoutsHashWriter.end());
    }
    // Sequences
    if (
      !(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      const sequenceHashWriter = bufferutils_1.BufferWriter.withCapacity(
        4 * this.ins.length,
      );
      this.ins.forEach((txIn) => {
        sequenceHashWriter.writeUInt32(txIn.sequence);
      });
      hashSequence = bcrypto.hash256(sequenceHashWriter.end());
    }
    // Issuances
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      const sizeOfIssuances = this.ins.reduce(
        (sum, txIn) => (txIn.issuance ? sum + getIssuanceSize(txIn) : sum + 1),
        0,
      );
      const size = sizeOfIssuances === 0 ? this.ins.length : sizeOfIssuances;
      const issuancesHashWriter = bufferutils_1.BufferWriter.withCapacity(size);
      this.ins.forEach((txIn) => {
        if (txIn.issuance) {
          issuancesHashWriter.writeSlice(txIn.issuance.assetBlindingNonce);
          issuancesHashWriter.writeSlice(txIn.issuance.assetEntropy);
          issuancesHashWriter.writeSlice(txIn.issuance.assetAmount);
          issuancesHashWriter.writeSlice(txIn.issuance.tokenAmount);
        } else {
          issuancesHashWriter.writeSlice(Buffer.of(0x00));
        }
      });
      hashIssuances = bcrypto.hash256(issuancesHashWriter.end());
    }
    // Outputs
    if (
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      const txOutsSize = this.outs.reduce(
        (sum, output) =>
          sum +
          output.asset.length +
          output.value.length +
          output.nonce.length +
          (0, bufferutils_1.varSliceSize)(output.script),
        0,
      );
      const outputsHashWriter =
        bufferutils_1.BufferWriter.withCapacity(txOutsSize);
      this.outs.forEach((out) => {
        outputsHashWriter.writeSlice(out.asset);
        outputsHashWriter.writeSlice(out.value);
        outputsHashWriter.writeSlice(out.nonce);
        outputsHashWriter.writeVarSlice(out.script);
      });
      hashOutputs = bcrypto.hash256(outputsHashWriter.end());
    } else if (
      (hashType & 0x1f) === Transaction.SIGHASH_SINGLE &&
      inIndex < this.outs.length
    ) {
      const output = this.outs[inIndex];
      const size =
        output.asset.length +
        output.value.length +
        output.nonce.length +
        (0, bufferutils_1.varSliceSize)(output.script);
      const outputsHashWriter = bufferutils_1.BufferWriter.withCapacity(size);
      outputsHashWriter.writeSlice(output.asset);
      outputsHashWriter.writeSlice(output.value);
      outputsHashWriter.writeSlice(output.nonce);
      outputsHashWriter.writeVarSlice(output.script);
      hashOutputs = bcrypto.hash256(outputsHashWriter.end());
    }
    const input = this.ins[inIndex];
    const hasIssuance = input.issuance !== undefined;
    const bufferSize =
      4 + // version
      hashPrevouts.length +
      hashSequence.length +
      hashIssuances.length +
      input.hash.length +
      4 + // input.index
      (0, bufferutils_1.varSliceSize)(prevOutScript) +
      value.length +
      4 + // input.sequence
      hashOutputs.length +
      getIssuanceSize(input) +
      4 + // locktime
      4; // hashType
    const sigWriter = bufferutils_1.BufferWriter.withCapacity(bufferSize);
    sigWriter.writeUInt32(this.version);
    sigWriter.writeSlice(hashPrevouts);
    sigWriter.writeSlice(hashSequence);
    sigWriter.writeSlice(hashIssuances);
    sigWriter.writeSlice(input.hash);
    sigWriter.writeUInt32(input.index);
    sigWriter.writeVarSlice(prevOutScript);
    sigWriter.writeSlice(value);
    sigWriter.writeUInt32(input.sequence);
    if (hasIssuance) {
      sigWriter.writeSlice(input.issuance.assetBlindingNonce);
      sigWriter.writeSlice(input.issuance.assetEntropy);
      sigWriter.writeSlice(input.issuance.assetAmount);
      sigWriter.writeSlice(input.issuance.tokenAmount);
    }
    sigWriter.writeSlice(hashOutputs);
    sigWriter.writeUInt32(this.locktime);
    sigWriter.writeUInt32(hashType);
    return bcrypto.hash256(sigWriter.end());
  }
  getHash(forWitness) {
    // wtxid for coinbase is always 32 bytes of 0x00
    if (forWitness && this.isCoinbase()) return Buffer.alloc(32, 0);
    return bcrypto.hash256(
      this.__toBuffer(undefined, undefined, forWitness, true),
    );
  }
  getId() {
    // transaction hash's are displayed in reverse order
    return (0, bufferutils_1.reverseBuffer)(this.getHash(false)).toString(
      'hex',
    );
  }
  toBuffer(buffer, initialOffset) {
    return this.__toBuffer(buffer, initialOffset, true, false);
  }
  toHex() {
    return this.toBuffer(undefined, undefined).toString('hex');
  }
  setInputScript(index, scriptSig) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.ins[index].script = scriptSig;
  }
  setWitness(index, witness) {
    typeforce(types.tuple(types.Number, [types.Buffer]), arguments);
    this.ins[index].witness = witness;
  }
  setPeginWitness(index, peginWitness) {
    typeforce(types.tuple(types.Number, [types.Buffer]), arguments);
    this.ins[index].peginWitness = peginWitness;
  }
  setInputIssuanceRangeProof(index, issuanceRangeProof) {
    typeforce(types.tuple(types.Buffer), arguments);
    if (this.ins[index].issuance === undefined)
      throw new Error('Issuance not set for input #' + index);
    this.ins[index].issuanceRangeProof = issuanceRangeProof;
  }
  setInputInflationRangeProof(index, inflationRangeProof) {
    typeforce(types.tuple(types.Buffer), arguments);
    if (this.ins[index].issuance === undefined)
      throw new Error('Issuance not set for input #' + index);
    this.ins[index].inflationRangeProof = inflationRangeProof;
  }
  setOutputNonce(index, nonce) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.outs[index].nonce = nonce;
  }
  setOutputRangeProof(index, proof) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.outs[index].rangeProof = proof;
  }
  setOutputSurjectionProof(index, proof) {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);
    this.outs[index].surjectionProof = proof;
  }
  __byteLength(_ALLOW_WITNESS, forSignature) {
    const extraByte = forSignature ? 0 : 1;
    let size =
      8 +
      extraByte +
      bufferutils_1.varuint.encodingLength(this.ins.length) +
      bufferutils_1.varuint.encodingLength(this.outs.length);
    for (const txIn of this.ins) {
      size += 40 + (0, bufferutils_1.varSliceSize)(txIn.script);
      if (txIn.issuance) {
        size +=
          64 +
          txIn.issuance.assetAmount.length +
          txIn.issuance.tokenAmount.length;
      }
    }
    for (const txOut of this.outs) {
      size +=
        txOut.asset.length +
        txOut.value.length +
        txOut.nonce.length +
        (0, bufferutils_1.varSliceSize)(txOut.script);
    }
    if (_ALLOW_WITNESS && this.hasWitnesses()) {
      for (const txIn of this.ins) {
        size += (0, bufferutils_1.varSliceSize)(txIn.issuanceRangeProof);
        size += (0, bufferutils_1.varSliceSize)(txIn.inflationRangeProof);
        size += bufferutils_1.varuint.encodingLength(txIn.witness.length);
        for (const wit of txIn.witness) {
          size += (0, bufferutils_1.varSliceSize)(wit);
        }
        size += bufferutils_1.varuint.encodingLength(
          (txIn.peginWitness || []).length,
        );
        for (const wit of txIn.peginWitness || []) {
          size += (0, bufferutils_1.varSliceSize)(wit);
        }
      }
      for (const txOut of this.outs) {
        size += (0, bufferutils_1.varSliceSize)(txOut.surjectionProof);
        size += (0, bufferutils_1.varSliceSize)(txOut.rangeProof);
      }
    }
    return size;
  }
  __toBuffer(
    buffer,
    initialOffset,
    _ALLOW_WITNESS,
    forceZeroFlag,
    forSignature,
  ) {
    if (!buffer)
      buffer = Buffer.allocUnsafe(
        this.__byteLength(_ALLOW_WITNESS, forSignature),
      );
    const bufferWriter = new bufferutils_1.BufferWriter(
      buffer,
      initialOffset || 0,
    );
    bufferWriter.writeInt32(this.version);
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    if (!forSignature) {
      let flags = 0;
      if (hasWitnesses && !forceZeroFlag) {
        flags |= Transaction.ADVANCED_TRANSACTION_FLAG;
      }
      bufferWriter.writeUInt8(flags);
    }
    bufferWriter.writeVarInt(this.ins.length);
    this.ins.forEach((txIn) => {
      bufferWriter.writeSlice(txIn.hash);
      let prevIndex = txIn.index;
      if (txIn.issuance) {
        prevIndex = (prevIndex | OUTPOINT_ISSUANCE_FLAG) >>> 0;
      }
      if (txIn.isPegin) {
        prevIndex = (prevIndex | OUTPOINT_PEGIN_FLAG) >>> 0;
      }
      bufferWriter.writeUInt32(prevIndex);
      bufferWriter.writeVarSlice(txIn.script);
      bufferWriter.writeUInt32(txIn.sequence);
      if (txIn.issuance) {
        bufferWriter.writeSlice(txIn.issuance.assetBlindingNonce);
        bufferWriter.writeSlice(txIn.issuance.assetEntropy);
        bufferWriter.writeSlice(txIn.issuance.assetAmount);
        bufferWriter.writeSlice(txIn.issuance.tokenAmount);
      }
    });
    bufferWriter.writeVarInt(this.outs.length);
    this.outs.forEach((txOut) => {
      // if we are serializing a confidential output for producing a signature,
      // we must exclude the confidential value from the serialization and
      // use the satoshi 0 value instead, as done for typical bitcoin witness signatures.
      const val = forSignature && hasWitnesses ? Buffer.alloc(1) : txOut.value;
      bufferWriter.writeSlice(txOut.asset);
      bufferWriter.writeSlice(val);
      bufferWriter.writeSlice(txOut.nonce);
      if (forSignature && hasWitnesses) bufferWriter.writeUInt64(0);
      bufferWriter.writeVarSlice(txOut.script);
    });
    bufferWriter.writeUInt32(this.locktime);
    if (!forSignature && hasWitnesses) {
      this.ins.forEach((input) => {
        bufferWriter.writeConfidentialInFields(input);
      });
      this.outs.forEach((output) => {
        bufferWriter.writeConfidentialOutFields(output);
      });
    }
    // avoid slicing unless necessary
    if (initialOffset !== undefined)
      return buffer.slice(initialOffset, bufferWriter.offset);
    return buffer;
  }
}
exports.Transaction = Transaction;
Transaction.DEFAULT_SEQUENCE = 0xffffffff;
Transaction.SIGHASH_DEFAULT = 0x00;
Transaction.SIGHASH_ALL = 0x01;
Transaction.SIGHASH_NONE = 0x02;
Transaction.SIGHASH_SINGLE = 0x03;
Transaction.SIGHASH_ANYONECANPAY = 0x80;
Transaction.SIGHASH_OUTPUT_MASK = 0x03;
Transaction.SIGHASH_INPUT_MASK = 0x80;
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01;
function getOutputWitnessesSHA256(outs) {
  const outProofsSize = (o) =>
    (0, bufferutils_1.varSliceSize)(o.rangeProof || Buffer.alloc(0)) +
    (0, bufferutils_1.varSliceSize)(o.surjectionProof || Buffer.alloc(0));
  const size = outs.reduce((sum, o) => sum + outProofsSize(o), 0);
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(size);
  for (const out of outs) {
    bufferWriter.writeVarSlice(out.surjectionProof || Buffer.of(0x00));
    bufferWriter.writeVarSlice(out.rangeProof || Buffer.of(0x00));
  }
  return bcrypto.sha256(bufferWriter.end());
}
function getIssuanceProofsSHA256(ins) {
  const inProofsSize = (i) =>
    (0, bufferutils_1.varSliceSize)(i.issuanceRangeProof || Buffer.alloc(1)) +
    (0, bufferutils_1.varSliceSize)(i.inflationRangeProof || Buffer.alloc(1));
  const size = ins.reduce((sum, i) => sum + inProofsSize(i), 0);
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(size);
  for (const input of ins) {
    bufferWriter.writeVarSlice(input.issuanceRangeProof || Buffer.of(0x00));
    bufferWriter.writeVarSlice(input.inflationRangeProof || Buffer.of(0x00));
  }
  return bcrypto.sha256(bufferWriter.end());
}
function getSpentAssetsAmountsSHA256(outs) {
  const size = outs.reduce(
    (sum, o) => sum + o.asset.length + o.value.length,
    0,
  );
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(size);
  for (const out of outs) {
    bufferWriter.writeSlice(out.asset);
    bufferWriter.writeSlice(out.value);
  }
  return bcrypto.sha256(bufferWriter.end());
}
function getInputFlag(input) {
  const hasIssuance = input.issuance !== undefined;
  return (
    (hasIssuance ? OUTPOINT_ISSUANCE_FLAG >>> 24 : 0) |
    (input.isPegin ? OUTPOINT_PEGIN_FLAG >>> 24 : 0)
  );
}
function getOutpointFlagsSHA256(ins) {
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(ins.length);
  for (const input of ins) {
    bufferWriter.writeUInt8(getInputFlag(input));
  }
  return bcrypto.sha256(bufferWriter.end());
}
function getIssuanceSize(txIn) {
  if (txIn.issuance) {
    return (
      txIn.issuance.assetBlindingNonce.length +
      txIn.issuance.assetEntropy.length +
      txIn.issuance.assetAmount.length +
      txIn.issuance.tokenAmount.length
    );
  }
  return 0;
}
function getPrevoutsSHA256(inputs) {
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
    inputs.length * (32 + 4),
  );
  for (const i of inputs) {
    bufferWriter.writeSlice(i.hash);
    bufferWriter.writeUInt32(i.index);
  }
  return bcrypto.sha256(bufferWriter.end());
}
function getPrevoutScriptsSHA256(scripts) {
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
    scripts.map(bufferutils_1.varSliceSize).reduce((a, b) => a + b),
  );
  scripts.forEach((prevOutScript) => bufferWriter.writeVarSlice(prevOutScript));
  return bcrypto.sha256(bufferWriter.end());
}
function getSequenceSHA256(inputs) {
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(
    4 * inputs.length,
  );
  inputs.forEach((txIn) => bufferWriter.writeUInt32(txIn.sequence));
  return bcrypto.sha256(bufferWriter.end());
}
function getIssuanceSHA256(inputs) {
  const sizeOfIssuances = inputs.reduce(
    (sum, txIn) => (txIn.issuance ? sum + getIssuanceSize(txIn) : sum + 1),
    0,
  );
  const size = sizeOfIssuances === 0 ? inputs.length : sizeOfIssuances;
  const writer = bufferutils_1.BufferWriter.withCapacity(size);
  inputs.forEach((txIn) => {
    if (txIn.issuance) {
      writer.writeSlice(txIn.issuance.assetBlindingNonce);
      writer.writeSlice(txIn.issuance.assetEntropy);
      writer.writeSlice(txIn.issuance.assetAmount);
      writer.writeSlice(txIn.issuance.tokenAmount);
    } else {
      writer.writeSlice(Buffer.of(0x00));
    }
  });
  return bcrypto.sha256(writer.end());
}
function getOutputsSHA256(outputs) {
  const txOutsSize = outputs.reduce(
    (sum, output) =>
      sum +
      output.asset.length +
      output.value.length +
      output.nonce.length +
      (0, bufferutils_1.varSliceSize)(output.script),
    0,
  );
  const bufferWriter = bufferutils_1.BufferWriter.withCapacity(txOutsSize);
  outputs.forEach((out) => {
    bufferWriter.writeSlice(out.asset);
    bufferWriter.writeSlice(out.value);
    bufferWriter.writeSlice(out.nonce);
    bufferWriter.writeVarSlice(out.script);
  });
  return bcrypto.sha256(bufferWriter.end());
}
