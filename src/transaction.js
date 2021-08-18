'use strict';
var __importStar =
  (this && this.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
const bufferutils_1 = require('./bufferutils');
const bcrypto = __importStar(require('./crypto'));
const bscript = __importStar(require('./script'));
const script_1 = require('./script');
const types = __importStar(require('./types'));
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');
function varSliceSize(someScript) {
  const length = someScript.length;
  return varuint.encodingLength(length) + length;
}
const EMPTY_SCRIPT = Buffer.allocUnsafe(0);
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
  script: EMPTY_SCRIPT,
  asset: exports.ZERO,
  nonce: exports.ZERO,
  value: VALUE_UINT64_MAX,
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
        issuanceRangeProof: EMPTY_SCRIPT,
        inflationRangeProof: EMPTY_SCRIPT,
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
        rangeProof: EMPTY_SCRIPT,
        surjectionProof: EMPTY_SCRIPT,
      });
    }
    tx.locktime = bufferReader.readUInt32();
    if (tx.flag === 1) {
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
        const {
          rangeProof,
          surjectionProof,
        } = bufferReader.readConfidentialOutFields();
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
        witness: EMPTY_WITNESS,
        peginWitness: EMPTY_WITNESS,
        issuanceRangeProof: EMPTY_SCRIPT,
        inflationRangeProof: EMPTY_SCRIPT,
        script: scriptSig || EMPTY_SCRIPT,
        sequence: sequence || Transaction.DEFAULT_SEQUENCE,
      }) - 1
    );
  }
  addOutput(scriptPubKey, value, asset, nonce, rangeProof, surjectionProof) {
    typeforce(
      types.tuple(
        types.Buffer,
        types.oneOf(
          types.ConfidentialValue,
          types.ConfidentialCommitment,
          types.BufferOne,
        ),
        types.oneOf(types.ConfidentialCommitment, types.BufferOne),
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
        nonce,
        rangeProof: rangeProof || EMPTY_SCRIPT,
        surjectionProof: surjectionProof || EMPTY_SCRIPT,
      }) - 1
    );
  }
  hasWitnesses() {
    return (
      this.flag === 1 ||
      this.ins.some(x => {
        return x.witness.length !== 0;
      }) ||
      this.outs.some(x => {
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
    newTx.ins = this.ins.map(txIn => {
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
    newTx.outs = this.outs.map(txOut => {
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
      bscript.decompile(prevOutScript).filter(x => {
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
      txTmp.ins.forEach(input => {
        input.script = EMPTY_SCRIPT;
      });
      txTmp.ins[inIndex].script = ourScript;
    }
    // serialize and hash
    const buffer = Buffer.allocUnsafe(txTmp.__byteLength(false, true) + 4);
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false, true, true);
    return bcrypto.hash256(buffer);
  }
  hashForWitnessV0(inIndex, prevOutScript, value, hashType) {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, types.Buffer, types.UInt32),
      arguments,
    );
    function writeInputs(ins) {
      const tBuffer = Buffer.allocUnsafe(36 * ins.length);
      const tBufferWriter = new bufferutils_1.BufferWriter(tBuffer, 0);
      ins.forEach(txIn => {
        tBufferWriter.writeSlice(txIn.hash);
        tBufferWriter.writeUInt32(txIn.index);
      });
      return bcrypto.hash256(tBuffer);
    }
    function writeSequences(ins) {
      const tBuffer = Buffer.allocUnsafe(4 * ins.length);
      const tBufferWriter = new bufferutils_1.BufferWriter(tBuffer, 0);
      ins.forEach(txIn => {
        tBufferWriter.writeUInt32(txIn.sequence);
      });
      return bcrypto.hash256(tBuffer);
    }
    function issuanceSize(ins) {
      return ins.reduce(
        (sum, txIn) =>
          !types.Null(txIn.issuance)
            ? sum +
              txIn.issuance.assetBlindingNonce.length +
              txIn.issuance.assetEntropy.length +
              txIn.issuance.assetAmount.length +
              txIn.issuance.tokenAmount.length
            : sum, // we'll use the empty 00 Buffer if issuance is not set
        0,
      );
    }
    function writeIssuances(ins, sizeIssuances) {
      const size = sizeIssuances === 0 ? ins.length : sizeIssuances;
      const tBuffer = Buffer.allocUnsafe(size);
      const tBufferWriter = new bufferutils_1.BufferWriter(tBuffer, 0);
      ins.forEach(txIn => {
        if (!types.Null(txIn.issuance)) {
          tBufferWriter.writeSlice(txIn.issuance.assetBlindingNonce);
          tBufferWriter.writeSlice(txIn.issuance.assetEntropy);
          tBufferWriter.writeSlice(txIn.issuance.assetAmount);
          tBufferWriter.writeSlice(txIn.issuance.tokenAmount);
        } else {
          tBufferWriter.writeSlice(Buffer.from('00', 'hex'));
        }
      });
      return bcrypto.hash256(tBuffer);
    }
    function writeOutputs(outs) {
      const outsSize = outs.reduce(
        (sum, txOut) =>
          sum +
          txOut.asset.length +
          txOut.value.length +
          txOut.nonce.length +
          varSliceSize(txOut.script),
        0,
      );
      const tBuffer = Buffer.allocUnsafe(outsSize);
      const tBufferWriter = new bufferutils_1.BufferWriter(tBuffer, 0);
      outs.forEach(txOut => {
        tBufferWriter.writeSlice(txOut.asset);
        tBufferWriter.writeSlice(txOut.value);
        tBufferWriter.writeSlice(txOut.nonce);
        tBufferWriter.writeVarSlice(txOut.script);
      });
      return bcrypto.hash256(tBuffer);
    }
    let hashOutputs = exports.ZERO;
    let hashPrevouts = exports.ZERO;
    let hashSequences = exports.ZERO;
    let hashIssuances = exports.ZERO;
    let sizeOfIssuances = 0;
    // Inputs
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      hashPrevouts = writeInputs(this.ins);
    }
    // Sequences
    if (
      !(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      hashSequences = writeSequences(this.ins);
    }
    // Issuances
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      sizeOfIssuances = issuanceSize(this.ins);
      hashIssuances = writeIssuances(this.ins, sizeOfIssuances);
    }
    // Outputs
    if (
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      hashOutputs = writeOutputs(this.outs);
    } else if (
      (hashType & 0x1f) === Transaction.SIGHASH_SINGLE &&
      inIndex < this.outs.length
    ) {
      hashOutputs = writeOutputs([this.outs[inIndex]]);
    }
    const input = this.ins[inIndex];
    const hasIssuance = !types.Null(input.issuance);
    const bufferSize =
      4 + // version
      hashPrevouts.length +
      hashSequences.length +
      hashIssuances.length +
      input.hash.length +
      4 + // input.index
      varSliceSize(prevOutScript) +
      value.length +
      4 + // input.sequence
      hashOutputs.length +
      sizeOfIssuances +
      4 + // locktime
      4; // hashType
    const buffer = Buffer.allocUnsafe(bufferSize);
    const bufferWriter = new bufferutils_1.BufferWriter(buffer, 0);
    bufferWriter.writeUInt32(this.version);
    bufferWriter.writeSlice(hashPrevouts);
    bufferWriter.writeSlice(hashSequences);
    bufferWriter.writeSlice(hashIssuances);
    bufferWriter.writeSlice(input.hash);
    bufferWriter.writeUInt32(input.index);
    bufferWriter.writeVarSlice(prevOutScript);
    bufferWriter.writeSlice(value);
    bufferWriter.writeUInt32(input.sequence);
    if (hasIssuance) {
      bufferWriter.writeSlice(input.issuance.assetBlindingNonce);
      bufferWriter.writeSlice(input.issuance.assetEntropy);
      bufferWriter.writeSlice(input.issuance.assetAmount);
      bufferWriter.writeSlice(input.issuance.tokenAmount);
    }
    bufferWriter.writeSlice(hashOutputs);
    bufferWriter.writeUInt32(this.locktime);
    bufferWriter.writeUInt32(hashType);
    return bcrypto.hash256(buffer);
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
    return bufferutils_1.reverseBuffer(this.getHash(false)).toString('hex');
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
      varuint.encodingLength(this.ins.length) +
      varuint.encodingLength(this.outs.length);
    for (const txIn of this.ins) {
      size += 40 + varSliceSize(txIn.script);
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
        varSliceSize(txOut.script);
    }
    if (_ALLOW_WITNESS && this.hasWitnesses()) {
      for (const txIn of this.ins) {
        size += varSliceSize(txIn.issuanceRangeProof);
        size += varSliceSize(txIn.inflationRangeProof);
        size += varuint.encodingLength(txIn.witness.length);
        for (const wit of txIn.witness) {
          size += varSliceSize(wit);
        }
        size += varuint.encodingLength((txIn.peginWitness || []).length);
        for (const wit of txIn.peginWitness || []) {
          size += varSliceSize(wit);
        }
      }
      for (const txOut of this.outs) {
        size += varSliceSize(txOut.surjectionProof);
        size += varSliceSize(txOut.rangeProof);
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
      let value = Transaction.ADVANCED_TRANSACTION_MARKER;
      if (hasWitnesses && !forceZeroFlag) {
        value = Transaction.ADVANCED_TRANSACTION_FLAG;
      }
      bufferWriter.writeUInt8(value);
    }
    bufferWriter.writeVarInt(this.ins.length);
    this.ins.forEach(txIn => {
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
    this.outs.forEach(txOut => {
      // if we are serializing a confidential output for producing a signature,
      // we must exclude the confidential value from the serialization and
      // use the satoshi 0 value instead, as done for typical bitcoin witness signatures.
      const val = forSignature && hasWitnesses ? Buffer.alloc(0) : txOut.value;
      bufferWriter.writeSlice(txOut.asset);
      bufferWriter.writeSlice(val);
      bufferWriter.writeSlice(txOut.nonce);
      if (forSignature && hasWitnesses) bufferWriter.writeUInt64(0);
      bufferWriter.writeVarSlice(txOut.script);
    });
    bufferWriter.writeUInt32(this.locktime);
    if (!forSignature && hasWitnesses) {
      this.ins.forEach(input => {
        bufferWriter.writeConfidentialInFields(input);
      });
      this.outs.forEach(output => {
        bufferWriter.writeConfidentialOutFields(output);
      });
    }
    // avoid slicing unless necessary
    if (initialOffset !== undefined)
      return buffer.slice(initialOffset, bufferWriter.offset);
    return buffer;
  }
}
Transaction.DEFAULT_SEQUENCE = 0xffffffff;
Transaction.SIGHASH_ALL = 0x01;
Transaction.SIGHASH_NONE = 0x02;
Transaction.SIGHASH_SINGLE = 0x03;
Transaction.SIGHASH_ANYONECANPAY = 0x80;
Transaction.ADVANCED_TRANSACTION_MARKER = 0x00;
Transaction.ADVANCED_TRANSACTION_FLAG = 0x01;
exports.Transaction = Transaction;
