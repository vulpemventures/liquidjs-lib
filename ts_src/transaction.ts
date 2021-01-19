import { BufferReader, BufferWriter, reverseBuffer } from './bufferutils';
import * as bcrypto from './crypto';
import * as bscript from './script';
import { OPS as opcodes } from './script';
import * as types from './types';

const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');

function varSliceSize(someScript: Buffer): number {
  const length = someScript.length;

  return varuint.encodingLength(length) + length;
}

const EMPTY_SCRIPT: Buffer = Buffer.allocUnsafe(0);
const EMPTY_WITNESS: Buffer[] = [];
export const ZERO: Buffer = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex',
);
const ONE: Buffer = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);
const WITNESS_SCALE_FACTOR = 4;
const OUTPOINT_ISSUANCE_FLAG = (1 << 31) >>> 0;
const OUTPOINT_PEGIN_FLAG = (1 << 30) >>> 0;
const OUTPOINT_INDEX_MASK = 0x3fffffff;
const MINUS_1 = 4294967295;
const VALUE_UINT64_MAX: Buffer = Buffer.from('ffffffffffffffff', 'hex');
const BLANK_OUTPUT = {
  script: EMPTY_SCRIPT,
  asset: ZERO,
  nonce: ZERO,
  value: VALUE_UINT64_MAX,
};

export interface Output {
  script: Buffer;
  value: Buffer;
  asset: Buffer;
  nonce: Buffer;
  rangeProof?: Buffer;
  surjectionProof?: Buffer;
}

export interface Issuance {
  assetBlindingNonce: Buffer;
  assetEntropy: Buffer;
  assetAmount: Buffer;
  tokenAmount: Buffer;
}

export interface Input {
  hash: Buffer;
  index: number;
  script: Buffer;
  sequence: number;
  witness: Buffer[];
  isPegin?: boolean;
  issuance?: Issuance;
  peginWitness?: Buffer[];
  issuanceRangeProof?: Buffer;
  inflationRangeProof?: Buffer;
}

export class Transaction {
  static readonly DEFAULT_SEQUENCE = 0xffffffff;
  static readonly SIGHASH_ALL = 0x01;
  static readonly SIGHASH_NONE = 0x02;
  static readonly SIGHASH_SINGLE = 0x03;
  static readonly SIGHASH_ANYONECANPAY = 0x80;
  static readonly ADVANCED_TRANSACTION_MARKER = 0x00;
  static readonly ADVANCED_TRANSACTION_FLAG = 0x01;

  static fromBuffer(buffer: Buffer, _NO_STRICT?: boolean): Transaction {
    const bufferReader = new BufferReader(buffer);
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

      let inIssuance: Issuance | undefined;
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

  static fromHex(hex: string): Transaction {
    return Transaction.fromBuffer(Buffer.from(hex, 'hex'), false);
  }

  static isCoinbaseHash(buffer: Buffer): boolean {
    typeforce(types.Hash256bit, buffer);
    for (let i = 0; i < 32; ++i) {
      if (buffer[i] !== 0) return false;
    }
    return true;
  }

  version: number = 1;
  locktime: number = 0;
  flag: number = 0;
  ins: Input[] = [];
  outs: Output[] = [];

  isCoinbase(): boolean {
    return (
      this.ins.length === 1 && Transaction.isCoinbaseHash(this.ins[0].hash)
    );
  }

  // A quick and reliable way to validate that all the buffers are of correct type and length
  validateIssuance(
    assetBlindingNonce: Buffer,
    assetEntropy: Buffer,
    assetAmount: Buffer,
    tokenAmount: Buffer,
  ): boolean {
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

  addInput(
    hash: Buffer,
    index: number,
    sequence?: number,
    scriptSig?: Buffer,
    issuance?: Issuance,
  ): number {
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

  addOutput(
    scriptPubKey: Buffer,
    value: Buffer,
    asset: Buffer,
    nonce: Buffer,
    rangeProof?: Buffer,
    surjectionProof?: Buffer,
  ): number {
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

  hasWitnesses(): boolean {
    return (
      this.flag === 1 ||
      this.ins.some(x => {
        return x.witness.length !== 0;
      }) ||
      this.outs.some(x => {
        return x.rangeProof!.length !== 0 && x.surjectionProof!.length !== 0;
      })
    );
  }

  weight(): number {
    const base = this.__byteLength(false);
    const total = this.__byteLength(true);
    return base * (WITNESS_SCALE_FACTOR - 1) + total;
  }

  virtualSize(): number {
    const vsize =
      (this.weight() + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    return Math.floor(vsize);
  }

  byteLength(_ALLOW_WITNESS?: boolean): number {
    return this.__byteLength(_ALLOW_WITNESS || true);
  }

  clone(): Transaction {
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
  hashForSignature(
    inIndex: number,
    prevOutScript: Buffer,
    hashType: number,
  ): Buffer {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, /* types.UInt8 */ types.Number),
      arguments,
    );

    // https://github.com/bitcoin/bitcoin/blob/master/src/test/sighash_tests.cpp#L29
    if (inIndex >= this.ins.length) return ONE;

    // ignore OP_CODESEPARATOR
    const ourScript = bscript.compile(
      bscript.decompile(prevOutScript)!.filter(x => {
        return x !== opcodes.OP_CODESEPARATOR;
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
        (txTmp.outs as any)[i] = BLANK_OUTPUT;
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
    const buffer: Buffer = Buffer.allocUnsafe(
      txTmp.__byteLength(false, true) + 4,
    );
    buffer.writeInt32LE(hashType, buffer.length - 4);
    txTmp.__toBuffer(buffer, 0, false, true, true);

    return bcrypto.hash256(buffer);
  }

  hashForWitnessV0(
    inIndex: number,
    prevOutScript: Buffer,
    value: Buffer,
    hashType: number,
  ): Buffer {
    typeforce(
      types.tuple(types.UInt32, types.Buffer, types.Buffer, types.UInt32),
      arguments,
    );

    function writeInputs(ins: Input[]): Buffer {
      const tBuffer: Buffer = Buffer.allocUnsafe(36 * ins.length);
      const tBufferWriter: BufferWriter = new BufferWriter(tBuffer, 0);

      ins.forEach((txIn: Input) => {
        tBufferWriter.writeSlice(txIn.hash);
        tBufferWriter.writeUInt32(txIn.index);
      });

      return bcrypto.hash256(tBuffer);
    }

    function writeSequences(ins: Input[]): Buffer {
      const tBuffer: Buffer = Buffer.allocUnsafe(4 * ins.length);
      const tBufferWriter: BufferWriter = new BufferWriter(tBuffer, 0);

      ins.forEach((txIn: Input) => {
        tBufferWriter.writeUInt32(txIn.sequence);
      });

      return bcrypto.hash256(tBuffer);
    }

    function writeIssuances(ins: Input[]): Buffer {
      const issuanceSize = ins.reduce(
        (sum, txIn) =>
          !types.Null(txIn.issuance)
            ? sum +
              txIn.issuance!.assetBlindingNonce.length +
              txIn.issuance!.assetEntropy.length +
              txIn.issuance!.assetAmount.length +
              txIn.issuance!.tokenAmount.length
            : sum + 1, // we'll use the empty 00 Buffer if issuance is not set
        0,
      );
      const tBuffer: Buffer = Buffer.allocUnsafe(issuanceSize);
      const tBufferWriter: BufferWriter = new BufferWriter(tBuffer, 0);

      ins.forEach((txIn: Input) => {
        if (!types.Null(txIn.issuance)) {
          tBufferWriter.writeSlice(txIn.issuance!.assetBlindingNonce);
          tBufferWriter.writeSlice(txIn.issuance!.assetEntropy);
          tBufferWriter.writeSlice(txIn.issuance!.assetAmount);
          tBufferWriter.writeSlice(txIn.issuance!.tokenAmount);
        } else {
          tBufferWriter.writeSlice(Buffer.from('00', 'hex'));
        }
      });
      return bcrypto.hash256(tBuffer);
    }

    function writeOutputs(outs: Output[]): Buffer {
      const outsSize = outs.reduce(
        (sum: number, txOut: Output) =>
          sum +
          txOut.asset.length +
          txOut.value.length +
          txOut.nonce.length +
          varSliceSize(txOut.script),
        0,
      );

      const tBuffer: Buffer = Buffer.allocUnsafe(outsSize);
      const tBufferWriter: BufferWriter = new BufferWriter(tBuffer, 0);

      outs.forEach((txOut: Output) => {
        tBufferWriter.writeSlice(txOut.asset);
        tBufferWriter.writeSlice(txOut.value);
        tBufferWriter.writeSlice(txOut.nonce);
        tBufferWriter.writeVarSlice(txOut.script);
      });
      return bcrypto.hash256(tBuffer);
    }

    let hashOutputs = ZERO;
    let hashPrevouts = ZERO;
    let hashSequences = ZERO;
    let hashIssuances = ZERO;

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
      hashIssuances = writeIssuances(this.ins);
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
      4 + // locktime
      4; // hashType

    const buffer: Buffer = Buffer.allocUnsafe(bufferSize);
    const bufferWriter: BufferWriter = new BufferWriter(buffer, 0);

    bufferWriter.writeUInt32(this.version);
    bufferWriter.writeSlice(hashPrevouts);
    bufferWriter.writeSlice(hashSequences);
    bufferWriter.writeSlice(hashIssuances);
    bufferWriter.writeSlice(input.hash);
    bufferWriter.writeUInt32(input.index);
    bufferWriter.writeVarSlice(prevOutScript);
    bufferWriter.writeSlice(value);
    bufferWriter.writeUInt32(input.sequence);
    if (!types.Null(input.issuance)) {
      bufferWriter.writeSlice(input.issuance!.assetBlindingNonce);
      bufferWriter.writeSlice(input.issuance!.assetEntropy);
      bufferWriter.writeSlice(input.issuance!.assetAmount);
      bufferWriter.writeSlice(input.issuance!.tokenAmount);
    }
    bufferWriter.writeSlice(hashOutputs);
    bufferWriter.writeUInt32(this.locktime);
    bufferWriter.writeUInt32(hashType);

    return bcrypto.hash256(buffer);
  }

  getHash(forWitness?: boolean): Buffer {
    // wtxid for coinbase is always 32 bytes of 0x00
    if (forWitness && this.isCoinbase()) return Buffer.alloc(32, 0);
    return bcrypto.hash256(
      this.__toBuffer(undefined, undefined, forWitness, true),
    );
  }

  getId(): string {
    // transaction hash's are displayed in reverse order
    return reverseBuffer(this.getHash(false)).toString('hex');
  }

  toBuffer(buffer?: Buffer, initialOffset?: number): Buffer {
    return this.__toBuffer(buffer, initialOffset, true);
  }

  toHex(): string {
    return this.toBuffer(undefined, undefined).toString('hex');
  }

  setInputScript(index: number, scriptSig: Buffer): void {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);

    this.ins[index].script = scriptSig;
  }

  setWitness(index: number, witness: Buffer[]): void {
    typeforce(types.tuple(types.Number, [types.Buffer]), arguments);

    this.ins[index].witness = witness;
  }

  setPeginWitness(index: number, peginWitness: Buffer[]): void {
    typeforce(types.tuple(types.Number, [types.Buffer]), arguments);

    this.ins[index].peginWitness = peginWitness;
  }

  setInputIssuanceRangeProof(index: number, issuanceRangeProof: Buffer): void {
    typeforce(types.tuple(types.Buffer), arguments);
    if (this.ins[index].issuance === undefined)
      throw new Error('Issuance not set for input #' + index);
    this.ins[index].issuanceRangeProof = issuanceRangeProof;
  }

  setInputInflationRangeProof(
    index: number,
    inflationRangeProof: Buffer,
  ): void {
    typeforce(types.tuple(types.Buffer), arguments);
    if (this.ins[index].issuance === undefined)
      throw new Error('Issuance not set for input #' + index);
    this.ins[index].inflationRangeProof = inflationRangeProof;
  }

  setOutputNonce(index: number, nonce: Buffer): void {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);

    this.outs[index].nonce = nonce;
  }

  setOutputRangeProof(index: number, proof: Buffer): void {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);

    this.outs[index].rangeProof = proof;
  }

  setOutputSurjectionProof(index: number, proof: Buffer): void {
    typeforce(types.tuple(types.Number, types.Buffer), arguments);

    this.outs[index].surjectionProof = proof;
  }

  private __byteLength(
    _ALLOW_WITNESS: boolean,
    forSignature?: boolean,
  ): number {
    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    return (
      8 +
      (forSignature ? 0 : 1) +
      varuint.encodingLength(this.ins.length) +
      varuint.encodingLength(this.outs.length) +
      this.ins.reduce((sum, input) => {
        return (
          sum +
          40 +
          varSliceSize(input.script) +
          (input.issuance
            ? 64 +
              input.issuance.assetAmount.length +
              input.issuance.tokenAmount.length
            : 0)
        );
      }, 0) +
      this.outs.reduce((sum, output) => {
        return (
          sum +
          output.asset.length +
          output.value.length +
          output.nonce.length +
          varSliceSize(output.script)
        );
      }, 0) +
      (hasWitnesses
        ? this.ins.reduce((sum, input) => {
            return (
              sum +
              varSliceSize(input.issuanceRangeProof!) +
              varSliceSize(input.inflationRangeProof!) +
              varuint.encodingLength(input.witness.length) +
              input.witness.reduce((scriptSum, scriptWit) => {
                return scriptSum + varSliceSize(scriptWit);
              }, 0) +
              varuint.encodingLength(input.peginWitness!.length) +
              input.peginWitness!.reduce((peginSum, peginWit) => {
                return peginSum + varSliceSize(peginWit);
              }, 0)
            );
          }, 0)
        : 0) +
      (hasWitnesses
        ? this.outs.reduce((sum, output) => {
            return (
              sum +
              varSliceSize(output.surjectionProof!) +
              varSliceSize(output.rangeProof!)
            );
          }, 0)
        : 0)
    );
  }

  private __toBuffer(
    buffer?: Buffer,
    initialOffset?: number,
    _ALLOW_WITNESS?: boolean,
    forceZeroFlag?: boolean,
    forSignature?: boolean,
  ): Buffer {
    if (!buffer)
      buffer = Buffer.allocUnsafe(
        this.__byteLength(_ALLOW_WITNESS!, forSignature),
      ) as Buffer;

    const bufferWriter = new BufferWriter(buffer, initialOffset || 0);

    bufferWriter.writeInt32(this.version);

    const hasWitnesses = _ALLOW_WITNESS && this.hasWitnesses();
    if (!forSignature) {
      if (
        hasWitnesses &&
        (forceZeroFlag === false || forceZeroFlag === undefined)
      )
        bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_FLAG);
      else bufferWriter.writeUInt8(Transaction.ADVANCED_TRANSACTION_MARKER);
    }

    bufferWriter.writeVarInt(this.ins.length);

    this.ins.forEach(txIn => {
      bufferWriter.writeSlice(txIn.hash);
      let prevIndex = txIn.index;
      if (forceZeroFlag === false || forceZeroFlag === undefined) {
        if (txIn.issuance) {
          prevIndex = (prevIndex | OUTPOINT_ISSUANCE_FLAG) >>> 0;
        }
        if (txIn.isPegin) {
          prevIndex = (prevIndex | OUTPOINT_PEGIN_FLAG) >>> 0;
        }
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
      this.ins.forEach((input: Input) => {
        bufferWriter.writeConfidentialInFields(input);
      });
      this.outs.forEach((output: Output) => {
        bufferWriter.writeConfidentialOutFields(output);
      });
    }

    // avoid slicing unless necessary
    if (initialOffset !== undefined)
      return buffer.slice(initialOffset, bufferWriter.offset);
    return buffer;
  }
}
