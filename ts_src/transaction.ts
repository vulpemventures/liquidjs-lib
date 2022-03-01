import {
  BufferReader,
  BufferWriter,
  reverseBuffer,
  varuint,
} from './bufferutils';
import * as bcrypto from './crypto';
import { Issuance } from './issuance';
import * as bscript from './script';
import { OPS as opcodes } from './script';
import * as types from './types';
const { typeforce } = types;

function varSliceSize(someScript: Buffer): number {
  const length = someScript.length;
  return varuint.encodingLength(length) + length;
}

const EMPTY_BUFFER: Buffer = Buffer.allocUnsafe(0);
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
  script: EMPTY_BUFFER,
  asset: ZERO,
  nonce: ZERO,
  valueBuffer: VALUE_UINT64_MAX,
};

export interface Output {
  script: Buffer;
  value: Buffer;
  asset: Buffer;
  nonce: Buffer;
  rangeProof?: Buffer;
  surjectionProof?: Buffer;
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

export type GenesisBlockHash = Buffer;
const strToGenesisHash = (str: string): GenesisBlockHash =>
  Buffer.from(str, 'hex').reverse();
export const RegtestGenesisBlockHash = strToGenesisHash(
  '00902a6b70c2ca83b5d9c815d96a0e2f4202179316970d14ea1847dae5b1ca21',
);
export const TestnetGenesisBlockHash = strToGenesisHash(
  'a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1',
);
export const LiquidGenesisBlockHash = strToGenesisHash(
  '1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003',
);

export class Transaction {
  static readonly DEFAULT_SEQUENCE = 0xffffffff;
  static readonly SIGHASH_DEFAULT = 0x00;
  static readonly SIGHASH_ALL = 0x01;
  static readonly SIGHASH_NONE = 0x02;
  static readonly SIGHASH_SINGLE = 0x03;
  static readonly SIGHASH_ANYONECANPAY = 0x80;
  static readonly SIGHASH_OUTPUT_MASK = 0x03;
  static readonly SIGHASH_INPUT_MASK = 0x80;
  static readonly ADVANCED_TRANSACTION_FLAG = 0x01;

  static fromBuffer(buffer: Buffer, _NO_STRICT?: boolean): Transaction {
    const bufferReader = new BufferReader(buffer);

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
        script: scriptSig || EMPTY_BUFFER,
        witness: EMPTY_WITNESS,
        peginWitness: EMPTY_WITNESS,
        issuanceRangeProof: EMPTY_BUFFER,
        inflationRangeProof: EMPTY_BUFFER,
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
        input.script = EMPTY_BUFFER;
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

  // differs from bitcoin core
  // https://github.com/ElementsProject/elements/blob/84b3f7b0045b50a585d60e56e77e8914b6cf6040/doc/taproot-sighash.mediawiki
  hashForWitnessV1(
    inIndex: number,
    prevOutScripts: Buffer[],
    prevoutAssetsValues: { asset: Buffer; value: Buffer }[],
    hashType: number,
    genesisBlockHash: GenesisBlockHash,
    leafHash?: Buffer,
    annex?: Buffer,
  ): Buffer {
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
    // elements
    const hashOutpointsFlags = getOutpointFlagsSHA256(this.ins);
    const hashIssuanceRangeproofs = getIssuanceRangeProofsSHA256(this.ins);
    const hashOutputWitnesses = getOutputWitnessesSHA256(this.outs);
    const hashSpentAssetsAmounts = getSpentAssetsAmountsSHA256(
      prevoutAssetsValues,
    );

    if (!isAnyoneCanPay) {
      // Inputs
      // outpoints sha256 (hashPrevouts)
      let bufferWriter = BufferWriter.withCapacity(this.ins.length * (32 + 4));
      for (const i of this.ins) {
        bufferWriter.writeSlice(i.hash);
        bufferWriter.writeUInt32(i.index);
      }
      hashPrevouts = bcrypto.sha256(bufferWriter.end());

      // scripts sha256 (hashScriptPubKeys)
      bufferWriter = BufferWriter.withCapacity(
        prevOutScripts.map(varSliceSize).reduce((a, b) => a + b),
      );
      prevOutScripts.forEach(prevOutScript =>
        bufferWriter.writeVarSlice(prevOutScript),
      );
      hashScriptPubKeys = bcrypto.sha256(bufferWriter.end());

      // Sequences
      bufferWriter = BufferWriter.withCapacity(4 * this.ins.length);
      this.ins.forEach(txIn => bufferWriter.writeUInt32(txIn.sequence));
      hashSequences = bcrypto.sha256(bufferWriter.end());

      // Issuances
      const sizeOfIssuances = this.ins.reduce(
        (sum, txIn) => (txIn.issuance ? sum + getIssuanceSize(txIn) : sum + 1),
        0,
      );
      const size = sizeOfIssuances === 0 ? this.ins.length : sizeOfIssuances;
      const writer = BufferWriter.withCapacity(size);
      this.ins.forEach((txIn: Input) => {
        if (txIn.issuance) {
          writer.writeSlice(txIn.issuance!.assetBlindingNonce);
          writer.writeSlice(txIn.issuance!.assetEntropy);
          writer.writeSlice(txIn.issuance!.assetAmount);
          writer.writeSlice(txIn.issuance!.tokenAmount);
        } else {
          writer.writeSlice(Buffer.of(0x00));
        }
      });

      hashIssuances = bcrypto.sha256(writer.end());
    }

    if (!(isNone || isSingle)) {
      const txOutsSize = this.outs.reduce(
        (sum, output) =>
          sum +
          output.asset.length +
          output.value.length +
          output.nonce.length +
          varSliceSize(output.script),
        0,
      );
      const bufferWriter = BufferWriter.withCapacity(txOutsSize);

      this.outs.forEach(out => {
        bufferWriter.writeSlice(out.asset);
        bufferWriter.writeSlice(out.value);
        bufferWriter.writeSlice(out.nonce);
        bufferWriter.writeVarSlice(out.script);
      });

      hashOutputs = bcrypto.sha256(bufferWriter.end());
    } else if (isSingle && inIndex < this.outs.length) {
      const output = this.outs[inIndex];

      const bufferWriter = BufferWriter.withCapacity(
        output.asset.length +
          output.value.length +
          output.nonce.length +
          varSliceSize(output.script),
      );
      bufferWriter.writeSlice(output.asset);
      bufferWriter.writeSlice(output.value);
      bufferWriter.writeSlice(output.nonce);
      bufferWriter.writeVarSlice(output.script);
      hashOutputs = bcrypto.sha256(bufferWriter.end());
    }

    const spendType = (leafHash ? 2 : 0) + (annex ? 1 : 0);

    // Length calculation from:
    // https://github.com/ElementsProject/elements/blob/84b3f7b0045b50a585d60e56e77e8914b6cf6040/doc/taproot-sighash.mediawiki
    const inputPartSize = isAnyoneCanPay
      ? 1 +
        32 +
        4 +
        32 +
        32 +
        varSliceSize(prevOutScripts[inIndex]) +
        4 +
        (this.ins[inIndex].issuance ? 32 * 4 + 32 : 1)
      : 4;
    const fullMsgSize = 32 * 2 + 1 + 4 + 4 + 1 + inputPartSize;
    const sigMsgSize =
      fullMsgSize +
      (!isAnyoneCanPay ? 7 * 32 : 0) +
      (!(isNone || isSingle) ? 32 + 32 : 0) +
      (annex ? 32 : 0) +
      (isSingle ? 32 : 0) +
      (leafHash ? 37 : 0);

    const sigMsgWriter = BufferWriter.withCapacity(sigMsgSize);

    // this is "blockchain rationale", only used in elements
    // it prevents signatures to be reused accront different Elements instance
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
      sigMsgWriter.writeSlice(hashIssuanceRangeproofs);
    }
    if (!(isNone || isSingle)) {
      sigMsgWriter.writeSlice(hashOutputs);
      sigMsgWriter.writeSlice(hashOutputWitnesses);
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
        sigMsgWriter.writeSlice(input.issuance!.assetBlindingNonce);
        sigMsgWriter.writeSlice(input.issuance!.assetEntropy);
        sigMsgWriter.writeSlice(input.issuance!.assetAmount);
        sigMsgWriter.writeSlice(input.issuance!.tokenAmount);

        const bufferWriter = BufferWriter.withCapacity(
          varSliceSize(input.issuanceRangeProof!) +
            varSliceSize(input.inflationRangeProof!),
        );
        bufferWriter.writeVarSlice(input.issuanceRangeProof);
        bufferWriter.writeVarSlice(input.inflationRangeProof);

        const hashIssuance = bcrypto.sha256(bufferWriter.end());
        sigMsgWriter.writeSlice(hashIssuance);
      } else {
        sigMsgWriter.writeSlice(Buffer.of(0x00));
      }
    } else {
      sigMsgWriter.writeUInt32(inIndex);
    }
    if (annex) {
      const bufferWriter = BufferWriter.withCapacity(varSliceSize(annex));
      bufferWriter.writeVarSlice(annex);
      sigMsgWriter.writeSlice(bcrypto.sha256(bufferWriter.end()));
    }
    // Output
    if (isSingle) {
      sigMsgWriter.writeSlice(hashOutputs);
    }
    // BIP342 extension
    if (leafHash) {
      sigMsgWriter.writeSlice(leafHash);
      sigMsgWriter.writeUInt8(0);
      sigMsgWriter.writeUInt32(0xffffffff);
    }

    console.log('length', sigMsgWriter.buffer.length);

    return bcrypto.taggedHash('TapSighash/elements', sigMsgWriter.end());
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

    let hashOutputs = ZERO;
    let hashPrevouts = ZERO;
    let hashSequence = ZERO;
    let hashIssuances = ZERO;

    // Inputs
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      const writer = BufferWriter.withCapacity((32 + 4) * this.ins.length);
      this.ins.forEach(txIn => {
        writer.writeSlice(txIn.hash);
        writer.writeUInt32(txIn.index);
      });

      hashPrevouts = bcrypto.hash256(writer.end());
    }

    // Sequences
    if (
      !(hashType & Transaction.SIGHASH_ANYONECANPAY) &&
      (hashType & 0x1f) !== Transaction.SIGHASH_SINGLE &&
      (hashType & 0x1f) !== Transaction.SIGHASH_NONE
    ) {
      const writer = BufferWriter.withCapacity(4 * this.ins.length);
      this.ins.forEach(txIn => {
        writer.writeUInt32(txIn.sequence);
      });

      hashSequence = bcrypto.hash256(writer.end());
    }

    // Issuances
    if (!(hashType & Transaction.SIGHASH_ANYONECANPAY)) {
      const sizeOfIssuances = this.ins.reduce(
        (sum, txIn) => (txIn.issuance ? sum + getIssuanceSize(txIn) : sum + 1),
        0,
      );
      const size = sizeOfIssuances === 0 ? this.ins.length : sizeOfIssuances;
      const writer = BufferWriter.withCapacity(size);
      this.ins.forEach((txIn: Input) => {
        if (txIn.issuance) {
          writer.writeSlice(txIn.issuance!.assetBlindingNonce);
          writer.writeSlice(txIn.issuance!.assetEntropy);
          writer.writeSlice(txIn.issuance!.assetAmount);
          writer.writeSlice(txIn.issuance!.tokenAmount);
        } else {
          writer.writeSlice(Buffer.of(0x00));
        }
      });

      hashIssuances = bcrypto.hash256(writer.end());
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
          varSliceSize(output.script),
        0,
      );
      const writer = BufferWriter.withCapacity(txOutsSize);
      this.outs.forEach(out => {
        writer.writeSlice(out.asset);
        writer.writeSlice(out.value);
        writer.writeSlice(out.nonce);
        writer.writeVarSlice(out.script);
      });
      hashOutputs = bcrypto.hash256(writer.end());
    } else if (
      (hashType & 0x1f) === Transaction.SIGHASH_SINGLE &&
      inIndex < this.outs.length
    ) {
      const output = this.outs[inIndex];
      const size =
        output.asset.length +
        output.value.length +
        output.nonce.length +
        varSliceSize(output.script);
      const writer = BufferWriter.withCapacity(size);
      writer.writeSlice(output.asset);
      writer.writeSlice(output.value);
      writer.writeSlice(output.nonce);
      writer.writeVarSlice(output.script);
      hashOutputs = bcrypto.hash256(writer.end());
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
      varSliceSize(prevOutScript) +
      value.length +
      4 + // input.sequence
      hashOutputs.length +
      getIssuanceSize(input) +
      4 + // locktime
      4; // hashType

    const buffer: Buffer = Buffer.allocUnsafe(bufferSize);
    const writer: BufferWriter = new BufferWriter(buffer, 0);

    writer.writeUInt32(this.version);
    writer.writeSlice(hashPrevouts);
    writer.writeSlice(hashSequence);
    writer.writeSlice(hashIssuances);
    writer.writeSlice(input.hash);
    writer.writeUInt32(input.index);
    writer.writeVarSlice(prevOutScript);
    writer.writeSlice(value);
    writer.writeUInt32(input.sequence);
    if (hasIssuance) {
      writer.writeSlice(input.issuance!.assetBlindingNonce);
      writer.writeSlice(input.issuance!.assetEntropy);
      writer.writeSlice(input.issuance!.assetAmount);
      writer.writeSlice(input.issuance!.tokenAmount);
    }
    writer.writeSlice(hashOutputs);
    writer.writeUInt32(this.locktime);
    writer.writeUInt32(hashType);
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
    return this.__toBuffer(buffer, initialOffset, true, false);
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
        size += varSliceSize(txIn.issuanceRangeProof!);
        size += varSliceSize(txIn.inflationRangeProof!);

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
        size += varSliceSize(txOut.surjectionProof!);
        size += varSliceSize(txOut.rangeProof!);
      }
    }

    return size;
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
      let flags = 0;
      if (hasWitnesses && !forceZeroFlag) {
        flags |= Transaction.ADVANCED_TRANSACTION_FLAG;
      }

      bufferWriter.writeUInt8(flags);
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
      const val = forSignature && hasWitnesses ? Buffer.alloc(1) : txOut.value;
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

function getOutputWitnessesSHA256(outs: Output[]): Buffer {
  const outProofsSize = (o: Output) =>
    varSliceSize(o.rangeProof || Buffer.alloc(0)) +
    varSliceSize(o.surjectionProof || Buffer.alloc(0));
  const size = outs.reduce((sum, o) => sum + outProofsSize(o), 0);
  const bufferWriter = BufferWriter.withCapacity(size);
  for (const out of outs) {
    bufferWriter.writeVarSlice(out.rangeProof);
    bufferWriter.writeVarSlice(out.surjectionProof);
  }
  return bcrypto.sha256(bufferWriter.end());
}

function getIssuanceRangeProofsSHA256(ins: Input[]): Buffer {
  const inProofsSize = (i: Input) =>
    varSliceSize(i.issuanceRangeProof || Buffer.alloc(1)) +
    varSliceSize(i.inflationRangeProof || Buffer.alloc(1));
  const size = ins.reduce((sum, i) => sum + inProofsSize(i), 0);
  const bufferWriter = BufferWriter.withCapacity(size);

  for (const input of ins) {
    bufferWriter.writeVarSlice(input.issuanceRangeProof);
    bufferWriter.writeVarSlice(input.inflationRangeProof);
  }

  return bcrypto.sha256(bufferWriter.end());
}

function getSpentAssetsAmountsSHA256(
  outs: { asset: Buffer; value: Buffer }[],
): Buffer {
  const size = outs.reduce(
    (sum, o) => sum + o.asset.length + o.value.length,
    0,
  );
  const bufferWriter = BufferWriter.withCapacity(size);
  for (const out of outs) {
    bufferWriter.writeSlice(out.asset);
    bufferWriter.writeSlice(out.value);
  }

  return bcrypto.sha256(bufferWriter.end());
}

function getInputFlag(input: Input): number {
  const hasIssuance = input.issuance !== undefined;
  return (
    (hasIssuance ? OUTPOINT_ISSUANCE_FLAG >>> 24 : 0) |
    (input.isPegin ? OUTPOINT_PEGIN_FLAG >>> 24 : 0)
  );
}

function getOutpointFlagsSHA256(ins: Input[]): Buffer {
  const bufferWriter = BufferWriter.withCapacity(ins.length);

  for (const input of ins) {
    bufferWriter.writeUInt8(getInputFlag(input));
  }

  return bcrypto.sha256(bufferWriter.end());
}

function getIssuanceSize(txIn: Input): number {
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
