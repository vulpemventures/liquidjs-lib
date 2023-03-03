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
exports.Block = void 0;
const bufferutils_1 = require('./bufferutils');
const bcrypto = __importStar(require('./crypto'));
const transaction_1 = require('./transaction');
const types = __importStar(require('./types'));
const fastMerkleRoot = require('merkle-lib/fastRoot');
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');
const errorMerkleNoTxes = new TypeError(
  'Cannot compute merkle root for zero transactions',
);
const errorWitnessNotSegwit = new TypeError(
  'Cannot compute witness commit for non-segwit block',
);
class Block {
  constructor() {
    this.version = 1;
    this.prevHash = undefined;
    this.merkleRoot = undefined;
    this.timestamp = 0;
    this.witnessCommit = undefined;
    this.bits = 0;
    this.nonce = 0;
    this.transactions = undefined;
    this.blockHeight = 0;
    // DYNAMIC FEDERATION PARAMS
    // current compact params
    this.currentSignBlockScript = undefined;
    this.currentSignBlockWitnessLimit = 0;
    this.currentElidedRoot = undefined;
    // current full param
    this.currentSignBlockScriptFull = undefined;
    this.currentSignBlockWitnessLimitFull = 0;
    this.currentFedpegProgram = undefined;
    this.currentFedpegScript = undefined;
    this.currentExtensionSpace = undefined;
    // proposed compact params
    this.proposedSignBlockScript = undefined;
    this.proposedSignBlockWitnessLimit = 0;
    this.proposedElidedRoot = undefined;
    // proposed full param
    this.proposedSignBlockScriptFull = undefined;
    this.proposedSignBlockWitnessLimitFull = 0;
    this.proposedFedpegProgram = undefined;
    this.proposedFedpegScript = undefined;
    this.proposedExtensionSpace = undefined;
    // SignBlockWitness
    this.signBlockWitness = undefined;
    this.challenge = undefined;
    this.solution = undefined;
  }
  static fromBuffer(buffer) {
    if (buffer.length < 80) throw new Error('Buffer too small (< 80 bytes)');
    let offset = 0;
    const readSlice = (n) => {
      offset += n;
      return buffer.slice(offset - n, offset);
    };
    const readUInt32 = () => {
      const i = buffer.readUInt32LE(offset);
      offset += 4;
      return i;
    };
    const readUInt8 = () => {
      const i = buffer.readUInt8(offset);
      offset += 1;
      return i;
    };
    const readVarInt = () => {
      const vi = varuint.decode(buffer, offset);
      offset += varuint.decode.bytes;
      return vi;
    };
    const block = new Block();
    block.version = readUInt32();
    const isDyna = block.version >>> 31 === 1;
    if (isDyna) {
      block.version &= 2147483647;
    }
    block.prevHash = readSlice(32);
    block.merkleRoot = readSlice(32);
    block.timestamp = readUInt32();
    block.blockHeight = readUInt32();
    if (isDyna) {
      // current params
      let serializeType = readUInt8();
      switch (serializeType) {
        case 0: // null
          break;
        case 1: // compact params
          const signBlockScriptLengthCompact = readVarInt();
          const signBlockScriptCompact = readSlice(
            signBlockScriptLengthCompact,
          );
          const signBlockWitnessLimitCompact = readUInt32();
          const elidedRootCompact = readSlice(32);
          block.currentSignBlockScript = signBlockScriptCompact;
          block.currentSignBlockWitnessLimit = signBlockWitnessLimitCompact;
          block.currentElidedRoot = elidedRootCompact;
          break;
        case 2: // full params
          const signBlockScriptLengthFull = readVarInt();
          const signBlockScriptFull = readSlice(signBlockScriptLengthFull);
          const signBlockWitnessLimitFull = readUInt32();
          const fedpegProgramLength = readVarInt();
          const fedpegProgram = readSlice(fedpegProgramLength);
          const fedpegScriptLength = readVarInt();
          const fedpegScript = readSlice(fedpegScriptLength);
          const extensionSpaceLength = readVarInt();
          const extensionSpace = [];
          for (let i = 0; i < extensionSpaceLength; i++) {
            const tmpLen = readVarInt();
            const tmp = readSlice(tmpLen);
            extensionSpace.unshift(tmp);
          }
          block.currentSignBlockScriptFull = signBlockScriptFull;
          block.currentSignBlockWitnessLimitFull = signBlockWitnessLimitFull;
          block.currentFedpegProgram = fedpegProgram;
          block.currentFedpegScript = fedpegScript;
          block.currentExtensionSpace = extensionSpace;
          break;
        default:
          throw new Error('bad serialize type for dynafed parameters');
      }
      // proposed params
      serializeType = readUInt8();
      switch (serializeType) {
        case 0: // null
          break;
        case 1: // compact params
          const signBlockScriptLengthCompact = readVarInt();
          const signBlockScriptCompact = readSlice(
            signBlockScriptLengthCompact,
          );
          const signBlockWitnessLimitCompact = readUInt8();
          const elidedRootCompact = readSlice(32);
          block.proposedSignBlockScript = signBlockScriptCompact;
          block.proposedSignBlockWitnessLimit = signBlockWitnessLimitCompact;
          block.proposedElidedRoot = elidedRootCompact;
          break;
        case 2: // full params
          const signBlockScriptLengthFull = readVarInt();
          const signBlockScriptFull = readSlice(signBlockScriptLengthFull);
          const signBlockWitnessLimitFull = readUInt32();
          const fedpegProgramLength = readVarInt();
          const fedpegProgram = readSlice(fedpegProgramLength);
          const fedpegScriptLength = readVarInt();
          const fedpegScript = readSlice(fedpegScriptLength);
          const extensionSpaceLength = readVarInt();
          const extensionSpace = [];
          for (let i = 0; i < extensionSpaceLength; i++) {
            const tmpLen = readVarInt();
            const tmp = readSlice(tmpLen);
            extensionSpace.unshift(tmp);
          }
          block.proposedSignBlockScriptFull = signBlockScriptFull;
          block.proposedSignBlockWitnessLimitFull = signBlockWitnessLimitFull;
          block.proposedFedpegProgram = fedpegProgram;
          block.proposedFedpegScript = fedpegScript;
          block.proposedExtensionSpace = extensionSpace;
          break;
        default:
          throw new Error('bad serialize type for dynafed parameters');
      }
      const signBlockWitnessLength = readVarInt();
      const signBlockWitness = [];
      for (let i = 0; i < signBlockWitnessLength; i++) {
        const tmpLen = readVarInt();
        const tmp = readSlice(tmpLen);
        signBlockWitness.unshift(tmp);
      }
      block.signBlockWitness = signBlockWitness;
    } else {
      const challengeLength = readVarInt();
      const challenge = readSlice(challengeLength);
      const solutionLength = readVarInt();
      const solution = readSlice(solutionLength);
      block.challenge = challenge;
      block.solution = solution;
    }
    if (buffer.length === 80) return block;
    const readTransaction = () => {
      const tx = transaction_1.Transaction.fromBuffer(
        buffer.slice(offset),
        true,
      );
      offset += tx.byteLength();
      return tx;
    };
    const nTransactions = readVarInt();
    block.transactions = [];
    for (let i = 0; i < nTransactions; ++i) {
      const tx = readTransaction();
      block.transactions.push(tx);
    }
    const witnessCommit = block.getWitnessCommit();
    // This Block contains a witness commit
    if (witnessCommit) block.witnessCommit = witnessCommit;
    return block;
  }
  static fromHex(hex) {
    return Block.fromBuffer(Buffer.from(hex, 'hex'));
  }
  static calculateTarget(bits) {
    const exponent = ((bits & 0xff000000) >> 24) - 3;
    const mantissa = bits & 0x007fffff;
    const target = Buffer.alloc(32, 0);
    target.writeUIntBE(mantissa, 29 - exponent, 3);
    return target;
  }
  static calculateMerkleRoot(transactions, forWitness) {
    typeforce([{ getHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;
    if (forWitness && !txesHaveWitnessCommit(transactions))
      throw errorWitnessNotSegwit;
    const hashes = transactions.map((transaction) =>
      transaction.getHash(forWitness),
    );
    const rootHash = fastMerkleRoot(hashes, bcrypto.hash256);
    return forWitness
      ? bcrypto.hash256(
          Buffer.concat([rootHash, transactions[0].ins[0].witness[0]]),
        )
      : rootHash;
  }
  getWitnessCommit() {
    if (!txesHaveWitnessCommit(this.transactions)) return null;
    // The merkle root for the witness data is in an OP_RETURN output.
    // There is no rule for the index of the output, so use filter to find it.
    // The root is prepended with 0xaa21a9ed so check for 0x6a24aa21a9ed
    // If multiple commits are found, the output with highest index is assumed.
    const witnessCommits = this.transactions[0].outs
      .filter((out) =>
        out.script.slice(0, 6).equals(Buffer.from('6a24aa21a9ed', 'hex')),
      )
      .map((out) => out.script.slice(6, 38));
    if (witnessCommits.length === 0) return null;
    // Use the commit with the highest output (should only be one though)
    const result = witnessCommits[witnessCommits.length - 1];
    if (!(result instanceof Buffer && result.length === 32)) return null;
    return result;
  }
  hasWitnessCommit() {
    if (
      this.witnessCommit instanceof Buffer &&
      this.witnessCommit.length === 32
    )
      return true;
    if (this.getWitnessCommit() !== null) return true;
    return false;
  }
  hasWitness() {
    return anyTxHasWitness(this.transactions);
  }
  weight() {
    const base = this.byteLength(false, false);
    const total = this.byteLength(false, true);
    return base * 3 + total;
  }
  byteLength(headersOnly, allowWitness = true) {
    if (headersOnly || !this.transactions) return 80;
    return (
      80 +
      varuint.encodingLength(this.transactions.length) +
      this.transactions.reduce((a, x) => a + x.byteLength(allowWitness), 0)
    );
  }
  getHash() {
    return bcrypto.hash256(this.toBuffer(true));
  }
  getId() {
    return (0, bufferutils_1.reverseBuffer)(this.getHash()).toString('hex');
  }
  getUTCDate() {
    const date = new Date(0); // epoch
    date.setUTCSeconds(this.timestamp);
    return date;
  }
  // TODO: buffer, offset compatibility
  toBuffer(headersOnly) {
    const buffer = Buffer.allocUnsafe(this.byteLength(headersOnly));
    let offset = 0;
    const writeSlice = (slice) => {
      slice.copy(buffer, offset);
      offset += slice.length;
    };
    const writeInt32 = (i) => {
      buffer.writeInt32LE(i, offset);
      offset += 4;
    };
    const writeUInt32 = (i) => {
      buffer.writeUInt32LE(i, offset);
      offset += 4;
    };
    writeInt32(this.version);
    writeSlice(this.prevHash);
    writeSlice(this.merkleRoot);
    writeUInt32(this.timestamp);
    writeUInt32(this.bits);
    writeUInt32(this.nonce);
    if (headersOnly || !this.transactions) return buffer;
    varuint.encode(this.transactions.length, buffer, offset);
    offset += varuint.encode.bytes;
    this.transactions.forEach((tx) => {
      const txSize = tx.byteLength(); // TODO: extract from toBuffer?
      tx.toBuffer(buffer, offset);
      offset += txSize;
    });
    return buffer;
  }
  toHex(headersOnly) {
    return this.toBuffer(headersOnly).toString('hex');
  }
  checkTxRoots() {
    // If the Block has segwit transactions but no witness commit,
    // there's no way it can be valid, so fail the check.
    const hasWitnessCommit = this.hasWitnessCommit();
    if (!hasWitnessCommit && this.hasWitness()) return false;
    return (
      this.__checkMerkleRoot() &&
      (hasWitnessCommit ? this.__checkWitnessCommit() : true)
    );
  }
  checkProofOfWork() {
    const hash = (0, bufferutils_1.reverseBuffer)(this.getHash());
    const target = Block.calculateTarget(this.bits);
    return hash.compare(target) <= 0;
  }
  __checkMerkleRoot() {
    if (!this.transactions) throw errorMerkleNoTxes;
    const actualMerkleRoot = Block.calculateMerkleRoot(this.transactions);
    return this.merkleRoot.compare(actualMerkleRoot) === 0;
  }
  __checkWitnessCommit() {
    if (!this.transactions) throw errorMerkleNoTxes;
    if (!this.hasWitnessCommit()) throw errorWitnessNotSegwit;
    const actualWitnessCommit = Block.calculateMerkleRoot(
      this.transactions,
      true,
    );
    return this.witnessCommit.compare(actualWitnessCommit) === 0;
  }
}
exports.Block = Block;
function txesHaveWitnessCommit(transactions) {
  return (
    transactions instanceof Array &&
    transactions[0] &&
    transactions[0].ins &&
    transactions[0].ins instanceof Array &&
    transactions[0].ins[0] &&
    transactions[0].ins[0].witness &&
    transactions[0].ins[0].witness instanceof Array &&
    transactions[0].ins[0].witness.length > 0
  );
}
function anyTxHasWitness(transactions) {
  return (
    transactions instanceof Array &&
    transactions.some(
      (tx) =>
        typeof tx === 'object' &&
        tx.ins instanceof Array &&
        tx.ins.some(
          (input) =>
            typeof input === 'object' &&
            input.witness instanceof Array &&
            input.witness.length > 0,
        ),
    )
  );
}
