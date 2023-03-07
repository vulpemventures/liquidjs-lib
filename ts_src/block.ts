import { reverseBuffer } from './bufferutils';
import * as bcrypto from './crypto';
import { Transaction } from './transaction';
import * as types from './types';

const fastMerkleRoot = require('merkle-lib/fastRoot');
const typeforce = require('typeforce');
const varuint = require('varuint-bitcoin');

const errorMerkleNoTxes = new TypeError(
  'Cannot compute merkle root for zero transactions',
);
const errorWitnessNotSegwit = new TypeError(
  'Cannot compute witness commit for non-segwit block',
);

export class Block {
  static fromBuffer(buffer: Buffer): Block {
    if (buffer.length < 80) throw new Error('Buffer too small (< 80 bytes)');

    let offset: number = 0;
    const readSlice = (n: number): Buffer => {
      offset += n;
      return buffer.slice(offset - n, offset);
    };

    const readUInt32 = (): number => {
      const i = buffer.readUInt32LE(offset);
      offset += 4;
      return i;
    };

    const readUInt8 = (): number => {
      const i = buffer.readUInt8(offset);
      offset += 1;
      return i;
    };

    const readVarInt = (): number => {
      const vi = varuint.decode(buffer, offset);
      offset += varuint.decode.bytes;
      return vi;
    };

    const block = new Block();
    block.version = readUInt32();

    const isDyna = block.version >>> 31 === 1;
    if (isDyna) {
      block.version &= 0x7fff_ffff;
      block.isDyna = true;
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
          block.isCurrent = true;
          block.isCurrentCompact = true;
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
            extensionSpace.push(tmp);
          }
          block.currentSignBlockScriptFull = signBlockScriptFull;
          block.currentSignBlockWitnessLimitFull = signBlockWitnessLimitFull;
          block.currentFedpegProgram = fedpegProgram;
          block.currentFedpegScript = fedpegScript;
          block.currentExtensionSpace = extensionSpace;
          block.isCurrent = true;
          block.isCurrentFull = true;
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
          block.isProposed = true;
          block.isProposedCompact = true;
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
            extensionSpace.push(tmp);
          }
          block.proposedSignBlockScriptFull = signBlockScriptFull;
          block.proposedSignBlockWitnessLimitFull = signBlockWitnessLimitFull;
          block.proposedFedpegProgram = fedpegProgram;
          block.proposedFedpegScript = fedpegScript;
          block.proposedExtensionSpace = extensionSpace;
          block.isProposed = true;
          block.isProposedFull = true;
          break;
        default:
          throw new Error('bad serialize type for dynafed parameters');
      }
      const signBlockWitnessLength = readVarInt();
      const signBlockWitness = [];
      for (let i = 0; i < signBlockWitnessLength; i++) {
        const tmpLen = readVarInt();
        const tmp = readSlice(tmpLen);
        signBlockWitness.push(tmp);
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

    const readTransaction = (): any => {
      const tx = Transaction.fromBuffer(buffer.slice(offset), true);
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

  static fromHex(hex: string): Block {
    return Block.fromBuffer(Buffer.from(hex, 'hex'));
  }

  static calculateTarget(bits: number): Buffer {
    const exponent = ((bits & 0xff000000) >> 24) - 3;
    const mantissa = bits & 0x007fffff;
    const target = Buffer.alloc(32, 0);
    target.writeUIntBE(mantissa, 29 - exponent, 3);
    return target;
  }

  static calculateMerkleRoot(
    transactions: Transaction[],
    forWitness?: boolean,
  ): Buffer {
    typeforce([{ getHash: types.Function }], transactions);
    if (transactions.length === 0) throw errorMerkleNoTxes;
    if (forWitness && !txesHaveWitnessCommit(transactions))
      throw errorWitnessNotSegwit;

    const hashes = transactions.map((transaction) =>
      transaction.getHash(forWitness!),
    );

    const rootHash = fastMerkleRoot(hashes, bcrypto.hash256);

    return forWitness
      ? bcrypto.hash256(
          Buffer.concat([rootHash, transactions[0].ins[0].witness[0]]),
        )
      : rootHash;
  }

  version: number = 1;
  prevHash?: Buffer = undefined;
  merkleRoot?: Buffer = undefined;
  timestamp: number = 0;
  witnessCommit?: Buffer = undefined;
  bits: number = 0;
  nonce: number = 0;
  transactions?: Transaction[] = undefined;
  blockHeight: number = 0;

  // DYNAMIC FEDERATION PARAMS
  isCurrent: boolean = false;
  // current compact params
  isCurrentCompact: boolean = false;
  currentSignBlockScript?: Buffer = undefined;
  currentSignBlockWitnessLimit: number = 0;
  currentElidedRoot?: Buffer = undefined;
  // current full param
  isCurrentFull: boolean = false;
  currentSignBlockScriptFull?: Buffer = undefined;
  currentSignBlockWitnessLimitFull: number = 0;
  currentFedpegProgram?: Buffer = undefined;
  currentFedpegScript?: Buffer = undefined;
  currentExtensionSpace?: Buffer[] = undefined;

  isProposed: boolean = false;
  // proposed compact params
  isProposedCompact: boolean = false;
  proposedSignBlockScript?: Buffer = undefined;
  proposedSignBlockWitnessLimit: number = 0;
  proposedElidedRoot?: Buffer = undefined;
  // proposed full param
  isProposedFull: boolean = false;
  proposedSignBlockScriptFull?: Buffer = undefined;
  proposedSignBlockWitnessLimitFull: number = 0;
  proposedFedpegProgram?: Buffer = undefined;
  proposedFedpegScript?: Buffer = undefined;
  proposedExtensionSpace?: Buffer[] = undefined;
  // SignBlockWitness
  signBlockWitness?: Buffer[] = undefined;
  isDyna: boolean = false;

  challenge?: Buffer = undefined;
  solution?: Buffer = undefined;

  getWitnessCommit(): Buffer | null {
    if (!txesHaveWitnessCommit(this.transactions!)) return null;

    // The merkle root for the witness data is in an OP_RETURN output.
    // There is no rule for the index of the output, so use filter to find it.
    // The root is prepended with 0xaa21a9ed so check for 0x6a24aa21a9ed
    // If multiple commits are found, the output with highest index is assumed.
    const witnessCommits = this.transactions![0].outs.filter((out) =>
      out.script.slice(0, 6).equals(Buffer.from('6a24aa21a9ed', 'hex')),
    ).map((out) => out.script.slice(6, 38));
    if (witnessCommits.length === 0) return null;
    // Use the commit with the highest output (should only be one though)
    const result = witnessCommits[witnessCommits.length - 1];

    if (!(result instanceof Buffer && result.length === 32)) return null;
    return result;
  }

  hasWitnessCommit(): boolean {
    if (
      this.witnessCommit instanceof Buffer &&
      this.witnessCommit.length === 32
    )
      return true;
    if (this.getWitnessCommit() !== null) return true;
    return false;
  }

  hasWitness(): boolean {
    return anyTxHasWitness(this.transactions!);
  }

  weight(): number {
    const base = this.byteLength(false, false);
    const total = this.byteLength(false, true);
    return base * 3 + total;
  }

  getHash(): Buffer {
    return bcrypto.hash256(this.toBuffer(true));
  }

  getId(): string {
    return reverseBuffer(this.getHash()).toString('hex');
  }

  getUTCDate(): Date {
    const date = new Date(0); // epoch
    date.setUTCSeconds(this.timestamp);

    return date;
  }

  // TODO: buffer, offset compatibility
  toBuffer(headersOnly?: boolean): Buffer {
    const buffer: Buffer = Buffer.allocUnsafe(this.byteLength(headersOnly));

    let offset: number = 0;
    const writeSlice = (slice: Buffer): void => {
      slice.copy(buffer, offset);
      offset += slice.length;
    };
    const writeInt32 = (i: number): void => {
      buffer.writeInt32LE(i, offset);
      offset += 4;
    };
    const writeUInt32 = (i: number): void => {
      buffer.writeUInt32LE(i, offset);
      offset += 4;
    };
    const writeUInt8 = (i: number): void => {
      buffer.writeUInt8(i, offset);
      offset += 1;
    };
    const writeVarInt = (i: number): void => {
      varuint.encode(i, buffer, offset);
      offset += varuint.encode.bytes;
    };

    let version: number = this.version;
    if (this.isDyna) {
      const mask: number = 1 << 31;
      version |= mask;
    }

    writeInt32(version);
    writeSlice(this.prevHash!);
    writeSlice(this.merkleRoot!);
    writeUInt32(this.timestamp);
    writeUInt32(this.blockHeight);

    if (this.isDyna) {
      if (this.isCurrent) {
        if (this.isCurrentCompact == null && this.isCurrentFull == null) {
          writeUInt8(0);
        }
        if (this.isCurrentCompact) {
          writeUInt8(1);
          writeVarInt(this.currentSignBlockScript!.length);
          writeSlice(this.currentSignBlockScript!);
          writeUInt32(this.currentSignBlockWitnessLimit);
          writeSlice(this.currentElidedRoot!);
        }
        if (this.isCurrentFull) {
          writeUInt8(2);
          writeVarInt(this.currentSignBlockScriptFull!.length);
          writeSlice(this.currentSignBlockScriptFull!);
          writeUInt32(this.currentSignBlockWitnessLimitFull);
          writeVarInt(this.currentFedpegProgram!.length);
          writeSlice(this.currentFedpegProgram!);
          writeVarInt(this.currentFedpegScript!.length);
          writeSlice(this.currentFedpegScript!);
          writeVarInt(this.currentExtensionSpace!.length);
          this.currentExtensionSpace!.forEach((item) => {
            writeVarInt(item!.length);
            writeSlice(item);
          });
        }
      } else {
        writeUInt8(0);
      }
      if (this.isProposed) {
        if (this.isProposedCompact) {
          writeUInt8(1);
          writeVarInt(this.proposedSignBlockScript!.length);
          writeSlice(this.proposedSignBlockScript!);
          writeUInt32(this.proposedSignBlockWitnessLimit);
          writeSlice(this.proposedElidedRoot!);
        }
        if (this.isProposedFull) {
          writeUInt8(2);
          writeVarInt(this.proposedSignBlockScriptFull!.length);
          writeSlice(this.proposedSignBlockScriptFull!);
          writeUInt32(this.proposedSignBlockWitnessLimitFull);
          writeVarInt(this.proposedFedpegProgram!.length);
          writeSlice(this.proposedFedpegProgram!);
          writeVarInt(this.proposedFedpegScript!.length);
          writeSlice(this.proposedFedpegScript!);
          writeVarInt(this.proposedExtensionSpace!.length);
          this.proposedExtensionSpace!.forEach((item) => {
            writeVarInt(item!.length);
            writeSlice(item);
          });
        } else {
          writeUInt8(0);
        }
      } else {
        writeUInt8(0);
      }
      if (!headersOnly) {
        writeVarInt(this.signBlockWitness!.length);
        this.signBlockWitness!.forEach((item) => {
          writeVarInt(item!.length);
          writeSlice(item);
        });
      }
    } else {
      writeVarInt(this.challenge!.length);
      writeSlice(this.challenge!);
      if (!headersOnly) {
        writeVarInt(this.solution!.length);
        writeSlice(this.solution!);
      }
    }

    if (headersOnly || !this.transactions) return buffer;

    writeVarInt(this.transactions.length);
    this.transactions.forEach((tx) => {
      const txSize = tx.byteLength(); // TODO: extract from toBuffer?
      tx.toBuffer(buffer, offset);
      offset += txSize;
    });

    return buffer;
  }

  toHex(headersOnly?: boolean): string {
    return this.toBuffer(headersOnly).toString('hex');
  }

  checkTxRoots(): boolean {
    // If the Block has segwit transactions but no witness commit,
    // there's no way it can be valid, so fail the check.
    const hasWitnessCommit = this.hasWitnessCommit();
    if (!hasWitnessCommit && this.hasWitness()) return false;
    return (
      this.__checkMerkleRoot() &&
      (hasWitnessCommit ? this.__checkWitnessCommit() : true)
    );
  }

  checkProofOfWork(): boolean {
    const hash: Buffer = reverseBuffer(this.getHash());
    const target = Block.calculateTarget(this.bits);

    return hash.compare(target) <= 0;
  }

  private __checkMerkleRoot(): boolean {
    if (!this.transactions) throw errorMerkleNoTxes;

    const actualMerkleRoot = Block.calculateMerkleRoot(this.transactions);
    return this.merkleRoot!.compare(actualMerkleRoot) === 0;
  }

  private __checkWitnessCommit(): boolean {
    if (!this.transactions) throw errorMerkleNoTxes;
    if (!this.hasWitnessCommit()) throw errorWitnessNotSegwit;

    const actualWitnessCommit = Block.calculateMerkleRoot(
      this.transactions,
      true,
    );
    return this.witnessCommit!.compare(actualWitnessCommit) === 0;
  }

  byteLength(forHash?: boolean, allowWitness: boolean = true): number {
    let size = 0;
    size += 4; // version
    size += 32; // prevHash
    size += 32; // merkleRoot
    size += 4; // timestamp
    size += 4; // height

    if (this.isDyna) {
      size += 2; // dyna params type current/propose
      if (this.isCurrent) {
        if (this.isCurrentCompact) {
          size += getNumberMinByteSize(this.currentSignBlockScript!.length); // currentSignBlockScript length
          size += this.currentSignBlockScript!.length; // currentSignBlockScript
          size += 4; // currentSignBlockWitnessLimit
          size += 32; // currentElidedRoot
        }
        if (this.isCurrentFull) {
          size += getNumberMinByteSize(this.currentSignBlockScriptFull!.length); // currentSignBlockScriptFull length
          size += this.currentSignBlockScriptFull!.length; // currentSignBlockScriptFull
          size += 4; // currentSignBlockWitnessLimitFull
          size += getNumberMinByteSize(this.currentFedpegProgram!.length); // currentFedpegProgram length
          size += this.currentFedpegProgram!.length; // currentFedpegProgram
          size += getNumberMinByteSize(this.currentFedpegScript!.length); // currentFedpegScript length
          size += this.currentFedpegScript!.length; // currentFedpegScript
          size += getNumberMinByteSize(this.currentExtensionSpace!.length); // currentExtensionSpace length
          this.currentExtensionSpace!.forEach((item) => {
            size += getNumberMinByteSize(item!.length); // currentExtensionSpace item length
            size += item!.length; // currentExtensionSpace item
          });
        }
      }
      if (this.isProposed) {
        if (this.isProposedCompact) {
          size += getNumberMinByteSize(this.proposedSignBlockScript!.length); // proposedSignBlockScript length
          size += this.proposedSignBlockScript!.length; // proposedSignBlockScript
          size += 4; // proposedSignBlockWitnessLimit
          size += 32; // proposedElidedRoot
        }
        if (this.isProposedFull) {
          size += getNumberMinByteSize(
            this.proposedSignBlockScriptFull!.length,
          ); // proposedSignBlockScriptFull length
          size += this.proposedSignBlockScriptFull!.length; // proposedSignBlockScriptFull
          size += 4; // proposedSignBlockWitnessLimitFull
          size += getNumberMinByteSize(this.proposedFedpegProgram!.length); // proposedFedpegProgram length
          size += this.proposedFedpegProgram!.length; // proposedFedpegProgram
          size += getNumberMinByteSize(this.proposedFedpegScript!.length); // proposedFedpegScript length
          size += this.proposedFedpegScript!.length; // proposedFedpegScript
          size += getNumberMinByteSize(this.proposedExtensionSpace!.length); // proposedExtensionSpace length
          this.proposedExtensionSpace!.forEach((item) => {
            size += getNumberMinByteSize(item!.length); // proposedExtensionSpace item length
            size += item!.length; // proposedExtensionSpace item
          });
        }
      }
      if (!forHash) {
        size += getNumberMinByteSize(this.signBlockWitness!.length);
        this.signBlockWitness!.forEach((item) => {
          size += getNumberMinByteSize(item!.length); // signBlockWitness item length
          size += item!.length; // signBlockWitness item
        });
      }
    } else {
      const challengeLength = this.challenge?.length ?? 0;
      size += getNumberMinByteSize(challengeLength);
      size += challengeLength; // challenge
      if (!forHash) {
        const solutionLength = this.solution?.length ?? 0;
        size += getNumberMinByteSize(solutionLength);
        size += solutionLength; // solution
      }
    }
    if (!forHash) {
      size += this.transactions?.length
        ? varuint.encodingLength(this.transactions.length)
        : 0;
      size +=
        this.transactions?.reduce(
          (a, x) => a + x.byteLength(allowWitness),
          0,
        ) ?? 0;
    }
    return size;
  }
}

function getNumberMinByteSize(num: number): number {
  if (num < 0) {
    throw new Error('negative numbers are not supported.');
  }
  for (let i = 1; i <= 8; i++) {
    const maxVal = Math.pow(2, i * 8) - 1;
    if (num <= maxVal) {
      return i;
    }
  }
  throw new Error(
    'number is too large to be represented as a JavaScript number.',
  );
}

function txesHaveWitnessCommit(transactions: Transaction[]): boolean {
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

function anyTxHasWitness(transactions: Transaction[]): boolean {
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
