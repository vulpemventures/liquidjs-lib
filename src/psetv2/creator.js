'use strict';
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.Creator = exports.CreatorOutput = exports.CreatorInput = void 0;
const globals_1 = require('./globals');
const pset_1 = require('./pset');
const input_1 = require('./input');
const output_1 = require('./output');
const bufferutils_1 = require('../bufferutils');
const asset_1 = require('../asset');
const transaction_1 = require('../transaction');
const bitset_1 = __importDefault(require('bitset'));
class CreatorInput {
  constructor(txid, txIndex, sequence, heightLocktime, timeLocktime) {
    this.txid = txid;
    this.txIndex = txIndex;
    this.sequence = sequence || transaction_1.Transaction.DEFAULT_SEQUENCE;
    this.heightLocktime = heightLocktime || 0;
    this.timeLocktime = timeLocktime || 0;
  }
  validate() {
    if (this.txid.length === 0) {
      throw new Error('missing prevout txid');
    }
    if (this.txid.length !== 64) {
      throw new Error('invalid prevout txid length');
    }
    if (this.txIndex < 0) {
      throw new Error('missing prevout tx index');
    }
  }
  toPartialInput() {
    const prevTxid = (0, bufferutils_1.reverseBuffer)(
      Buffer.from(this.txid, 'hex'),
    );
    const input = new input_1.PsetInput(prevTxid, this.txIndex, this.sequence);
    input.requiredHeightLocktime = this.heightLocktime;
    input.requiredTimeLocktime = this.timeLocktime;
    return input;
  }
}
exports.CreatorInput = CreatorInput;
class CreatorOutput {
  constructor(asset, amount, script, blindingPublicKey, blinderIndex) {
    this.asset = asset;
    this.amount = amount;
    this.script = script;
    this.blindingPublicKey = blindingPublicKey;
    this.blinderIndex = blinderIndex;
  }
  validate() {
    if (this.asset.length === 0) {
      throw new Error('missing asset');
    }
    if (Buffer.from(this.asset, 'hex').length !== 32) {
      throw new Error('invalid asset length');
    }
    if (
      this.blindingPublicKey &&
      (this.blinderIndex === undefined || this.blinderIndex < 0)
    ) {
      throw new Error('missing blinder index for confidential output');
    }
  }
  toPartialOutput() {
    const asset = asset_1.AssetHash.fromHex(this.asset);
    const output = new output_1.PsetOutput(
      this.amount,
      asset.bytesWithoutPrefix,
      this.script || Buffer.of(),
    );
    if (this.blindingPublicKey) {
      output.blinderIndex = this.blinderIndex;
      output.blindingPubkey = this.blindingPublicKey;
    }
    return output;
  }
}
exports.CreatorOutput = CreatorOutput;
class Creator {
  static newPset(args) {
    const locktime = args ? args.locktime : undefined;
    const txModifiable = new bitset_1.default(0);
    txModifiable.set(0);
    txModifiable.set(1);
    const globals = new globals_1.PsetGlobal(2, 0, 0, 2, locktime);
    globals.txModifiable = txModifiable;
    globals.xpubs = [];
    globals.scalars = [];
    globals.proprietaryData = [];
    globals.unknowns = [];
    const pset = new pset_1.Pset(globals);
    if (args && args.inputs)
      args.inputs.forEach((input) => {
        input.validate();
        pset.addInput(input.toPartialInput());
      });
    if (args && args.outputs)
      args.outputs.forEach((output) => {
        output.validate();
        pset.addOutput(output.toPartialOutput());
      });
    return pset;
  }
}
exports.Creator = Creator;
