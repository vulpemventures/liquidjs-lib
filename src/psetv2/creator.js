'use strict';
var __importDefault =
  (this && this.__importDefault) ||
  function(mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.Creator = exports.Output = exports.Input = void 0;
const bitset_1 = __importDefault(require('bitset'));
const globals_1 = require('./globals');
const pset_1 = require('./pset');
const input_1 = require('./input');
const output_1 = require('./output');
const bufferutils_1 = require('../bufferutils');
const address_1 = require('../address');
const asset_1 = require('../asset');
const transaction_1 = require('../transaction');
const ops_1 = require('../ops');
class Input {
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
    const input = new input_1.Input(prevTxid, this.txIndex, this.sequence);
    input.requiredHeightLocktime = this.heightLocktime;
    input.requiredTimeLocktime = this.timeLocktime;
    return input;
  }
}
exports.Input = Input;
class Output {
  constructor(asset, amount, address, blinderIndex) {
    this.asset = asset;
    this.amount = amount;
    this.address = address;
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
      this.address &&
      (0, address_1.isConfidential)(this.address) &&
      (this.blinderIndex === undefined || this.blinderIndex < 0)
    ) {
      throw new Error('missing blinder index for confidential output');
    }
  }
  toPartialOutput() {
    let script = Buffer.from([]);
    if (this.address && this.address.length > 0) {
      script =
        this.amount > 0
          ? (0, address_1.toOutputScript)(this.address)
          : Buffer.of(ops_1.OPS.OP_RETURN);
    }
    const asset = asset_1.AssetHash.fromHex(this.asset);
    const output = new output_1.Output(
      this.amount,
      asset.bytesWithoutPrefix,
      script,
    );
    if (this.address && (0, address_1.isConfidential)(this.address)) {
      const { blindingKey } = (0, address_1.fromConfidential)(this.address);
      output.blinderIndex = this.blinderIndex;
      output.blindingPubkey = blindingKey;
    }
    return output;
  }
}
exports.Output = Output;
class Creator {
  static newPset(args) {
    const modifiable = new bitset_1.default(0);
    const txModifiable = new bitset_1.default(0);
    txModifiable.set(0);
    txModifiable.set(1);
    const globals = new globals_1.Global(2, 0, 0, 2);
    globals.modifiable = modifiable;
    globals.txModifiable = txModifiable;
    globals.xpub = [];
    globals.scalars = [];
    globals.proprietaryData = [];
    globals.unknowns = [];
    const pset = new pset_1.Pset(globals);
    args.inputs &&
      args.inputs.forEach(input => {
        input.validate();
        pset.addInput(input.toPartialInput());
      });
    args.outputs &&
      args.outputs.forEach(output => {
        output.validate();
        pset.addOutput(output.toPartialOutput());
      });
    return pset;
  }
}
exports.Creator = Creator;
