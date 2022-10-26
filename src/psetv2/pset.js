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
exports.Pset = exports.magicPrefixWithSeparator = exports.magicPrefix = void 0;
const ecpair_1 = require('ecpair');
const bufferutils_1 = require('../bufferutils');
const crypto_1 = require('../crypto');
const transaction_1 = require('../transaction');
const fields_1 = require('./fields');
const globals_1 = require('./globals');
const input_1 = require('./input');
const output_1 = require('./output');
const bscript = __importStar(require('../script'));
const address_1 = require('../address');
const payments_1 = require('../payments');
const value_1 = require('../value');
const asset_1 = require('../asset');
const utils_1 = require('./utils');
exports.magicPrefix = Buffer.from([0x70, 0x73, 0x65, 0x74]);
exports.magicPrefixWithSeparator = Buffer.concat([
  exports.magicPrefix,
  Buffer.of(0xff),
]);
class Pset {
  constructor(globals, inputs, outputs) {
    this.inputs = inputs || [];
    this.outputs = outputs || [];
    this.globals = globals || new globals_1.PsetGlobal();
  }
  static fromBase64(data) {
    const buf = Buffer.from(data, 'base64');
    return this.fromBuffer(buf);
  }
  static fromBuffer(buf) {
    const r = new bufferutils_1.BufferReader(buf);
    const magic = r.readSlice(exports.magicPrefixWithSeparator.length);
    if (!magic.equals(exports.magicPrefixWithSeparator)) {
      throw new Error('invalid magic prefix');
    }
    const globals = globals_1.PsetGlobal.fromBuffer(r);
    const inputs = [];
    for (let i = 0; i < globals.inputCount; i++) {
      const input = input_1.PsetInput.fromBuffer(r);
      inputs.push(input);
    }
    const outputs = [];
    for (let i = 0; i < globals.outputCount; i++) {
      const output = output_1.PsetOutput.fromBuffer(r);
      outputs.push(output);
    }
    const pset = new Pset(globals, inputs, outputs);
    pset.sanityCheck();
    return pset;
  }
  static ECCKeysGenerator(ec) {
    return (opts) => {
      const privateKey = (0, utils_1.randomBytes)(opts);
      const publicKey = (0, ecpair_1.ECPairFactory)(ec).fromPrivateKey(
        privateKey,
      ).publicKey;
      return {
        privateKey,
        publicKey,
      };
    };
  }
  static ECDSASigValidator(ecc) {
    return (pubkey, msghash, signature) => {
      return (0, ecpair_1.ECPairFactory)(ecc)
        .fromPublicKey(pubkey)
        .verify(msghash, signature);
    };
  }
  static SchnorrSigValidator(ecc) {
    return (pubkey, msghash, signature) =>
      ecc.verifySchnorr(msghash, pubkey, signature.slice(0, 64));
  }
  sanityCheck() {
    this.globals.sanityCheck();
    this.inputs.forEach((input) => input.sanityCheck());
    this.outputs.forEach((output) => output.sanityCheck());
    if (
      this.isFullyBlinded() &&
      this.globals.scalars &&
      this.globals.scalars.length > 0
    ) {
      throw new Error('global scalars must be empty for fully blinded pset');
    }
    return this;
  }
  copy() {
    return new Pset(this.globals, this.inputs, this.outputs);
  }
  inputsModifiable() {
    if (!this.globals.txModifiable) {
      return true;
    }
    return this.globals.txModifiable.get(0) === 1;
  }
  outputsModifiable() {
    if (!this.globals.txModifiable) {
      return true;
    }
    return this.globals.txModifiable.get(1) === 1;
  }
  hasSighashSingle() {
    if (!this.globals.txModifiable) {
      return false;
    }
    return this.globals.txModifiable.get(2) === 1;
  }
  needsBlinding() {
    return this.outputs.some(
      (out) => out.needsBlinding() && !out.isFullyBlinded(),
    );
  }
  isFullyBlinded() {
    if (!this.needsBlinding()) {
      return false;
    }
    return !this.outputs.some(
      (out) => out.needsBlinding() && !out.isFullyBlinded(),
    );
  }
  isComplete() {
    return this.inputs.every((input) => input.isFinalized());
  }
  locktime() {
    let heightLocktime = 0;
    let timeLocktime = 0;
    this.inputs.forEach((input) => {
      if (input.requiredTimeLocktime > 0) {
        if (input.requiredTimeLocktime > timeLocktime) {
          timeLocktime = input.requiredTimeLocktime;
        }
      }
      if (input.requiredHeightLocktime > 0) {
        if (input.requiredHeightLocktime > heightLocktime) {
          heightLocktime = input.requiredHeightLocktime;
        }
      }
    });
    if (heightLocktime > 0) {
      return heightLocktime;
    }
    if (timeLocktime > 0) {
      return timeLocktime;
    }
    return this.globals.fallbackLocktime || 0;
  }
  unsignedTx() {
    const tx = new transaction_1.Transaction();
    tx.version = this.globals.txVersion;
    tx.locktime = this.locktime();
    this.inputs.forEach((input) => {
      let issuance;
      if (input.hasIssuance() || input.hasReissuance()) {
        let assetAmount = input.issuanceValueCommitment;
        if (!assetAmount || assetAmount.length === 0) {
          assetAmount = value_1.ElementsValue.fromNumber(
            input.issuanceValue,
          ).bytes;
        }
        let tokenAmount = input.issuanceInflationKeysCommitment;
        if (!tokenAmount || tokenAmount.length === 0) {
          tokenAmount = !input.issuanceInflationKeys
            ? Buffer.of(0x00)
            : value_1.ElementsValue.fromNumber(input.issuanceInflationKeys)
                .bytes;
        }
        const assetEntropy = input.issuanceAssetEntropy;
        const assetBlindingNonce = input.issuanceBlindingNonce;
        issuance = {
          assetEntropy,
          assetAmount,
          tokenAmount,
          assetBlindingNonce,
        };
      }
      tx.addInput(
        input.previousTxid,
        input.previousTxIndex,
        input.sequence,
        undefined,
        issuance,
      );
    });
    this.outputs.forEach((output) => {
      const value =
        output.valueCommitment ||
        value_1.ElementsValue.fromNumber(output.value).bytes;
      const asset =
        output.assetCommitment ||
        asset_1.AssetHash.fromBytes(output.asset).bytes;
      const script = output.script || Buffer.from([]);
      const nonce = output.ecdhPubkey || Buffer.of(0x00);
      tx.addOutput(
        script,
        value,
        asset,
        nonce,
        output.valueRangeproof,
        output.assetSurjectionProof,
      );
    });
    return tx;
  }
  validateAllSignatures(validator) {
    return this.inputs.every((_, i) =>
      this.validateInputSignatures(i, validator),
    );
  }
  addInput(newInput) {
    newInput.sanityCheck();
    if (this.isDuplicatedInput(newInput)) {
      throw new Error('given input already exists in pset');
    }
    if (!this.inputsModifiable()) {
      throw new Error('pset is locked for updates on inputs');
    }
    if (
      newInput.requiredHeightLocktime > 0 ||
      newInput.requiredTimeLocktime > 0
    ) {
      const oldLocktime = this.locktime();
      let timeLocktime = newInput.requiredTimeLocktime;
      let heightLocktime = newInput.requiredHeightLocktime;
      let hasSigs = false;
      this.inputs.forEach((input) => {
        if (input.requiredTimeLocktime > 0 && !input.requiredHeightLocktime) {
          heightLocktime = 0;
          if (timeLocktime === 0) {
            throw new Error('invalid input locktime');
          }
        }
        if (!input.requiredTimeLocktime && input.requiredHeightLocktime > 0) {
          timeLocktime = 0;
          if (heightLocktime === 0) {
            throw new Error('invalid input locktime');
          }
        }
        if (input.requiredTimeLocktime > 0 && timeLocktime > 0) {
          timeLocktime = Math.max(timeLocktime, input.requiredTimeLocktime);
        }
        if (input.requiredHeightLocktime > 0 && heightLocktime > 0) {
          heightLocktime = Math.max(
            heightLocktime,
            input.requiredHeightLocktime,
          );
        }
        if (input.partialSigs.length > 0) {
          hasSigs = true;
        }
      });
      let newLocktime = this.globals.fallbackLocktime;
      if (timeLocktime > 0) {
        newLocktime = timeLocktime;
      }
      if (heightLocktime > 0) {
        newLocktime = heightLocktime;
      }
      if (hasSigs && oldLocktime !== newLocktime) {
        throw new Error('invalid input locktime');
      }
    }
    this.inputs.push(newInput);
    this.globals.inputCount++;
    return this;
  }
  addOutput(newOutput) {
    newOutput.sanityCheck();
    if (!this.outputsModifiable()) {
      throw new Error('pset is locked for updates on outputs');
    }
    this.outputs.push(newOutput);
    this.globals.outputCount++;
    return this;
  }
  validateInputSignatures(index, validator) {
    if (index < 0 || index >= this.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const input = this.inputs[index];
    if (!input.partialSigs || input.partialSigs.length === 0) {
      return false;
    }
    return input.partialSigs.every((ps) =>
      this.validatePartialSignature(index, validator, ps),
    );
  }
  validatePartialSignature(index, validator, ps) {
    if (index < 0 || index >= this.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const input = this.inputs[index];
    if (!input.partialSigs || input.partialSigs.length === 0) {
      return false;
    }
    const prevout = input.getUtxo();
    if (!prevout) {
      throw new Error('missing input (non-)witness utxo');
    }
    const sighashType = ps.signature[ps.signature.length - 1];
    const preimage = this.getInputPreimage(index, sighashType);
    const script = input.redeemScript || input.witnessScript || prevout.script;
    checkScriptForPubkey(ps.pubkey, script, 'verify');
    const { signature } = bscript.signature.decode(ps.signature);
    return validator(ps.pubkey, preimage, signature);
  }
  getInputPreimage(index, sighashType, genesisBlockHash, leafHash) {
    if (index < 0 || index >= this.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const input = this.inputs[index];
    const prevout = input.getUtxo();
    if (!prevout) {
      throw new Error('missing input (non-)witness utxo');
    }
    const unsignedTx = this.unsignedTx();
    if (input.isTaproot()) {
      if (!genesisBlockHash || genesisBlockHash.length !== 32) {
        throw new Error('Missing or invalid genesis block hash');
      }
      const prevoutScripts = [];
      const prevoutAssetsValues = [];
      this.inputs.forEach((v, i) => {
        const u = v.getUtxo();
        if (!u) throw new Error(`Missing input ${i} (non-)witness utxo`);
        prevoutScripts.push(u.script);
        prevoutAssetsValues.push({
          asset: u.asset,
          value: u.value,
        });
      });
      return unsignedTx.hashForWitnessV1(
        index,
        prevoutScripts,
        prevoutAssetsValues,
        sighashType,
        genesisBlockHash,
        leafHash,
      );
    }
    const script = input.redeemScript || prevout.script;
    const scriptType = (0, address_1.getScriptType)(script);
    switch (scriptType) {
      case address_1.ScriptType.P2Pkh:
      case address_1.ScriptType.P2Sh:
        return unsignedTx.hashForSignature(index, script, sighashType);
      case address_1.ScriptType.P2Wpkh:
        const legacyScript = (0, payments_1.p2pkh)({
          hash: prevout.script.slice(2),
        }).output;
        return unsignedTx.hashForWitnessV0(
          index,
          legacyScript,
          prevout.value,
          sighashType,
        );
      case address_1.ScriptType.P2Wsh:
        if (!input.witnessScript || input.witnessScript.length === 0) {
          throw new Error('missing witness script for p2wsh input');
        }
        return unsignedTx.hashForWitnessV0(
          index,
          input.witnessScript,
          prevout.value,
          sighashType,
        );
      default:
        throw new Error('unknown input (non-)witness utxo script type');
    }
  }
  toBase64() {
    const buffer = this.toBuffer();
    return buffer.toString('base64');
  }
  toBuffer() {
    let size = exports.magicPrefixWithSeparator.length;
    const globalsBuffer = this.globals.toBuffer();
    size += globalsBuffer.length + 1;
    const inputBuffers = this.inputs.map((input) => input.toBuffer());
    inputBuffers.forEach((buf) => (size += buf.length + 1));
    const outputBuffers = this.outputs.map((output) => output.toBuffer());
    outputBuffers.forEach((buf) => (size += buf.length + 1));
    const w = bufferutils_1.BufferWriter.withCapacity(size);
    w.writeSlice(exports.magicPrefixWithSeparator);
    w.writeSlice(globalsBuffer);
    w.writeUInt8(fields_1.separator);
    inputBuffers.forEach((buf) => {
      w.writeSlice(buf);
      w.writeUInt8(fields_1.separator);
    });
    outputBuffers.forEach((buf) => {
      w.writeSlice(buf);
      w.writeUInt8(fields_1.separator);
    });
    return w.buffer;
  }
  isDuplicatedInput(input) {
    return this.inputs.some(
      (inp) =>
        inp.previousTxid.equals(input.previousTxid) &&
        inp.previousTxIndex === input.previousTxIndex,
    );
  }
}
exports.Pset = Pset;
function checkScriptForPubkey(pubkey, script, action) {
  if (!pubkeyInScript(pubkey, script)) {
    throw new Error(
      `Cannot ${action} for this input with the key ${pubkey.toString('hex')}`,
    );
  }
}
function pubkeyInScript(pubkey, script) {
  const pubkeyHash = (0, crypto_1.hash160)(pubkey);
  const decompiled = bscript.decompile(script);
  if (decompiled === null) throw new Error('Unknown script error');
  return decompiled.some((element) => {
    if (typeof element === 'number') return false;
    return element.equals(pubkey) || element.equals(pubkeyHash);
  });
}
