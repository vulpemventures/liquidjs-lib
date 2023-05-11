import type { Ecc as Secp256k1Interface } from '../secp256k1-zkp';
import { ECPairFactory } from 'ecpair';
import { BufferReader, BufferWriter } from '../bufferutils';
import { hash160 } from '../crypto';
import { Issuance } from '../issuance';
import { Transaction } from '../transaction';
import { separator } from './fields';
import { PsetGlobal } from './globals';
import { PsetInput } from './input';
import { PartialSig, RngOpts } from './interfaces';
import { PsetOutput } from './output';
import * as bscript from '../script';
import { getScriptType, ScriptType } from '../address';
import { p2pkh } from '../payments';
import { ElementsValue } from '../value';
import { AssetHash } from '../asset';
import { randomBytes } from './utils';

export const magicPrefix = Buffer.from([0x70, 0x73, 0x65, 0x74]);
export const magicPrefixWithSeparator = Buffer.concat([
  magicPrefix,
  Buffer.of(0xff),
]);

// msghash is 32 byte hash of preimage, signature is 64 byte compact signature (r,s 32 bytes each)
export type ValidateSigFunction = (
  pubkey: Buffer,
  msghash: Buffer,
  signature: Buffer,
) => boolean;

export type KeysGenerator = (opts?: RngOpts) => {
  publicKey: Buffer;
  privateKey: Buffer;
};

export class Pset {
  static fromBase64(data: string): Pset {
    const buf = Buffer.from(data, 'base64');
    return this.fromBuffer(buf);
  }

  static fromBuffer(buf: Buffer): Pset {
    const r = new BufferReader(buf);

    const magic = r.readSlice(magicPrefixWithSeparator.length);
    if (!magic.equals(magicPrefixWithSeparator)) {
      throw new Error('invalid magic prefix');
    }

    const globals = PsetGlobal.fromBuffer(r);
    const inputs = [];
    for (let i = 0; i < globals.inputCount; i++) {
      const input = PsetInput.fromBuffer(r);
      inputs.push(input);
    }
    const outputs = [];
    for (let i = 0; i < globals.outputCount; i++) {
      const output = PsetOutput.fromBuffer(r);
      outputs.push(output);
    }

    const pset = new Pset(globals, inputs, outputs);
    pset.sanityCheck();
    return pset;
  }

  static ECCKeysGenerator(ec: Secp256k1Interface): KeysGenerator {
    return (opts?: RngOpts) => {
      const privateKey = randomBytes(opts);
      const publicKey = ECPairFactory(ec).fromPrivateKey(privateKey).publicKey;
      return {
        privateKey,
        publicKey,
      };
    };
  }

  static ECDSASigValidator(ecc: Secp256k1Interface): ValidateSigFunction {
    return (pubkey: Buffer, msghash: Buffer, signature: Buffer) => {
      return ECPairFactory(ecc)
        .fromPublicKey(pubkey)
        .verify(msghash, signature);
    };
  }

  static SchnorrSigValidator(ecc: Secp256k1Interface): ValidateSigFunction {
    return (pubkey: Buffer, msghash: Buffer, signature: Buffer) =>
      ecc.verifySchnorr(msghash, pubkey, signature.slice(0, 64));
  }

  inputs: PsetInput[];
  outputs: PsetOutput[];
  globals: PsetGlobal;

  constructor(
    globals?: PsetGlobal,
    inputs?: PsetInput[],
    outputs?: PsetOutput[],
  ) {
    this.inputs = inputs || [];
    this.outputs = outputs || [];
    this.globals = globals || new PsetGlobal();
  }

  sanityCheck(): this {
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

  copy(): Pset {
    return new Pset(this.globals, this.inputs, this.outputs);
  }

  inputsModifiable(): boolean {
    if (!this.globals.txModifiable) {
      return true;
    }

    return this.globals.txModifiable!.get(0) === 1;
  }

  outputsModifiable(): boolean {
    if (!this.globals.txModifiable) {
      return true;
    }

    return this.globals.txModifiable!.get(1) === 1;
  }

  hasSighashSingle(): boolean {
    if (!this.globals.txModifiable) {
      return false;
    }

    return this.globals.txModifiable!.get(2) === 1;
  }

  needsBlinding(): boolean {
    return this.outputs.some(
      (out) => out.needsBlinding() && !out.isFullyBlinded(),
    );
  }

  isFullyBlinded(): boolean {
    if (!this.needsBlinding()) {
      return false;
    }
    return !this.outputs.some(
      (out) => out.needsBlinding() && !out.isFullyBlinded(),
    );
  }

  isComplete(): boolean {
    return this.inputs.every((input) => input.isFinalized());
  }

  locktime(): number {
    let heightLocktime = 0;
    let timeLocktime = 0;

    this.inputs.forEach((input) => {
      if (input.requiredTimeLocktime! > 0) {
        if (input.requiredTimeLocktime! > timeLocktime) {
          timeLocktime = input.requiredTimeLocktime!;
        }
      }
      if (input.requiredHeightLocktime! > 0) {
        if (input.requiredHeightLocktime! > heightLocktime) {
          heightLocktime = input.requiredHeightLocktime!;
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

  unsignedTx(): Transaction {
    const tx = new Transaction();
    tx.version = this.globals.txVersion;
    tx.locktime = this.locktime();

    this.inputs.forEach((input) => {
      let issuance: Issuance | undefined;
      if (input.hasIssuance() || input.hasReissuance()) {
        let assetAmount = input.issuanceValueCommitment;
        if (!assetAmount || assetAmount.length === 0) {
          assetAmount = ElementsValue.fromNumber(input.issuanceValue!).bytes;
        }
        let tokenAmount = input.issuanceInflationKeysCommitment;
        if (!tokenAmount || tokenAmount.length === 0) {
          tokenAmount = !input.issuanceInflationKeys
            ? Buffer.of(0x00)
            : ElementsValue.fromNumber(input.issuanceInflationKeys!).bytes;
        }
        const assetEntropy = input.issuanceAssetEntropy!;
        const assetBlindingNonce = input.issuanceBlindingNonce!;
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
        output.valueCommitment || ElementsValue.fromNumber(output.value).bytes;
      const asset =
        output.assetCommitment || AssetHash.fromBytes(output.asset!).bytes;
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

  validateAllSignatures(validator: ValidateSigFunction): boolean {
    return this.inputs.every((_, i) =>
      this.validateInputSignatures(i, validator),
    );
  }

  addInput(newInput: PsetInput): this {
    newInput.sanityCheck();

    if (this.isDuplicatedInput(newInput)) {
      throw new Error('given input already exists in pset');
    }

    if (!this.inputsModifiable()) {
      throw new Error('pset is locked for updates on inputs');
    }

    if (
      newInput.requiredHeightLocktime! > 0 ||
      newInput.requiredTimeLocktime! > 0
    ) {
      const oldLocktime = this.locktime();
      let timeLocktime = newInput.requiredTimeLocktime!;
      let heightLocktime = newInput.requiredHeightLocktime!;
      let hasSigs = false;
      this.inputs.forEach((input) => {
        if (input.requiredTimeLocktime! > 0 && !input.requiredHeightLocktime!) {
          heightLocktime = 0;
          if (timeLocktime === 0) {
            throw new Error('invalid input locktime');
          }
        }
        if (!input.requiredTimeLocktime && input.requiredHeightLocktime! > 0) {
          timeLocktime = 0;
          if (heightLocktime === 0) {
            throw new Error('invalid input locktime');
          }
        }
        if (input.requiredTimeLocktime! > 0 && timeLocktime > 0) {
          timeLocktime = Math.max(timeLocktime, input.requiredTimeLocktime!);
        }
        if (input.requiredHeightLocktime! > 0 && heightLocktime > 0) {
          heightLocktime = Math.max(
            heightLocktime,
            input.requiredHeightLocktime!,
          );
        }
        if ((input.partialSigs ?? []).length > 0) {
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

  addOutput(newOutput: PsetOutput): this {
    newOutput.sanityCheck();

    if (!this.outputsModifiable()) {
      throw new Error('pset is locked for updates on outputs');
    }

    this.outputs.push(newOutput);
    this.globals.outputCount++;

    return this;
  }

  validateInputSignatures(
    index: number,
    validator: ValidateSigFunction,
  ): boolean {
    if (index < 0 || index >= this.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const input = this.inputs[index];
    if (!input.partialSigs || input.partialSigs!.length === 0) {
      return false;
    }

    return input.partialSigs!.every((ps) =>
      this.validatePartialSignature(index, validator, ps),
    );
  }

  validatePartialSignature(
    index: number,
    validator: ValidateSigFunction,
    ps: PartialSig,
  ): boolean {
    if (index < 0 || index >= this.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const input = this.inputs[index];
    if (!input.partialSigs || input.partialSigs!.length === 0) {
      return false;
    }
    const prevout = input.getUtxo();
    if (!prevout) {
      throw new Error('missing input (non-)witness utxo');
    }

    const sighashType = ps.signature[ps.signature.length - 1];
    const preimage = this.getInputPreimage(index, sighashType);
    const script = input.witnessScript || input.redeemScript || prevout.script;
    checkScriptForPubkey(ps.pubkey, script, 'verify');
    const { signature } = bscript.signature.decode(ps.signature);
    return validator(ps.pubkey, preimage, signature);
  }

  getInputPreimage(
    index: number,
    sighashType: number,
    genesisBlockHash?: Buffer,
    leafHash?: Buffer,
  ): Buffer {
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
      const prevoutScripts: Buffer[] = [];
      const prevoutAssetsValues: { asset: Buffer; value: Buffer }[] = [];
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
        genesisBlockHash!,
        leafHash,
      );
    }
    const script = input.redeemScript || prevout!.script;
    const scriptType = getScriptType(script);

    switch (scriptType) {
      case ScriptType.P2Pkh:
      case ScriptType.P2Sh:
        return unsignedTx.hashForSignature(index, script, sighashType);
      case ScriptType.P2Wpkh:
        const legacyScript = p2pkh({ hash: prevout.script.slice(2) }).output!;
        return unsignedTx.hashForWitnessV0(
          index,
          legacyScript,
          prevout.value,
          sighashType,
        );
      case ScriptType.P2Wsh:
        if (!input.witnessScript || input.witnessScript!.length === 0) {
          throw new Error('missing witness script for p2wsh input');
        }
        return unsignedTx.hashForWitnessV0(
          index,
          input.witnessScript!,
          prevout.value,
          sighashType,
        );
      default:
        throw new Error('unknown input (non-)witness utxo script type');
    }
  }

  toBase64(): string {
    const buffer = this.toBuffer();
    return buffer.toString('base64');
  }

  toBuffer(): Buffer {
    let size = magicPrefixWithSeparator.length;
    const globalsBuffer = this.globals.toBuffer();
    size += globalsBuffer.length + 1;
    const inputBuffers = this.inputs.map((input) => input.toBuffer());
    inputBuffers.forEach((buf) => (size += buf.length + 1));
    const outputBuffers = this.outputs.map((output) => output.toBuffer());
    outputBuffers.forEach((buf) => (size += buf.length + 1));

    const w = BufferWriter.withCapacity(size);

    w.writeSlice(magicPrefixWithSeparator);
    w.writeSlice(globalsBuffer);
    w.writeUInt8(separator);

    inputBuffers.forEach((buf) => {
      w.writeSlice(buf);
      w.writeUInt8(separator);
    });

    outputBuffers.forEach((buf) => {
      w.writeSlice(buf);
      w.writeUInt8(separator);
    });

    return w.buffer;
  }

  private isDuplicatedInput(input: PsetInput): boolean {
    return this.inputs.some(
      (inp) =>
        inp.previousTxid.equals(input.previousTxid) &&
        inp.previousTxIndex === input.previousTxIndex,
    );
  }
}

function checkScriptForPubkey(
  pubkey: Buffer,
  script: Buffer,
  action: string,
): void {
  if (!pubkeyInScript(pubkey, script)) {
    throw new Error(
      `Cannot ${action} for this input with the key ${pubkey.toString('hex')}`,
    );
  }
}

function pubkeyInScript(pubkey: Buffer, script: Buffer): boolean {
  const pubkeyHash = hash160(pubkey);

  const decompiled = bscript.decompile(script);
  if (decompiled === null) throw new Error('Unknown script error');

  return decompiled.some((element) => {
    if (typeof element === 'number') return false;
    return element.equals(pubkey) || element.equals(pubkeyHash);
  });
}
