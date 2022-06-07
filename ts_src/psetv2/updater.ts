import { TxOutput } from '..';
import { getNetwork, isConfidential } from '../address';
import { AssetHash } from '../asset';
import {
  calculateAsset,
  calculateReissuanceToken,
  generateEntropy,
  IssuanceContract,
  newIssuance,
} from '../issuance';
import { Transaction } from '../transaction';
import { Input, Output } from './creator';
import { Bip32Derivation, PartialSig } from './interfaces';
import { Pset, ValidateSigFunction } from './pset';
import * as bscript from '../script';

export interface AddInIssuanceArgs {
  assetAmount?: number;
  tokenAmount?: number;
  contract?: IssuanceContract;
  assetAddress?: string;
  tokenAddress?: string;
  blindedIssuance: boolean;
}

export interface AddInReissuanceArgs {
  entropy: string | Buffer;
  assetAmount: number;
  assetAddress: string;
  tokenAmount: number;
  tokenAddress: string;
  tokenAssetBlinder: string | Buffer;
}

export class Updater {
  pset: Pset;

  constructor(pset: Pset) {
    pset.sanityCheck();
    this.pset = pset;
  }

  addInputs(ins: Input[]): void {
    const pset = this.pset.copy();

    ins.forEach(input => {
      input.validate();
      pset.addInput(input.toPartialInput());
    });

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addOutputs(outs: Output[]): void {
    const pset = this.pset.copy();

    outs.forEach(output => {
      output.validate();
      pset.addOutput(output.toPartialOutput());
    });

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInNonWitnessUtxo(inIndex: number, nonWitnessUtxo: Transaction): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const pset = this.pset.copy();
    const txid = nonWitnessUtxo.getHash(false);
    if (!txid.equals(pset.inputs[inIndex].previousTxid)) {
      throw new Error('non-witness utxo hash does not match prevout txid');
    }
    pset.inputs[inIndex].nonWitnessUtxo = nonWitnessUtxo;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInWitnessUtxo(inIndex: number, witnessUtxo: TxOutput): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].witnessUtxo = witnessUtxo;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInRedeemScript(inIndex: number, redeemScript: Buffer): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].redeemScript = redeemScript;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInWitnessScript(inIndex: number, witnessScript: Buffer): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const pset = this.pset.copy();
    pset.inputs[inIndex].witnessScript = witnessScript;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInBIP32Derivation(inIndex: number, d: Bip32Derivation): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }

    if (d.pubkey.length !== 33) {
      throw new Error('invalid pubkey length');
    }

    const pset = this.pset.copy();
    if (!pset.inputs[inIndex].bip32Derivation) {
      pset.inputs[inIndex].bip32Derivation = [];
    }
    if (
      pset.inputs[inIndex].bip32Derivation!.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('duplicated bip32 derivation pubkey');
    }
    pset.inputs[inIndex].bip32Derivation!.push(d);
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInSighashType(inIndex: number, sighashType: number): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }
    if (sighashType <= 0) {
      throw new Error('invalid sighash type');
    }

    const pset = this.pset.copy();
    pset.inputs[inIndex].sighashType = sighashType;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInIssuance(inIndex: number, args: AddInIssuanceArgs): void {
    this.validateIssuanceInput(inIndex);
    validateAddInIssuanceArgs(args);

    const pset = this.pset.copy();

    const assetAmount = args.assetAmount || 0;
    const tokenAmount = args.tokenAmount || 0;
    const issuance = newIssuance(assetAmount, tokenAmount, args.contract);

    pset.inputs[inIndex].issuanceValue = assetAmount;
    pset.inputs[inIndex].issuanceInflationKeys = tokenAmount;
    pset.inputs[inIndex].issuanceAssetEntropy = issuance.assetEntropy;
    pset.inputs[inIndex].issuanceBlindingNonce = issuance.assetBlindingNonce;

    const entropy = generateEntropy(
      {
        txHash: pset.inputs[inIndex].previousTxid,
        vout: pset.inputs[inIndex].previousTxIndex,
      },
      issuance.assetEntropy,
    );

    if (assetAmount > 0) {
      const issuedAsset = AssetHash.fromBytes(calculateAsset(entropy)).hex;
      const blinderIndex = isConfidential(args.assetAddress!)
        ? inIndex
        : undefined;
      const output = new Output(
        issuedAsset,
        assetAmount,
        args.assetAddress,
        blinderIndex,
      );
      pset.addOutput(output.toPartialOutput());
    }

    if (tokenAmount > 0) {
      const reissuanceToken = AssetHash.fromBytes(
        calculateReissuanceToken(entropy, args.blindedIssuance),
      ).hex;
      const blinderIndex = isConfidential(args.tokenAddress!)
        ? inIndex
        : undefined;
      const output = new Output(
        reissuanceToken,
        tokenAmount,
        args.tokenAddress,
        blinderIndex,
      );
      pset.addOutput(output.toPartialOutput());
    }

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInReissuance(inIndex: number, args: AddInReissuanceArgs): void {
    this.validateReissuanceInput(inIndex);
    validateAddInReissuanceArgs(args);

    const pset = this.pset.copy();

    const entropy =
      typeof args.entropy === 'string'
        ? Buffer.from(args.entropy, 'hex').reverse()
        : args.entropy;
    const blindingNonce =
      typeof args.tokenAssetBlinder === 'string'
        ? Buffer.from(args.tokenAssetBlinder, 'hex').reverse()
        : args.tokenAssetBlinder;
    const asset = AssetHash.fromBytes(calculateAsset(entropy)).hex;
    const reissuanceToken = AssetHash.fromBytes(
      calculateReissuanceToken(entropy, true),
    ).hex;

    pset.inputs[inIndex].issuanceAssetEntropy = entropy;
    pset.inputs[inIndex].issuanceBlindingNonce = blindingNonce;
    pset.inputs[inIndex].issuanceValue = args.assetAmount;
    pset.inputs[inIndex].issuanceInflationKeys = args.tokenAmount;

    const assetOutput = new Output(
      asset,
      args.assetAmount,
      args.assetAddress,
      inIndex,
    );
    const tokenOutput = new Output(
      reissuanceToken,
      args.tokenAmount,
      args.tokenAddress,
      inIndex,
    );
    pset.addOutput(assetOutput.toPartialOutput());
    pset.addOutput(tokenOutput.toPartialOutput());

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addInPartialSignature(
    inIndex: number,
    ps: PartialSig,
    validator: ValidateSigFunction,
  ): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }

    // ensure the pubkey and signature are valid
    validatePartialSignature(ps);

    // check for duplicates
    if (
      (this.pset.inputs[inIndex].partialSigs || []).some(({ pubkey }) =>
        pubkey.equals(ps.pubkey),
      )
    ) {
      throw new Error('duplicated signature pubkey');
    }

    const pset = this.pset.copy();

    // validate signature against input's preimage and pubkey
    const sighashType = ps.signature.slice(-1)[0];
    const preimage = pset.getInputPreimage(inIndex, sighashType);
    const { signature } = bscript.signature.decode(ps.signature);
    if (!validator(ps.pubkey, preimage, signature)) {
      throw new Error('invalid signature');
    }

    if (!pset.inputs[inIndex].partialSigs) {
      pset.inputs[inIndex].partialSigs = [];
    }
    pset.inputs[inIndex].partialSigs!.push(ps);

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addOutBIP32Derivation(outIndex: number, d: Bip32Derivation): void {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('output index out of range');
    }

    if (d.pubkey.length !== 33) {
      throw new Error('invalid pubkey length');
    }

    const pset = this.pset.copy();
    if (!pset.outputs[outIndex].bip32Derivation) {
      pset.outputs[outIndex].bip32Derivation = [];
    }
    if (
      pset.outputs[outIndex].bip32Derivation!.some(({ pubkey }) =>
        pubkey.equals(d.pubkey),
      )
    ) {
      throw new Error('duplicated bip32 derivation pubkey');
    }
    pset.outputs[outIndex].bip32Derivation!.push(d);
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addOutRedeemScript(outIndex: number, redeemScript: Buffer): void {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('output index out of range');
    }
    const pset = this.pset.copy();
    pset.outputs[outIndex].redeemScript = redeemScript;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  addOutWitnessScript(outIndex: number, witnessScript: Buffer): void {
    if (outIndex < 0 || outIndex >= this.pset.globals.outputCount) {
      throw new Error('output index out of range');
    }
    const pset = this.pset.copy();
    pset.outputs[outIndex].witnessScript = witnessScript;
    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  private validateIssuanceInput(inIndex: number): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }

    const input = this.pset.inputs[inIndex];
    if (input.issuanceAssetEntropy! && input.issuanceAssetEntropy!.length > 0) {
      throw new Error('input ' + inIndex + ' already has an issuance');
    }
  }

  private validateReissuanceInput(inIndex: number): void {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }

    const input = this.pset.inputs[inIndex];
    if (input.issuanceAssetEntropy! && input.issuanceAssetEntropy!.length > 0) {
      throw new Error('input ' + inIndex + ' already has an issuance');
    }
    const prevout = input.getUtxo();
    if (!prevout) {
      throw new Error('input is missing prevout (non-)witness utxo');
    }
    if (prevout.nonce.length <= 1) {
      throw new Error('input prevout (non-)witness utxo must be confidential');
    }
  }
}

function validateAddInIssuanceArgs(args: AddInIssuanceArgs): void {
  const assetAmount = args.assetAmount || 0;
  const tokenAmount = args.tokenAmount || 0;
  if (assetAmount <= 0 && tokenAmount <= 0) {
    throw new Error('either asset or token amounts must be a positive number');
  }

  if (assetAmount > 0) {
    if (!args.assetAddress || args.assetAddress!.length === 0) {
      throw new Error(
        'asset address must be defined if asset amount is non-zero',
      );
    }
  }
  if (tokenAmount > 0) {
    if (!args.tokenAddress || args.tokenAddress!.length === 0) {
      throw new Error(
        'token address must be defined if token amount is non-zero',
      );
    }
  }

  if (!matchAddressesType(args.assetAddress, args.tokenAddress)) {
    throw new Error(
      'asset and token addresses must be of same network and both unconfidential or confidential',
    );
  }
}

function validateAddInReissuanceArgs(args: AddInReissuanceArgs): void {
  const entropy =
    typeof args.entropy === 'string'
      ? Buffer.from(args.entropy, 'hex').reverse()
      : args.entropy;
  if (entropy.length !== 32) {
    throw new Error('invalid entropy length');
  }
  const blinder =
    typeof args.tokenAssetBlinder === 'string'
      ? Buffer.from(args.tokenAssetBlinder, 'hex').reverse()
      : args.tokenAssetBlinder;
  if (blinder.length !== 32) {
    throw new Error('invalid token asset blinder length');
  }
  if (args.assetAmount <= 0) {
    throw new Error('asset amount must be a positive number');
  }
  if (args.tokenAmount <= 0) {
    throw new Error('token amount must be a positive number');
  }
  if (args.assetAddress.length === 0) {
    throw new Error('missing asset address');
  }
  if (args.tokenAddress.length === 0) {
    throw new Error('missing token address');
  }

  if (!matchAddressesType(args.assetAddress, args.tokenAddress)) {
    throw new Error(
      'asset and token addresses must be both of same network and both confidential',
    );
  }
  if (!isConfidential(args.assetAddress)) {
    throw new Error('asset and token addresses must be both confidential');
  }
}

function matchAddressesType(addrA?: string, addrB?: string): boolean {
  if (!addrA || addrA!.length === 0 || (!addrB || addrB!.length === 0)) {
    return true;
  }

  const netA = getNetwork(addrA);
  const netB = getNetwork(addrB);
  if (netA.name !== netB.name) {
    return false;
  }

  const isConfidentialA = isConfidential(addrA);
  const isConfidentialB = isConfidential(addrB);
  if (isConfidentialA !== isConfidentialB) {
    return false;
  }

  return true;
}

function validatePartialSignature(psig: PartialSig): void {
  if (psig.pubkey.length !== 33) {
    throw new Error('invalid pubkey length');
  }
  bscript.signature.decode(psig.signature);
}
