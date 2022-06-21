import { Transaction } from '../transaction';
import { PartialSig, TapKeySig, TapScriptSig } from './interfaces';
import { Pset, ValidateSigFunction } from './pset';
import { Updater } from './updater';
import { isP2WPKH, isP2WSH } from './utils';

export interface BIP174SigningData {
  partialSig: PartialSig;
  redeemScript?: Buffer;
  witnessScript?: Buffer;
}

export interface BIP371SigningData {
  tapKeySig?: TapKeySig;
  tapScriptSigs?: TapScriptSig[];
  genesisBlockHash: Buffer;
}

export class Signer {
  pset: Pset;

  constructor(pset: Pset) {
    pset.sanityCheck();
    this.pset = pset;
  }

  addSignature(
    inIndex: number,
    sigData: BIP174SigningData | BIP371SigningData,
    validator: ValidateSigFunction,
  ): this {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const input = this.pset.inputs[inIndex];
    if (input.isFinalized()) {
      throw new Error('Input is already finalized');
    }
    if (input.sighashType === undefined) {
      throw new Error('Missing input sighash type');
    }
    if ((input.sighashType & 0x1f) === Transaction.SIGHASH_ALL) {
      if (
        this.pset.outputs.some(out => out.isBlinded() && !out.isFullyBlinded())
      ) {
        throw new Error('Pset must be fully blinded');
      }
    }

    if (input.isTaproot()) {
      return this._signTaprootInput(inIndex, sigData, validator);
    }

    return this._signInput(inIndex, sigData, validator);
  }

  private _signInput(
    inIndex: number,
    data: BIP174SigningData | BIP371SigningData,
    validator: ValidateSigFunction,
  ): this {
    const input = this.pset.inputs[inIndex];
    const pset = this.pset.copy();
    const sighashType = input.sighashType!;

    const {
      partialSig,
      witnessScript,
      redeemScript,
    } = data as BIP174SigningData;
    if (!partialSig) {
      throw new Error('Missing partial signature for input');
    }
    if (partialSig.signature.slice(-1)[0] !== sighashType) {
      throw new Error('Input and signature sighash types must match');
    }

    // in case a witness script is passed, we make sure that the input witness
    // utxo is set and we eventually unset the non-witness one if necessary.
    const u = new Updater(pset);
    if (witnessScript! && witnessScript!.length > 0) {
      u.addInWitnessScript(inIndex, witnessScript!);
      if (!input.witnessUtxo) {
        u.addInWitnessUtxo(
          inIndex,
          input.nonWitnessUtxo!.outs[input.previousTxIndex],
        );
        pset.inputs[inIndex].nonWitnessUtxo = undefined;
      }
    }
    // in case a redeem script is passed and it's a native segwit one, again,
    // we make sure that the input witness utxo is set.
    if (redeemScript! && redeemScript!.length > 0) {
      u.addInRedeemScript(inIndex, redeemScript);
      const isSegwit = isP2WPKH(redeemScript) || isP2WSH(redeemScript);
      if (isSegwit && !input.witnessUtxo) {
        u.addInWitnessUtxo(
          inIndex,
          input.nonWitnessUtxo!.outs[input.previousTxIndex],
        );
        pset.inputs[inIndex].nonWitnessUtxo = undefined;
      }
    }

    // at this point, if the input non-witness utxo is still set, we make sure to
    // transform it to a witness one if it's native segwit.
    if (pset.inputs[inIndex].nonWitnessUtxo!) {
      const script = input.nonWitnessUtxo!.outs[input.previousTxIndex].script;
      const isSegwit = isP2WPKH(script) || isP2WSH(script);
      if (isSegwit) {
        u.addInWitnessUtxo(
          inIndex,
          input.nonWitnessUtxo!.outs[input.previousTxIndex],
        );
        pset.inputs[inIndex].nonWitnessUtxo = undefined;
      }
    }

    u.addInPartialSignature(inIndex, partialSig, validator);

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }

  private _signTaprootInput(
    inIndex: number,
    data: BIP174SigningData | BIP371SigningData,
    validator: ValidateSigFunction,
  ): this {
    const pset = this.pset.copy();

    const {
      tapKeySig,
      tapScriptSigs,
      genesisBlockHash,
    } = data as BIP371SigningData;
    if (!tapKeySig && (!tapScriptSigs || !tapScriptSigs.length)) {
      throw new Error('Missing taproot signature');
    }

    const u = new Updater(pset);
    if (!!tapKeySig) {
      u.addInTapKeySig(inIndex, tapKeySig, genesisBlockHash, validator);
    }
    if (!!tapScriptSigs) {
      tapScriptSigs.forEach(tapScriptSig => {
        u.addInTapScriptSig(inIndex, tapScriptSig, genesisBlockHash, validator);
      });
    }

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;

    return this;
  }
}
