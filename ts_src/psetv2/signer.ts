import { Transaction } from '../transaction';
import { PartialSig } from './interfaces';
import { Pset, ValidateSigFunction } from './pset';
import { Updater } from './updater';
import { isP2WPKH, isP2WSH } from './utils';

export class Signer {
  pset: Pset;

  constructor(pset: Pset) {
    pset.sanityCheck();
    this.pset = pset;
  }

  signInput(
    inIndex: number,
    psig: PartialSig,
    validator: ValidateSigFunction,
    redeemScript?: Buffer,
    witnessScript?: Buffer,
  ) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('input index out of range');
    }
    const input = this.pset.inputs[inIndex];
    if (input.isFinalized()) {
      return;
    }
    if (!input.sighashType) {
      throw new Error('missing input sighash type');
    }

    const pset = this.pset.copy();
    const sighashType = input.sighashType!;
    if (psig.signature.slice(-1)[0] !== sighashType) {
      throw new Error('input and signature sighash types must match');
    }
    if ((sighashType & 0x1f) === Transaction.SIGHASH_ALL) {
      if (pset.outputs.some(out => out.isBlinded() && !out.isFullyBlinded())) {
        throw new Error('pset must be fully blinded');
      }
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

    u.addInPartialSignature(inIndex, psig, validator);

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }
}
