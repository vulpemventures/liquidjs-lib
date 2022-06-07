import { payments } from '..';
import { witnessStackToScriptWitness } from '../psbt';
import { Input } from './input';
import { PartialSig } from './interfaces';
import { Pset } from './pset';
import { classifyScript, getPayment, hasSigs, isP2WPKH } from './utils';

export type FinalScriptsFunc = (
  inputIndex: number, // Which input is it?
  input: Input, // The PSBT input contents
  script: Buffer, // The "meaningful" locking script Buffer (redeemScript for P2SH etc.)
  isSegwit: boolean, // Is it segwit?
  isP2SH: boolean, // Is it P2SH?
  isP2WSH: boolean, // Is it P2WSH?
) => {
  finalScriptSig: Buffer | undefined;
  finalScriptWitness: Buffer | undefined;
};

export type FinalTaprootScriptsFunc = (
  inputIndex: number, // Which input is it?
  input: Input, // The PSBT input contents
  tapLeafHashToFinalize?: Buffer, // Only finalize this specific leaf
) => {
  finalScriptWitness: Buffer | undefined;
};

export class Finalizer {
  pset: Pset;

  constructor(pset: Pset) {
    pset.sanityCheck();
    this.pset = pset;
  }

  finalize() {
    const pset = this.pset.copy();

    pset.inputs.forEach((_, i) => {
      this.finalizeInput(i);
    });

    pset.sanityCheck;

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }

  finalizeInput(
    inputIndex: number,
    finalScriptsFunc?: FinalScriptsFunc | FinalTaprootScriptsFunc,
  ) {
    // TODO: finalize taproot input
    return this._finalizeInput(
      inputIndex,
      finalScriptsFunc as FinalScriptsFunc,
    );
  }

  private _finalizeInput(
    inIndex: number,
    finalScriptsFunc: FinalScriptsFunc = getFinalScripts,
  ) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }

    const input = this.pset.inputs[inIndex];
    if (input.isFinalized()) {
      return;
    }
    if (input.sighashType! <= 0) {
      throw new Error('Missing input sighash type');
    }
    if (!input.getUtxo()) {
      throw new Error('Missing input (non-)witness utxo');
    }
    if (!input.partialSigs || input.partialSigs!.length === 0) {
      throw new Error('Missing input partial signatures');
    }

    const pset = this.pset.copy();

    const { script, isP2SH, isP2WSH, isSegwit } = getScriptFromInput(input);
    if (!script) {
      throw new Error(`No script found for input #${inIndex}`);
    }

    if (
      input.partialSigs!.some(
        ({ signature }) => signature.slice(-1)[0] !== input.sighashType!,
      )
    ) {
      throw new Error(
        'input #${inIndex} and signature sighash types do not match',
      );
    }

    const { finalScriptSig, finalScriptWitness } = finalScriptsFunc(
      inIndex,
      input,
      script,
      isSegwit,
      isP2SH,
      isP2WSH,
    );

    if (finalScriptSig) {
      pset.inputs[inIndex].finalScriptSig = finalScriptSig;
    }
    if (finalScriptWitness) {
      pset.inputs[inIndex].finalScriptWitness = finalScriptWitness;
    }
    if (!finalScriptSig && !finalScriptWitness && !input.finalScriptWitness) {
      throw new Error(`Unknown error finalizing input #${inIndex}`);
    }

    pset.sanityCheck();

    this.pset.globals = pset.globals;
    this.pset.inputs = pset.inputs;
    this.pset.outputs = pset.outputs;
  }
}

interface GetScriptReturn {
  script: Buffer | null;
  isSegwit: boolean;
  isP2SH: boolean;
  isP2WSH: boolean;
}

function getScriptFromInput(input: Input): GetScriptReturn {
  const res: GetScriptReturn = {
    script: null,
    isSegwit: false,
    isP2SH: false,
    isP2WSH: false,
  };
  res.isP2SH = !!input.redeemScript;
  res.isP2WSH = !!input.witnessScript;
  if (input.witnessScript) {
    res.script = input.witnessScript!;
  } else if (input.redeemScript) {
    res.script = input.redeemScript!;
  } else {
    if (input.nonWitnessUtxo) {
      res.script = input.nonWitnessUtxo!.outs[input.previousTxIndex].script;
    } else if (input.witnessUtxo) {
      res.script = input.witnessUtxo!.script;
    }
  }
  if (input.witnessScript || isP2WPKH(res.script!)) {
    res.isSegwit = true;
  }
  return res;
}

function getFinalScripts(
  inputIndex: number,
  input: Input,
  script: Buffer,
  isSegwit: boolean,
  isP2SH: boolean,
  isP2WSH: boolean,
): {
  finalScriptSig: Buffer | undefined;
  finalScriptWitness: Buffer | undefined;
} {
  const scriptType = classifyScript(script);
  if (!canFinalize(input, script, scriptType))
    throw new Error(`Can not finalize input #${inputIndex}`);
  return prepareFinalScripts(
    script,
    scriptType,
    input.partialSigs!,
    isSegwit,
    isP2SH,
    isP2WSH,
  );
}

function prepareFinalScripts(
  script: Buffer,
  scriptType: string,
  partialSig: PartialSig[],
  isSegwit: boolean,
  isP2SH: boolean,
  isP2WSH: boolean,
): {
  finalScriptSig: Buffer | undefined;
  finalScriptWitness: Buffer | undefined;
} {
  if (scriptType === 'nonstandard')
    return {
      finalScriptSig: undefined,
      finalScriptWitness: undefined,
    };

  let finalScriptSig: Buffer | undefined;
  let finalScriptWitness: Buffer | undefined;

  // Wow, the payments API is very handy
  const payment: payments.Payment = getPayment(script, scriptType, partialSig);
  const p2wsh = !isP2WSH ? null : payments.p2wsh({ redeem: payment });
  const p2sh = !isP2SH ? null : payments.p2sh({ redeem: p2wsh || payment });

  if (isSegwit) {
    if (p2wsh) {
      finalScriptWitness = witnessStackToScriptWitness(p2wsh.witness!);
    } else {
      finalScriptWitness = witnessStackToScriptWitness(payment.witness!);
    }
    if (p2sh) {
      finalScriptSig = p2sh.input;
    }
  } else {
    if (p2sh) {
      finalScriptSig = p2sh.input;
    } else {
      finalScriptSig = payment.input;
    }
  }
  return {
    finalScriptSig,
    finalScriptWitness,
  };
}

function canFinalize(
  input: Input,
  script: Buffer,
  scriptType: string,
): boolean {
  switch (scriptType) {
    case 'pubkey':
    case 'pubkeyhash':
    case 'witnesspubkeyhash':
      return hasSigs(1, input.partialSigs!);
    case 'multisig':
      const p2ms = payments.p2ms({ output: script });
      return hasSigs(p2ms.m!, input.partialSigs!, p2ms.pubkeys);
    case 'nonstandard':
      if (script[0] === 81) return true;
    default:
      return false;
  }
}
