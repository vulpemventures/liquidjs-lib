'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.Finalizer = void 0;
const __1 = require('..');
const bip371_1 = require('./bip371');
const utils_1 = require('./utils');
class Finalizer {
  constructor(pset) {
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
  finalizeInput(inIndex, finalizeFunc = defaultFinalizer) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const input = this.pset.inputs[inIndex];
    if (input.isFinalized()) {
      return this;
    }
    if (input.sighashType === undefined) {
      throw new Error('Missing input sighash type');
    }
    if (!input.getUtxo()) {
      throw new Error('Missing input (non-)witness utxo');
    }
    const pset = this.pset.copy();
    const { finalScriptSig, finalScriptWitness } = finalizeFunc(inIndex, pset);
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
    return this;
  }
}
exports.Finalizer = Finalizer;
function getScriptFromInput(input) {
  const res = {
    script: null,
    isSegwit: false,
    isP2SH: false,
    isP2WSH: false,
  };
  res.isP2SH = !!input.redeemScript;
  res.isP2WSH = !!input.witnessScript;
  if (input.witnessScript) {
    res.script = input.witnessScript;
  } else if (input.redeemScript) {
    res.script = input.redeemScript;
  } else {
    if (input.nonWitnessUtxo) {
      res.script = input.nonWitnessUtxo.outs[input.previousTxIndex].script;
    } else if (input.witnessUtxo) {
      res.script = input.witnessUtxo.script;
    }
  }
  if (input.witnessScript || (0, utils_1.isP2WPKH)(res.script)) {
    res.isSegwit = true;
  }
  return res;
}
const defaultFinalizer = (inIndex, pset) => {
  const input = pset.inputs[inIndex];
  // if we use the defaut finalizer we assume the input script has a CHECKSIG operation
  if (
    (!input.partialSigs || input.partialSigs.length === 0) &&
    (!input.tapKeySig || input.tapKeySig.length === 0) &&
    (!input.tapScriptSig || input.tapScriptSig.length === 0)
  ) {
    throw new Error(
      `Missing partial signatures for input at index ${inIndex}. If the script does not have a CHECKSIG operation you must pass a custom finalizer function`,
    );
  }
  if (input.isTaproot()) return finalizeTaprootInput(inIndex, pset);
  return finalizeInput(inIndex, pset);
};
const finalizeInput = (inIndex, pset) => {
  const input = pset.inputs[inIndex];
  const { script, isP2SH, isP2WSH, isSegwit } = getScriptFromInput(input);
  if (!script) throw new Error(`No script found for input #${inIndex}`);
  return getFinalScripts(inIndex, input, script, isSegwit, isP2SH, isP2WSH);
};
const finalizeTaprootInput = (inIndex, pset) => {
  const input = pset.inputs[inIndex];
  if (!input.witnessUtxo)
    throw new Error(
      `Cannot finalize input #${inIndex}. Missing withness utxo.`,
    );
  // Check key spend first. Increased privacy and reduced block space.
  if (input.tapKeySig) {
    return {
      finalScriptWitness: (0, utils_1.witnessStackToScriptWitness)([
        input.tapKeySig,
      ]),
    };
  } else {
    return getTaprootFinalScripts(inIndex, input);
  }
};
function getFinalScripts(inputIndex, input, script, isSegwit, isP2SH, isP2WSH) {
  const scriptType = (0, utils_1.classifyScript)(script);
  if (!canFinalize(input, script, scriptType))
    throw new Error(`Can not finalize input #${inputIndex}`);
  return prepareFinalScripts(
    script,
    scriptType,
    input.partialSigs,
    isSegwit,
    isP2SH,
    isP2WSH,
  );
}
function prepareFinalScripts(
  script,
  scriptType,
  partialSig,
  isSegwit,
  isP2SH,
  isP2WSH,
) {
  if (scriptType === 'nonstandard')
    return {
      finalScriptSig: undefined,
      finalScriptWitness: undefined,
    };
  let finalScriptSig;
  let finalScriptWitness;
  // Wow, the payments API is very handy
  const payment = (0, utils_1.getPayment)(script, scriptType, partialSig);
  const p2wsh = !isP2WSH ? null : __1.payments.p2wsh({ redeem: payment });
  const p2sh = !isP2SH ? null : __1.payments.p2sh({ redeem: p2wsh || payment });
  if (isSegwit) {
    if (p2wsh) {
      finalScriptWitness = (0, utils_1.witnessStackToScriptWitness)(
        p2wsh.witness,
      );
    } else {
      finalScriptWitness = (0, utils_1.witnessStackToScriptWitness)(
        payment.witness,
      );
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
function canFinalize(input, script, scriptType) {
  switch (scriptType) {
    case 'pubkey':
    case 'pubkeyhash':
    case 'witnesspubkeyhash':
      return (0, utils_1.hasSigs)(1, input.partialSigs);
    case 'multisig':
      const p2ms = __1.payments.p2ms({ output: script });
      return (0, utils_1.hasSigs)(p2ms.m, input.partialSigs, p2ms.pubkeys);
    default:
      return false;
  }
}
function getTaprootFinalScripts(inputIndex, input, tapLeafHashToFinalize) {
  const tapLeaf = (0, bip371_1.findTapLeafToFinalize)(
    input,
    inputIndex,
    tapLeafHashToFinalize,
  );
  try {
    const sigs = (0, bip371_1.sortSignatures)(input, tapLeaf);
    const witness = sigs.concat(tapLeaf.script).concat(tapLeaf.controlBlock);
    return {
      finalScriptWitness: (0, utils_1.witnessStackToScriptWitness)(witness),
    };
  } catch (err) {
    throw new Error(`Can not finalize taproot input #${inputIndex}: ${err}`);
  }
}
