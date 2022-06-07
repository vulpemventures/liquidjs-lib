'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.Finalizer = void 0;
const __1 = require('..');
const psbt_1 = require('../psbt');
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
  finalizeInput(inputIndex, finalScriptsFunc) {
    // TODO: finalize taproot input
    return this._finalizeInput(inputIndex, finalScriptsFunc);
  }
  _finalizeInput(inIndex, finalScriptsFunc = getFinalScripts) {
    if (inIndex < 0 || inIndex >= this.pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    const input = this.pset.inputs[inIndex];
    if (input.isFinalized()) {
      return;
    }
    if (input.sighashType <= 0) {
      throw new Error('Missing input sighash type');
    }
    if (!input.getUtxo()) {
      throw new Error('Missing input (non-)witness utxo');
    }
    if (!input.partialSigs || input.partialSigs.length === 0) {
      throw new Error('Missing input partial signatures');
    }
    const pset = this.pset.copy();
    const { script, isP2SH, isP2WSH, isSegwit } = getScriptFromInput(input);
    if (!script) {
      throw new Error(`No script found for input #${inIndex}`);
    }
    if (
      input.partialSigs.some(
        ({ signature }) => signature.slice(-1)[0] !== input.sighashType,
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
      finalScriptWitness = (0, psbt_1.witnessStackToScriptWitness)(
        p2wsh.witness,
      );
    } else {
      finalScriptWitness = (0, psbt_1.witnessStackToScriptWitness)(
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
    case 'nonstandard':
      if (script[0] === 81) return true;
    default:
      return false;
  }
}
