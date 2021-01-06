'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const confidential = require('./confidential');
function bufferNotEmptyOrNull(buffer) {
  return (
    buffer != null && buffer.length > 0 && buffer != Buffer.from('0x00', 'hex')
  );
}
function isConfidentialUtxo(witnessUtxo) {
  return (
    bufferNotEmptyOrNull(witnessUtxo.rangeProof) &&
    bufferNotEmptyOrNull(witnessUtxo.surjectionProof) &&
    bufferNotEmptyOrNull(witnessUtxo.nonce)
  );
}
exports.isConfidentialUtxo = isConfidentialUtxo;
function tryToUnblindWitnessUtxo(prevout, blindingPrivKey) {
  const unblindPrevout = {
    value: '',
    ag: Buffer.alloc(0),
    abf: Buffer.alloc(0),
    vbf: Buffer.alloc(0),
  };
  const unblindProof = confidential.unblindOutput(
    prevout.nonce,
    blindingPrivKey,
    prevout.rangeProof,
    prevout.value,
    prevout.asset,
    prevout.script,
  );
  unblindPrevout.ag = unblindProof.asset;
  unblindPrevout.value = unblindProof.value;
  unblindPrevout.abf = unblindProof.assetBlindingFactor;
  unblindPrevout.vbf = unblindProof.valueBlindingFactor;
  return unblindPrevout;
}
exports.tryToUnblindWitnessUtxo = tryToUnblindWitnessUtxo;
function tryToUnblindWithSetOfPrivKeys(prevout, blindingPrivKeys) {
  for (const key of blindingPrivKeys) {
    try {
      const unblindResult = tryToUnblindWitnessUtxo(prevout, key);
      return {
        result: unblindResult,
        success: true,
      };
    } catch (_) {
      continue;
    }
  }
  return {
    result: undefined,
    success: false,
  };
}
exports.tryToUnblindWithSetOfPrivKeys = tryToUnblindWithSetOfPrivKeys;
