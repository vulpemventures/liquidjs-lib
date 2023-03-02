'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.findTapLeafToFinalize =
  exports.sortSignatures =
  exports.serializeTaprootSignature =
  exports.toXOnly =
    void 0;
const bip341_1 = require('../bip341');
const utils_1 = require('./utils');
const toXOnly = (pubkey) => {
  switch (pubkey.length) {
    case 32:
      return pubkey;
    case 33:
      return Buffer.from(pubkey.slice(1));
    default:
      throw new Error('Invalid pubkey length');
  }
};
exports.toXOnly = toXOnly;
function serializeTaprootSignature(sig, sighashType) {
  const sighashTypeByte = sighashType
    ? Buffer.from([sighashType])
    : Buffer.from([]);
  return Buffer.concat([sig, sighashTypeByte]);
}
exports.serializeTaprootSignature = serializeTaprootSignature;
function sortSignatures(input, tapLeaf) {
  const leafHash = (0, bip341_1.tapLeafHash)({
    scriptHex: tapLeaf.script.toString('hex'),
    version: tapLeaf.leafVersion,
  });
  return (input.tapScriptSig || [])
    .filter((tss) => tss.leafHash.equals(leafHash))
    .map((tss) => addPubkeyPositionInScript(tapLeaf.script, tss))
    .sort((t1, t2) => t2.positionInScript - t1.positionInScript)
    .map((t) => t.signature);
}
exports.sortSignatures = sortSignatures;
function addPubkeyPositionInScript(script, tss) {
  return Object.assign(
    {
      positionInScript: (0, utils_1.pubkeyPositionInScript)(tss.pubkey, script),
    },
    tss,
  );
}
/**
 * Find tapleaf by hash, or get the signed tapleaf with the shortest path.
 */
function findTapLeafToFinalize(input, inputIndex, leafHashToFinalize) {
  if (!input.tapScriptSig || !input.tapScriptSig.length)
    throw new Error(
      `Can not finalize taproot input #${inputIndex}. No tapleaf script signature provided.`,
    );
  const tapLeaf = (input.tapLeafScript || [])
    .sort((a, b) => a.controlBlock.length - b.controlBlock.length)
    .find((leaf) =>
      canFinalizeLeaf(leaf, input.tapScriptSig, leafHashToFinalize),
    );
  if (!tapLeaf)
    throw new Error(
      `Can not finalize taproot input #${inputIndex}. Signature for tapleaf script not found.`,
    );
  return tapLeaf;
}
exports.findTapLeafToFinalize = findTapLeafToFinalize;
function canFinalizeLeaf(leaf, tapScriptSig, hash) {
  const leafHash = (0, bip341_1.tapLeafHash)({
    scriptHex: leaf.script.toString('hex'),
    version: leaf.leafVersion,
  });
  const whiteListedHash = !hash || hash.equals(leafHash);
  return (
    whiteListedHash &&
    tapScriptSig.find((tss) => tss.leafHash.equals(leafHash)) !== undefined
  );
}
