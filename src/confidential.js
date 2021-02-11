'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
const bufferutils = require('./bufferutils');
const crypto = require('./crypto');
const secp256k1 = require('secp256k1-zkp');
function nonceHash(pubkey, privkey) {
  return crypto.sha256(secp256k1.ecdh.ecdh(pubkey, privkey));
}
function valueBlindingFactor(
  inValues,
  outValues,
  inGenerators,
  outGenerators,
  inFactors,
  outFactors,
) {
  const values = inValues.concat(outValues);
  const nInputs = inValues.length;
  const generators = inGenerators.concat(outGenerators);
  const factors = inFactors.concat(outFactors);
  return secp256k1.pedersen.blindGeneratorBlindSum(
    values,
    nInputs,
    generators,
    factors,
  );
}
exports.valueBlindingFactor = valueBlindingFactor;
function valueCommitment(value, generator, factor) {
  const gen = secp256k1.generator.parse(generator);
  const commit = secp256k1.pedersen.commit(factor, value, gen);
  return secp256k1.pedersen.commitSerialize(commit);
}
exports.valueCommitment = valueCommitment;
function assetCommitment(asset, factor) {
  const generator = secp256k1.generator.generateBlinded(asset, factor);
  return secp256k1.generator.serialize(generator);
}
exports.assetCommitment = assetCommitment;
function unblindOutputWithKey(out, blindingPrivKey) {
  const nonce = nonceHash(out.nonce, blindingPrivKey);
  return unblindOutputWithNonce(out, nonce);
}
exports.unblindOutputWithKey = unblindOutputWithKey;
function unblindOutputWithNonce(out, nonce) {
  const gen = secp256k1.generator.parse(out.asset);
  const { value, blindFactor, message } = secp256k1.rangeproof.rewind(
    out.value,
    out.rangeProof,
    nonce,
    gen,
    out.script,
  );
  return {
    value,
    asset: message.slice(0, 32),
    valueBlindingFactor: blindFactor,
    assetBlindingFactor: message.slice(32),
  };
}
exports.unblindOutputWithNonce = unblindOutputWithNonce;
function rangeProofInfo(proof) {
  const { exp, mantissa, minValue, maxValue } = secp256k1.rangeproof.info(
    proof,
  );
  return {
    minValue: parseInt(minValue, 10),
    maxValue: parseInt(maxValue, 10),
    ctExp: exp,
    ctBits: parseInt(mantissa, 10),
  };
}
exports.rangeProofInfo = rangeProofInfo;
function rangeProof(
  value,
  blindingPubkey,
  ephemeralPrivkey,
  asset,
  assetBlindingFactor,
  valueBlindFactor,
  valueCommit,
  scriptPubkey,
  minValue,
  exp,
  minBits,
) {
  const nonce = nonceHash(blindingPubkey, ephemeralPrivkey);
  const gen = secp256k1.generator.generateBlinded(asset, assetBlindingFactor);
  const message = Buffer.concat([asset, assetBlindingFactor]);
  const commit = secp256k1.pedersen.commitParse(valueCommit);
  const mv = minValue ? minValue : '1';
  const e = exp ? exp : 0;
  const mb = minBits ? minBits : 36;
  return secp256k1.rangeproof.sign(
    commit,
    valueBlindFactor,
    nonce,
    value,
    gen,
    mv,
    e,
    mb,
    message,
    scriptPubkey,
  );
}
exports.rangeProof = rangeProof;
function surjectionProof(
  outputAsset,
  outputAssetBlindingFactor,
  inputAssets,
  inputAssetBlindingFactors,
  seed,
) {
  const outputGenerator = secp256k1.generator.generateBlinded(
    outputAsset,
    outputAssetBlindingFactor,
  );
  const inputGenerators = inputAssets.map((v, i) =>
    secp256k1.generator.generateBlinded(v, inputAssetBlindingFactors[i]),
  );
  const nInputsToUse = inputAssets.length > 3 ? 3 : inputAssets.length;
  const maxIterations = 100;
  const init = secp256k1.surjectionproof.initialize(
    inputAssets,
    nInputsToUse,
    outputAsset,
    maxIterations,
    seed,
  );
  const proof = secp256k1.surjectionproof.generate(
    init.proof,
    inputGenerators,
    outputGenerator,
    init.inputIndex,
    inputAssetBlindingFactors[init.inputIndex],
    outputAssetBlindingFactor,
  );
  return secp256k1.surjectionproof.serialize(proof);
}
exports.surjectionProof = surjectionProof;
const CONFIDENTIAL_VALUE = 9; // explicit size of confidential values
function confidentialValueToSatoshi(value) {
  if (!isUnconfidentialValue(value)) {
    throw new Error(
      'Value must be unconfidential, length or the prefix are not valid',
    );
  }
  const reverseValueBuffer = Buffer.allocUnsafe(CONFIDENTIAL_VALUE - 1);
  value.slice(1, CONFIDENTIAL_VALUE).copy(reverseValueBuffer, 0);
  bufferutils.reverseBuffer(reverseValueBuffer);
  return bufferutils.readUInt64LE(reverseValueBuffer, 0);
}
exports.confidentialValueToSatoshi = confidentialValueToSatoshi;
function satoshiToConfidentialValue(amount) {
  const unconfPrefix = Buffer.allocUnsafe(1);
  const valueBuffer = Buffer.allocUnsafe(CONFIDENTIAL_VALUE - 1);
  unconfPrefix.writeUInt8(1, 0);
  bufferutils.writeUInt64LE(valueBuffer, amount, 0);
  return Buffer.concat([unconfPrefix, bufferutils.reverseBuffer(valueBuffer)]);
}
exports.satoshiToConfidentialValue = satoshiToConfidentialValue;
function isUnconfidentialValue(value) {
  return value.length === CONFIDENTIAL_VALUE && value.readUInt8(0) === 1;
}
exports.isUnconfidentialValue = isUnconfidentialValue;
