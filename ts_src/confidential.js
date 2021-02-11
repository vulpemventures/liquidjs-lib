"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const bufferutils = require("./bufferutils");
const crypto = require("./crypto");
const secp256k1_zkp_1 = require("secp256k1-zkp");
const secp256k1Promise = secp256k1_zkp_1.default();
async function nonceHash(pubkey, privkey) {
    const { ecdh } = await secp256k1Promise;
    return crypto.sha256(ecdh(pubkey, privkey));
}
async function valueBlindingFactor(inValues, outValues, inGenerators, outGenerators, inFactors, outFactors) {
    const { pedersen } = await secp256k1Promise;
    const values = inValues.concat(outValues);
    const nInputs = inValues.length;
    const generators = inGenerators.concat(outGenerators);
    const factors = inFactors.concat(outFactors);
    return pedersen.blindGeneratorBlindSum(values, nInputs, generators, factors);
}
exports.valueBlindingFactor = valueBlindingFactor;
async function valueCommitment(value, gen, factor) {
    const { generator, pedersen } = await secp256k1Promise;
    const generatorParsed = generator.parse(gen);
    const commit = pedersen.commit(factor, value, generatorParsed);
    return pedersen.commitSerialize(commit);
}
exports.valueCommitment = valueCommitment;
async function assetCommitment(asset, factor) {
    const { generator } = await secp256k1Promise;
    const gen = generator.generateBlinded(asset, factor);
    return generator.serialize(gen);
}
exports.assetCommitment = assetCommitment;
async function unblindOutputWithKey(out, blindingPrivKey) {
    const nonce = await nonceHash(out.nonce, blindingPrivKey);
    return unblindOutputWithNonce(out, nonce);
}
exports.unblindOutputWithKey = unblindOutputWithKey;
async function unblindOutputWithNonce(out, nonce) {
    const secp = await secp256k1Promise;
    const gen = secp.generator.parse(out.asset);
    const { value, blindFactor, message } = secp.rangeproof.rewind(out.value, out.rangeProof, nonce, gen, out.script);
    return {
        value,
        asset: message.slice(0, 32),
        valueBlindingFactor: blindFactor,
        assetBlindingFactor: message.slice(32),
    };
}
exports.unblindOutputWithNonce = unblindOutputWithNonce;
async function rangeProofInfo(proof) {
    const { rangeproof } = await secp256k1Promise;
    const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
    return {
        minValue: parseInt(minValue, 10),
        maxValue: parseInt(maxValue, 10),
        ctExp: exp,
        ctBits: parseInt(mantissa, 10),
    };
}
exports.rangeProofInfo = rangeProofInfo;
async function rangeProof(value, blindingPubkey, ephemeralPrivkey, asset, assetBlindingFactor, valueBlindFactor, valueCommit, scriptPubkey, minValue, exp, minBits) {
    const { generator, pedersen, rangeproof } = await secp256k1Promise;
    const nonce = await nonceHash(blindingPubkey, ephemeralPrivkey);
    const gen = generator.generateBlinded(asset, assetBlindingFactor);
    const message = Buffer.concat([asset, assetBlindingFactor]);
    const commit = pedersen.commitParse(valueCommit);
    const mv = minValue ? minValue : '1';
    const e = exp ? exp : 0;
    const mb = minBits ? minBits : 36;
    return rangeproof.sign(commit, valueBlindFactor, nonce, value, gen, mv, e, mb, message, scriptPubkey);
}
exports.rangeProof = rangeProof;
async function surjectionProof(outputAsset, outputAssetBlindingFactor, inputAssets, inputAssetBlindingFactors, seed) {
    const { generator, surjectionproof } = await secp256k1Promise;
    const outputGenerator = generator.generateBlinded(outputAsset, outputAssetBlindingFactor);
    const inputGenerators = inputAssets.map((v, i) => generator.generateBlinded(v, inputAssetBlindingFactors[i]));
    const nInputsToUse = inputAssets.length > 3 ? 3 : inputAssets.length;
    const maxIterations = 100;
    const init = surjectionproof.initialize(inputAssets, nInputsToUse, outputAsset, maxIterations, seed);
    const proof = surjectionproof.generate(init.proof, inputGenerators, outputGenerator, init.inputIndex, inputAssetBlindingFactors[init.inputIndex], outputAssetBlindingFactor);
    return surjectionproof.serialize(proof);
}
exports.surjectionProof = surjectionProof;
const CONFIDENTIAL_VALUE = 9; // explicit size of confidential values
function confidentialValueToSatoshi(value) {
    if (!isUnconfidentialValue(value)) {
        throw new Error('Value must be unconfidential, length or the prefix are not valid');
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
