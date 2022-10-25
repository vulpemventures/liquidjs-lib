'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function (o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.satoshiToConfidentialValue =
  exports.confidentialValueToSatoshi =
  exports.Confidential =
    void 0;
const crypto = __importStar(require('./crypto'));
const transaction_1 = require('./transaction');
const value_1 = require('./value');
class Confidential {
  constructor(zkp) {
    this.zkp = zkp;
  }
  nonceHash(pubkey, privkey) {
    return crypto.sha256(this.zkp.ecdh(pubkey, privkey));
  }
  valueBlindingFactor(
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
    return this.zkp.pedersen.blindGeneratorBlindSum(
      values,
      nInputs,
      generators,
      factors,
    );
  }
  valueCommitment(value, gen, factor) {
    const { generator, pedersen } = this.zkp;
    const generatorParsed = generator.parse(gen);
    const commit = pedersen.commit(factor, value, generatorParsed);
    return pedersen.commitSerialize(commit);
  }
  assetCommitment(asset, factor) {
    const { generator } = this.zkp;
    const gen = generator.generateBlinded(asset, factor);
    return generator.serialize(gen);
  }
  unblindOutputWithKey(out, blindingPrivKey) {
    const nonce = this.nonceHash(out.nonce, blindingPrivKey);
    return this.unblindOutputWithNonce(out, nonce);
  }
  unblindOutputWithNonce(out, nonce) {
    if (!out.rangeProof || out.rangeProof.length === 0) {
      throw new Error('Missing rangeproof to rewind');
    }
    const secp = this.zkp;
    const gen = secp.generator.parse(out.asset);
    const { value, blindFactor, message } = secp.rangeproof.rewind(
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
  rangeProofInfo(proof) {
    const { rangeproof } = this.zkp;
    const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
    return {
      minValue: parseInt(minValue, 10),
      maxValue: parseInt(maxValue, 10),
      ctExp: exp,
      ctBits: parseInt(mantissa, 10),
    };
  }
  /**
   *  nonceHash from blinding key + ephemeral key and then rangeProof computation
   */
  rangeProofWithNonceHash(
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
    const nonce = this.nonceHash(blindingPubkey, ephemeralPrivkey);
    return this.rangeProof(
      value,
      nonce,
      asset,
      assetBlindingFactor,
      valueBlindFactor,
      valueCommit,
      scriptPubkey,
      minValue,
      exp,
      minBits,
    );
  }
  rangeProofVerify(valueCommit, assetCommit, proof, script) {
    const { generator, pedersen, rangeproof } = this.zkp;
    const gen = generator.parse(assetCommit);
    const commit = pedersen.commitParse(valueCommit);
    return rangeproof.verify(commit, proof, gen, script);
  }
  /**
   *  rangeProof computation without nonceHash step.
   */
  rangeProof(
    value,
    nonce,
    asset,
    assetBlindingFactor,
    valueBlindFactor,
    valueCommit,
    scriptPubkey,
    minValue,
    exp,
    minBits,
  ) {
    const { generator, pedersen, rangeproof } = this.zkp;
    const gen = generator.generateBlinded(asset, assetBlindingFactor);
    const message = Buffer.concat([asset, assetBlindingFactor]);
    const commit = pedersen.commitParse(valueCommit);
    const mv = value === '0' ? '0' : minValue ? minValue : '1';
    const e = exp ? exp : 0;
    const mb = minBits ? minBits : 52;
    return rangeproof.sign(
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
  surjectionProof(
    outputAsset,
    outputAssetBlindingFactor,
    inputAssets,
    inputAssetBlindingFactors,
    seed,
  ) {
    const { generator, surjectionproof } = this.zkp;
    const outputGenerator = generator.generateBlinded(
      outputAsset,
      outputAssetBlindingFactor,
    );
    const inputGenerators = inputAssets.map((v, i) =>
      generator.generateBlinded(v, inputAssetBlindingFactors[i]),
    );
    const nInputsToUse = inputAssets.length > 3 ? 3 : inputAssets.length;
    const maxIterations = 100;
    const init = surjectionproof.initialize(
      inputAssets,
      nInputsToUse,
      outputAsset,
      maxIterations,
      seed,
    );
    const proof = surjectionproof.generate(
      init.proof,
      inputGenerators,
      outputGenerator,
      init.inputIndex,
      inputAssetBlindingFactors[init.inputIndex],
      outputAssetBlindingFactor,
    );
    return surjectionproof.serialize(proof);
  }
  surjectionProofVerify(
    inAssets,
    inAssetBlinders,
    outAsset,
    outAssetBlinder,
    proof,
  ) {
    const { generator, surjectionproof } = this.zkp;
    const inGenerators = inAssets.map((v, i) =>
      generator.generateBlinded(v, inAssetBlinders[i]),
    );
    const outGenerator = generator.generateBlinded(outAsset, outAssetBlinder);
    const sProof = surjectionproof.parse(proof);
    return surjectionproof.verify(sProof, inGenerators, outGenerator);
  }
  blindValueProof(value, valueCommit, assetCommit, valueBlinder, nonce) {
    const { generator, pedersen, rangeproof } = this.zkp;
    const gen = generator.parse(assetCommit);
    const commit = pedersen.commitParse(valueCommit);
    return rangeproof.sign(commit, valueBlinder, nonce, value, gen, value, -1);
  }
  blindAssetProof(asset, assetCommit, assetBlinder) {
    const { generator, surjectionproof } = this.zkp;
    const nInputsToUse = 1;
    const maxIterations = 100;
    const init = surjectionproof.initialize(
      [asset],
      nInputsToUse,
      asset,
      maxIterations,
      transaction_1.ZERO,
    );
    const gen = generator.generate(asset);
    const assetGen = generator.parse(assetCommit);
    const proof = surjectionproof.generate(
      init.proof,
      [gen],
      assetGen,
      init.inputIndex,
      transaction_1.ZERO,
      assetBlinder,
    );
    return surjectionproof.serialize(proof);
  }
  assetBlindProofVerify(asset, assetCommit, proof) {
    const { generator, surjectionproof } = this.zkp;
    const inGenerators = [generator.generate(asset)];
    const outGenerator = generator.parse(assetCommit);
    const sProof = surjectionproof.parse(proof);
    return surjectionproof.verify(sProof, inGenerators, outGenerator);
  }
}
exports.Confidential = Confidential;
function confidentialValueToSatoshi(value) {
  return value_1.ElementsValue.fromBytes(value).number;
}
exports.confidentialValueToSatoshi = confidentialValueToSatoshi;
function satoshiToConfidentialValue(amount) {
  return value_1.ElementsValue.fromNumber(amount).bytes;
}
exports.satoshiToConfidentialValue = satoshiToConfidentialValue;
