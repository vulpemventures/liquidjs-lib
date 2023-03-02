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
    return crypto.sha256(Buffer.from(this.zkp.ecdh(pubkey, privkey)));
  }
  valueBlindingFactor(
    inValues,
    outValues,
    inAssetBlinders,
    outAssetBlinders,
    inValueBlinders,
    outValueBlinders,
  ) {
    const values = inValues.concat(outValues);
    const nInputs = inValues.length;
    const assetBlinders = inAssetBlinders.concat(outAssetBlinders);
    const valueBlinders = inValueBlinders.concat(outValueBlinders);
    return Buffer.from(
      this.zkp.pedersen.blindGeneratorBlindSum(
        values,
        assetBlinders,
        valueBlinders,
        nInputs,
      ),
    );
  }
  valueCommitment(value, generator, blinder) {
    const { pedersen } = this.zkp;
    return Buffer.from(pedersen.commitment(value, generator, blinder));
  }
  assetCommitment(asset, factor) {
    const { generator } = this.zkp;
    return Buffer.from(generator.generateBlinded(asset, factor));
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
    const { value, blinder, message } = secp.rangeproof.rewind(
      out.rangeProof,
      out.value,
      out.asset,
      nonce,
      out.script,
    );
    return {
      value,
      asset: Buffer.from(message.slice(0, 32)),
      valueBlindingFactor: Buffer.from(blinder),
      assetBlindingFactor: Buffer.from(message.slice(32)),
    };
  }
  rangeProofInfo(proof) {
    const { rangeproof } = this.zkp;
    const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
    return {
      minValue: parseInt(minValue, 10),
      maxValue: parseInt(maxValue, 10),
      ctExp: parseInt(exp, 10),
      ctBits: parseInt(mantissa, 10),
    };
  }
  /**
   *  nonceHash from blinding key + ephemeral key and then rangeProof computation
   */
  rangeProofWithNonceHash(
    blindingPubkey,
    ephemeralPrivkey,
    value,
    asset,
    valueCommitment,
    assetCommitment,
    valueBlinder,
    assetBlinder,
    scriptPubkey,
    minValue,
    exp,
    minBits,
  ) {
    const nonce = this.nonceHash(blindingPubkey, ephemeralPrivkey);
    return this.rangeProof(
      value,
      asset,
      valueCommitment,
      assetCommitment,
      valueBlinder,
      assetBlinder,
      nonce,
      scriptPubkey,
      minValue,
      exp,
      minBits,
    );
  }
  rangeProofVerify(proof, valueCommitment, assetCommitment, script) {
    const { rangeproof } = this.zkp;
    return rangeproof.verify(proof, valueCommitment, assetCommitment, script);
  }
  /**
   *  rangeProof computation without nonceHash step.
   */
  rangeProof(
    value,
    asset,
    valueCommitment,
    assetCommitment,
    valueBlinder,
    assetBlinder,
    nonce,
    scriptPubkey,
    minValue = '1',
    exp = '0',
    minBits = '52',
  ) {
    const { rangeproof } = this.zkp;
    const message = Buffer.concat([asset, assetBlinder]);
    return Buffer.from(
      rangeproof.sign(
        value,
        valueCommitment,
        assetCommitment,
        valueBlinder,
        nonce,
        parseInt(value, 10) === 0 ? '0' : minValue,
        exp,
        minBits,
        message,
        scriptPubkey,
      ),
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
    const maxIterations = 100;
    const init = surjectionproof.initialize(
      inputAssets,
      outputAsset,
      maxIterations,
      seed,
    );
    return Buffer.from(
      surjectionproof.generate(
        init.proof,
        inputGenerators,
        outputGenerator,
        init.inputIndex,
        inputAssetBlindingFactors[init.inputIndex],
        outputAssetBlindingFactor,
      ),
    );
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
    return surjectionproof.verify(proof, inGenerators, outGenerator);
  }
  blindValueProof(
    value,
    valueCommitment,
    assetCommitment,
    valueBlinder,
    nonce,
  ) {
    const { rangeproof } = this.zkp;
    return Buffer.from(
      rangeproof.sign(
        value,
        valueCommitment,
        assetCommitment,
        valueBlinder,
        nonce,
        value,
        '-1',
      ),
    );
  }
  blindAssetProof(asset, assetCommitment, assetBlinder) {
    const { generator, surjectionproof } = this.zkp;
    const maxIterations = 100;
    const gen = generator.generate(asset);
    const init = surjectionproof.initialize(
      [asset],
      asset,
      maxIterations,
      transaction_1.ZERO,
    );
    return Buffer.from(
      surjectionproof.generate(
        init.proof,
        [gen],
        assetCommitment,
        init.inputIndex,
        transaction_1.ZERO,
        assetBlinder,
      ),
    );
  }
  assetBlindProofVerify(asset, assetCommitment, proof) {
    const { generator, surjectionproof } = this.zkp;
    const inGenerators = [generator.generate(asset)];
    const outGenerator = assetCommitment;
    return surjectionproof.verify(proof, inGenerators, outGenerator);
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
