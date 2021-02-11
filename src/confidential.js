'use strict';
var __awaiter =
  (this && this.__awaiter) ||
  function(thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function(resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator['throw'](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done
          ? resolve(result.value)
          : new P(function(resolve) {
              resolve(result.value);
            }).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  };
var __importStar =
  (this && this.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };
var __importDefault =
  (this && this.__importDefault) ||
  function(mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
const bufferutils = __importStar(require('./bufferutils'));
const crypto = __importStar(require('./crypto'));
const secp256k1_zkp_1 = __importDefault(require('secp256k1-zkp'));
const secp256k1Promise = secp256k1_zkp_1.default();
function nonceHash(pubkey, privkey) {
  return __awaiter(this, void 0, void 0, function*() {
    const { ecdh } = yield secp256k1Promise;
    return crypto.sha256(ecdh(pubkey, privkey));
  });
}
function valueBlindingFactor(
  inValues,
  outValues,
  inGenerators,
  outGenerators,
  inFactors,
  outFactors,
) {
  return __awaiter(this, void 0, void 0, function*() {
    const { pedersen } = yield secp256k1Promise;
    const values = inValues.concat(outValues);
    const nInputs = inValues.length;
    const generators = inGenerators.concat(outGenerators);
    const factors = inFactors.concat(outFactors);
    return pedersen.blindGeneratorBlindSum(
      values,
      nInputs,
      generators,
      factors,
    );
  });
}
exports.valueBlindingFactor = valueBlindingFactor;
function valueCommitment(value, gen, factor) {
  return __awaiter(this, void 0, void 0, function*() {
    const { generator, pedersen } = yield secp256k1Promise;
    const generatorParsed = generator.parse(gen);
    const commit = pedersen.commit(factor, value, generatorParsed);
    return pedersen.commitSerialize(commit);
  });
}
exports.valueCommitment = valueCommitment;
function assetCommitment(asset, factor) {
  return __awaiter(this, void 0, void 0, function*() {
    const { generator } = yield secp256k1Promise;
    const gen = generator.generateBlinded(asset, factor);
    return generator.serialize(gen);
  });
}
exports.assetCommitment = assetCommitment;
function unblindOutputWithKey(out, blindingPrivKey) {
  return __awaiter(this, void 0, void 0, function*() {
    const nonce = yield nonceHash(out.nonce, blindingPrivKey);
    return unblindOutputWithNonce(out, nonce);
  });
}
exports.unblindOutputWithKey = unblindOutputWithKey;
function unblindOutputWithNonce(out, nonce) {
  return __awaiter(this, void 0, void 0, function*() {
    const secp = yield secp256k1Promise;
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
  });
}
exports.unblindOutputWithNonce = unblindOutputWithNonce;
function rangeProofInfo(proof) {
  return __awaiter(this, void 0, void 0, function*() {
    const { rangeproof } = yield secp256k1Promise;
    const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
    return {
      minValue: parseInt(minValue, 10),
      maxValue: parseInt(maxValue, 10),
      ctExp: exp,
      ctBits: parseInt(mantissa, 10),
    };
  });
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
  return __awaiter(this, void 0, void 0, function*() {
    const { generator, pedersen, rangeproof } = yield secp256k1Promise;
    const nonce = yield nonceHash(blindingPubkey, ephemeralPrivkey);
    const gen = generator.generateBlinded(asset, assetBlindingFactor);
    const message = Buffer.concat([asset, assetBlindingFactor]);
    const commit = pedersen.commitParse(valueCommit);
    const mv = minValue ? minValue : '1';
    const e = exp ? exp : 0;
    const mb = minBits ? minBits : 36;
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
  });
}
exports.rangeProof = rangeProof;
function surjectionProof(
  outputAsset,
  outputAssetBlindingFactor,
  inputAssets,
  inputAssetBlindingFactors,
  seed,
) {
  return __awaiter(this, void 0, void 0, function*() {
    const { generator, surjectionproof } = yield secp256k1Promise;
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
  });
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
