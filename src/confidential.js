'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function() {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function(o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function(o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
var __importDefault =
  (this && this.__importDefault) ||
  function(mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.ZKPGenerator = exports.ZKPValidator = exports.assetBlindProofVerify = exports.blindAssetProof = exports.blindValueProof = exports.surjectionProofVerify = exports.surjectionProof = exports.rangeProof = exports.rangeProofVerify = exports.rangeProofWithNonceHash = exports.rangeProofInfo = exports.unblindOutputWithNonce = exports.unblindOutputWithKey = exports.assetCommitment = exports.valueCommitment = exports.valueBlindingFactor = void 0;
const crypto = __importStar(require('./crypto'));
const transaction_1 = require('./transaction');
const secp256k1_zkp_1 = __importDefault(
  require('@vulpemventures/secp256k1-zkp'),
);
const slip77_1 = require('slip77');
const value_1 = require('./value');
const ecpair_1 = require('ecpair');
const _randomBytes = require('randombytes');
const ecc = require('tiny-secp256k1');
const secp256k1Promise = (0, secp256k1_zkp_1.default)();
async function nonceHash(pubkey, privkey) {
  const { ecdh } = await secp256k1Promise;
  return crypto.sha256(ecdh(pubkey, privkey));
}
async function valueBlindingFactor(
  inValues,
  outValues,
  inGenerators,
  outGenerators,
  inFactors,
  outFactors,
) {
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
  if (!out.rangeProof || out.rangeProof.length === 0) {
    throw new Error('Missing rangeproof to rewind');
  }
  const secp = await secp256k1Promise;
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
/**
 *  nonceHash from blinding key + ephemeral key and then rangeProof computation
 */
async function rangeProofWithNonceHash(
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
  const nonce = await nonceHash(blindingPubkey, ephemeralPrivkey);
  return rangeProof(
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
exports.rangeProofWithNonceHash = rangeProofWithNonceHash;
async function rangeProofVerify(valueCommit, assetCommit, proof, script) {
  const { generator, pedersen, rangeproof } = await secp256k1Promise;
  const gen = generator.parse(assetCommit);
  const commit = pedersen.commitParse(valueCommit);
  return rangeproof.verify(commit, proof, gen, script);
}
exports.rangeProofVerify = rangeProofVerify;
/**
 *  rangeProof computation without nonceHash step.
 */
async function rangeProof(
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
  const { generator, pedersen, rangeproof } = await secp256k1Promise;
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
exports.rangeProof = rangeProof;
async function surjectionProof(
  outputAsset,
  outputAssetBlindingFactor,
  inputAssets,
  inputAssetBlindingFactors,
  seed,
) {
  const { generator, surjectionproof } = await secp256k1Promise;
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
exports.surjectionProof = surjectionProof;
async function surjectionProofVerify(
  inAssets,
  inAssetBlinders,
  outAsset,
  outAssetBlinder,
  proof,
) {
  const { generator, surjectionproof } = await secp256k1Promise;
  const inGenerators = inAssets.map((v, i) =>
    generator.generateBlinded(v, inAssetBlinders[i]),
  );
  const outGenerator = generator.generateBlinded(outAsset, outAssetBlinder);
  const sProof = surjectionproof.parse(proof);
  return surjectionproof.verify(sProof, inGenerators, outGenerator);
}
exports.surjectionProofVerify = surjectionProofVerify;
async function blindValueProof(
  value,
  valueCommit,
  assetCommit,
  valueBlinder,
  opts,
) {
  const { generator, pedersen, rangeproof } = await secp256k1Promise;
  const gen = generator.parse(assetCommit);
  const commit = pedersen.commitParse(valueCommit);
  const nonce = randomBytes(opts);
  return rangeproof.sign(commit, valueBlinder, nonce, value, gen, value, -1);
}
exports.blindValueProof = blindValueProof;
async function blindAssetProof(asset, assetCommit, assetBlinder) {
  const { generator, surjectionproof } = await secp256k1Promise;
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
exports.blindAssetProof = blindAssetProof;
async function assetBlindProofVerify(asset, assetCommit, proof) {
  const { generator, surjectionproof } = await secp256k1Promise;
  const inGenerators = [generator.generate(asset)];
  const outGenerator = generator.parse(assetCommit);
  const sProof = surjectionproof.parse(proof);
  return surjectionproof.verify(sProof, inGenerators, outGenerator);
}
exports.assetBlindProofVerify = assetBlindProofVerify;
class ZKPValidator {
  async verifyValueRangeProof(valueCommit, assetCommit, proof, script) {
    try {
      return await rangeProofVerify(valueCommit, assetCommit, proof, script);
    } catch (ignore) {
      return false;
    }
  }
  async verifyAssetSurjectionProof(
    inAssets,
    inAssetBlinders,
    outAsset,
    outAssetBlinder,
    proof,
  ) {
    try {
      return await surjectionProofVerify(
        inAssets,
        inAssetBlinders,
        outAsset,
        outAssetBlinder,
        proof,
      );
    } catch (ignore) {
      return false;
    }
  }
  async verifyBlindValueProof(valueCommit, assetCommit, proof) {
    try {
      return await rangeProofVerify(valueCommit, assetCommit, proof);
    } catch (ignore) {
      return false;
    }
  }
  async verifyBlindAssetProof(asset, assetCommit, proof) {
    try {
      return await assetBlindProofVerify(asset, assetCommit, proof);
    } catch (ignore) {
      return false;
    }
  }
}
exports.ZKPValidator = ZKPValidator;
class ZKPGenerator {
  constructor() {}
  static fromOwnedInputs(ownedInputs) {
    const bg = new ZKPGenerator();
    bg.ownedInputs = ownedInputs;
    return bg;
  }
  static fromInBlindingKeys(inBlindingKeys) {
    const bg = new ZKPGenerator();
    bg.inBlindingKeys = inBlindingKeys;
    return bg;
  }
  static fromMasterBlindingKey(masterKey) {
    const bg = new ZKPGenerator();
    bg.masterBlindingKey = (0, slip77_1.SLIP77Factory)(
      ecc,
    ).fromMasterBlindingKey(masterKey);
    return bg;
  }
  static ECCKeysGenerator(ec) {
    return opts => {
      const privateKey = randomBytes(opts);
      const publicKey = (0, ecpair_1.ECPairFactory)(ec).fromPrivateKey(
        privateKey,
      ).publicKey;
      return {
        privateKey,
        publicKey,
      };
    };
  }
  async computeAndAddToScalarOffset(scalar, value, assetBlinder, valueBlinder) {
    // If both asset and value blinders are null, 0 is added to the offset, so nothing actually happens
    if (
      assetBlinder.equals(transaction_1.ZERO) &&
      valueBlinder.equals(transaction_1.ZERO)
    ) {
      return scalar.slice();
    }
    const scalarOffset = await this.calculateScalarOffset(
      value,
      assetBlinder,
      valueBlinder,
    );
    // When we start out, the result (a) is 0, so just set it to the scalar we just computed.
    if (scalar.equals(transaction_1.ZERO)) {
      return scalarOffset;
    }
    const { ec } = await secp256k1Promise;
    const negScalarOffset = ec.prvkeyNegate(scalarOffset);
    if (scalar.equals(negScalarOffset)) {
      return transaction_1.ZERO;
    }
    return ec.prvkeyTweakAdd(scalar, scalarOffset);
  }
  async subtractScalars(inputScalar, outputScalar) {
    if (outputScalar.equals(transaction_1.ZERO)) {
      return inputScalar.slice();
    }
    const { ec } = await secp256k1Promise;
    const negOutputScalar = ec.prvkeyNegate(outputScalar);
    if (inputScalar.equals(transaction_1.ZERO)) {
      return negOutputScalar;
    }
    return ec.prvkeyTweakAdd(inputScalar, negOutputScalar);
  }
  async lastValueCommitment(value, asset, blinder) {
    return valueCommitment(value, asset, blinder);
  }
  async lastBlindValueProof(value, valueCommit, assetCommit, blinder) {
    return blindValueProof(value, valueCommit, assetCommit, blinder);
  }
  async lastValueRangeProof(
    value,
    asset,
    valueCommit,
    valueBlinder,
    assetBlinder,
    script,
    nonce,
  ) {
    return rangeProof(
      value,
      nonce,
      asset,
      assetBlinder,
      valueBlinder,
      valueCommit,
      script,
    );
  }
  async unblindInputs(pset, inIndexes) {
    validatePset(pset);
    if (inIndexes) {
      validateInIndexes(pset, inIndexes);
    }
    const inputIndexes =
      inIndexes || Array.from({ length: pset.globals.inputCount }, (_, i) => i);
    if (this.ownedInputs && this.ownedInputs.length > 0) {
      return this.ownedInputs;
    }
    const revealedInputs = await Promise.all(
      inputIndexes.map(async i => {
        const prevout = pset.inputs[i].getUtxo();
        const revealedInput = await this.unblindUtxo(prevout);
        revealedInput.index = i;
        return revealedInput;
      }),
    );
    this.ownedInputs = revealedInputs;
    return revealedInputs;
  }
  async blindIssuances(pset, blindingKeysByIndex) {
    validatePset(pset);
    validateBlindingKeysByIndex(pset, blindingKeysByIndex);
    return Promise.all(
      Object.entries(blindingKeysByIndex).map(async ([i, key]) => {
        const input = pset.inputs[parseInt(i, 10)];
        let blindingArgs = {};
        if (input.issuanceValue > 0) {
          const value = input.issuanceValue.toString(10);
          const asset = input.getIssuanceAssetHash();
          const blinder = randomBytes(this.opts);
          const assetCommit = await assetCommitment(asset, transaction_1.ZERO);
          const valueCommit = await valueCommitment(
            value,
            assetCommit,
            blinder,
          );
          const blindproof = await blindValueProof(
            value,
            valueCommit,
            assetCommit,
            blinder,
          );
          const rangeproof = await rangeProof(
            value,
            key,
            asset,
            transaction_1.ZERO,
            blinder,
            valueCommit,
            Buffer.from([]),
          );
          blindingArgs = {
            ...blindingArgs,
            index: parseInt(i, 10),
            issuanceAsset: asset,
            issuanceValueCommitment: valueCommit,
            issuanceValueRangeProof: rangeproof,
            issuanceValueBlindProof: blindproof,
            issuanceValueBlinder: blinder,
          };
        }
        if (input.issuanceInflationKeys > 0) {
          const token = input.issuanceInflationKeys.toString(10);
          const asset = input.getIssuanceInflationKeysHash(true);
          const blinder = randomBytes(this.opts);
          const assetCommit = await assetCommitment(asset, transaction_1.ZERO);
          const tokenCommit = await valueCommitment(
            token,
            assetCommit,
            blinder,
          );
          const blindproof = await blindValueProof(
            token,
            tokenCommit,
            assetCommit,
            blinder,
          );
          const rangeproof = await rangeProof(
            token,
            key,
            asset,
            transaction_1.ZERO,
            blinder,
            tokenCommit,
            Buffer.from([]),
          );
          blindingArgs = {
            ...blindingArgs,
            issuanceToken: asset,
            issuanceTokenCommitment: tokenCommit,
            issuanceTokenRangeProof: rangeproof,
            issuanceTokenBlindProof: blindproof,
            issuanceTokenBlinder: blinder,
          };
        }
        return blindingArgs;
      }),
    );
  }
  async blindOutputs(pset, keysGenerator, outIndexes, blindedIssuances) {
    validatePset(pset);
    if (outIndexes) {
      validateOutIndexes(pset, outIndexes);
    }
    if (blindedIssuances && blindedIssuances.length > 0) {
      validateBlindedIssuances(pset, blindedIssuances);
    }
    const outputIndexes =
      outIndexes && outIndexes.length > 0
        ? outIndexes
        : pset.outputs.reduce(
            (arr, out, i) => (out.needsBlinding() && arr.push(i), arr),
            [],
          );
    const { assets, assetBlinders } = await this.getInputAssetsAndBlinders(
      pset,
      blindedIssuances,
    );
    return Promise.all(
      outputIndexes.map(async i => {
        const output = pset.outputs[i];
        const assetBlinder = randomBytes(this.opts);
        const valueBlinder = randomBytes(this.opts);
        const seed = randomBytes(this.opts);
        const value = output.value.toString(10);
        const assetCommit = await assetCommitment(output.asset, assetBlinder);
        const valueCommit = await valueCommitment(
          value,
          assetCommit,
          valueBlinder,
        );
        const ephemeralKeyPair = keysGenerator();
        const nonceCommitment = ephemeralKeyPair.publicKey;
        const ecdhNonce = await nonceHash(
          output.blindingPubkey,
          ephemeralKeyPair.privateKey,
        );
        const script = output.script || Buffer.from([]);
        const rangeproof = await rangeProof(
          value,
          ecdhNonce,
          output.asset,
          assetBlinder,
          valueBlinder,
          valueCommit,
          script,
        );
        const surjectionproof = await surjectionProof(
          output.asset,
          assetBlinder,
          assets,
          assetBlinders,
          seed,
        );
        const valueBlindProof = await blindValueProof(
          value,
          valueCommit,
          assetCommit,
          valueBlinder,
        );
        const assetBlindProof = await blindAssetProof(
          output.asset,
          assetCommit,
          assetBlinder,
        );
        return {
          index: i,
          nonce: ecdhNonce,
          nonceCommitment,
          valueCommitment: valueCommit,
          assetCommitment: assetCommit,
          valueRangeProof: rangeproof,
          assetSurjectionProof: surjectionproof,
          valueBlindProof,
          assetBlindProof,
          valueBlinder,
          assetBlinder,
        };
      }),
    );
  }
  async calculateScalarOffset(value, assetBlinder, valueBlinder) {
    if (assetBlinder.equals(transaction_1.ZERO)) {
      return valueBlinder.slice();
    }
    if (value === '0') {
      return valueBlinder.slice();
    }
    const { ec } = await secp256k1Promise;
    const val = Buffer.alloc(32, 0);
    val.writeBigUInt64BE(BigInt(value), 24);
    const result = ec.prvkeyTweakMul(assetBlinder, val);
    if (valueBlinder.length === 0) {
      throw new Error('Missing value blinder');
    }
    const negVb = ec.prvkeyNegate(valueBlinder);
    if (negVb.equals(result)) {
      return transaction_1.ZERO;
    }
    return ec.prvkeyTweakAdd(result, valueBlinder);
  }
  async unblindUtxo(out) {
    if (out.nonce.length === 1) {
      return {
        index: 0,
        value: value_1.ElementsValue.fromBytes(out.value).number.toString(10),
        asset: out.asset.slice(1),
        valueBlinder: transaction_1.ZERO,
        assetBlinder: transaction_1.ZERO,
      };
    }
    if (!this.inBlindingKeys && !this.masterBlindingKey) {
      throw new Error(
        'Missing either input private blinding keys or SLIP-77 master blinding key',
      );
    }
    const keys = this.inBlindingKeys
      ? this.inBlindingKeys
      : [this.masterBlindingKey.derive(out.script).privateKey];
    for (const key of keys) {
      try {
        const revealed = await unblindOutputWithKey(out, key);
        return {
          index: 0,
          value: revealed.value,
          asset: revealed.asset,
          valueBlinder: revealed.valueBlindingFactor,
          assetBlinder: revealed.assetBlindingFactor,
        };
      } catch (ignore) {}
    }
    throw new Error('Could not unblind output with any blinding key');
  }
  async getInputAssetsAndBlinders(pset, issuanceBlindingArgs) {
    const unblindedIns = await this.maybeUnblindInUtxos(pset);
    pset.inputs.forEach((input, i) => {
      if (input.hasIssuance()) {
        unblindedIns.push({
          value: '',
          valueBlindingFactor: Buffer.from([]),
          asset: input.getIssuanceAssetHash(),
          assetBlindingFactor: transaction_1.ZERO,
        });
        if (input.issuanceInflationKeys > 0) {
          const isBlindedIssuance =
            issuanceBlindingArgs &&
            issuanceBlindingArgs.find(({ index }) => index === i) !== undefined;
          unblindedIns.push({
            value: '',
            valueBlindingFactor: Buffer.from([]),
            asset: input.getIssuanceInflationKeysHash(isBlindedIssuance),
            assetBlindingFactor: transaction_1.ZERO,
          });
        }
      }
    });
    const assets = [];
    const assetBlinders = [];
    unblindedIns.forEach(({ asset, assetBlindingFactor }) => {
      assets.push(asset);
      assetBlinders.push(assetBlindingFactor);
    });
    return { assets, assetBlinders };
  }
  async maybeUnblindInUtxos(pset) {
    if (this.ownedInputs && this.ownedInputs.length > 0) {
      return pset.inputs.map((input, i) => {
        const ownedInput = this.ownedInputs.find(({ index }) => index === i);
        if (ownedInput) {
          return {
            value: '',
            valueBlindingFactor: Buffer.from([]),
            asset: ownedInput.asset,
            assetBlindingFactor: ownedInput.assetBlinder,
          };
        }
        return {
          value: '',
          valueBlindingFactor: Buffer.from([]),
          asset: input.getUtxo().asset,
          assetBlindingFactor: transaction_1.ZERO,
        };
      });
    }
    if (!this.inBlindingKeys && !this.masterBlindingKey) {
      throw new Error(
        'Missing either input private blinding keys or SLIP-77 master blinding key',
      );
    }
    return Promise.all(
      pset.inputs.map(async input => {
        const prevout = input.getUtxo();
        try {
          const revealed = await this.unblindUtxo(prevout);
          return {
            value: revealed.value,
            asset: revealed.asset,
            valueBlindingFactor: revealed.valueBlinder,
            assetBlindingFactor: revealed.assetBlinder,
          };
        } catch (ignore) {
          return {
            value: '',
            asset: prevout.asset,
            valueBlindingFactor: Buffer.from([]),
            assetBlindingFactor: transaction_1.ZERO,
          };
        }
      }),
    );
  }
}
exports.ZKPGenerator = ZKPGenerator;
function validatePset(pset) {
  pset.sanityCheck();
  pset.inputs.forEach((input, i) => {
    if (!input.getUtxo()) {
      throw new Error('Missing (non-)witness utxo for input ' + i);
    }
  });
}
function validateInIndexes(pset, inIndexes) {
  if (inIndexes.length > 0) {
    inIndexes.forEach(i => {
      if (i < 0 || i >= pset.globals.inputCount) {
        throw new Error('Input index out of range');
      }
    });
  }
}
function validateOutIndexes(pset, outIndexes) {
  if (outIndexes.length > 0) {
    outIndexes.forEach(i => {
      if (i < 0 || i >= pset.globals.outputCount) {
        throw new Error('Output index out of range');
      }
    });
  }
}
function validateBlindingKeysByIndex(pset, keys) {
  Object.entries(keys).forEach(([k, v]) => {
    const i = parseInt(k, 10);
    if (i < 0 || i >= pset.globals.inputCount) {
      throw new Error('Input index out of range');
    }
    if (!pset.inputs[i].hasIssuance()) {
      throw new Error('Input does not have any issuance to blind');
    }
    if (v.length !== 32) {
      throw new Error('Invalid private blinding key length for input ' + i);
    }
  });
}
function validateBlindedIssuances(pset, blindedIssuances) {
  if (blindedIssuances.length > 0) {
    blindedIssuances.forEach(issuance => {
      if (issuance.index < 0 || issuance.index >= pset.globals.inputCount) {
        throw new Error('Input index of blinded issuance is out of range');
      }
    });
  }
}
function randomBytes(options) {
  if (options === undefined) options = {};
  const rng = options.rng || _randomBytes;
  return rng(32);
}
