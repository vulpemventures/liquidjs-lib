'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.ZKPGenerator = exports.ZKPValidator = void 0;
const confidential_1 = require('../confidential');
const transaction_1 = require('../transaction');
const value_1 = require('../value');
const utils_1 = require('./utils');
const issuance_1 = require('../issuance');
const asset_1 = require('../asset');
class ZKPValidator {
  constructor(zkpLib) {
    this.confidential = new confidential_1.Confidential(zkpLib);
  }
  verifyValueRangeProof(valueCommit, assetCommit, proof, script) {
    try {
      return this.confidential.rangeProofVerify(
        valueCommit,
        assetCommit,
        proof,
        script,
      );
    } catch (ignore) {
      return false;
    }
  }
  verifyAssetSurjectionProof(
    inAssets,
    inAssetBlinders,
    outAsset,
    outAssetBlinder,
    proof,
  ) {
    try {
      return this.confidential.surjectionProofVerify(
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
  verifyBlindValueProof(valueCommit, assetCommit, proof) {
    try {
      return this.confidential.rangeProofVerify(
        valueCommit,
        assetCommit,
        proof,
      );
    } catch (ignore) {
      return false;
    }
  }
  verifyBlindAssetProof(asset, assetCommit, proof) {
    try {
      return this.confidential.assetBlindProofVerify(asset, assetCommit, proof);
    } catch (ignore) {
      return false;
    }
  }
}
exports.ZKPValidator = ZKPValidator;
class ZKPGenerator {
  constructor(zkp, ...options) {
    this.zkp = zkp;
    this.confidential = new confidential_1.Confidential(zkp);
    for (const option of options) {
      option(this);
    }
  }
  static WithBlindingKeysOfInputs(inBlindingKeys) {
    return (g) => {
      g.inBlindingKeys = inBlindingKeys;
    };
  }
  static WithMasterBlindingKey(masterKey) {
    return (g) => {
      g.masterBlindingKey = masterKey;
    };
  }
  static WithOwnedInputs(ownedInputs) {
    return (g) => {
      g.ownedInputs = ownedInputs;
    };
  }
  computeAndAddToScalarOffset(scalar, value, assetBlinder, valueBlinder) {
    // If both asset and value blinders are null, 0 is added to the offset, so nothing actually happens
    if (
      assetBlinder.equals(transaction_1.ZERO) &&
      valueBlinder.equals(transaction_1.ZERO)
    ) {
      return scalar.slice();
    }
    const scalarOffset = this.calculateScalarOffset(
      value,
      assetBlinder,
      valueBlinder,
    );
    // When we start out, the result (a) is 0, so just set it to the scalar we just computed.
    if (scalar.equals(transaction_1.ZERO)) {
      return scalarOffset;
    }
    const { ec } = this.zkp;
    const negScalarOffset = ec.prvkeyNegate(scalarOffset);
    if (scalar.equals(negScalarOffset)) {
      return transaction_1.ZERO;
    }
    return ec.prvkeyTweakAdd(scalar, scalarOffset);
  }
  subtractScalars(inputScalar, outputScalar) {
    if (outputScalar.equals(transaction_1.ZERO)) {
      return inputScalar.slice();
    }
    const { ec } = this.zkp;
    const negOutputScalar = ec.prvkeyNegate(outputScalar);
    if (inputScalar.equals(transaction_1.ZERO)) {
      return negOutputScalar;
    }
    return ec.prvkeyTweakAdd(inputScalar, negOutputScalar);
  }
  lastValueCommitment(value, asset, blinder) {
    return this.confidential.valueCommitment(value, asset, blinder);
  }
  lastBlindValueProof(value, valueCommit, assetCommit, blinder) {
    const nonce = (0, utils_1.randomBytes)(this.opts);
    return this.confidential.blindValueProof(
      value,
      valueCommit,
      assetCommit,
      blinder,
      nonce,
    );
  }
  lastValueRangeProof(
    value,
    asset,
    valueCommit,
    valueBlinder,
    assetBlinder,
    script,
    nonce,
  ) {
    return this.confidential.rangeProof(
      value,
      nonce,
      asset,
      assetBlinder,
      valueBlinder,
      valueCommit,
      script,
    );
  }
  unblindInputs(pset, inIndexes) {
    validatePset(pset);
    if (inIndexes) {
      validateInIndexes(pset, inIndexes);
    }
    const inputIndexes =
      inIndexes || Array.from({ length: pset.globals.inputCount }, (_, i) => i);
    if (this.ownedInputs && this.ownedInputs.length > 0) {
      return this.ownedInputs;
    }
    const revealedInputs = inputIndexes.map((i) => {
      const prevout = pset.inputs[i].getUtxo();
      const revealedInput = this.unblindUtxo(prevout);
      revealedInput.index = i;
      return revealedInput;
    });
    this.ownedInputs = revealedInputs;
    return revealedInputs;
  }
  blindIssuances(pset, blindingKeysByIndex) {
    validatePset(pset);
    validateBlindingKeysByIndex(pset, blindingKeysByIndex);
    return Object.entries(blindingKeysByIndex).map(([i, key]) => {
      const input = pset.inputs[parseInt(i, 10)];
      let blindingArgs = {};
      if (input.issuanceValue > 0) {
        const value = input.issuanceValue.toString(10);
        const asset = input.getIssuanceAssetHash();
        const blinder = (0, utils_1.randomBytes)(this.opts);
        const assetCommit = this.confidential.assetCommitment(
          asset,
          transaction_1.ZERO,
        );
        const valueCommit = this.confidential.valueCommitment(
          value,
          assetCommit,
          blinder,
        );
        const nonce = (0, utils_1.randomBytes)(this.opts);
        const blindproof = this.confidential.blindValueProof(
          value,
          valueCommit,
          assetCommit,
          blinder,
          nonce,
        );
        const rangeproof = this.confidential.rangeProof(
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
        const entropy = input.getIssuanceEntropy();
        const asset = (0, issuance_1.calculateReissuanceToken)(entropy, true);
        if (!asset)
          throw new Error(
            'something went wrong during the inflation token hash computation',
          );
        const blinder = (0, utils_1.randomBytes)(this.opts);
        const assetCommit = this.confidential.assetCommitment(
          asset,
          transaction_1.ZERO,
        );
        const tokenCommit = this.confidential.valueCommitment(
          token,
          assetCommit,
          blinder,
        );
        const nonce = (0, utils_1.randomBytes)(this.opts);
        const blindproof = this.confidential.blindValueProof(
          token,
          tokenCommit,
          assetCommit,
          blinder,
          nonce,
        );
        const rangeproof = this.confidential.rangeProof(
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
    });
  }
  blindOutputs(pset, keysGenerator, outIndexes) {
    validatePset(pset);
    if (outIndexes) {
      validateOutIndexes(pset, outIndexes);
    }
    const outputIndexes =
      outIndexes && outIndexes.length > 0
        ? outIndexes
        : pset.outputs.reduce(
            (arr, out, i) => (out.needsBlinding() && arr.push(i), arr),
            [],
          );
    const { assets, assetBlinders } = this.getInputAssetsAndBlinders(pset);
    return outputIndexes.map((i) => {
      const output = pset.outputs[i];
      const assetBlinder = (0, utils_1.randomBytes)(this.opts);
      const valueBlinder = (0, utils_1.randomBytes)(this.opts);
      const seed = (0, utils_1.randomBytes)(this.opts);
      const value = output.value.toString(10);
      const assetCommit = this.confidential.assetCommitment(
        output.asset,
        assetBlinder,
      );
      const valueCommit = this.confidential.valueCommitment(
        value,
        assetCommit,
        valueBlinder,
      );
      const ephemeralKeyPair = keysGenerator();
      const nonceCommitment = ephemeralKeyPair.publicKey;
      const ecdhNonce = this.confidential.nonceHash(
        output.blindingPubkey,
        ephemeralKeyPair.privateKey,
      );
      const script = output.script || Buffer.from([]);
      const rangeproof = this.confidential.rangeProof(
        value,
        ecdhNonce,
        output.asset,
        assetBlinder,
        valueBlinder,
        valueCommit,
        script,
      );
      const surjectionproof = this.confidential.surjectionProof(
        output.asset,
        assetBlinder,
        assets,
        assetBlinders,
        seed,
      );
      const nonce = (0, utils_1.randomBytes)(this.opts);
      const valueBlindProof = this.confidential.blindValueProof(
        value,
        valueCommit,
        assetCommit,
        valueBlinder,
        nonce,
      );
      const assetBlindProof = this.confidential.blindAssetProof(
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
    });
  }
  calculateScalarOffset(value, assetBlinder, valueBlinder) {
    if (assetBlinder.equals(transaction_1.ZERO)) {
      return valueBlinder.slice();
    }
    if (value === '0') {
      return valueBlinder.slice();
    }
    const { ec } = this.zkp;
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
  unblindUtxo(out) {
    if (out.nonce.length === 1) {
      return {
        index: 0,
        value: value_1.ElementsValue.fromBytes(out.value).number.toString(10),
        asset: out.asset.slice(1),
        valueBlindingFactor: transaction_1.ZERO,
        assetBlindingFactor: transaction_1.ZERO,
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
        const revealed = this.confidential.unblindOutputWithKey(out, key);
        return {
          index: 0,
          value: revealed.value,
          asset: revealed.asset,
          valueBlindingFactor: revealed.valueBlindingFactor,
          assetBlindingFactor: revealed.assetBlindingFactor,
        };
      } catch (ignore) {}
    }
    throw new Error('Could not unblind output with any blinding key');
  }
  getInputAssetsAndBlinders(pset) {
    const assets = [];
    const assetBlinders = [];
    const unblindedIns = this.maybeUnblindInUtxos(pset);
    for (const unblindedIn of unblindedIns) {
      assets.push(unblindedIn.asset);
      assetBlinders.push(unblindedIn.assetBlindingFactor);
    }
    pset.inputs.forEach((input, i) => {
      if (input.hasIssuance() || input.hasReissuance()) {
        const issAssetHash = input.getIssuanceAssetHash();
        if (!issAssetHash)
          throw new Error(
            `something went wrong while getting the issuance asset hash on input #${i}`,
          );
        assets.push(issAssetHash);
        assetBlinders.push(transaction_1.ZERO);
        if (!input.hasReissuance() && input.issuanceInflationKeys > 0) {
          const entropy = input.getIssuanceEntropy();
          const inflationTokenAssetHash = (0,
          issuance_1.calculateReissuanceToken)(
            entropy,
            input.blindedIssuance ?? true,
          );
          if (!inflationTokenAssetHash)
            throw new Error(
              `something went wrong computing the issuance inflation keys hash on input #${i}`,
            );
          assets.push(inflationTokenAssetHash);
          assetBlinders.push(transaction_1.ZERO);
        }
      }
    });
    return { assets, assetBlinders };
  }
  maybeUnblindInUtxos(pset) {
    if (this.ownedInputs && this.ownedInputs.length > 0) {
      return pset.inputs.map((input, i) => {
        const ownedInput = this.ownedInputs?.find(({ index }) => index === i);
        if (ownedInput) {
          return {
            value: '',
            valueBlindingFactor: Buffer.from([]),
            asset: ownedInput.asset,
            assetBlindingFactor: ownedInput.assetBlindingFactor,
          };
        }
        const utxo = input.getUtxo();
        if (!utxo) {
          throw new Error(`Missing utxo for input #${i}`);
        }
        return {
          value: '',
          valueBlindingFactor: Buffer.from([]),
          asset: asset_1.AssetHash.fromBytes(utxo.asset).bytesWithoutPrefix,
          assetBlindingFactor: transaction_1.ZERO,
        };
      });
    }
    if (!this.inBlindingKeys && !this.masterBlindingKey) {
      throw new Error(
        'Missing either input private blinding keys or SLIP-77 master blinding key',
      );
    }
    return pset.inputs.map((input) => {
      const prevout = input.getUtxo();
      try {
        const revealed = this.unblindUtxo(prevout);
        return {
          value: revealed.value,
          asset: revealed.asset,
          valueBlindingFactor: revealed.valueBlindingFactor,
          assetBlindingFactor: revealed.assetBlindingFactor,
        };
      } catch (ignore) {
        return {
          value: '',
          asset: prevout.asset,
          valueBlindingFactor: Buffer.from([]),
          assetBlindingFactor: transaction_1.ZERO,
        };
      }
    });
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
    inIndexes.forEach((i) => {
      if (i < 0 || i >= pset.globals.inputCount) {
        throw new Error('Input index out of range');
      }
    });
  }
}
function validateOutIndexes(pset, outIndexes) {
  if (outIndexes.length > 0) {
    outIndexes.forEach((i) => {
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
    if (!pset.inputs[i].hasIssuance() && !pset.inputs[i].hasReissuance()) {
      throw new Error(
        'Input does not have any issuance or reissuance to blind',
      );
    }
    if (v.length !== 32) {
      throw new Error('Invalid private blinding key length for input ' + i);
    }
  });
}
