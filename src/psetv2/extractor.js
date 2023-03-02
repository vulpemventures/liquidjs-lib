'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.Extractor = void 0;
const asset_1 = require('../asset');
const transaction_1 = require('../transaction');
const value_1 = require('../value');
const utils_1 = require('./utils');
class Extractor {
  static extract(pset) {
    pset.sanityCheck();
    if (!pset.isComplete()) {
      throw new Error(
        'Pset must be completed to extract final raw transaction',
      );
    }
    const tx = new transaction_1.Transaction();
    tx.version = pset.globals.txVersion;
    tx.locktime = pset.locktime();
    pset.inputs.forEach((input) => {
      tx.addInput(input.previousTxid, input.previousTxIndex, input.sequence);
      const inIndex = tx.ins.length - 1;
      if (input.hasIssuance() || input.hasReissuance()) {
        const assetAmount =
          input.issuanceValueCommitment &&
          input.issuanceValueCommitment.length > 0
            ? input.issuanceValueCommitment
            : input.issuanceValue > 0
            ? value_1.ElementsValue.fromNumber(input.issuanceValue).bytes
            : Buffer.of(0x00);
        const tokenAmount =
          input.issuanceInflationKeysCommitment &&
          input.issuanceInflationKeysCommitment.length > 0
            ? input.issuanceInflationKeysCommitment
            : input.issuanceInflationKeys > 0
            ? value_1.ElementsValue.fromNumber(input.issuanceInflationKeys)
                .bytes
            : Buffer.of(0x00);
        tx.ins[inIndex].issuance = {
          assetAmount,
          tokenAmount,
          assetEntropy: input.issuanceAssetEntropy,
          assetBlindingNonce: input.issuanceBlindingNonce,
        };
        if (
          input.issuanceValueRangeproof &&
          input.issuanceValueRangeproof.length > 0
        ) {
          tx.ins[inIndex].issuanceRangeProof = input.issuanceValueRangeproof;
        }
        if (
          input.issuanceInflationKeysRangeproof &&
          input.issuanceInflationKeysRangeproof.length > 0
        ) {
          tx.ins[inIndex].inflationRangeProof =
            input.issuanceInflationKeysRangeproof;
        }
      }
      tx.ins[inIndex].isPegin =
        input.peginWitness && input.peginWitness.length > 0;
      if (tx.ins[inIndex].isPegin) {
        tx.ins[inIndex].peginWitness = input.peginWitness;
      }
      if (input.finalScriptSig && input.finalScriptSig.length > 0) {
        tx.ins[inIndex].script = input.finalScriptSig;
      }
      if (input.finalScriptWitness && input.finalScriptWitness.length > 0) {
        tx.ins[inIndex].witness = (0, utils_1.scriptWitnessToWitnessStack)(
          input.finalScriptWitness,
        );
      }
    });
    pset.outputs.forEach((output) => {
      const script = output.script || Buffer.from([]);
      const value =
        output.valueCommitment && output.valueCommitment.length > 0
          ? output.valueCommitment
          : value_1.ElementsValue.fromNumber(output.value).bytes;
      const asset =
        output.assetCommitment && output.assetCommitment.length > 0
          ? output.assetCommitment
          : asset_1.AssetHash.fromBytes(output.asset).bytes;
      const nonce =
        output.ecdhPubkey && output.ecdhPubkey.length > 0
          ? output.ecdhPubkey
          : Buffer.of(0x00);
      tx.addOutput(
        script,
        value,
        asset,
        nonce,
        output.valueRangeproof,
        output.assetSurjectionProof,
      );
    });
    return tx;
  }
}
exports.Extractor = Extractor;
