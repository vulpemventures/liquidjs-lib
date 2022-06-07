import { AssetHash } from '../asset';
import { Transaction } from '../transaction';
import { ElementsValue } from '../value';
import { Pset } from './pset';
import { scriptWitnessToWitnessStack } from './utils';

export class Extractor {
  static extract(pset: Pset): Transaction {
    pset.sanityCheck();

    if (!pset.isComplete()) {
      throw new Error(
        'Pset must be completed to extract final raw transaction',
      );
    }

    const tx = new Transaction();
    tx.version = pset.globals.txVersion;
    tx.locktime = pset.locktime();

    pset.inputs.forEach(input => {
      tx.addInput(input.previousTxid, input.previousTxIndex, input.sequence);
      const inIndex = tx.ins.length - 1;
      if (input.hasIssuance()) {
        const assetAmount =
          input.issuanceValueCommitment! &&
          input.issuanceValueCommitment!.length > 0
            ? input.issuanceValueCommitment!
            : input.issuanceValue! > 0
            ? ElementsValue.fromNumber(input.issuanceValue!).bytes
            : Buffer.of(0x00);
        const tokenAmount =
          input.issuanceInflationKeysCommitment! &&
          input.issuanceInflationKeysCommitment!.length > 0
            ? input.issuanceInflationKeysCommitment!
            : input.issuanceInflationKeys! > 0
            ? ElementsValue.fromNumber(input.issuanceInflationKeys!).bytes
            : Buffer.of(0x00);

        tx.ins[inIndex].issuance = {
          assetAmount,
          tokenAmount,
          assetEntropy: input.issuanceAssetEntropy!,
          assetBlindingNonce: input.issuanceBlindingNonce!,
        };

        if (
          input.issuanceValueRangeproof! &&
          input.issuanceValueRangeproof!.length > 0
        ) {
          tx.ins[inIndex].issuanceRangeProof = input.issuanceValueRangeproof;
        }
        if (
          input.issuanceInflationKeysRangeproof! &&
          input.issuanceInflationKeysRangeproof!.length > 0
        ) {
          tx.ins[inIndex].inflationRangeProof =
            input.issuanceInflationKeysRangeproof;
        }
      }
      tx.ins[inIndex].isPegin =
        input.peginWitness! && input.peginWitness!.length > 0;
      if (tx.ins[inIndex].isPegin) {
        tx.ins[inIndex].peginWitness = [input.peginWitness!];
      }
      if (input.finalScriptSig! && input.finalScriptSig!.length > 0) {
        tx.ins[inIndex].script = input.finalScriptSig!;
      }
      if (input.finalScriptWitness! && input.finalScriptWitness!.length > 0) {
        tx.ins[inIndex].witness = scriptWitnessToWitnessStack(
          input.finalScriptWitness!,
        );
      }
    });

    pset.outputs.forEach(output => {
      const script = output.script || Buffer.from([]);
      const value =
        output.valueCommitment! && output.valueCommitment!.length > 0
          ? output.valueCommitment!
          : ElementsValue.fromNumber(output.value).bytes;
      const asset =
        output.assetCommitment! && output.assetCommitment!.length > 0
          ? output.assetCommitment!
          : AssetHash.fromBytes(output.asset).bytes;
      const nonce =
        output.ecdhPubkey! && output.ecdhPubkey!.length > 0
          ? output.ecdhPubkey!
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
