import * as assert from 'assert';
import * as confidential from '../src/confidential';
import * as preFixtures from './fixtures/confidential.json';

import { describe, it } from 'mocha';

import { TxOutput } from '../ts_src/index';

const initBuffers = (object: any): typeof preFixtures =>
  JSON.parse(JSON.stringify(object), (_, value) => {
    const regex = new RegExp(/^Buffer.from\(['"](.*)['"], ['"](.*)['"]\)$/);
    const result = regex.exec(value);
    if (!result) return value;

    const data = result[1];
    const encoding = result[2];

    return Buffer.from(data, encoding as BufferEncoding);
  });

const fixtures = initBuffers(preFixtures);

describe('confidential', () => {
  it('valueCommitment', () => {
    fixtures.valid.valueCommitment.forEach((f: any) => {
      assert.strictEqual(
        confidential
          .valueCommitment(f.value, f.generator, f.factor)
          .toString('hex'),
        f.expected,
      );
    });
  });

  it('valueBlindingFactor', () => {
    fixtures.valid.valueBlindingFactor.forEach((f: any) => {
      const inGenerators = f.inGenerators.map((v: any) =>
        Buffer.from(v, 'hex'),
      );
      const outGenerators = f.outGenerators.map((v: any) =>
        Buffer.from(v, 'hex'),
      );
      const inFactors = f.inFactors.map((v: any) => Buffer.from(v, 'hex'));
      const outFactors = f.outFactors.map((v: any) => Buffer.from(v, 'hex'));
      const vbf = confidential.valueBlindingFactor(
        f.inValues,
        f.outValues,
        inGenerators,
        outGenerators,
        inFactors,
        outFactors,
      );
      assert.strictEqual(vbf.toString('hex'), f.expected);
    });
  });

  it('assetCommitment', () => {
    fixtures.valid.assetCommitment.forEach((f: any) => {
      assert.strictEqual(
        confidential.assetCommitment(f.asset, f.factor).toString('hex'),
        f.expected,
      );
    });
  });

  it('unblind', () => {
    fixtures.valid.unblind.forEach((f: any) => {
      const out: TxOutput = {
        value: f.valueCommitment,
        asset: f.assetGenerator,
        script: f.scriptPubkey,
        rangeProof: f.rangeproof,
        nonce: f.ephemeralPubkey,
      };
      const unblindProof = confidential.unblindOutputWithKey(
        out,
        f.blindingPrivkey,
      );
      assert.strictEqual(unblindProof.value, f.expected.value);
      assert.strictEqual(
        unblindProof.valueBlindingFactor.toString('hex'),
        f.expected.valueBlindingFactor,
      );
      assert.strictEqual(unblindProof.asset.toString('hex'), f.expected.asset);
      assert.strictEqual(
        unblindProof.assetBlindingFactor.toString('hex'),
        f.expected.assetBlindingFactor,
      );
    });
  });

  it('rangeProofInfo', () => {
    fixtures.valid.rangeproofInfo.forEach((f: any) => {
      const proofInfo = confidential.rangeProofInfo(f.proof);
      assert.strictEqual(proofInfo.ctExp, f.expected.ctExp);
      assert.strictEqual(proofInfo.ctBits, f.expected.ctBits);
      assert.strictEqual(proofInfo.minValue, f.expected.minValue);
      assert.strictEqual(proofInfo.maxValue, f.expected.maxValue);
    });
  });

  it('rangeProof', () => {
    fixtures.valid.rangeproof.forEach((f: any) => {
      const minValue = '1';
      const exp = 0;
      const minBits = 36;

      const proof = confidential.rangeProof(
        f.value,
        f.blindingPubkey,
        f.ephemeralPrivkey,
        f.asset,
        f.assetBlindingFactor,
        f.valueBlindingFactor,
        f.valueCommitment,
        f.scriptPubkey,
        minValue,
        exp,
        minBits,
      );
      assert.strictEqual(proof.toString('hex'), f.expected);
    });
  });

  it('surjectionProof', () => {
    fixtures.valid.surjectionproof.forEach((f: any) => {
      const inputAssets = f.inputAssets.map((v: any) => Buffer.from(v, 'hex'));
      const inputAssetBlindingFactors = f.inputAssetBlindingFactors.map(
        (v: any) => Buffer.from(v, 'hex'),
      );
      const proof = confidential.surjectionProof(
        f.outputAsset,
        f.outputAssetBlindingFactor,
        inputAssets,
        inputAssetBlindingFactors,
        f.seed,
      );
      assert.strictEqual(proof.toString('hex'), f.expected);
    });
  });
});
