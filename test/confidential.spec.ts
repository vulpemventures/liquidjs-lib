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
  it('valueCommitment', async () => {
    for (const f of fixtures.valid.valueCommitment) {
      const valueCommitment = await confidential.valueCommitment(
        f.value,
        Buffer.from(f.generator, 'hex'),
        Buffer.from(f.factor, 'hex'),
      );
      assert.strictEqual(valueCommitment.toString('hex'), f.expected);
    }
  });

  it('valueBlindingFactor', async () => {
    for (const f of fixtures.valid.valueBlindingFactor) {
      const inGenerators = f.inGenerators.map((v: any) =>
        Buffer.from(v, 'hex'),
      );
      const outGenerators = f.outGenerators.map((v: any) =>
        Buffer.from(v, 'hex'),
      );
      const inFactors = f.inFactors.map((v: any) => Buffer.from(v, 'hex'));
      const outFactors = f.outFactors.map((v: any) => Buffer.from(v, 'hex'));
      const vbf = await confidential.valueBlindingFactor(
        f.inValues,
        f.outValues,
        inGenerators,
        outGenerators,
        inFactors,
        outFactors,
      );
      assert.strictEqual(vbf.toString('hex'), f.expected);
    }
  });

  it('assetCommitment', async () => {
    for (const f of fixtures.valid.assetCommitment) {
      const assetCommitment = await confidential.assetCommitment(
        Buffer.from(f.asset, 'hex'),
        Buffer.from(f.factor, 'hex'),
      );
      assert.strictEqual(assetCommitment.toString('hex'), f.expected);
    }
  });

  it('unblind', () => {
    fixtures.valid.unblind.forEach(async (f: any) => {
      const out: TxOutput = {
        value: f.valueCommitment,
        asset: f.assetGenerator,
        script: f.scriptPubkey,
        rangeProof: f.rangeproof,
        nonce: f.ephemeralPubkey,
      };
      const unblindProof = await confidential.unblindOutputWithKey(
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

  it('rangeProofInfo', async () => {
    for (const f of fixtures.valid.rangeproofInfo) {
      const proofInfo = await confidential.rangeProofInfo(
        Buffer.from(f.proof, 'hex'),
      );
      assert.strictEqual(proofInfo.ctExp, f.expected.ctExp);
      assert.strictEqual(proofInfo.ctBits, f.expected.ctBits);
      assert.strictEqual(proofInfo.minValue, f.expected.minValue);
      assert.strictEqual(proofInfo.maxValue, f.expected.maxValue);
    }
  });

  it('rangeProof', async () => {
    for (const f of fixtures.valid.rangeproof) {
      const minValue = '1';
      const exp = 0;
      const minBits = 36;

      const proof = await confidential.rangeProof(
        f.value,
        Buffer.from(f.blindingPubkey, 'hex'),
        Buffer.from(f.ephemeralPrivkey, 'hex'),
        Buffer.from(f.asset, 'hex'),
        Buffer.from(f.assetBlindingFactor, 'hex'),
        Buffer.from(f.valueBlindingFactor, 'hex'),
        Buffer.from(f.valueCommitment, 'hex'),
        Buffer.from(f.scriptPubkey, 'hex'),
        minValue,
        exp,
        minBits,
      );
      assert.strictEqual(proof.toString('hex'), f.expected);
    }
  });

  it('surjectionProof', async () => {
    for (const f of fixtures.valid.surjectionproof) {
      const inputAssets = f.inputAssets.map((v: any) => Buffer.from(v, 'hex'));
      const inputAssetBlindingFactors = f.inputAssetBlindingFactors.map(
        (v: any) => Buffer.from(v, 'hex'),
      );
      const proof = await confidential.surjectionProof(
        Buffer.from(f.outputAsset, 'hex'),
        Buffer.from(f.outputAssetBlindingFactor, 'hex'),
        inputAssets,
        inputAssetBlindingFactors,
        Buffer.from(f.seed, 'hex'),
      );
      assert.strictEqual(proof.toString('hex'), f.expected);
    }
  });
});
