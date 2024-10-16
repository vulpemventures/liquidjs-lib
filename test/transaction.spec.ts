import { AssetHash, Transaction } from '../ts_src';
import jsonFixture from './fixtures/transaction.json';
import * as assert from 'assert';

const fromHex = (hex: string): Buffer => Buffer.from(hex, 'hex');

describe('Transaction', () => {
  describe('hashForWitnessV1', () => {
    const fixtures = jsonFixture.hashForWitnessV1;
    for (const test of fixtures) {
      it(test.description, () => {
        const tx = Transaction.fromHex(test.txHex);
        const hash = tx.hashForWitnessV1(
          test.inIndex,
          test.prevouts.map((p) => fromHex(p.script)),
          test.prevouts.map((p) => ({
            asset: AssetHash.fromHex(p.asset).bytes,
            value: fromHex(p.value),
          })),
          test.type,
          fromHex(test.genesisHash).reverse(),
          test.leafHash != null ? fromHex(test.leafHash) : undefined,
        );

        assert.strictEqual(hash.toString('hex'), test.expectedHash);
      });
    }
  });

  describe('calculates weight and virtualSize', () => {
    const fixtures = jsonFixture.discountCT;
    for (const test of fixtures) {
      it(test.description, () => {
        const tx = Transaction.fromHex(test.txHex);
        assert.strictEqual(tx.weight(false), test.weight);
        assert.strictEqual(tx.virtualSize(false), test.vSize);

        assert.strictEqual(tx.weight(true), test.discountWeight);
        assert.strictEqual(tx.virtualSize(true), test.discountVSize);

        // Check that the default behavior is discounted CT
        assert.strictEqual(tx.weight(), test.discountWeight);
        assert.strictEqual(tx.virtualSize(), test.discountVSize);
      });
    }
  });
});
