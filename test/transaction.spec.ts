import { AssetHash, Transaction } from '../ts_src';
import jsonFixture from './fixtures/transaction.json';
import * as assert from 'assert';
import { isUnconfidentialValue } from '../ts_src/confidential';

const fromHex = (hex: string): Buffer => Buffer.from(hex, 'hex');

describe('Transaction', () => {
  describe('hashForWitnessV1', () => {
    const fixtures = jsonFixture.hashForWitnessV1;
    for (const test of fixtures) {
      it(test.description, () => {
        const tx = Transaction.fromHex(test.txHex);
        const hash = tx.hashForWitnessV1(
          test.inIndex,
          test.prevouts.map(p => fromHex(p.script)),
          test.prevouts.map(p => ({
            asset: AssetHash.fromHex(
              p.asset,
              !isUnconfidentialValue(fromHex(p.value)),
            ).bytes,
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
});
