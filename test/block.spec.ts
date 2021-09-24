import * as assert from 'assert';
import { describe } from 'mocha';
import * as fixtures from './fixtures/block_deserialize.json';
import { Block } from '../ts_src/block';

describe('block deserialization ', () => {
  fixtures.test.forEach(f => {
    it(f.name, () => {
      const block = Block.fromBuffer(Buffer.from(f.hex, 'hex'));

      if (f.name.includes('compact current')) {
        assert.strictEqual(block.getHash().toString('hex'), f.hash);
        assert.strictEqual(block.version, parseInt(f.version || '', 16));
        assert.strictEqual(
          block.currentSignBlockWitnessLimit,
          f.signBlockWitnessLimit,
        );
      }

      if (f.name.includes('full current')) {
        assert.strictEqual(block.getHash().toString('hex'), f.hash);
      }

      assert.strictEqual(block.transactions!.length, f.numOfTx);
    });
  });
});
