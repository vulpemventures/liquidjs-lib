import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as issuance from '../ts_src/issuance';

import * as fixture from './fixtures/issuance.json';

console.log(fixture);

describe('Issuance', () => {
  describe(`entropy from ${fixture.prevout}`, () => {
    it('should be equals to ' + fixture.entropy);
    const prevout: issuance.OutPoint = {
      txHash: fixture.prevout.txid,
      vout: fixture.prevout.vout,
    };

    const entropy = issuance.generateEntropy(prevout);
    assert.strictEqual(entropy.toString('hex'), fixture.entropy);
  });

  describe('asset calculation from entropy', () => {
    it('should compute the right asset hex', () => {
      const expectedAssetHex: string = fixture.asset;
      const asset = issuance.calculateAsset(
        Buffer.from(fixture.entropy, 'hex').reverse(),
      );

      console.log('asset', asset);

      assert.strictEqual(asset, expectedAssetHex);
    });
  });
});
