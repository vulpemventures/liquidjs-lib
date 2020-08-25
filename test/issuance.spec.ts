import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as issuance from '../ts_src/issuance';

import * as fixture from './fixtures/issuance.json';

describe('Issuance', () => {
  let entropy: Buffer;
  let asset: Buffer;
  let token: Buffer;

  describe(`entropy from txhash = ${fixture.prevout.txHash} and index = ${
    fixture.prevout.index
  }`, () => {
    it('should be equals to ' + fixture.expectedEntropy, () => {
      const prevout: issuance.OutPoint = {
        txHash: Buffer.from(fixture.prevout.txHash, 'hex').reverse(),
        vout: fixture.prevout.index,
      };

      entropy = issuance.generateEntropy(prevout);
      assert.strictEqual(entropy.toString('hex'), fixture.expectedEntropy);
    });
  });

  describe('asset calculation from entropy', () => {
    it('should compute the right asset hex', () => {
      asset = issuance.calculateAsset(entropy);
      assert.strictEqual(
        asset.reverse().toString('hex'),
        fixture.expectedAsset,
      );
    });
  });

  describe('token calculation from entropy', () => {
    it('should compute the right reissuance token hex', () => {
      token = issuance.calculateReissuanceToken(entropy);
      assert.strictEqual(
        token.reverse().toString('hex'),
        fixture.expectedToken,
      );
    });
  });
});
