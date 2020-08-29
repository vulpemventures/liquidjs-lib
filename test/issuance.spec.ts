import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as issuance from '../ts_src/issuance';
import * as types from '../ts_src/types';

import * as fixture from './fixtures/issuance.json';

const typeforce = require('typeforce');

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

  describe('create issuance object', () => {
    it('should create a correct Issuance object', () => {
      const {
        assetEntropy,
        assetBlindingNonce,
        assetAmount,
        tokenAmount,
      } = issuance.newIssuance(10, 22, {
        txHash: Buffer.from(fixture.prevout.txHash, 'hex').reverse(),
        vout: 1,
      });
      const validate = (): boolean => {
        try {
          typeforce(types.Hash256bit, assetBlindingNonce);
          typeforce(types.Hash256bit, assetEntropy);
          typeforce(
            types.oneOf(
              types.ConfidentialValue,
              types.ConfidentialCommitment,
              types.BufferOne,
            ),
            assetAmount,
          );
          typeforce(
            types.oneOf(
              types.ConfidentialValue,
              types.ConfidentialCommitment,
              types.BufferOne,
            ),
            tokenAmount,
          );
          return true;
        } catch (err) {
          return false;
        }
      };

      assert.strictEqual(validate(), true);
    });
  });
});
