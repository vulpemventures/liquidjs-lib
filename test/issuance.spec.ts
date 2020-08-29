import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as issuance from '../ts_src/issuance';
import * as types from '../ts_src/types';

import * as fixtures from './fixtures/issuance.json';

const typeforce = require('typeforce');

describe('Issuance', () => {
  let entropy: Buffer;
  let asset: Buffer;
  let token: Buffer;

  const fixture = fixtures.emptyContract;
  const fixtureWithContract = fixtures.withContract;

  describe('entropy from txhash and index', () => {
    it('should be equals to ' + fixture.expectedEntropy, () => {
      if (!fixture.prevout) throw new Error('no prevout in issuance.json');

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
    it('should create a correct Issuance object (without contract)', () => {
      if (!fixture.prevout) throw new Error('no prevout in issuance.json');
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

    it('should create a valid Issuance object (with asset contract)', () => {
      const contract = fixtureWithContract.contract as issuance.IssuanceContract;

      if (
        !fixtureWithContract.txHash ||
        !fixtureWithContract.index ||
        !fixtureWithContract.assetAmount ||
        !fixtureWithContract.tokenAmount
      )
        throw new Error('missing data in fixture.');

      const out: issuance.OutPoint = {
        txHash: Buffer.from(fixtureWithContract.txHash, 'hex').reverse(),
        vout: fixtureWithContract.index,
      };
      const {
        assetAmount,
        tokenAmount,
        assetBlindingNonce,
        assetEntropy,
      } = issuance.newIssuance(
        fixtureWithContract.assetAmount,
        fixtureWithContract.tokenAmount,
        out,
        fixtureWithContract.precision,
        contract,
      );

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
