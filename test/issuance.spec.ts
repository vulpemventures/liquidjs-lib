import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as issuance from '../ts_src/issuance';
import * as types from '../ts_src/types';
import { regtest } from './../ts_src/networks';
import {
  AddIssuanceArgs,
  Issuance,
  Transaction,
} from './../ts_src/transaction';

import { satoshiToConfidentialValue } from './../ts_src/confidential';
import * as fixtures from './fixtures/issuance.json';

const typeforce = require('typeforce');

describe('Issuance', () => {
  const fixture = fixtures.emptyContract;
  const fixtureWithContract = fixtures.withContract;
  const prevout: issuance.OutPoint = {
    txHash: Buffer.from(fixture.prevout.txHash, 'hex').reverse(),
    vout: fixture.prevout.index,
  };

  describe('Issuance artifacts generation (entropy, asset value and token value)', () => {
    it('should properly generate the entropy from a prevout point of the blockchain', () => {
      const entropy = issuance.generateEntropy(prevout);
      assert.strictEqual(entropy.toString('hex'), fixture.expectedEntropy);
    });

    it('should compute the asset value from an entropy previously generated', () => {
      const asset = issuance.calculateAsset(
        Buffer.from(fixture.expectedEntropy, 'hex'),
      );
      assert.strictEqual(
        asset.reverse().toString('hex'),
        fixture.expectedAsset,
      );
    });

    it('should compute the reissuance token value from an entropy previously generated', () => {
      const token = issuance.calculateReissuanceToken(
        Buffer.from(fixture.expectedEntropy, 'hex'),
      );
      assert.strictEqual(
        token.reverse().toString('hex'),
        fixture.expectedToken,
      );
    });
  });

  describe('Issuance object generation', () => {
    function validate(i: Issuance): boolean {
      try {
        typeforce(types.Hash256bit, i.assetBlindingNonce);
        typeforce(types.Hash256bit, i.assetEntropy);
        typeforce(
          types.oneOf(
            types.ConfidentialValue,
            types.ConfidentialCommitment,
            types.BufferOne,
          ),
          i.assetAmount,
        );
        typeforce(
          types.oneOf(
            types.ConfidentialValue,
            types.ConfidentialCommitment,
            types.BufferOne,
          ),
          i.tokenAmount,
        );
        return true;
      } catch (err) {
        return false;
      }
    }

    it('should create a correct Issuance object without an issuance contract', () => {
      if (!fixture.prevout) throw new Error('no prevout in issuance.json');
      const iss: Issuance = issuance.newIssuance(10, 22, {
        txHash: Buffer.from(fixture.prevout.txHash, 'hex').reverse(),
        vout: 1,
      });

      assert.strictEqual(validate(iss), true);
    });

    it('should create a valid Issuance object with an issuance contract', () => {
      const contract = fixtureWithContract.contract as issuance.IssuanceContract;
      const out: issuance.OutPoint = {
        txHash: Buffer.from(fixtureWithContract.txHash, 'hex').reverse(),
        vout: fixtureWithContract.index,
      };
      const iss: Issuance = issuance.newIssuance(
        fixtureWithContract.assetAmount,
        fixtureWithContract.tokenAmount,
        out,
        fixtureWithContract.precision,
        contract,
      );
      assert.strictEqual(validate(iss), true);
    });
  });

  describe('Transaction class: add issuance to input', () => {
    function createTx(): Transaction {
      const f = fixtures.unspent;
      const tx = new Transaction();
      tx.addInput(Buffer.from(f.txid, 'hex').reverse(), f.vout);
      tx.addOutput(
        Buffer.alloc(0),
        satoshiToConfidentialValue(f.amount),
        Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(f.asset, 'hex').reverse(),
        ]),
        Buffer.from('00', 'hex'),
      );
      return tx;
    }

    it('should keep the transaction serializable and deserializable after adding an issuance input', () => {
      const args: AddIssuanceArgs = {
        assetAmount: 100,
        assetAddress: fixtures.unspent.assetAddress,
        tokenAmount: 1,
        tokenAddress: fixtures.unspent.tokenAddress,
        precision: 8,
        confidential: false,
        net: regtest,
      };
      const tx = createTx();
      tx.addIssuance(args);
      assert.deepStrictEqual(tx, Transaction.fromHex(tx.toHex()));
    });
  });
});
