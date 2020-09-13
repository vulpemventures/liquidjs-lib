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
  const entropy31bytes = Buffer.from(
    '2b73af1c9ae64a6903b3055361dd7b75082003a85374049982fc1e8f31b9a8',
    'hex',
  );
  const prevout: issuance.OutPoint = {
    txHash: Buffer.from(fixture.prevout.txHash, 'hex').reverse(),
    vout: fixture.prevout.index,
  };

  describe('Issuance artifacts generation (entropy, asset value and token value)', () => {
    describe('Entropy generation', () => {
      it('should properly generate the entropy from a prevout point of the blockchain', () => {
        const entropy = issuance.generateEntropy(prevout);
        assert.strictEqual(entropy.toString('hex'), fixture.expectedEntropy);
      });
    });

    describe('Asset calculation', () => {
      it('should compute the asset value from an entropy previously generated', () => {
        const asset = issuance.calculateAsset(
          Buffer.from(fixture.expectedEntropy, 'hex'),
        );
        assert.strictEqual(
          asset.reverse().toString('hex'),
          fixture.expectedAsset,
        );
      });

      it('should throw an error if the entropy has not a lenght of 32 bytes', () => {
        assert.throws(() => issuance.calculateAsset(entropy31bytes));
      });
    });

    describe('Token calculation', () => {
      it('should compute the reissuance token value from an entropy previously generated', () => {
        const token = issuance.calculateReissuanceToken(
          Buffer.from(fixture.expectedEntropy, 'hex'),
        );
        assert.strictEqual(
          token.reverse().toString('hex'),
          fixture.expectedToken,
        );
      });

      it('should throw an error if the entropy has not a lenght of 32 bytes', () => {
        assert.throws(() => issuance.calculateReissuanceToken(entropy31bytes));
      });
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
      const iss: Issuance = issuance.newIssuance(10, 22);
      assert.strictEqual(validate(iss), true);
    });

    it('should create a valid Issuance object with an issuance contract', () => {
      const contract = fixtureWithContract.contract as issuance.IssuanceContract;
      const iss: Issuance = issuance.newIssuance(
        fixtureWithContract.assetAmount,
        fixtureWithContract.tokenAmount,
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
      // explicit fee output
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

    function createTxWithNoInput(): Transaction {
      const f = fixtures.unspent;
      const tx = new Transaction();
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

    const issueArgs: AddIssuanceArgs = {
      assetAmount: 100,
      assetAddress: fixtures.unspent.assetAddress,
      tokenAmount: 1,
      tokenAddress: fixtures.unspent.tokenAddress,
      precision: 8,
      confidential: false,
      net: regtest,
    };

    function createTxWith1IssuanceInput(): Transaction {
      const tx = createTx();
      tx.addIssuance(issueArgs);
      return tx;
    }

    it('should keep the transaction serializable and deserializable after adding an issuance input', () => {
      const tx = createTxWith1IssuanceInput();
      assert.deepStrictEqual(tx, Transaction.fromHex(tx.toHex()));
    });

    it('should throw an error after adding an issuance to a transaction with no inputs', () => {
      const tx = createTxWithNoInput();
      assert.throws(() => tx.addIssuance(issueArgs));
    });

    it('should throw an error if the transaction inputs have already issuances', () => {
      const tx = createTxWith1IssuanceInput();
      assert.throws(() => tx.addIssuance(issueArgs));
    });

    it('should throw an error if the token amount is < 0', () => {
      const tx = createTx();
      const argsInvalidToken = { ...issueArgs, tokenAmount: -2 };
      assert.throws(() => tx.addIssuance(argsInvalidToken));
    });

    it('should throw an error if the asset amount is <= 0', () => {
      const tx = createTx();
      const argsInvalidAsset = { ...issueArgs, assetAmount: 0 };
      assert.throws(() => tx.addIssuance(argsInvalidAsset));
    });

    it('should throw an error if token amount > 0 and token address is undefined', () => {
      const tx = createTx();
      assert.throws(() =>
        tx.addIssuance({ ...issueArgs, tokenAddress: undefined }),
      );
    });

    it('should not throw an error if token amount = 0 and token address is undefined', () => {
      const tx = createTx();
      assert.doesNotThrow(() => {
        tx.addIssuance({
          ...issueArgs,
          tokenAmount: 0,
          tokenAddress: undefined,
        });
      });
    });

    it('should add two outputs if token amount > 0', () => {
      const tx = createTx();
      const lenOutsBeforeIssuance = tx.outs.length;
      tx.addIssuance(issueArgs);
      const lenOutsAfterIssuance = tx.outs.length;
      assert.equal(lenOutsAfterIssuance - lenOutsBeforeIssuance, 2);
    });

    it('should add one output if token amount = 0', () => {
      const tx = createTx();
      const lenOutsBeforeIssuance = tx.outs.length;
      tx.addIssuance({ ...issueArgs, tokenAmount: 0 });
      const lenOutsAfterIssuance = tx.outs.length;
      assert.equal(lenOutsAfterIssuance - lenOutsBeforeIssuance, 1);
    });

    it('should allow the user to choose the input where to add the issuance', () => {
      const tx = createTx();
      tx.addIssuance(issueArgs, 0);
      assert.ok(tx.ins[0].issuance);
    });

    it('should throw an error if the chosen input does not exist', () => {
      const tx = createTxWithNoInput();
      assert.throws(() => tx.addIssuance(issueArgs, 1));
    });

    it('should throw an error if the chose input has already issuance data', () => {
      const tx = createTxWith1IssuanceInput();
      assert.throws(() => tx.addIssuance(issueArgs, 0));
    });
  });

  // describe('Psbt class: add issuance to input', () => {});
});
