import * as assert from 'assert';
import { describe, it } from 'mocha';
import * as issuance from '../ts_src/issuance';
import * as types from '../ts_src/types';
import { Psbt } from './../ts_src/psbt';
import { Transaction } from './../ts_src/transaction';

import { ECPair, networks } from '../ts_src';
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
  const prevout: issuance.Outpoint = {
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
    function validate(i: issuance.Issuance): boolean {
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
      const iss: issuance.Issuance = issuance.newIssuance(10, 22);
      assert.strictEqual(validate(iss), true);
      // check if the asset entropy (i.e the contract hash) is empty
      assert.strictEqual(
        iss.assetEntropy.toString('hex'),
        Buffer.alloc(32).toString('hex'),
      );
    });

    it('should create a valid Issuance object with an issuance contract', () => {
      const contract = fixtureWithContract.contract as issuance.IssuanceContract;
      const iss: issuance.Issuance = issuance.newIssuance(
        fixtureWithContract.assetAmount,
        fixtureWithContract.tokenAmount,
        fixtureWithContract.precision,
        contract,
      );
      assert.strictEqual(validate(iss), true);
      assert.strictEqual(
        iss.assetEntropy.toString('hex'),
        issuance.hashContract(contract).toString('hex'),
      );
    });
  });

  // a static set of arguments using with the function addIssuance.
  const issueArgs: issuance.AddIssuanceArgs = {
    assetAmount: 100,
    assetAddress:
      'AzpudM1xn9jKRwnDFyDPDPTQ8jaxEUaSwe5JSFtVdULh6CwJftVVZcQWZbNacvYLLG24jTpKKNsNUVii',
    tokenAmount: 1,
    tokenAddress:
      'AzpudM1xn9jKRwnDFyDPDPTQ8jaxEUaSwe5JSFtVdULh6CwJftVVZcQWZbNacvYLLG24jTpKKNsNUVii',
    precision: 8,
  };

  describe('Psbt: add issuance to input', () => {
    // key pair using to test
    const alice = ECPair.fromWIF(
      'cPNMJD4VyFnQjGbGs3kcydRzAbDCXrLAbvH6wTCqs88qg1SkZT3J',
      networks.regtest,
    );

    const input = {
      hash: '9d64f0343e264f9992aa024185319b349586ec4cbbfcedcda5a05678ab10e580',
      index: 0,
      nonWitnessUtxo: Buffer.from(
        '0200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6' +
          'd428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e' +
          '9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c5325954387' +
          '2e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c40' +
          '1dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2dda' +
          'b03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3' +
          'c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2dda' +
          'b03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000190000000000000',
        'hex',
      ),
      sighashType: 1,
    };

    const output = {
      asset: Buffer.concat([
        Buffer.from('01', 'hex'),
        Buffer.from(
          '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
          'hex',
        ).reverse(),
      ]),
      nonce: Buffer.from('00', 'hex'),
      script: Buffer.from(
        '76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac',
        'hex',
      ),
      value: satoshiToConfidentialValue(80000),
    };

    function signAndfinalizeWithAlice(psbt: Psbt, inputIndex: number): Psbt {
      return psbt.signInput(inputIndex, alice).finalizeInput(inputIndex);
    }

    // factory function ->
    function createPsbt(): Psbt {
      return new Psbt().addInput(input).addOutput(output);
    }

    function createPsbtWithNoInput(): Psbt {
      return new Psbt().addOutput(output);
    }

    function createPsbtWithIssuance(): Psbt {
      return createPsbt().addIssuance(issueArgs);
    }

    // <- factory

    it('should create a valid psbt (if the input index is undefined)', () => {
      const psbt = createPsbtWithIssuance();
      const finalizedPsbt = signAndfinalizeWithAlice(psbt, 0);
      const tx = finalizedPsbt.extractTransaction();
      assert.deepStrictEqual(tx, Transaction.fromHex(tx.toHex()));
    });

    it('should create a valid psbt (if the input index is specified)', () => {
      const inputIndex = 0;
      const psbt = createPsbt().addIssuance(issueArgs, inputIndex);
      const finalizedPsbt = signAndfinalizeWithAlice(psbt, inputIndex);
      const tx = finalizedPsbt.extractTransaction();

      assert.ok(tx.ins[inputIndex].issuance);
      assert.deepStrictEqual(tx, Transaction.fromHex(tx.toHex()));
    });

    it('should throw an error if the input has already an issuance', () => {
      const psbt = createPsbt().addIssuance(issueArgs, 0);
      assert.throws(() => psbt.addIssuance(issueArgs, 0));
    });

    it('should throw an error if the psbt has 0 inputs', () => {
      const psbt = createPsbtWithNoInput();
      assert.throws(() => psbt.addIssuance(issueArgs, 0));
    });

    it('should throw an error if the transaction inputs have already issuances', () => {
      const psbt = createPsbtWithIssuance();
      assert.throws(() => psbt.addIssuance(issueArgs));
    });

    it('should throw an error if the token amount is < 0', () => {
      const psbt = createPsbt();
      const argsInvalidToken = { ...issueArgs, tokenAmount: -2 };
      assert.throws(() => psbt.addIssuance(argsInvalidToken));
    });

    it('should throw an error if the asset amount is 0', () => {
      const psbt = createPsbt();
      const argsInvalidAsset = { ...issueArgs, assetAmount: 0 };
      assert.throws(() => psbt.addIssuance(argsInvalidAsset));
    });

    it('should throw an error if the asset amount is < 0', () => {
      const psbt = createPsbt();
      const argsInvalidAsset = { ...issueArgs, assetAmount: -12 };
      assert.throws(() => psbt.addIssuance(argsInvalidAsset));
    });

    it('should throw an error if token amount > 0 and token address is undefined', () => {
      const psbt = createPsbt();
      assert.throws(() =>
        psbt.addIssuance({ ...issueArgs, tokenAddress: undefined }),
      );
    });

    it('should not throw an error if token amount = 0 and token address is undefined', () => {
      const psbt = createPsbt();
      assert.doesNotThrow(() => {
        psbt.addIssuance({
          ...issueArgs,
          tokenAmount: 0,
          tokenAddress: undefined,
        });
      });
    });

    it('should add two outputs if token amount > 0', () => {
      const psbt = createPsbt();
      const lenOutsBeforeIssuance = psbt.data.outputs.length;
      psbt.addIssuance(issueArgs);
      const lenOutsAfterIssuance = psbt.data.outputs.length;
      assert.strictEqual(lenOutsAfterIssuance - lenOutsBeforeIssuance, 2);
    });

    it('should add one output if token amount = 0', () => {
      const psbt = createPsbt();
      const lenOutsBeforeIssuance = psbt.data.outputs.length;
      psbt.addIssuance({ ...issueArgs, tokenAmount: 0 });
      const lenOutsAfterIssuance = psbt.data.outputs.length;
      assert.strictEqual(lenOutsAfterIssuance - lenOutsBeforeIssuance, 1);
    });

    it('should throw an error if the chosen input does not exist', () => {
      const psbt = createPsbtWithNoInput();
      assert.throws(() => psbt.addIssuance(issueArgs, 1));
    });

    it('should throw an error if the chose input has already issuance data', () => {
      const psbt = createPsbtWithIssuance();
      assert.throws(() => psbt.addIssuance(issueArgs, 0));
    });

    describe('issuance encoding', () => {
      it('should decode signed transaction correctly', () => {
        const hex =
          '020000000001dc736ea2996712a5bf87068adef5e7b1d0a3e43b7fb6cd58bc8cbaefcb312c34010000806b483045022100934f462b019abc90ff8ece302b296b9ec0602dfb82ca45a514c9216b4069914402202e0069c47d7c70bfd0ae54f02047b11be6f225605cf2cf0b232362b050274d76012103cce710765135f8ab6268bc9feaff5e3f7015db9c50367bc8a66c4a45139af71affffffff0000000000000000000000000000000000000000000000000000000000000000527ca453f91b44c8526f7f73b27be2d652fea8e028e599f41107c94949d9e7d90100000002540be400010000000005f5e1000401daeb30d111910906722aee0d0dce5f9cff351b3124cf9b8bb73a87f85ad448b00100000002540be400001976a914356593fbd8faf90c9d1ed148cb5eb92cd1f1851d88ac011ddf5d5d0041f4c9c3690ee0e3754017cc12b21505f033d52fd974167c9f4689010000000005f5e100001976a9147065f43cc0f7e15ef30998f4118e97116a7c3caf88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5d354001976a914a3f34531581a1e967b67c98e0d13b0d87ee5a8de88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000dac000000000000';
        const expectedEntropy =
          '527ca453f91b44c8526f7f73b27be2d652fea8e028e599f41107c94949d9e7d9';

        assert.strictEqual(
          Transaction.fromHex(hex).ins[0].issuance!.assetEntropy.toString(
            'hex',
          ),
          expectedEntropy,
        );
      });
    });
  });
});
