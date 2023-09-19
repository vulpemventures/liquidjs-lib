import secp256k1 from '@vulpemventures/secp256k1-zkp';
import * as tinyecc from 'tiny-secp256k1';
import assert from 'node:assert';
import { ECPairFactory } from 'ecpair';
import { networks, silentpayment } from '../ts_src';
const { SilentPayment } = silentpayment;

import jsonImput from './fixtures/silent_payments.json';

const ECPair = ECPairFactory(tinyecc);

type TestCase = {
  comment: string;
  given: {
    outpoints: [string, number][];
    input_priv_keys: [string, boolean][];
    recipients: [string, number][];
  };
  expected: {
    outputs: [string, number][];
  };
};

const tests = jsonImput as unknown as Array<TestCase>;

describe('silentPayments', () => {
  let ecc: any;

  before(async () => {
    ecc = (await secp256k1()).ecc;
    ecc = {
      ...ecc,
      privateMultiply: ecc.privateMul,
      pointAdd: tinyecc.pointAdd,
      pointMultiply: tinyecc.pointMultiply,
    };
  });

  /* Sending tests from the BIP352 test vectors */
  tests.forEach((testCase) => {
    // Prepare the 'inputs' array
    const inputs = testCase.given.outpoints.map((outpoint, idx) => ({
      txid: outpoint[0],
      vout: outpoint[1],
      WIF: ECPair.fromPrivateKey(
        Buffer.from(testCase.given.input_priv_keys[idx][0], 'hex'),
      ).toWIF(),
      isTaproot: testCase.given.input_priv_keys[idx][1],
    }));

    // Prepare the 'recipients' array
    const recipients: silentpayment.Target[] = testCase.given.recipients.map(
      (recipient) => ({
        silentPaymentAddress: recipient[0],
        value: recipient[1],
        asset: networks.regtest.assetHash,
      }),
    );

    it(`Test Case: ${testCase.comment} works`, () => {
      const sp = new SilentPayment(ecc);
      const outpointsHash = silentpayment.outpointsHash(inputs);
      const sumPrivateKeys = sp.sumSecretKeys(inputs.map(castWIF));

      assert.deepStrictEqual(
        sp.pay(outpointsHash, sumPrivateKeys, recipients),
        testCase.expected.outputs.map((output) => {
          const address = '5120' + output[0];
          const value = output[1];
          return {
            scriptPubKey: address,
            value: value,
            asset: networks.regtest.assetHash,
          };
        }),
      );
    });
  });

  it('silentpayment.outpointHash() works', () => {
    assert.deepStrictEqual(
      silentpayment
        .outpointsHash([
          {
            txid: 'a2365547d16b555593e3f58a2b67143fc8ab84e7e1257b1c13d2a9a2ec3a2efb',
            vout: 0,
          },
        ])
        .toString('hex'),
      'dc28dfeffd23899e1ec394a601ef543fa4f29c59e8548ceeca8f3b40fef5d041',
    );

    // multiple outpoints

    assert.deepStrictEqual(
      silentpayment
        .outpointsHash([
          {
            txid: 'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16',
            vout: 0,
          },
          {
            txid: 'a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d',
            vout: 0,
          },
        ])
        .toString('hex'),
      '210fef5d624db17c965c7597e2c6c9f60ef440c831d149c43567c50158557f12',
    );
  });
});

function castWIF<T extends { WIF: string }>(
  obj: T,
): Omit<T, 'WIF'> & { key: Buffer } {
  const { WIF, ...rest } = obj;
  const keyPair = ECPair.fromWIF(WIF);
  if (!keyPair.privateKey) throw new Error('WIF is not a private key');
  return {
    ...rest,
    key: keyPair.privateKey,
  };
}
