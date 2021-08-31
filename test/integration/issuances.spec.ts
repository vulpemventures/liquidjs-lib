import { IssuanceBlindingKeys } from './../../ts_src/types';
import { networks as NETWORKS } from '../..';
import { createPayment, getInputData } from './utils';
import { broadcast } from './_regtest';
import { address, confidential, ECPair, Psbt } from '../../ts_src';
import { strictEqual } from 'assert';
const { regtest } = NETWORKS;

const nonce = Buffer.from('00', 'hex');
const asset = Buffer.concat([
  Buffer.from('01', 'hex'),
  Buffer.from(regtest.assetHash, 'hex').reverse(),
]);

describe('liquidjs-lib (issuances transactions with psbt)', () => {
  it('can create a 1-to-1 confidential Transaction (and broadcast via 3PBP) with blinded issuance', async () => {
    const alice1 = createPayment('p2wpkh', undefined, undefined, true);
    const inputData = await getInputData(alice1.payment, true, 'noredeem');
    const blindingPrivkeys = alice1.blindingKeys;

    const assetPay = createPayment('p2wpkh', undefined, undefined, true);
    const tokenPay = createPayment('p2wpkh', undefined, undefined, true);
    const issuanceBlindingKeys = ['', ''].map(
      () => ECPair.makeRandom({ network: regtest }).privateKey!,
    );

    const blindingPubKeys = ['', ''].map(
      () => ECPair.makeRandom({ network: regtest }).publicKey,
    );

    const psbt = new Psbt();
    psbt
      .addInput(inputData)
      .addIssuance({
        assetAddress: address.fromOutputScript(
          assetPay.payment.output,
          regtest,
        ),
        tokenAddress: address.fromOutputScript(
          tokenPay.payment.output,
          regtest,
        ),
        assetAmount: 100,
        tokenAmount: 1,
        precision: 8,
        confidential: true, // must be true, we'll blind the issuance!
        contract: {
          name: 'testcoin',
          ticker: 'T-COIN',
          entity: {
            domain: 'vulpemventures.com',
          },
          version: 0,
          precision: 8,
        },
      })
      .addOutputs([
        {
          nonce,
          asset,
          value: confidential.satoshiToConfidentialValue(99999500),
          script: alice1.payment.output,
        },
        {
          nonce,
          asset,
          value: confidential.satoshiToConfidentialValue(500),
          script: Buffer.alloc(0),
        },
      ]);

    await psbt.blindOutputsByIndex(
      new Map<number, Buffer>().set(0, blindingPrivkeys[0]),
      new Map<number, Buffer>()
        .set(0, blindingPubKeys[0])
        .set(1, blindingPubKeys[1]),
      new Map<number, IssuanceBlindingKeys>().set(0, {
        assetKey: issuanceBlindingKeys[0],
        tokenKey: issuanceBlindingKeys[1],
      }),
    );

    psbt.signAllInputs(alice1.keys[0]);
    const valid = psbt.validateSignaturesOfInput(0);
    if (!valid) {
      throw new Error('signature is not valid');
    }
    psbt.finalizeAllInputs();
    const hex = psbt.extractTransaction().toHex();
    await broadcast(hex);
  });

  it('can create a 1-to-1 confidential Transaction (and broadcast via 3PBP) with unblinded issuance', async () => {
    const alice1 = createPayment('p2wpkh', undefined, undefined, true);
    const inputData = await getInputData(alice1.payment, true, 'noredeem');
    const blindingPrivkeys = alice1.blindingKeys;

    const assetPay = createPayment('p2wpkh', undefined, undefined, false);
    const tokenPay = createPayment('p2wpkh', undefined, undefined, false);
    const blindingPubKeys = ['', ''].map(
      () => ECPair.makeRandom({ network: regtest }).publicKey,
    );

    const psbt = new Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput(inputData);
    psbt.addIssuance({
      assetAddress: address.fromOutputScript(assetPay.payment.output, regtest),
      tokenAddress: address.fromOutputScript(tokenPay.payment.output, regtest),
      assetAmount: 100,
      tokenAmount: 1,
      precision: 8,
      contract: {
        name: 'testcoin-bis',
        ticker: 'T-COI',
        entity: {
          domain: 'vulpemventures.com',
        },
        version: 0,
        precision: 8,
      },
    });
    psbt.addOutputs([
      {
        nonce,
        asset,
        value: confidential.satoshiToConfidentialValue(99996500),
        script: alice1.payment.output,
      },
      {
        nonce,
        asset,
        value: confidential.satoshiToConfidentialValue(3500),
        script: Buffer.alloc(0),
      },
    ]);
    await psbt.blindOutputsByIndex(
      new Map<number, Buffer>().set(0, blindingPrivkeys[0]),
      new Map<number, Buffer>()
        .set(0, blindingPubKeys[0])
        .set(1, blindingPubKeys[1]),
    );
    psbt.signInput(0, alice1.keys[0]);

    strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();
    const hex = psbt.extractTransaction().toHex();
    await broadcast(hex);
  });

  it('can create a 1-to-1 unconfidential Transaction (and broadcast via 3PBP) with unblinded issuance', async () => {
    const alice1 = createPayment('p2wpkh', undefined, undefined, false);
    const inputData = await getInputData(alice1.payment, true, 'noredeem');

    const assetPay = createPayment('p2wpkh', undefined, undefined, true); // unconfidential
    const tokenPay = createPayment('p2wpkh', undefined, undefined, true); // unconfidential

    const psbt = new Psbt();
    psbt.addInput(inputData);
    psbt.addIssuance({
      assetAddress: address.fromOutputScript(assetPay.payment.output, regtest),
      tokenAddress: address.fromOutputScript(tokenPay.payment.output, regtest),
      assetAmount: 100,
      tokenAmount: 1,
      precision: 8,
      contract: {
        name: 'testcoin-bis',
        ticker: 'T-COI',
        entity: {
          domain: 'vulpemventures.com',
        },
        version: 0,
        precision: 8,
      },
    });
    psbt.addOutputs([
      {
        nonce,
        asset,
        value: confidential.satoshiToConfidentialValue(99999500),
        script: alice1.payment.output,
      },
      {
        nonce,
        asset,
        value: confidential.satoshiToConfidentialValue(500),
        script: Buffer.alloc(0),
      },
    ]);

    psbt.signAllInputs(alice1.keys[0]);

    const valid = psbt.validateSignaturesOfAllInputs();
    strictEqual(valid, true);

    psbt.finalizeAllInputs();
    const hex = psbt.extractTransaction().toHex();
    await broadcast(hex);
  });
});
