import { IssuanceBlindingKeys } from './../../ts_src/types';
import { createPayment, getInputData } from './utils';
import { broadcast } from './_regtest';
import {
  address,
  confidential,
  ECPair,
  Psbt,
  Transaction,
  networks as NETWORKS,
} from '../../ts_src';
import { strictEqual } from 'assert';
import { issuanceEntropyFromInput } from '../../ts_src/issuance';
import { fromConfidential } from '../../ts_src/address';

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

  it('can create a confidential reissuance transaction from confidential issuance transaction', async () => {
    // Issuance
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const inputData = await getInputData(alice.payment, true, 'noredeem');
    const aliceBlindingPrivkeys = alice.blindingKeys;

    const assetPay = createPayment('p2wpkh', undefined, undefined, true);
    const issuanceBlindingKeys = ['', '', ''].map(
      () => ECPair.makeRandom({ network: regtest }).privateKey!,
    );

    const blindingKeysPair = ['', '', ''].map(() =>
      ECPair.makeRandom({ network: regtest }),
    );

    const assetAddress = assetPay.payment.confidentialAddress;
    const tokenAddress = alice.payment.confidentialAddress;

    const issuancePset = new Psbt({ network: NETWORKS.regtest });
    issuancePset
      .addInput(inputData)
      .addIssuance({
        assetAddress,
        tokenAddress,
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
          script: alice.payment.output,
        },
        {
          nonce,
          asset,
          value: confidential.satoshiToConfidentialValue(500),
          script: Buffer.alloc(0),
        },
      ]);

    await issuancePset.blindOutputsByIndex(
      new Map<number, Buffer>().set(0, aliceBlindingPrivkeys[0]),
      new Map<number, Buffer>()
        .set(0, blindingKeysPair[0].publicKey)
        .set(1, fromConfidential(tokenAddress).blindingKey)
        .set(2, fromConfidential(tokenAddress).blindingKey),
      new Map<number, IssuanceBlindingKeys>().set(0, {
        assetKey: issuanceBlindingKeys[0],
        tokenKey: issuanceBlindingKeys[1],
      }),
    );

    issuancePset.signAllInputs(alice.keys[0]);
    const valid = issuancePset.validateSignaturesOfAllInputs();
    if (!valid) {
      throw new Error('signature is not valid');
    }
    issuancePset.finalizeAllInputs();
    const hex = issuancePset.extractTransaction().toHex();
    await broadcast(hex);

    // RE-ISSUANCE
    const issuanceTx = Transaction.fromHex(hex);
    const issuanceInput = issuanceTx.ins[0];

    if (!issuanceInput.issuance) {
      throw new Error('no issuance in issuance input');
    }

    const entropy = issuanceEntropyFromInput(issuanceInput);

    const tokenOutput = issuanceTx.outs[1];
    const changeOutput = issuanceTx.outs[2];

    const unblindedTokenOutput = await confidential.unblindOutputWithKey(
      tokenOutput,
      aliceBlindingPrivkeys[0],
    );

    const tokenBlinder = unblindedTokenOutput.assetBlindingFactor;

    const reissuancePset = new Psbt({ network: NETWORKS.regtest });

    reissuancePset
      .addInput({
        hash: issuanceTx.getId(),
        index: 2,
        witnessUtxo: changeOutput,
      })
      .addOutput({
        nonce,
        asset,
        value: confidential.satoshiToConfidentialValue(99999000),
        script: alice.payment.output,
      })
      .addReissuance({
        tokenPrevout: { txHash: issuanceTx.getHash(false), vout: 1 },
        prevoutBlinder: tokenBlinder,
        entropy,
        assetAmount: 2000,
        tokenAmount: 1,
        assetAddress,
        tokenAddress,
        witnessUtxo: tokenOutput,
        precision: 8,
      })
      .addOutput({
        nonce,
        asset,
        value: confidential.satoshiToConfidentialValue(500),
        script: Buffer.alloc(0),
      });

    await reissuancePset.blindOutputsByIndex(
      new Map<number, Buffer>()
        .set(0, aliceBlindingPrivkeys[0])
        .set(1, aliceBlindingPrivkeys[0]),
      new Map<number, Buffer>()
        .set(0, fromConfidential(alice.payment.confidentialAddress).blindingKey)
        .set(1, blindingKeysPair[1].publicKey)
        .set(2, blindingKeysPair[2].publicKey),
      new Map<number, IssuanceBlindingKeys>().set(1, {
        assetKey: issuanceBlindingKeys[0],
      }),
    );

    reissuancePset.signAllInputs(alice.keys[0]);
    const validReissuance = reissuancePset.validateSignaturesOfAllInputs();
    if (!validReissuance) {
      throw new Error('signature is not valid');
    }
    reissuancePset.finalizeAllInputs();
    const reissuanceHex = issuancePset.extractTransaction().toHex();
    await broadcast(reissuanceHex);
  });
});
