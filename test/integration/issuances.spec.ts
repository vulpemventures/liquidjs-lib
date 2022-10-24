import { IssuanceBlindingKeys } from './../../ts_src/types';
import { createPayment, getInputData } from './utils';
import { broadcast, faucet } from './_regtest';
import {
  address,
  confidential,
  ElementsValue,
  Psbt,
  Transaction,
  networks as NETWORKS,
} from '../../ts_src';
import { ECPair, ecc } from '../ecc';
import { strictEqual } from 'assert';
import {
  amountWithPrecisionToSatoshis,
  issuanceEntropyFromInput,
} from '../../ts_src/issuance';
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
        assetSats: amountWithPrecisionToSatoshis(100),
        tokenSats: amountWithPrecisionToSatoshis(1),
        blindedIssuance: true, // must be true, we'll blind the issuance!
        contract: {
          issuer_pubkey: '0000',
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
          value: ElementsValue.fromNumber(99999500).bytes,
          script: alice1.payment.output,
        },
        {
          nonce,
          asset,
          value: ElementsValue.fromNumber(500).bytes,
          script: Buffer.alloc(0),
        },
      ]);

    await psbt.blindOutputsByIndex(
      Psbt.ECCKeysGenerator(ecc),
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
    const valid = psbt.validateSignaturesOfInput(
      0,
      Psbt.ECDSASigValidator(ecc),
    );
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
      assetSats: 100_0000_0000,
      tokenSats: 1_0000_0000,
      contract: {
        issuer_pubkey: '0000',
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
        value: ElementsValue.fromNumber(99996500).bytes,
        script: alice1.payment.output,
      },
      {
        nonce,
        asset,
        value: ElementsValue.fromNumber(3500).bytes,
        script: Buffer.alloc(0),
      },
    ]);
    await psbt.blindOutputsByIndex(
      Psbt.ECCKeysGenerator(ecc),
      new Map<number, Buffer>().set(0, blindingPrivkeys[0]),
      new Map<number, Buffer>()
        .set(0, blindingPubKeys[0])
        .set(1, blindingPubKeys[1]),
    );
    psbt.signInput(0, alice1.keys[0]);

    strictEqual(
      psbt.validateSignaturesOfInput(0, Psbt.ECDSASigValidator(ecc)),
      true,
    );
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
      assetSats: 100_0000_0000,
      tokenSats: 1_0000_0000,
      contract: {
        issuer_pubkey: '0000',
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
        value: ElementsValue.fromNumber(99999500).bytes,
        script: alice1.payment.output,
      },
      {
        nonce,
        asset,
        value: ElementsValue.fromNumber(500).bytes,
        script: Buffer.alloc(0),
      },
    ]);

    psbt.signAllInputs(alice1.keys[0]);

    const valid = psbt.validateSignaturesOfAllInputs(
      Psbt.ECDSASigValidator(ecc),
    );
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
        assetSats: 100_0000_0000,
        tokenSats: 1_0000_0000,
        blindedIssuance: true, // must be true, we'll blind the issuance!
        contract: {
          issuer_pubkey: '0000',
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
          value: ElementsValue.fromNumber(99999000).bytes,
          script: alice.payment.output,
        },
        {
          nonce,
          asset,
          value: ElementsValue.fromNumber(1000).bytes,
          script: Buffer.alloc(0),
        },
      ]);

    await issuancePset.blindOutputsByIndex(
      Psbt.ECCKeysGenerator(ecc),
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
    const valid = issuancePset.validateSignaturesOfAllInputs(
      Psbt.ECDSASigValidator(ecc),
    );
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
        value: ElementsValue.fromNumber(99998000).bytes,
        script: alice.payment.output,
      })
      .addReissuance({
        tokenPrevout: { txHash: issuanceTx.getHash(false), vout: 1 },
        prevoutBlinder: tokenBlinder,
        entropy,
        assetSats: amountWithPrecisionToSatoshis(2000),
        tokenSats: amountWithPrecisionToSatoshis(1),
        assetAddress,
        tokenAddress,
        witnessUtxo: tokenOutput,
        blindedIssuance: true, // must be true, we'll blind the issuance!
      })
      .addOutput({
        nonce,
        asset,
        value: ElementsValue.fromNumber(1000).bytes,
        script: Buffer.alloc(0),
      });

    await reissuancePset.blindOutputsByIndex(
      Psbt.ECCKeysGenerator(ecc),
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
    const validReissuance = reissuancePset.validateSignaturesOfAllInputs(
      Psbt.ECDSASigValidator(ecc),
    );
    strictEqual(validReissuance, true);
    reissuancePset.finalizeAllInputs();

    const reissuanceHex = reissuancePset.extractTransaction().toHex();
    await broadcast(reissuanceHex);
  });

  it('can create an unconfidential issuance tx, make the token output confidential and reissue', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, false);
    const aliceBlindKeys = ECPair.makeRandom({ network: regtest });
    alice.blindingKeys[0] = aliceBlindKeys.privateKey;
    const inputData = await getInputData(alice.payment, true, 'noredeem');

    const assetPay = createPayment('p2wpkh'); // unconfidential

    // 1. issue tx
    const issuePsbt = new Psbt();
    issuePsbt.addInput(inputData);
    issuePsbt.addIssuance({
      assetAddress: address.fromOutputScript(assetPay.payment.output, regtest),
      tokenAddress: address.fromOutputScript(alice.payment.output, regtest),
      assetSats: 1_0000_0000,
      tokenSats: 2_0000_0000,
      // confidentialFlag: true,
    });
    issuePsbt.addOutputs([
      {
        nonce,
        asset,
        value: ElementsValue.fromNumber(99999000).bytes,
        script: alice.payment.output,
      },
      {
        nonce,
        asset,
        value: ElementsValue.fromNumber(1000).bytes,
        script: Buffer.alloc(0),
      },
    ]);

    issuePsbt.signAllInputs(alice.keys[0]);
    const valid = issuePsbt.validateSignaturesOfAllInputs(
      Psbt.ECDSASigValidator(ecc),
    );
    strictEqual(valid, true);

    issuePsbt.finalizeAllInputs();
    const hex = issuePsbt.extractTransaction().toHex();
    await broadcast(hex);

    // 2. make the token output confidential
    const issuanceTx = Transaction.fromHex(hex);
    let changeOutput = issuanceTx.outs[2];
    let tokenOutput = issuanceTx.outs[1];

    const makeConfPsbt = new Psbt({ network: NETWORKS.regtest })
      .addInput({
        hash: issuanceTx.getId(),
        index: 2,
        witnessUtxo: changeOutput,
      })
      .addInput({
        hash: issuanceTx.getId(),
        index: 1,
        witnessUtxo: tokenOutput,
      })
      .addOutputs([
        {
          nonce,
          asset: tokenOutput.asset,
          value: ElementsValue.fromNumber(amountWithPrecisionToSatoshis(2))
            .bytes,
          script: alice.payment.output,
        },
        {
          nonce,
          asset,
          value: ElementsValue.fromNumber(99998000).bytes,
          script: alice.payment.output,
        },
        {
          nonce,
          asset,
          value: ElementsValue.fromNumber(1000).bytes,
          script: Buffer.alloc(0),
        },
      ]);

    await makeConfPsbt.blindOutputsByIndex(
      Psbt.ECCKeysGenerator(ecc),
      new Map(),
      new Map()
        .set(0, aliceBlindKeys.publicKey)
        .set(1, aliceBlindKeys.publicKey),
    );

    makeConfPsbt.signAllInputs(alice.keys[0]);
    strictEqual(
      makeConfPsbt.validateSignaturesOfAllInputs(Psbt.ECDSASigValidator(ecc)),
      true,
    );

    makeConfPsbt.finalizeAllInputs();
    const confHex = makeConfPsbt.extractTransaction().toHex();
    await broadcast(confHex);
    // faucet will generate a block (avoid mempool conflicts)
    await faucet(
      'Azps6Zm22NyVzbPCLqTdmE88LN7bM91Sevsnb7xvHE7j5s7WqGbdUnwgXj7KP4SuKDP4KLLDW3ZetVYG',
    );

    // 3. reissue from confidential token output
    const confTx = Transaction.fromHex(confHex);
    changeOutput = confTx.outs[1];
    tokenOutput = confTx.outs[0];

    const issuanceInput = issuanceTx.ins[0];
    const entropy = issuanceEntropyFromInput(issuanceInput);

    const unblindedTokenOutput = await confidential.unblindOutputWithKey(
      tokenOutput,
      alice.blindingKeys[0],
    );

    const tokenBlinder = unblindedTokenOutput.assetBlindingFactor;
    const aliceConfidential = createPayment(
      'p2wpkh',
      undefined,
      undefined,
      true,
    );

    const reissuancePset = new Psbt({ network: NETWORKS.regtest })
      .addInput({
        hash: confTx.getId(),
        index: 1,
        witnessUtxo: changeOutput,
      })
      .addOutput({
        nonce,
        asset,
        value: ElementsValue.fromNumber(99997000).bytes,
        script: alice.payment.output,
      })
      .addReissuance({
        tokenPrevout: { txHash: confTx.getHash(false), vout: 0 },
        prevoutBlinder: tokenBlinder,
        entropy,
        assetSats: amountWithPrecisionToSatoshis(200),
        tokenSats: amountWithPrecisionToSatoshis(2),
        assetAddress: aliceConfidential.payment.confidentialAddress,
        tokenAddress: aliceConfidential.payment.confidentialAddress,
        witnessUtxo: tokenOutput,
        blindedIssuance: false,
      })
      .addOutput({
        nonce,
        asset,
        value: ElementsValue.fromNumber(1000).bytes,
        script: Buffer.alloc(0),
      });

    await reissuancePset.blindOutputsByIndex(
      Psbt.ECCKeysGenerator(ecc),
      new Map<number, Buffer>()
        .set(0, alice.blindingKeys[0])
        .set(1, alice.blindingKeys[0]),
      new Map<number, Buffer>().set(0, aliceBlindKeys.publicKey),
    );

    reissuancePset.signAllInputs(alice.keys[0]);
    const validReissuance = reissuancePset.validateSignaturesOfAllInputs(
      Psbt.ECDSASigValidator(ecc),
    );
    strictEqual(validReissuance, true);
    reissuancePset.finalizeAllInputs();
    const reissuanceHex = reissuancePset.extractTransaction().toHex();
    await broadcast(reissuanceHex);
  });

  it('can create a 1-to-1 confidential Transaction with token-only issuance', async () => {
    const alice1 = createPayment('p2wpkh', undefined, undefined, true);
    const inputData = await getInputData(alice1.payment, true, 'noredeem');
    const blindingPrivkeys = alice1.blindingKeys;

    const issuanceBlindingKeys = ['', ''].map((_) =>
      ECPair.makeRandom({ network: regtest }),
    );

    const tokenPay = createPayment('p2wpkh', undefined, undefined, true);

    const blindingPubKeys = ['', ''].map(
      () => ECPair.makeRandom({ network: regtest }).publicKey,
    );

    const psbt = new Psbt();
    psbt
      .addInput(inputData)
      .addIssuance({
        tokenAddress: address.fromOutputScript(
          tokenPay.payment.output,
          regtest,
        ),
        assetSats: 0,
        tokenSats: 1,
        blindedIssuance: true, // must be true, we'll blind the issuance!
        contract: {
          issuer_pubkey: '0000',
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
          value: ElementsValue.fromNumber(99999500).bytes,
          script: alice1.payment.output,
        },
        {
          nonce,
          asset,
          value: ElementsValue.fromNumber(500).bytes,
          script: Buffer.alloc(0),
        },
      ]);

    await psbt.blindOutputsByIndex(
      Psbt.ECCKeysGenerator(ecc),
      new Map<number, Buffer>().set(0, blindingPrivkeys[0]),
      new Map<number, Buffer>()
        .set(0, blindingPubKeys[0])
        .set(1, blindingPubKeys[1]),
      new Map<number, IssuanceBlindingKeys>().set(0, {
        assetKey: issuanceBlindingKeys[0].privateKey,
        tokenKey: issuanceBlindingKeys[1].privateKey,
      }),
    );

    psbt.signAllInputs(alice1.keys[0]);
    const valid = psbt.validateSignaturesOfInput(
      0,
      Psbt.ECDSASigValidator(ecc),
    );
    if (!valid) {
      throw new Error('signature is not valid');
    }
    psbt.finalizeAllInputs();
    const t = psbt.extractTransaction();
    const hex = t.toHex();
    await broadcast(hex);
  });
});
