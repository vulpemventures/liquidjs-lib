import * as assert from 'assert';
import * as bip32 from 'bip32';
import * as liquid from '../..';
import * as regtestUtils from './_regtest';

import { describe, it } from 'mocha';

import { networks as NETWORKS } from '../..';
import { createPayment, getInputData, nonWitnessUtxoBuffer } from './utils';

const rng = require('randombytes');
const { regtest } = NETWORKS;
const {
  satoshiToConfidentialValue,
  unblindOutputWithKey,
} = liquid.confidential;

// See bottom of file for some helper functions used to make the payment objects needed.

describe('liquidjs-lib (transactions with psbt)', () => {
  const alice = liquid.ECPair.fromWIF(
    'cPNMJD4VyFnQjGbGs3kcydRzAbDCXrLAbvH6wTCqs88qg1SkZT3J',
    regtest,
  );
  const bob = liquid.ECPair.fromWIF(
    'cQ7z41awTvKtmiD9p6zkjbgvYbV8g5EDDNcTnKZS9aZ8XdjQiZMU',
    regtest,
  );

  const nonce = Buffer.from('00', 'hex');
  const asset = Buffer.concat([
    Buffer.from('01', 'hex'),
    Buffer.from(regtest.assetHash, 'hex').reverse(),
  ]);

  it('can create a 1-to-1 Transaction', () => {
    const psbt = new liquid.Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput({
      // if hash is string, txid, if hash is Buffer, is reversed compared to txid
      hash: '9d64f0343e264f9992aa024185319b349586ec4cbbfcedcda5a05678ab10e580',
      index: 0,
      // non-segwit inputs now require passing the whole previous tx as Buffer
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
    });
    psbt.addOutputs([
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.confidential.satoshiToConfidentialValue(50000000),
        script: Buffer.from(
          '76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac',
          'hex',
        ),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.confidential.satoshiToConfidentialValue(49999100),
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
      {
        nonce: Buffer.from('00', 'hex'),
        value: liquid.confidential.satoshiToConfidentialValue(500),
        script: Buffer.alloc(0),
        asset: Buffer.concat([
          Buffer.from('01', 'hex'),
          Buffer.from(
            '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225',
            'hex',
          ).reverse(),
        ]),
      },
    ]);
    psbt.signInput(0, alice);
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    assert.strictEqual(
      psbt.extractTransaction().toHex(),
      '02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f' +
        '0649d000000006a47304402201e868b2bea22df05229746a27e7df2ca0f584880546f7f' +
        '6d55dad71cbd50d35302203a04a4cc49fca739c8974c97d3de924c99835e15ad1d85b96' +
        'ad24ea072d2e63e01210251464420fcc98a2e4cd347afe28a32d769287dacd861476ab8' +
        '58baa43bd308f3ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0' +
        'b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469' +
        'afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e7' +
        '7c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3' +
        'a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4f' +
        'c0e5cf6c95a0100000000000001f4000000000000',
    );
  });

  it('can create a 1-to-1 confidential Transaction', () => {
    const blindingPrivkeys = [
      Buffer.from(
        '13d4dbfdb5074705e6b9758d1542d7dd8c03055086c0da421620eaa04717a9f7',
        'hex',
      ),
    ];
    const bliningPubkeys = [''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );

    const psbt = new liquid.Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput({
      // if hash is string, txid, if hash is Buffer, is reversed compared to txid
      hash: 'dd983c9c0419fce6bcc0eaf875b54a2c19f9d6e761faa58b1afd199638275475',
      index: 0,
      // non-segwit inputs now require passing the whole previous tx as Buffer
      nonWitnessUtxo: nonWitnessUtxoBuffer,
    });
    psbt.addOutputs([
      {
        nonce,
        asset,
        value: liquid.confidential.satoshiToConfidentialValue(99996500),
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
      },
      {
        nonce,
        asset,
        value: liquid.confidential.satoshiToConfidentialValue(3500),
        script: Buffer.alloc(0),
      },
    ]);
    psbt.blindOutputs(blindingPrivkeys, bliningPubkeys);
    psbt.signInput(0, bob);
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    psbt.extractTransaction();
  });

  it('can create (and broadcast via 3PBP) a typical Transaction', async () => {
    // these are { payment: Payment; keys: ECPair[] }
    const alice1 = createPayment('p2pkh');
    const alice2 = createPayment('p2pkh');

    // give Alice 2 unspent outputs
    const inputData1 = await getInputData(alice1.payment, false, 'noredeem');
    const inputData2 = await getInputData(alice2.payment, false, 'noredeem');
    {
      const {
        hash, // string of txid or Buffer of tx hash. (txid and hash are reverse order)
        index, // the output index of the txo you are spending
        nonWitnessUtxo, // the full previous transaction as a Buffer
      } = inputData1;
      assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData1);
    }

    // network is only needed if you pass an address to addOutput
    // using script (Buffer of scriptPubkey) instead will avoid needed network.
    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData1) // alice1 unspent
      .addInput(inputData2) // alice2 unspent
      .addOutput({
        asset,
        nonce,
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        value: satoshiToConfidentialValue(150000000),
      }) // the actual spend
      .addOutput({
        asset,
        nonce,
        script: alice2.payment.output,
        value: satoshiToConfidentialValue(49999300),
      }) // Alice's change
      .addOutput({
        asset,
        nonce,
        script: Buffer.alloc(0),
        value: satoshiToConfidentialValue(700),
      }); // fees in Liquid are explicit

    // Let's show a new feature with PSBT.
    // We can have multiple signers sign in parrallel and combine them.
    // (this is not necessary, but a nice feature)

    // encode to send out to the signers
    const psbtBaseText = psbt.toBase64();

    // each signer imports
    const signer1 = liquid.Psbt.fromBase64(psbtBaseText);
    const signer2 = liquid.Psbt.fromBase64(psbtBaseText);

    // Alice signs each input with the respective private keys
    // signInput and signInputAsync are better
    // (They take the input index explicitly as the first arg)
    signer1.signAllInputs(alice1.keys[0]);
    signer2.signAllInputs(alice2.keys[0]);

    // If your signer object's sign method returns a promise, use the following
    // await signer2.signAllInputsAsync(alice2.keys[0])

    // encode to send back to combiner (signer 1 and 2 are not near each other)
    const s1text = signer1.toBase64();
    const s2text = signer2.toBase64();

    const final1 = liquid.Psbt.fromBase64(s1text);
    const final2 = liquid.Psbt.fromBase64(s2text);

    // final1.combine(final2) would give the exact same result
    psbt.combine(final1, final2);

    // Finalizer wants to check all signatures are valid before finalizing.
    // If the finalizer wants to check for specific pubkeys, the second arg
    // can be passed. See the first multisig example below.
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(psbt.validateSignaturesOfInput(1), true);

    // This step it new. Since we separate the signing operation and
    // the creation of the scriptSig and witness stack, we are able to
    psbt.finalizeAllInputs();

    // build and broadcast our RegTest network
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    // to build and broadcast to the actual Bitcoin network, see https://github.com/bitcoinjs/bitcoinjs-lib/issues/839
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction', async () => {
    // these are { payment: Payment; keys: ECPair[] }
    const alice1 = createPayment('p2pkh', undefined, undefined, true);
    const blindingPubkeys = ['', ''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );

    // give Alice 2 unspent outputs
    const inputData1 = await getInputData(alice1.payment, false, 'noredeem');
    {
      const {
        hash, // string of txid or Buffer of tx hash. (txid and hash are reverse order)
        index, // the output index of the txo you are spending
        nonWitnessUtxo, // the full previous transaction as a Buffer
      } = inputData1;
      assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData1);
    }

    // network is only needed if you pass an address to addOutput
    // using script (Buffer of scriptPubkey) instead will avoid needed network.
    let psbt = await new liquid.Psbt({ network: regtest })
      .addInput(inputData1) // alice1 unspent
      .addOutput({
        asset,
        nonce,
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        value: satoshiToConfidentialValue(50000000),
      }) // the actual spend
      .addOutput({
        asset,
        nonce,
        script: alice1.payment.output,
        value: satoshiToConfidentialValue(49993000),
      }) // Alice's change
      .addOutput({
        asset,
        nonce,
        script: Buffer.alloc(0),
        value: satoshiToConfidentialValue(7000),
      }) // fees in Liquid are explicit
      .blindOutputs(alice1.blindingKeys, blindingPubkeys);

    psbt = psbt.signAllInputs(alice1.keys[0]);

    // Finalizer wants to check all signatures are valid before finalizing.
    // If the finalizer wants to check for specific pubkeys, the second arg
    // can be passed. See the first multisig example below.
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);

    // This step it new. Since we separate the signing operation and
    // the creation of the scriptSig and witness stack, we are able to
    psbt.finalizeAllInputs();

    // build and broadcast our RegTest network
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    // to build and broadcast to the actual Bitcoin network, see https://github.com/bitcoinjs/bitcoinjs-lib/issues/839
  });

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction' +
      ' with confidential AND unconfidential outputs',
    async () => {
      // these are { payment: Payment; keys: ECPair[] }
      const alicePayment = createPayment('p2pkh', undefined, undefined, true); // confidential
      const bobPayment = createPayment('p2pkh', undefined, undefined, false); // unconfidential

      const aliceBlindingPubKey = liquid.ECPair.fromPrivateKey(
        alicePayment.blindingKeys[0],
      ).publicKey!;

      const aliceBlindingPrivateKey: Buffer = alicePayment.blindingKeys[0];

      // give Alice unspent outputs
      const inputData1 = await getInputData(
        alicePayment.payment,
        false,
        'noredeem',
      );
      {
        const {
          hash, // string of txid or Buffer of tx hash. (txid and hash are reverse order)
          index, // the output index of the txo you are spending
          nonWitnessUtxo, // the full previous transaction as a Buffer
        } = inputData1;
        assert.deepStrictEqual({ hash, index, nonWitnessUtxo }, inputData1);
      }

      // network is only needed if you pass an address to addOutput
      // using script (Buffer of scriptPubkey) instead will avoid needed network.
      let psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData1) // alice unspent
        .addOutput({
          asset,
          nonce,
          script: bobPayment.payment.output,
          value: satoshiToConfidentialValue(50000000),
        }) // the actual spend to bob
        .addOutput({
          asset,
          nonce,
          script: alicePayment.payment.output,
          value: satoshiToConfidentialValue(29993000),
        }) // Alice's change
        .addOutput({
          asset,
          nonce,
          script: alicePayment.payment.output,
          value: satoshiToConfidentialValue(20000000),
        }) // Alice's change bis
        .addOutput({
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: satoshiToConfidentialValue(7000),
        }) // fees in Liquid are explicit
        .blindOutputsByIndex(
          new Map().set(0, aliceBlindingPrivateKey),
          new Map().set(1, aliceBlindingPubKey).set(2, aliceBlindingPubKey),
        );

      psbt = psbt.signAllInputs(alicePayment.keys[0]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      psbt.finalizeAllInputs();

      // build and broadcast our RegTest network
      await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction' +
      ' with confidential AND unconfidential inputs',
    async () => {
      // these are { payment: Payment; keys: ECPair[] }
      const alicePaymentUnconfidential = createPayment(
        'p2pkh',
        undefined,
        undefined,
        false,
      ); // unconfidential

      const alicePaymentConfidential = createPayment(
        'p2pkh',
        undefined,
        undefined,
        true,
      ); // confidential
      const bobPayment = createPayment('p2pkh', undefined, undefined, false); // unconfidential

      const aliceBlindingPubKey = liquid.ECPair.fromPrivateKey(
        alicePaymentConfidential.blindingKeys[0],
      ).publicKey!;

      const aliceBlindingPrivateKey: Buffer =
        alicePaymentConfidential.blindingKeys[0];

      // give Alice unspent outputs
      const inputDataUnconfidential = await getInputData(
        alicePaymentUnconfidential.payment,
        false,
        'noredeem',
      );

      const inputDataConfidential = await getInputData(
        alicePaymentConfidential.payment,
        false,
        'noredeem',
      );

      // network is only needed if you pass an address to addOutput
      // using script (Buffer of scriptPubkey) instead will avoid needed network.
      let psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputDataUnconfidential) // alice unspent (unconfidential)
        .addInput(inputDataConfidential) // alice unspent (confidential)
        .addOutput({
          asset,
          nonce,
          script: bobPayment.payment.output,
          value: satoshiToConfidentialValue(99993000),
        }) // the actual spend to bob
        .addOutput({
          asset,
          nonce,
          script: alicePaymentConfidential.payment.output,
          value: satoshiToConfidentialValue(99999000),
        }) // Alice's change
        .addOutput({
          asset,
          nonce,
          script: alicePaymentConfidential.payment.output,
          value: satoshiToConfidentialValue(1000),
        }) // Alice's change bis (need two blind outputs)
        .addOutput({
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: satoshiToConfidentialValue(7000),
        }) // fees in Liquid are explicit
        .blindOutputsByIndex(
          new Map().set(1, aliceBlindingPrivateKey),
          new Map().set(1, aliceBlindingPubKey).set(2, aliceBlindingPubKey),
        );

      psbt = psbt
        .signInput(0, alicePaymentUnconfidential.keys[0])
        .signInput(1, alicePaymentConfidential.keys[0]);

      assert.doesNotThrow(() => liquid.Psbt.fromBase64(psbt.toBase64()));

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      assert.strictEqual(psbt.validateSignaturesOfInput(1), true);

      psbt.finalizeAllInputs();

      // build and broadcast our RegTest network
      await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction' +
      ' using blinders',
    async () => {
      // these are { payment: Payment; keys: ECPair[] }
      const alicePaymentConfidential = createPayment(
        'p2wpkh',
        undefined,
        undefined,
        true,
      ); // confidential

      const bobPayment = createPayment('p2pkh', undefined, undefined, false); // unconfidential

      const aliceBlindingPubKey = liquid.ECPair.fromPrivateKey(
        alicePaymentConfidential.blindingKeys[0],
      ).publicKey!;

      const aliceBlindingPrivateKey: Buffer =
        alicePaymentConfidential.blindingKeys[0];

      const inputDataConfidential = await getInputData(
        alicePaymentConfidential.payment,
        true,
        'noredeem',
      );

      const inputBlindingData = unblindOutputWithKey(
        inputDataConfidential.witnessUtxo,
        aliceBlindingPrivateKey,
      );

      // network is only needed if you pass an address to addOutput
      // using script (Buffer of scriptPubkey) instead will avoid needed network.
      const psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputDataConfidential) // alice unspent (confidential)
        .addOutput({
          asset,
          nonce,
          script: bobPayment.payment.output,
          value: satoshiToConfidentialValue(1000),
        }) // the actual spend to bob
        .addOutput({
          asset,
          nonce,
          script: alicePaymentConfidential.payment.output,
          value: satoshiToConfidentialValue(99991000),
        }) // Alice's change
        .addOutput({
          asset,
          nonce,
          script: alicePaymentConfidential.payment.output,
          value: satoshiToConfidentialValue(1000),
        }) // Alice's change bis (need two blind outputs)
        .addOutput({
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: satoshiToConfidentialValue(7000),
        }) // fees in Liquid are explicit
        .blindOutputsByIndex(
          new Map().set(0, inputBlindingData),
          new Map().set(1, aliceBlindingPubKey).set(2, aliceBlindingPubKey),
        );

      psbt.signInput(0, alicePaymentConfidential.keys[0]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);

      psbt.finalizeAllInputs();

      // build and broadcast our RegTest network
      await regtestUtils.broadcast(psbt.extractTransaction().toHex());
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction with an OP_RETURN output', async () => {
    const alice1 = createPayment('p2pkh');
    const inputData1 = await getInputData(alice1.payment, false, 'noredeem');

    const data = Buffer.from('bitcoinjs-lib', 'utf8');
    const embed = liquid.payments.embed({ data: [data] });

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData1)
      .addOutput({
        asset,
        nonce,
        script: embed.output!,
        value: liquid.confidential.satoshiToConfidentialValue(500),
      })
      .addOutput({
        asset,
        nonce,
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
        value: liquid.confidential.satoshiToConfidentialValue(99999000),
      })
      .addOutput({
        asset,
        nonce,
        script: Buffer.alloc(0),
        value: liquid.confidential.satoshiToConfidentialValue(500),
      })
      .signInput(0, alice1.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    // build and broadcast to the RegTest network
    await regtestUtils.broadcast(psbt.extractTransaction().toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2MS(2 of 4)) (multisig) input', async () => {
    const multisig = createPayment('p2sh-p2ms(2 of 4)');
    const inputData1 = await getInputData(multisig.payment, false, 'p2sh');
    {
      const {
        hash,
        index,
        nonWitnessUtxo,
        redeemScript, // NEW: P2SH needs to give redeemScript when adding an input.
      } = inputData1;
      assert.deepStrictEqual(
        { hash, index, nonWitnessUtxo, redeemScript },
        inputData1,
      );
    }

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData1)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, multisig.keys[0])
      .signInput(0, multisig.keys[2]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, multisig.keys[0].publicKey),
      true,
    );
    assert.throws(() => {
      psbt.validateSignaturesOfInput(0, multisig.keys[3].publicKey);
    }, new RegExp('No signatures for this pubkey'));
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2WPKH) input', async () => {
    const p2sh = createPayment('p2sh-p2wpkh');
    const inputData = await getInputData(p2sh.payment, true, 'p2sh');
    const inputData2 = await getInputData(p2sh.payment, true, 'p2sh');

    {
      const {
        hash,
        index,
        witnessUtxo, // NEW: this is an object of the output being spent { script: Buffer; value: Satoshis; }
        redeemScript,
      } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, redeemScript },
        inputData,
      );
    }
    const keyPair = p2sh.keys[0];
    const outputData = {
      asset: inputData.witnessUtxo.asset,
      nonce,
      script: p2sh.payment.output, // sending to myself for fun
      value: liquid.confidential.satoshiToConfidentialValue(199999300),
    };
    const outputData2 = {
      asset: inputData.witnessUtxo.asset,
      nonce,
      script: Buffer.alloc(0), // fees
      value: liquid.confidential.satoshiToConfidentialValue(700),
    };

    const tx = new liquid.Psbt()
      .addInputs([inputData, inputData2])
      .addOutputs([outputData, outputData2])
      .signAllInputs(keyPair)
      .finalizeAllInputs()
      .extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction, w/ a P2SH(P2WPKH) input', async () => {
    const p2sh = createPayment('p2sh-p2wpkh', undefined, undefined, true);
    const inputData = await getInputData(p2sh.payment, true, 'p2sh');
    const inputData2 = await getInputData(p2sh.payment, true, 'p2sh');
    const blindingKeys = ['', ''].map(() => p2sh.blindingKeys[0]);
    const blindingPubkeys = ['', ''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );

    {
      const { hash, index, witnessUtxo, redeemScript } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, redeemScript },
        inputData,
      );
    }
    const keyPair = p2sh.keys[0];
    const outputData = {
      asset,
      nonce,
      script: p2sh.payment.output, // change
      value: liquid.confidential.satoshiToConfidentialValue(159993000),
    };
    const outputData2 = {
      asset,
      nonce,
      script: Buffer.from(
        '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
        'hex',
      ), // actual spend
      value: liquid.confidential.satoshiToConfidentialValue(40000000),
    };
    const outputData3 = {
      asset,
      nonce,
      script: Buffer.alloc(0), // fees
      value: liquid.confidential.satoshiToConfidentialValue(7000),
    };

    const psbt = await new liquid.Psbt()
      .addInputs([inputData, inputData2])
      .addOutputs([outputData, outputData2, outputData3])
      .blindOutputs(blindingKeys, blindingPubkeys);

    const tx = psbt.signAllInputs(keyPair);

    const toBroadcast = liquid.Psbt.fromBase64(tx.toBase64())
      .finalizeAllInputs()
      .extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(toBroadcast.toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2SH(P2WPKH) input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2sh = createPayment('p2sh-p2wpkh');
    const inputData = await getInputData(p2sh.payment, false, 'p2sh');
    const inputData2 = await getInputData(p2sh.payment, false, 'p2sh');
    const keyPair = p2sh.keys[0];
    const outputData = {
      asset,
      nonce,
      script: p2sh.payment.output,
      value: liquid.confidential.satoshiToConfidentialValue(199999300),
    };
    const outputData2 = {
      asset,
      nonce,
      script: Buffer.alloc(0),
      value: liquid.confidential.satoshiToConfidentialValue(700),
    };
    const tx = new liquid.Psbt()
      .addInputs([inputData, inputData2])
      .addOutputs([outputData, outputData2])
      .signAllInputs(keyPair)
      .finalizeAllInputs()
      .extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
  });

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a' +
      'P2SH(P2WPKH) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2sh = createPayment('p2sh-p2wpkh', undefined, undefined, true);
      const inputData = await getInputData(p2sh.payment, false, 'p2sh');
      const inputData2 = await getInputData(p2sh.payment, false, 'p2sh');
      const blindingKeys = ['', ''].map(() => p2sh.blindingKeys[0]);
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const keyPair = p2sh.keys[0];
      const outputData = {
        asset,
        nonce,
        script: p2sh.payment.output,
        value: liquid.confidential.satoshiToConfidentialValue(199996500),
      };
      const outputData2 = {
        asset,
        nonce,
        script: Buffer.alloc(0),
        value: liquid.confidential.satoshiToConfidentialValue(3500),
      };
      const psbt = await new liquid.Psbt()
        .addInputs([inputData, inputData2])
        .addOutputs([outputData, outputData2])
        .blindOutputs(blindingKeys, blindingPubkeys);

      const tx = psbt
        .signAllInputs(keyPair)
        .finalizeAllInputs()
        .extractTransaction();

      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input', async () => {
    // the only thing that changes is you don't give a redeemscript for input data

    const p2wpkh = createPayment('p2wpkh');
    const inputData = await getInputData(p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, p2wpkh.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction, w/ a P2WPKH input', async () => {
    // the only thing that changes is you don't give a redeemscript for input data

    const p2wpkh = createPayment('p2wpkh', undefined, undefined, true);
    const blindingPubkeys = [''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );
    const inputData = await getInputData(p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    let psbt = await new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99996500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(3500),
        },
      ])
      .blindOutputs(p2wpkh.blindingKeys, blindingPubkeys);

    psbt = psbt.signInput(0, p2wpkh.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2wpkh = createPayment('p2wpkh');
    const inputData = await getInputData(p2wpkh.payment, false, 'noredeem');
    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, p2wpkh.keys[0]);
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
  });

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a' +
      'P2WPKH input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2wpkh = createPayment('p2wpkh', undefined, undefined, true);
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2wpkh.payment, false, 'noredeem');
      let psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2wpkh.blindingKeys, blindingPubkeys);

      psbt = psbt.signInput(0, p2wpkh.keys[0]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WSH(P2PK) input', async () => {
    const p2wsh = createPayment('p2wsh-p2pk');
    const inputData = await getInputData(p2wsh.payment, true, 'p2wsh');
    {
      const {
        hash,
        index,
        witnessUtxo,
        witnessScript, // NEW: A Buffer of the witnessScript
      } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, witnessScript },
        inputData,
      );
    }

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, p2wsh.keys[0]);

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction, w/ a P2WSH(P2PK) input', async () => {
    const p2wsh = createPayment('p2wsh-p2pk', undefined, undefined, true);
    const blindingPubkeys = [''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );
    const inputData = await getInputData(p2wsh.payment, true, 'p2wsh');
    {
      const {
        hash,
        index,
        witnessUtxo,
        witnessScript, // NEW: A Buffer of the witnessScript
      } = inputData;
      assert.deepStrictEqual(
        { hash, index, witnessUtxo, witnessScript },
        inputData,
      );
    }

    let psbt = await new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99996500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(3500),
        },
      ])
      .blindOutputs(p2wsh.blindingKeys, blindingPubkeys);

    psbt = psbt.signInput(0, p2wsh.keys[0]);
    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WSH(P2PK) input with nonWitnessUtxo', async () => {
    // For learning purposes, ignore this test.
    // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
    const p2wsh = createPayment('p2wsh-p2pk');
    const inputData = await getInputData(p2wsh.payment, false, 'p2wsh');
    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInput(0, p2wsh.keys[0]);
    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();
    await regtestUtils.broadcast(tx.toHex());
  });

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a' +
      'P2WSH(P2PK) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2wsh = createPayment('p2wsh-p2pk', undefined, undefined, true);
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2wsh.payment, false, 'p2wsh');
      let psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2wsh.blindingKeys, blindingPubkeys);

      psbt = psbt.signInput(0, p2wsh.keys[0]).finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
      'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input',
    async () => {
      const p2sh = createPayment('p2sh-p2wsh-p2ms(3 of 4)');
      const inputData = await getInputData(p2sh.payment, true, 'p2sh-p2wsh');
      {
        const {
          hash,
          index,
          witnessUtxo,
          redeemScript,
          witnessScript,
        } = inputData;
        assert.deepStrictEqual(
          { hash, index, witnessUtxo, redeemScript, witnessScript },
          inputData,
        );
      }

      const psbt = new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99999500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(500),
          },
        ])
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      assert.strictEqual(
        psbt.validateSignaturesOfInput(0, p2sh.keys[3].publicKey),
        true,
      );
      assert.throws(() => {
        psbt.validateSignaturesOfInput(0, p2sh.keys[1].publicKey);
      }, new RegExp('No signatures for this pubkey'));
      psbt.finalizeAllInputs();

      const tx = psbt.extractTransaction();

      // build and broadcast to the Bitcoin RegTest network
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a ' +
      'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input',
    async () => {
      const p2sh = createPayment(
        'p2sh-p2wsh-p2ms(3 of 4)',
        undefined,
        undefined,
        true,
      );
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2sh.payment, true, 'p2sh-p2wsh');
      {
        const {
          hash,
          index,
          witnessUtxo,
          redeemScript,
          witnessScript,
        } = inputData;
        assert.deepStrictEqual(
          { hash, index, witnessUtxo, redeemScript, witnessScript },
          inputData,
        );
      }

      const psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2sh.blindingKeys, blindingPubkeys);

      psbt
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3]);

      assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
      assert.strictEqual(
        psbt.validateSignaturesOfInput(0, p2sh.keys[3].publicKey),
        true,
      );
      assert.throws(() => {
        psbt.validateSignaturesOfInput(0, p2sh.keys[1].publicKey);
      }, new RegExp('No signatures for this pubkey'));
      psbt.finalizeAllInputs();

      const tx = psbt.extractTransaction();

      // build and broadcast to the Bitcoin RegTest network
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
      'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2sh = createPayment('p2sh-p2wsh-p2ms(3 of 4)');
      const inputData = await getInputData(p2sh.payment, false, 'p2sh-p2wsh');
      const psbt = new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99999500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(500),
          },
        ])
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a ' +
      'P2SH(P2WSH(P2MS(3 of 4))) (SegWit multisig) input with nonWitnessUtxo',
    async () => {
      // For learning purposes, ignore this test.
      // REPEATING ABOVE BUT WITH nonWitnessUtxo by passing false to getInputData
      const p2sh = createPayment(
        'p2sh-p2wsh-p2ms(3 of 4)',
        undefined,
        undefined,
        true,
      );
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2sh.payment, false, 'p2sh-p2wsh');
      const psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2sh.blindingKeys, blindingPubkeys);

      psbt
        .signInput(0, p2sh.keys[0])
        .signInput(0, p2sh.keys[2])
        .signInput(0, p2sh.keys[3])
        .finalizeAllInputs();

      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a Transaction, w/ a ' +
      'P2SH(P2MS(2 of 2)) input with nonWitnessUtxo',
    async () => {
      const myKey = liquid.ECPair.makeRandom({ network: regtest });
      const myKeys = [
        myKey,
        liquid.ECPair.fromPrivateKey(myKey.privateKey!, { network: regtest }),
      ];
      const p2sh = createPayment('p2sh-p2ms(2 of 2)', myKeys);
      const inputData = await getInputData(p2sh.payment, false, 'p2sh');
      const psbt = new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99999500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(500),
          },
        ])
        .signInput(0, p2sh.keys[0]);
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it(
    'can create (and broadcast via 3PBP) a confidential Transaction, w/ a ' +
      'P2SH(P2MS(2 of 2)) input with nonWitnessUtxo',
    async () => {
      const myKey = liquid.ECPair.makeRandom({ network: regtest });
      const myKeys = [
        myKey,
        liquid.ECPair.fromPrivateKey(myKey.privateKey!, { network: regtest }),
      ];
      const p2sh = createPayment('p2sh-p2ms(2 of 2)', myKeys, undefined, true);
      const blindingPubkeys = [''].map(
        () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
      );
      const inputData = await getInputData(p2sh.payment, false, 'p2sh');
      const psbt = await new liquid.Psbt({ network: regtest })
        .addInput(inputData)
        .addOutputs([
          {
            asset,
            nonce,
            script: Buffer.from(
              '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
              'hex',
            ),
            value: liquid.confidential.satoshiToConfidentialValue(99996500),
          },
          {
            asset,
            nonce,
            script: Buffer.alloc(0),
            value: liquid.confidential.satoshiToConfidentialValue(3500),
          },
        ])
        .blindOutputs(p2sh.blindingKeys, blindingPubkeys);

      psbt.signInput(0, p2sh.keys[0]).finalizeAllInputs();
      const tx = psbt.extractTransaction();
      await regtestUtils.broadcast(tx.toHex());
    },
  );

  it('can create (and broadcast via 3PBP) a Transaction, w/ a P2WPKH input using HD', async () => {
    const hdRoot = bip32.fromSeed(rng(64));
    const masterFingerprint = hdRoot.fingerprint;
    const path = "m/84'/0'/0'/0/0";
    const childNode = hdRoot.derivePath(path);
    const pubkey = childNode.publicKey;

    // This information should be added to your input via updateInput
    // You can add multiple bip32Derivation objects for multisig, but
    // each must have a unique pubkey.
    //
    // This is useful because as long as you store the masterFingerprint on
    // the PSBT Creator's server, you can have the PSBT Creator do the heavy
    // lifting with derivation from your m/84'/0'/0' xpub, (deriving only 0/0 )
    // and your signer just needs to pass in an HDSigner interface (ie. bip32 library)
    const updateData = {
      bip32Derivation: [
        {
          masterFingerprint,
          path,
          pubkey,
        },
      ],
    };
    const p2wpkh = createPayment('p2wpkh', [childNode]);
    const inputData = await getInputData(p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    // You can add extra attributes for updateData into the addInput(s) object(s)
    Object.assign(inputData, updateData);

    const psbt = new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      // .updateInput(0, updateData) // if you didn't merge the bip32Derivation with inputData
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99999500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(500),
        },
      ])
      .signInputHD(0, hdRoot); // must sign with root!!!

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, childNode.publicKey),
      true,
    );
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();

    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction, w/ a P2WPKH input using HD', async () => {
    const hdRoot = bip32.fromSeed(rng(64));
    const masterFingerprint = hdRoot.fingerprint;
    const path = "m/84'/0'/0'/0/0";
    const childNode = hdRoot.derivePath(path);
    const pubkey = childNode.publicKey;

    // This information should be added to your input via updateInput
    // You can add multiple bip32Derivation objects for multisig, but
    // each must have a unique pubkey.
    //
    // This is useful because as long as you store the masterFingerprint on
    // the PSBT Creator's server, you can have the PSBT Creator do the heavy
    // lifting with derivation from your m/84'/0'/0' xpub, (deriving only 0/0 )
    // and your signer just needs to pass in an HDSigner interface (ie. bip32 library)
    const updateData = {
      bip32Derivation: [
        {
          masterFingerprint,
          path,
          pubkey,
        },
      ],
    };
    const p2wpkh = createPayment('p2wpkh', [childNode], undefined, true);
    const blindingPubkeys = [''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).publicKey,
    );
    const inputData = await getInputData(p2wpkh.payment, true, 'noredeem');
    {
      const { hash, index, witnessUtxo } = inputData;
      assert.deepStrictEqual({ hash, index, witnessUtxo }, inputData);
    }

    // You can add extra attributes for updateData into the addInput(s) object(s)
    Object.assign(inputData, updateData);

    const psbt = await new liquid.Psbt({ network: regtest })
      .addInput(inputData)
      // .updateInput(0, updateData) // if you didn't merge the bip32Derivation with inputData
      .addOutputs([
        {
          asset,
          nonce,
          script: Buffer.from(
            '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
            'hex',
          ),
          value: liquid.confidential.satoshiToConfidentialValue(99996500),
        },
        {
          asset,
          nonce,
          script: Buffer.alloc(0),
          value: liquid.confidential.satoshiToConfidentialValue(3500),
        },
      ])
      .blindOutputs(p2wpkh.blindingKeys, blindingPubkeys);

    psbt.signInputHD(0, hdRoot); // must sign with root!!!

    assert.strictEqual(psbt.validateSignaturesOfInput(0), true);
    assert.strictEqual(
      psbt.validateSignaturesOfInput(0, childNode.publicKey),
      true,
    );
    psbt.finalizeAllInputs();

    const tx = psbt.extractTransaction();
    // build and broadcast to the Bitcoin RegTest network
    await regtestUtils.broadcast(tx.toHex());
  });
});
