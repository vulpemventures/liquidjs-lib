import { IssuanceBlindingKeys } from './../../ts_src/types';
import * as assert from 'assert';
import { networks as NETWORKS } from '../..';
import * as liquid from '../..';
import {
  createPayment,
  getInputData,
  nonWitnessUtxoBuffer,
} from './transaction.spec';
import { broadcast } from './_regtest';
const { regtest } = NETWORKS;

const nonce = Buffer.from('00', 'hex');
const asset = Buffer.concat([
  Buffer.from('01', 'hex'),
  Buffer.from(regtest.assetHash, 'hex').reverse(),
]);

const bob = liquid.ECPair.fromWIF(
  'cQ7z41awTvKtmiD9p6zkjbgvYbV8g5EDDNcTnKZS9aZ8XdjQiZMU',
  regtest,
);

describe('liquidjs-lib (issuances transactions with psbt)', () => {
  it('can create a 1-to-1 confidential Transaction (and broadcast via 3PBP) with blinded issuance', async () => {
    const alice1 = createPayment('p2pkh', undefined, undefined, true);
    const inputData = await getInputData(alice1.payment, false, 'noredeem');
    const blindingPrivkeys = alice1.blindingKeys;

    const addressReceive =
      'AzpunXjDrpSRAKn96sCFc5jacgZdgewRiNCwNLneF1Nt2nyTWXGRBbDrucgh3Xdt4BtPJVwie1Xb8xk2';
    const addressBlindPubkey = liquid.address.fromConfidential(addressReceive)
      .blindingKey;
    const issuanceBlindingKeys = ['', ''].map(
      () => liquid.ECPair.makeRandom({ network: regtest }).privateKey!,
    );

    const psbt = new liquid.Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput(inputData);
    psbt.addIssuance({
      assetAddress: addressReceive,
      assetAmount: 100,
      tokenAddress: addressReceive,
      tokenAmount: 1,
      precision: 8,
      net: regtest,
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
    await psbt.blindOutputsByIndex(
      new Map<number, Buffer>().set(0, blindingPrivkeys[0]),
      new Map<number, Buffer>()
        .set(0, addressBlindPubkey)
        .set(1, addressBlindPubkey),
      new Map<number, IssuanceBlindingKeys>().set(0, {
        assetKey: issuanceBlindingKeys[0],
        tokenKey: issuanceBlindingKeys[1],
      }),
    );
    psbt.signInput(0, alice1.keys[0]);
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    const hex = psbt.extractTransaction().toHex();
    await broadcast(hex);
  });

  it('can create a 1-to-1 confidential Transaction (and broadcast via 3PBP) with unblinded issuance', async () => {
    const blindingPrivkeys = [
      Buffer.from(
        '13d4dbfdb5074705e6b9758d1542d7dd8c03055086c0da421620eaa04717a9f7',
        'hex',
      ),
    ];
    const blindingPubkeys = ['', '', ''].map(
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
    psbt.addIssuance({
      assetAddress: 'XBXiDkFNneyPtpXvqVWQoHA1MhoXa8FZLn',
      assetAmount: 100,
      tokenAddress: 'XBXiDkFNneyPtpXvqVWQoHA1MhoXa8FZLn',
      tokenAmount: 1,
      precision: 8,
      net: regtest,
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
    await psbt.blindOutputs(blindingPrivkeys, blindingPubkeys);
    psbt.signInput(0, bob);
    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    const hex = psbt.extractTransaction().toHex();
    assert.doesNotReject(() => broadcast(hex));
  });
});
