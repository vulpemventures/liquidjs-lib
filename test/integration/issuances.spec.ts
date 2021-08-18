import { IssuanceBlindingKeys } from './../../ts_src/types';
import { networks as NETWORKS } from '../..';
import * as liquid from '../..';
import { createPayment, getInputData } from './utils';
import { broadcast } from './_regtest';
import { Transaction } from '../../ts_src';
const { regtest } = NETWORKS;

const nonce = Buffer.from('00', 'hex');
const asset = Buffer.concat([
  Buffer.from('01', 'hex'),
  Buffer.from(regtest.assetHash, 'hex').reverse(),
]);

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
    psbt
      .addInput(inputData)
      .addIssuance({
        assetAddress: addressReceive,
        assetAmount: 100,
        tokenAddress: addressReceive,
        tokenAmount: 1,
        precision: 8,
        net: regtest,
        contract: {
          name: "testcoin",
          ticker: "T-COIN",
          entity: {
            domain: 'vulpemventures.com'
          },
          version: 0,
          precision: 8
        }
      })
      .addOutputs([
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
    const valid = psbt.validateSignaturesOfInput(0);
    if (!valid) {
      throw new Error('signature is not valid');
    }
    psbt.finalizeAllInputs();
    const hex = psbt.extractTransaction().toHex();
    console.log(hex);
    const fromHex = Transaction.fromHex(hex);
    console.log(fromHex.ins[0].issuance);
    console.log("---- index === ", fromHex.ins[0].index);
    await broadcast(hex);
  });

  it('can create a 1-to-1 confidential Transaction (and broadcast via 3PBP) with unblinded issuance', async () => {
    const alice1 = createPayment('p2pkh', undefined, undefined, true);
    const inputData = await getInputData(alice1.payment, false, 'noredeem');
    const blindingPrivkeys = alice1.blindingKeys;

    const addressReceive =
      'AzpunXjDrpSRAKn96sCFc5jacgZdgewRiNCwNLneF1Nt2nyTWXGRBbDrucgh3Xdt4BtPJVwie1Xb8xk2';
    const addressBlindPubkey = liquid.address.fromConfidential(addressReceive)
      .blindingKey;

    const psbt = new liquid.Psbt();
    psbt.setVersion(2); // These are defaults. This line is not needed.
    psbt.setLocktime(0); // These are defaults. This line is not needed.
    psbt.addInput(inputData);
    psbt.addIssuance({
      assetAddress: 'XBXiDkFNneyPtpXvqVWQoHA1MhoXa8FZLn',
      assetAmount: 100,
      tokenAddress: 'XBXiDkFNneyPtpXvqVWQoHA1MhoXa8FZLn',
      tokenAmount: 1,
      precision: 8,
      net: regtest,
      contract: {
        name: "testcoin-bis",
        ticker: "T-COI",
        entity: {
          domain: 'vulpemventures.com'
        },
        version: 0,
        precision: 8
      }
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
    );
    psbt.signInput(0, alice1.keys[0]);

    psbt.validateSignaturesOfInput(0);
    psbt.finalizeAllInputs();
    const hex = psbt.extractTransaction().toHex();
    console.log(hex);
    await broadcast(hex);
  });
});
