import { describe, it } from 'mocha';
import { networks as NETWORKS } from '../..';
import * as liquid from '../..';
import * as regtestUtils from './_regtest';
const NETWORK = NETWORKS.regtest;
const keyPairs = [
  liquid.ECPair.makeRandom({ network: NETWORK }),
  liquid.ECPair.makeRandom({ network: NETWORK }),
];

async function buildAndSign(
  depends: any,
  sender: any,
  redeemScript: any,
  witnessScript: any,
): Promise<string> {
  const unspent = await regtestUtils.faucet(sender.address);
  const txHex = await regtestUtils.fetchTx(unspent.txid);
  const asset = Buffer.concat([
    Buffer.from('01', 'hex'),
    Buffer.from(unspent.asset, 'hex').reverse(),
  ]);
  const nonce = Buffer.from('00', 'hex');

  const psbt = new liquid.Psbt({ network: NETWORK })
    .addInput({
      hash: unspent.txid,
      index: unspent.vout,
      nonWitnessUtxo: Buffer.from(txHex, 'hex'),
      ...(redeemScript ? { redeemScript } : {}),
      ...(witnessScript ? { witnessScript } : {}),
    })
    .addOutputs([
      {
        asset,
        nonce,
        value: liquid.confidential.satoshiToConfidentialValue(40000000),
        script: Buffer.from(
          '76a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac',
          'hex',
        ),
      },
      {
        asset,
        nonce,
        value: liquid.confidential.satoshiToConfidentialValue(
          unspent.value - 40000000 - 600,
        ),
        script: sender.output,
      },
      {
        asset,
        nonce,
        value: liquid.confidential.satoshiToConfidentialValue(600),
        script: Buffer.alloc(0),
      },
    ]);

  if (depends.signatures) {
    keyPairs.forEach(keyPair => {
      psbt.signInput(0, keyPair);
    });
  } else if (depends.signature) {
    psbt.signInput(0, keyPairs[0]);
  }
  const hex = psbt
    .finalizeAllInputs()
    .extractTransaction()
    .toHex();
  return regtestUtils.broadcast(hex);
}

['p2ms', 'p2pkh', 'p2wpkh'].forEach(k => {
  const fixtures = require('../fixtures/' + k);
  const { depends } = fixtures.dynamic;
  const fn: any = (liquid.payments as any)[k];

  const base: any = { network: NETWORK };
  if (depends.pubkey) base.pubkey = keyPairs[0].publicKey;
  if (depends.pubkeys) base.pubkeys = keyPairs.map(x => x.publicKey);
  if (depends.m) base.m = base.pubkeys.length;

  const sender = fn(base);
  if (!sender.output) throw new TypeError('Missing output');

  describe('liquidjs-lib (payments - ' + k + ')', () => {
    if (k !== 'p2ms') {
      it('can broadcast as an output, and be spent as an input', async () => {
        Object.assign(depends, { prevOutScriptType: k });
        await buildAndSign(depends, sender, undefined, undefined);
      });
    }

    it(
      'can (as P2SH(' +
        k +
        ')) broadcast as an output, and be spent as an input',
      async () => {
        const p2sh = liquid.payments.p2sh({
          redeem: { output: sender.output },
          network: NETWORK,
        });

        Object.assign(depends, { prevOutScriptType: 'p2sh-' + k });
        await buildAndSign(depends, p2sh, p2sh.redeem!.output, undefined);
      },
    );

    // NOTE: P2WPKH cannot be wrapped in P2WSH, consensus fail
    if (k === 'p2wpkh') return;

    it(
      'can (as P2WSH(' +
        k +
        ')) broadcast as an output, and be spent as an input',
      async () => {
        const p2wsh = liquid.payments.p2wsh({
          redeem: { output: sender.output },
          network: NETWORK,
        });
        Object.assign(depends, { prevOutScriptType: 'p2wsh-' + k });
        await buildAndSign(depends, p2wsh, undefined, p2wsh.redeem!.output);
      },
    );
  });
});
