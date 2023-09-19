import secp256k1 from '@vulpemventures/secp256k1-zkp';
import * as tinyecc from 'tiny-secp256k1';
import * as assert from 'assert';
import {
  BIP371SigningData,
  Creator,
  CreatorInput,
  CreatorOutput,
  Extractor,
  Finalizer,
  Pset,
  Signer,
  Transaction,
  Updater,
  networks,
  silentpayment,
} from '../../ts_src';
import { createPayment, getInputData } from './utils';
import { TinySecp256k1Interface } from '../../ts_src/silentpayment';
import { broadcast, signTransaction } from './_regtest';
import { ECPair } from '../ecc';

describe('Silent Payments', () => {
  let ecc: TinySecp256k1Interface;
  before(async () => {
    const { ecc: stepEcc, ecdh } = await secp256k1();
    ecc = {
      ...stepEcc,
      ecdh: ecdh,
      privateMultiply: stepEcc.privateMul,
      pointAdd: tinyecc.pointAdd,
      pointMultiply: (p: Uint8Array, tweak: Uint8Array) =>
        tinyecc.pointMultiply(p, tweak),
    };
  });

  it('should send payment to silent address', async () => {
    // create and faucet an alice wallet
    // bob will create a silent address, alice will send some L-BTC to it
    const alice = createPayment('p2wpkh', undefined, undefined, false);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const bobKeyPairSpend = ECPair.makeRandom(); // sec in cold storage, pub public
    const bobKeyPairScan = ECPair.makeRandom(); // sec & pub in hot storage, pub public

    // bob creates a silent address and shares it with alice
    const bob = new silentpayment.SilentPaymentAddress(
      bobKeyPairSpend.publicKey,
      bobKeyPairScan.publicKey,
    ).encode();

    // alice adds the input
    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid: string = Buffer.from(hash).reverse().toString('hex');
      return new CreatorInput(txid, index);
    });

    const pset = Creator.newPset({ inputs });
    const updater = new Updater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInUtxoRangeProof(0, aliceInputData.witnessUtxo.rangeProof);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);

    // alice creates the taproot "silent payment" outputs associated to bob's silent address
    const outpointsHash = silentpayment.outpointsHash(
      inputs.map((i) => ({ txid: i.txid, vout: i.txIndex })),
    );
    const sumPrivateKeys = new silentpayment.SilentPayment(ecc).sumSecretKeys([
      {
        key: alice.keys[0].privateKey,
      },
    ]);

    const sendAmount = 1000;
    const fee = 400;
    const change = 1_0000_0000 - sendAmount - fee;

    const outputs = new silentpayment.SilentPayment(ecc).pay(
      outpointsHash,
      sumPrivateKeys,
      [
        {
          silentPaymentAddress: bob,
          asset: networks.regtest.assetHash,
          value: sendAmount,
        },
      ],
    );

    // alice adds the outputs
    updater.addOutputs(
      outputs.map((o) => ({
        amount: o.value,
        asset: o.asset,
        script: Buffer.from(o.scriptPubKey, 'hex'),
      })),
    );

    // add change & fee outputs
    updater.addOutputs([
      {
        amount: change,
        asset: networks.regtest.assetHash,
        script: alice.payment.output,
      },
      {
        amount: fee,
        asset: networks.regtest.assetHash,
      },
    ]);

    // alice signs the transaction
    const signed = signTransaction(
      updater.pset,
      [alice.keys],
      Transaction.SIGHASH_ALL,
    );
    const tx = signed.toHex();
    await broadcast(tx);

    // check if bob can spend the output (key spend using private key)
    const outputToSpend = signed.outs[0];

    const bobInput = new CreatorInput(signed.getId(), 0);

    const bobOutput = new CreatorOutput(
      networks.regtest.assetHash,
      600,
      alice.payment.output,
    );

    const feeOutput = new CreatorOutput(networks.regtest.assetHash, fee);

    const bobPset = Creator.newPset({
      inputs: [bobInput],
      outputs: [bobOutput, feeOutput],
    });

    const bobUpdater = new Updater(bobPset);
    bobUpdater.addInWitnessUtxo(0, outputToSpend);
    bobUpdater.addInSighashType(0, Transaction.SIGHASH_DEFAULT);

    // to sign the input, bob has to compute the right privKey

    const sp = new silentpayment.SilentPayment(ecc);

    // 1. sum the outpoints public keys
    const inputPubKey = sp.sumPublicKeys([alice.keys[0].publicKey]);

    // 2. compute the tweak
    const ecdhSharedSecret = sp.makeSharedSecret(
      outpointsHash,
      inputPubKey,
      bobKeyPairScan.privateKey!,
    );

    // bob may recompute the pubkey to scan the chain
    const pubkey = sp.makePublicKey(
      bobKeyPairSpend.publicKey,
      0,
      ecdhSharedSecret,
    );
    assert.deepStrictEqual(pubkey.slice(1), outputToSpend.script.slice(2));

    // 3. compute the privKey
    let privKey = sp.makeSecretKey(
      bobKeyPairSpend.privateKey!,
      0,
      ecdhSharedSecret,
    );
    const pubeyFromPrv = Buffer.from(ecc.pointFromScalar(privKey)!);
    assert.deepStrictEqual(pubeyFromPrv.slice(1), pubkey.slice(1));

    // negate if necessary
    if (ecc.pointFromScalar(privKey)?.at(0) === 0x03) {
      privKey = Buffer.from(ecc.privateNegate(privKey));
    }

    const preimage = bobPset.getInputPreimage(
      0,
      Transaction.SIGHASH_DEFAULT,
      networks.regtest.genesisBlockHash,
    );

    const signature = Buffer.from(
      ecc.signSchnorr(preimage, privKey, Buffer.alloc(32)),
    );
    const signer = new Signer(bobPset);

    const partialSig: BIP371SigningData = {
      tapKeySig: serializeSchnnorrSig(signature, Transaction.SIGHASH_DEFAULT),
      genesisBlockHash: networks.regtest.genesisBlockHash,
    };
    signer.addSignature(0, partialSig, Pset.SchnorrSigValidator(ecc));

    const finalizer = new Finalizer(bobPset);
    finalizer.finalize();
    const bobTx = Extractor.extract(bobPset);
    const hex = bobTx.toHex();

    await broadcast(hex);
  });
});

const serializeSchnnorrSig = (sig: Buffer, hashtype: number) =>
  Buffer.concat([
    sig,
    hashtype !== 0x00 ? Buffer.of(hashtype) : Buffer.alloc(0),
  ]);
