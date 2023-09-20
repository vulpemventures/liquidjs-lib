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
  bip341,
  networks,
  silentpayment,
} from '../../ts_src';
import { createPayment, getInputData } from './utils';
import { broadcast, signTransaction } from './_regtest';
import { ECPair } from '../ecc';

describe('Silent Payments', () => {
  let ecc: bip341.BIP341Secp256k1Interface;
  let sp: silentpayment.SilentPayment;

  before(async () => {
    const { ecc: stepEcc } = await secp256k1();
    const ecc = {
      ...stepEcc,
      privateMultiply: stepEcc.privateMul,
      pointAdd: tinyecc.pointAdd,
      pointMultiply: (p: Uint8Array, tweak: Uint8Array) =>
        tinyecc.pointMultiply(p, tweak),
    };
    sp = silentpayment.SPFactory(ecc);
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

    const sendAmount = 1000;
    const fee = 400;
    const change = 1_0000_0000 - sendAmount - fee;

    const script = sp.makeScriptPubKey(
      inputs.map((i) => ({ txid: i.txid, vout: i.txIndex })),
      alice.keys[0].privateKey!,
      bob,
    );

    updater.addOutputs([
      {
        amount: sendAmount,
        asset: networks.regtest.assetHash,
        script,
      },
    ]);

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

    // bob can use its scan private key to check if the output can be unlocked by its spend key
    const isBob = sp.isMine(
      outputToSpend.script,
      inputs.map((i) => ({ txid: i.txid, vout: i.txIndex })),
      alice.keys[0].publicKey!,
      bobKeyPairScan.privateKey!,
    );

    assert.strictEqual(isBob, true, 'bob should be able to spend the output');

    // bob can spend the output by computing the right signing key from the spend key
    const privKey = sp.makeSigningKey(
      inputs.map((i) => ({ txid: i.txid, vout: i.txIndex })),
      alice.keys[0].publicKey!,
      bobKeyPairSpend.privateKey!,
    );

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
