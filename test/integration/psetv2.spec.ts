import { describe, it } from 'mocha';
import {
  Pset,
  Creator as PsetCreator,
  Updater as PsetUpdater,
  Input,
  Output,
  Signer as PsetSigner,
  Finalizer as PsetFinalizer,
  Extractor as PsetExtractor,
  Blinder as PsetBlinder,
} from '../../ts_src/psetv2';
import { AssetHash } from '../../ts_src/asset';
import { ZKPGenerator, ZKPValidator } from '../../ts_src/confidential';
import { Transaction, ZERO } from '../../ts_src/transaction';
import * as bscript from '../../ts_src/script';
import * as NETWORKS from '../../ts_src/networks';
import { ecc } from '../ecc';
import { createPayment, getInputData } from './utils';
import * as regtestUtils from './_regtest';

const { regtest } = NETWORKS;
const lbtc = regtest.assetHash;

describe('liquidjs-lib (transactions with psetv2)', () => {
  it('can create (and broadcast via 3PBP) a unconfidential Transaction', async () => {
    const alice = createPayment('p2wpkh');
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    const outputs = [
      new Output(lbtc, 60000000, 'ert1qqndj7dqs4emt4ty475an693hcput6l87m4rajq'),
      new Output(lbtc, 39999500, alice.payment.address!),
      new Output(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction w/ unconfidential inputs', async () => {
    const alice = createPayment('p2pkh');
    const bob = createPayment('p2wpkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    const outputs = [
      new Output(lbtc, 60000000, bob.payment.confidentialAddress!, 0),
      new Output(lbtc, 39999500, alice.payment.address!),
      new Output(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);

    const ownedInputs = [
      {
        index: 0,
        asset: AssetHash.fromHex(lbtc).bytesWithoutPrefix,
        value: '100000000',
        assetBlinder: ZERO,
        valueBlinder: ZERO,
      },
    ];
    const zkpGenerator = ZKPGenerator.fromOwnedInputs(ownedInputs);
    const zkpValidator = new ZKPValidator();
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction w/ confidential inputs', async () => {
    const alice = createPayment('p2pkh', undefined, undefined, true);
    const bob = createPayment('p2wpkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    const outputs = [
      new Output(lbtc, 60000000, bob.payment.confidentialAddress!, 0),
      new Output(lbtc, 39999500, alice.payment.confidentialAddress!, 0),
      new Output(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);

    const zkpGenerator = ZKPGenerator.fromInBlindingKeys(alice.blindingKeys);
    const zkpValidator = new ZKPValidator();
    const ownedInputs = await zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction w/ dummy confidential output', async () => {
    const alice = createPayment('p2pkh', undefined, undefined, true);
    const bob = createPayment('p2wpkh');
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    // dummy confidential output (3rd) has confidential address and 0 amount:
    //  - the confidential address is used only for setting the pset output's blinding pubkey
    //  - 0 amount is used to set the pset output's script to OP_RETURN.
    //
    const outputs = [
      new Output(lbtc, 60000000, bob.payment.address!, 0),
      new Output(lbtc, 39999500, alice.payment.address!, 0),
      new Output(lbtc, 0, alice.payment.confidentialAddress!, 0),
      new Output(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);

    const zkpGenerator = ZKPGenerator.fromInBlindingKeys(alice.blindingKeys);
    const zkpValidator = new ZKPValidator();
    const ownedInputs = await zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a unconfidential issuance Transaction', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const bob = createPayment('p2pkh');
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    const outputs = [
      new Output(lbtc, 99999500, alice.payment.confidentialAddress!, 0),
      new Output(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInIssuance(0, {
      assetAmount: 1000,
      tokenAmount: 1,
      assetAddress: alice.payment.address!,
      tokenAddress: bob.payment.address!,
      blindedIssuance: false,
    });

    const zkpGenerator = ZKPGenerator.fromInBlindingKeys(alice.blindingKeys);
    const zkpValidator = new ZKPValidator();
    const ownedInputs = await zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a unconfidential issuance Transaction w/ confidential outputs', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const bob = createPayment('p2sh-p2wpkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    const outputs = [
      new Output(lbtc, 99999500, alice.payment.confidentialAddress!, 0),
      new Output(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInIssuance(0, {
      assetAmount: 1000,
      tokenAmount: 1,
      assetAddress: alice.payment.confidentialAddress!,
      tokenAddress: bob.payment.confidentialAddress!,
      blindedIssuance: false,
    });

    const zkpGenerator = ZKPGenerator.fromInBlindingKeys(alice.blindingKeys);
    const zkpValidator = new ZKPValidator();
    const ownedInputs = await zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential issuance Transaction', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const bob = createPayment('p2pkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    const outputs = [
      new Output(lbtc, 99999500, alice.payment.address!),
      new Output(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInIssuance(0, {
      assetAmount: 1000,
      tokenAmount: 1,
      assetAddress: alice.payment.confidentialAddress!,
      tokenAddress: bob.payment.confidentialAddress!,
      blindedIssuance: true,
    });

    const zkpGenerator = ZKPGenerator.fromInBlindingKeys(alice.blindingKeys);
    const zkpValidator = new ZKPValidator();
    const ownedInputs = await zkpGenerator.unblindInputs(pset);
    const issuanceBlindingArgs = await zkpGenerator.blindIssuances(pset, {
      0: alice.blindingKeys[0],
    });
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
      undefined,
      issuanceBlindingArgs,
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({ issuanceBlindingArgs, outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential issuance Transaction w/ unconfidential outputs', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const bob = createPayment('p2wpkh');
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    const outputs = [
      new Output(lbtc, 99999500, alice.payment.confidentialAddress!, 0),
      new Output(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInIssuance(0, {
      assetAmount: 1000,
      tokenAmount: 1,
      assetAddress: alice.payment.address!,
      tokenAddress: bob.payment.address!,
      blindedIssuance: true,
    });

    const zkpGenerator = ZKPGenerator.fromInBlindingKeys(alice.blindingKeys);
    const zkpValidator = new ZKPValidator();
    const ownedInputs = await zkpGenerator.unblindInputs(pset);
    const issuanceBlindingArgs = await zkpGenerator.blindIssuances(pset, {
      0: alice.blindingKeys[0],
    });
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
      undefined,
      issuanceBlindingArgs,
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({ issuanceBlindingArgs, outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential swap', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const bob = createPayment('p2wpkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');
    const bobInputData = await regtestUtils.mint(
      bob.payment.confidentialAddress!,
      50000,
    );

    const usdt = bobInputData.asset;
    const aliceInputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash
        .slice()
        .reverse()
        .toString('hex');
      return new Input(txid, index);
    });
    const aliceOutputs = [
      new Output(usdt, 25000_00000000, alice.payment.confidentialAddress!, 0),
      new Output(lbtc, 49999000, alice.payment.confidentialAddress!, 0),
      new Output(lbtc, 1000),
    ];

    const pset = PsetCreator.newPset({
      inputs: aliceInputs,
      outputs: aliceOutputs,
    });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);

    const bobInputs = [bobInputData].map(({ txid, index }) => {
      return new Input(txid, index);
    });
    const bobOutputs = [
      new Output(lbtc, 50000000, bob.payment.confidentialAddress!, 1),
      new Output(usdt, 25000_00000000, bob.payment.confidentialAddress!, 1),
    ];

    updater.addInputs(bobInputs);
    updater.addOutputs(bobOutputs);

    const bobPrevTx = Transaction.fromHex(
      (await regtestUtils.fetchUtxo(bobInputs[0].txid)).txHex,
    );
    const bobWitnessUtxo = bobPrevTx.outs[bobInputs[0].txIndex];
    updater.addInWitnessUtxo(1, bobWitnessUtxo);
    updater.addInSighashType(1, Transaction.SIGHASH_ALL);

    const zkpGenerator = ZKPGenerator.fromInBlindingKeys(
      alice.blindingKeys.concat(bob.blindingKeys),
    );
    const zkpValidator = new ZKPValidator();
    const ownedInputs = await zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
    );

    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(
      pset,
      [alice.keys, bob.keys],
      Transaction.SIGHASH_ALL,
    );
    await regtestUtils.broadcast(rawTx.toHex());
  });
});

function signTransaction(
  pset: Pset,
  signers: any[],
  sighashType: number,
): Transaction {
  const signer = new PsetSigner(pset);

  signers.forEach((keyPairs, i) => {
    const preimage = pset.getInputPreimage(i, sighashType);
    keyPairs.forEach((kp: any) => {
      const partialSig = {
        pubkey: kp.publicKey,
        signature: bscript.signature.encode(kp.sign(preimage), sighashType),
      };
      signer.signInput(i, partialSig, Pset.ECDSASigValidator(ecc));
    });
  });

  const finalizer = new PsetFinalizer(pset);
  finalizer.finalize();
  return PsetExtractor.extract(pset);
}
