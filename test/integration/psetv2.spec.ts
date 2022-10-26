import { describe, it } from 'mocha';
import {
  Pset,
  Creator as PsetCreator,
  Updater as PsetUpdater,
  CreatorInput,
  CreatorOutput,
  Signer as PsetSigner,
  Finalizer as PsetFinalizer,
  Extractor as PsetExtractor,
  Blinder as PsetBlinder,
  BIP174SigningData,
  UpdaterInput,
  UpdaterOutput,
  ZKPGenerator,
  ZKPValidator,
} from '../../ts_src/psetv2';
import { AssetHash } from '../../ts_src/asset';
import { Transaction, ZERO } from '../../ts_src/transaction';
import * as bscript from '../../ts_src/script';
import * as NETWORKS from '../../ts_src/networks';
import { ecc, ECPair } from '../ecc';
import { createPayment, getInputData } from './utils';
import * as regtestUtils from './_regtest';
import { address, bip341 } from '../../ts_src';
import { BIP371SigningData } from '../../ts_src/psetv2';
import { toXOnly } from '../../ts_src/psetv2/bip371';
import secp256k1 from '@vulpemventures/secp256k1-zkp';
import { issuanceEntropyFromInput } from '../../ts_src/issuance';

const OPS = bscript.OPS;
const { BIP341Factory } = bip341;
const { regtest } = NETWORKS;
const lbtc = regtest.assetHash;

describe('liquidjs-lib (transactions with psetv2)', () => {
  it('can create (and broadcast via 3PBP) a unconfidential Transaction', async () => {
    const alice = createPayment('p2wpkh');
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const pset = PsetCreator.newPset();

    const inputs: UpdaterInput[] = [aliceInputData].map(({ hash, index }) => {
      const txid = hash.slice().reverse().toString('hex');
      return {
        txid,
        txIndex: index,
        witnessUtxo: aliceInputData.witnessUtxo,
        sighashType: Transaction.SIGHASH_ALL,
      };
    });
    const outputs: UpdaterOutput[] = [
      // we can mix UpdaterOutput as plain objects or use CreatorOutput as class which satisfies the interface
      new CreatorOutput(
        lbtc,
        60000000,
        address.toOutputScript('ert1qqndj7dqs4emt4ty475an693hcput6l87m4rajq'),
      ),
      {
        asset: lbtc,
        amount: 39999500,
        script: alice.payment.output,
      },
      {
        asset: lbtc,
        amount: 500,
      },
    ];

    const updater = new PsetUpdater(pset);
    updater.addInputs(inputs);
    updater.addOutputs(outputs);

    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction w/ unconfidential inputs', async () => {
    const alice = createPayment('p2pkh');
    const bob = createPayment('p2wpkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash.slice().reverse().toString('hex');
      return new CreatorInput(txid, index);
    });
    const outputs = [
      new CreatorOutput(
        lbtc,
        60000000,
        bob.payment.output,
        bob.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 39999500, alice.payment.output),
      new CreatorOutput(lbtc, 500),
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
        assetBlindingFactor: ZERO,
        valueBlindingFactor: ZERO,
      },
    ];
    const zkpLib = await secp256k1();
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithOwnedInputs(ownedInputs),
    );
    const zkpValidator = new ZKPValidator(zkpLib);
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction w/ confidential inputs', async () => {
    const alice = createPayment('p2pkh', undefined, undefined, true);
    const bob = createPayment('p2wpkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash.slice().reverse().toString('hex');
      return new CreatorInput(txid, index);
    });
    const outputs = [
      new CreatorOutput(
        lbtc,
        60000000,
        bob.payment.output,
        bob.payment.blindkey,
        0,
      ),
      new CreatorOutput(
        lbtc,
        39999500,
        alice.payment.output,
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInUtxoRangeProof(0, aliceInputData.witnessUtxo.rangeProof);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);

    const zkpLib = await secp256k1();
    const zkpValidator = new ZKPValidator(zkpLib);
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs(alice.blindingKeys),
    );
    const ownedInputs = zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential Transaction w/ dummy confidential output', async () => {
    const alice = createPayment('p2pkh', undefined, undefined, true);
    const bob = createPayment('p2wpkh');
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash.slice().reverse().toString('hex');
      return new CreatorInput(txid, index);
    });
    // dummy confidential output (3rd) has confidential address and 0 amount:
    //  - the confidential address is used only for setting the pset output's blinding pubkey
    //  - 0 amount is used to set the pset output's script to OP_RETURN.
    //
    const outputs = [
      new CreatorOutput(lbtc, 60000000, bob.payment.output),
      new CreatorOutput(lbtc, 39999500, alice.payment.output),
      new CreatorOutput(
        lbtc,
        0,
        Buffer.of(OPS.OP_RETURN),
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInUtxoRangeProof(0, aliceInputData.witnessUtxo.rangeProof);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);

    const zkpLib = await secp256k1();
    const zkpValidator = new ZKPValidator(zkpLib);
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs(alice.blindingKeys),
    );

    const ownedInputs = zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a unconfidential issuance Transaction', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const bob = createPayment('p2pkh');
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash.slice().reverse().toString('hex');
      return new CreatorInput(txid, index);
    });
    const outputs = [
      new CreatorOutput(
        lbtc,
        99999500,
        alice.payment.output,
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInUtxoRangeProof(0, aliceInputData.witnessUtxo.rangeProof);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInIssuance(0, {
      assetAmount: 1000,
      tokenAmount: 1,
      assetAddress: alice.payment.address!,
      tokenAddress: bob.payment.address!,
      blindedIssuance: false,
    });

    const zkpLib = await secp256k1();
    const zkpValidator = new ZKPValidator(zkpLib);
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs(alice.blindingKeys),
    );

    const ownedInputs = zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a unconfidential issuance Transaction w/ confidential outputs', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const bob = createPayment('p2sh-p2wpkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash.slice().reverse().toString('hex');
      return new CreatorInput(txid, index);
    });
    const outputs = [
      new CreatorOutput(
        lbtc,
        99999500,
        alice.payment.output,
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInUtxoRangeProof(0, aliceInputData.witnessUtxo.rangeProof);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInIssuance(0, {
      assetAmount: 1000,
      tokenAmount: 1,
      assetAddress: alice.payment.confidentialAddress!,
      tokenAddress: bob.payment.confidentialAddress!,
      blindedIssuance: false,
    });

    const zkpLib = await secp256k1();
    const zkpValidator = new ZKPValidator(zkpLib);
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs(alice.blindingKeys),
    );

    const ownedInputs = zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(pset, [alice.keys], Transaction.SIGHASH_ALL);
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential issuance and reissuance Transactions', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash.slice().reverse().toString('hex');
      return new CreatorInput(txid, index);
    });
    const outputs = [
      new CreatorOutput(
        lbtc,
        99999400,
        alice.payment.output,
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 600),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    let updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInUtxoRangeProof(0, aliceInputData.witnessUtxo.rangeProof);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInIssuance(0, {
      assetAmount: 1000,
      tokenAmount: 1,
      assetAddress: alice.payment.confidentialAddress!,
      tokenAddress: alice.payment.confidentialAddress!,
      blindedIssuance: true,
    });

    const zkpLib = await secp256k1();
    const zkpValidator = new ZKPValidator(zkpLib);
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs(alice.blindingKeys),
    );

    const ownedInputs = zkpGenerator.unblindInputs(pset);
    const issuanceBlindingArgs = zkpGenerator.blindIssuances(pset, {
      0: alice.blindingKeys[0],
    });
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
      undefined,
      issuanceBlindingArgs,
    );
    let blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    blinder.blindLast({ issuanceBlindingArgs, outputBlindingArgs });
    const issuanceTx = signTransaction(
      pset,
      [alice.keys],
      Transaction.SIGHASH_ALL,
    );
    const issuanceTxid = await regtestUtils.broadcast(issuanceTx.toHex());

    const assetEntropy = issuanceEntropyFromInput(issuanceTx.ins[0]);
    const reissuanceInputs = [
      new CreatorInput(issuanceTxid, 0),
      new CreatorInput(issuanceTxid, 3),
    ];
    const reissuanceOutputs = [
      new CreatorOutput(
        lbtc,
        99998700,
        alice.payment.output,
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 700),
    ];
    const reissuancePset = PsetCreator.newPset({
      inputs: reissuanceInputs,
      outputs: reissuanceOutputs,
    });

    updater = new PsetUpdater(reissuancePset);
    updater.addInWitnessUtxo(0, issuanceTx.outs[0]);
    updater.addInWitnessUtxo(1, issuanceTx.outs[3]);
    updater.addInUtxoRangeProof(0, issuanceTx.outs[0].rangeProof!);
    updater.addInUtxoRangeProof(1, issuanceTx.outs[3].rangeProof!);
    updater.addInReissuance(1, {
      entropy: assetEntropy,
      assetAmount: 1000,
      assetAddress: alice.payment.confidentialAddress!,
      tokenAmount: 1,
      tokenAddress: alice.payment.confidentialAddress!,
      tokenAssetBlinder: outputBlindingArgs[2].assetBlinder,
    });
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInSighashType(1, Transaction.SIGHASH_ALL);

    const zkpGenerator2 = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs([
        alice.blindingKeys[0],
        alice.blindingKeys[0],
      ]),
    );

    const reissuanceownedInputs = zkpGenerator2.unblindInputs(
      reissuancePset,
    );
    const reissuanceBlindingArgs = zkpGenerator2.blindIssuances(
      reissuancePset,
      {
        1: alice.blindingKeys[0],
      },
    );

    const reissuanceOutputBlindingArgs = zkpGenerator.blindOutputs(
      reissuancePset,
      Pset.ECCKeysGenerator(ecc),
      undefined,
      reissuanceBlindingArgs,
    );

    blinder = new PsetBlinder(
      reissuancePset,
      reissuanceownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    await blinder.blindLast({
      issuanceBlindingArgs: reissuanceBlindingArgs,
      outputBlindingArgs: reissuanceOutputBlindingArgs,
    });

    const reissuanceTx = signTransaction(
      reissuancePset,
      [alice.keys, alice.keys],
      Transaction.SIGHASH_ALL,
    );
    await regtestUtils.broadcast(reissuanceTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a confidential issuance Transaction w/ unconfidential outputs', async () => {
    const alice = createPayment('p2wpkh', undefined, undefined, true);
    const bob = createPayment('p2wpkh');
    const aliceInputData = await getInputData(alice.payment, true, 'noredeem');

    const inputs = [aliceInputData].map(({ hash, index }) => {
      const txid = hash.slice().reverse().toString('hex');
      return new CreatorInput(txid, index);
    });
    const outputs = [
      new CreatorOutput(
        lbtc,
        99999500,
        alice.payment.output,
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 500),
    ];

    const pset = PsetCreator.newPset({ inputs, outputs });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInUtxoRangeProof(0, aliceInputData.witnessUtxo.rangeProof);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInIssuance(0, {
      assetAmount: 1000,
      tokenAmount: 1,
      assetAddress: alice.payment.address!,
      tokenAddress: bob.payment.address!,
      blindedIssuance: true,
    });

    const zkpLib = await secp256k1();
    const zkpValidator = new ZKPValidator(zkpLib);
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs(alice.blindingKeys),
    );

    const ownedInputs = zkpGenerator.unblindInputs(pset);
    const issuanceBlindingArgs = zkpGenerator.blindIssuances(pset, {
      0: alice.blindingKeys[0],
    });
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
      undefined,
      issuanceBlindingArgs,
    );
    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    blinder.blindLast({ issuanceBlindingArgs, outputBlindingArgs });
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
      const txid: string = Buffer.from(hash).reverse().toString('hex');
      return new CreatorInput(txid, index);
    });
    const aliceOutputs = [
      new CreatorOutput(
        usdt,
        25000_00000000,
        alice.payment.output,
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(
        lbtc,
        49999000,
        alice.payment.output,
        alice.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, 1000),
    ];

    const pset = PsetCreator.newPset({
      inputs: aliceInputs,
      outputs: aliceOutputs,
    });
    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, aliceInputData.witnessUtxo);
    updater.addInUtxoRangeProof(0, aliceInputData.witnessUtxo.rangeProof);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);

    const bobInputs = [bobInputData].map(({ txid, index }) => {
      return new CreatorInput(txid, index);
    });
    const bobOutputs = [
      new CreatorOutput(
        lbtc,
        50000000,
        bob.payment.output,
        alice.payment.blindkey,
        1,
      ),
      new CreatorOutput(
        usdt,
        25000_00000000,
        bob.payment.output,
        bob.payment.blindkey,
        1,
      ),
    ];

    updater.addInputs(bobInputs);
    updater.addOutputs(bobOutputs);

    const bobPrevTx = Transaction.fromHex(
      (await regtestUtils.fetchUtxo(bobInputs[0].txid)).txHex,
    );
    const bobWitnessUtxo = bobPrevTx.outs[bobInputs[0].txIndex];
    updater.addInWitnessUtxo(1, bobWitnessUtxo);
    updater.addInUtxoRangeProof(1, bobWitnessUtxo.rangeProof!);
    updater.addInSighashType(1, Transaction.SIGHASH_ALL);

    const zkpLib = await secp256k1();
    const zkpValidator = new ZKPValidator(zkpLib);
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs(
        alice.blindingKeys.concat(bob.blindingKeys),
      ),
    );
    const ownedInputs = zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
    );

    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );
    blinder.blindLast({ outputBlindingArgs });
    const rawTx = signTransaction(
      pset,
      [alice.keys, bob.keys],
      Transaction.SIGHASH_ALL,
    );
    await regtestUtils.broadcast(rawTx.toHex());
  });

  it('can create (and broadcast via 3PBP) a transaction w/ unconfidential taproot keyspend input', async () => {
    const alice = ECPair.makeRandom({ network: regtest });

    const output = BIP341Factory(ecc).taprootOutputScript(alice.publicKey);
    const taprootAddress = address.fromOutputScript(output, regtest); // UNCONFIDENTIAL

    const utxo = await regtestUtils.faucet(taprootAddress);
    const txhex = await regtestUtils.fetchTx(utxo.txid);
    const prevoutTx = Transaction.fromHex(txhex);

    const FEES = 1000;
    const sendAmount = 10_000;
    const change = 1_0000_0000 - sendAmount - FEES;

    const inputs = [new CreatorInput(utxo.txid, utxo.vout)];

    const outputs = [
      new CreatorOutput(
        lbtc,
        sendAmount,
        address.toOutputScript('ert1qqndj7dqs4emt4ty475an693hcput6l87m4rajq'),
      ),
      new CreatorOutput(lbtc, change, address.toOutputScript(taprootAddress)),
      new CreatorOutput(lbtc, FEES),
    ];

    const pset = PsetCreator.newPset({
      inputs,
      outputs,
    });

    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, prevoutTx.outs[utxo.vout]);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    // Allthough not needed, let's add the tap internal key for completeness.
    updater.addInTapInternalKey(0, toXOnly(alice.publicKey));

    const preimage = pset.getInputPreimage(
      0,
      Transaction.SIGHASH_ALL,
      regtest.genesisBlockHash,
    );
    const signature = BIP341Factory(ecc).taprootSignKey(
      preimage,
      alice.privateKey!,
    );

    const signer = new PsetSigner(pset);

    const partialSig: BIP371SigningData = {
      tapKeySig: serializeSchnnorrSig(signature, Transaction.SIGHASH_ALL),
      genesisBlockHash: regtest.genesisBlockHash,
    };
    signer.addSignature(0, partialSig, Pset.SchnorrSigValidator(ecc));

    const finalizer = new PsetFinalizer(pset);
    finalizer.finalize();
    const tx = PsetExtractor.extract(pset);
    const hex = tx.toHex();

    await regtestUtils.broadcast(hex);
  });

  it('can create (and broadcast via 3PBP) a transaction w/ unconfidential taproot scriptspend input', async () => {
    const bobPay = createPayment('p2wpkh', undefined, undefined, true);
    const BOB = bobPay.keys[0];
    const alice = ECPair.makeRandom({ network: regtest });
    const bobScript = bscript.compile([
      BOB.publicKey.slice(1),
      OPS.OP_CHECKSIG,
    ]);

    // in this exemple, alice is the internal key (can spend via keypath spend)
    // however, the script tree allows bob to spend the coin with a simple p2pkh
    const leaves: bip341.TaprootLeaf[] = [
      {
        scriptHex: bobScript.toString('hex'),
      },
      {
        scriptHex:
          '20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac',
      },
    ];

    const hashTree = bip341.toHashTree(leaves);
    const output = BIP341Factory(ecc).taprootOutputScript(
      alice.publicKey,
      hashTree,
    );
    const taprootAddress = address.fromOutputScript(output, regtest); // UNCONFIDENTIAL

    const confUtxo = await regtestUtils.faucet(
      bobPay.payment.confidentialAddress!,
    );
    const utxo = await regtestUtils.faucet(taprootAddress);
    const txhex = await regtestUtils.fetchTx(utxo.txid);
    const confTxHex = await regtestUtils.fetchTx(confUtxo.txid);
    const prevoutTx = Transaction.fromHex(txhex);
    const prevoutConfTx = Transaction.fromHex(confTxHex);

    const FEES = 1000;
    const sendAmount = 10_000;
    const change = 2_0000_0000 - sendAmount - FEES;

    // bob spends the coin with the script path of the leaf
    // he gets the change and send the other one to the same taproot address

    const inputs = [
      new CreatorInput(confUtxo.txid, confUtxo.vout),
      new CreatorInput(utxo.txid, utxo.vout),
    ];

    const outputs = [
      new CreatorOutput(
        lbtc,
        sendAmount,
        bobPay.payment.output,
        bobPay.payment.blindkey,
        0,
      ),
      new CreatorOutput(lbtc, change, address.toOutputScript(taprootAddress)),
      new CreatorOutput(lbtc, FEES),
    ];

    const pset = PsetCreator.newPset({
      inputs,
      outputs,
    });

    const updater = new PsetUpdater(pset);
    updater.addInWitnessUtxo(0, prevoutConfTx.outs[confUtxo.vout]);
    updater.addInUtxoRangeProof(
      0,
      prevoutConfTx.outs[confUtxo.vout].rangeProof!,
    );
    updater.addInWitnessUtxo(1, prevoutTx.outs[utxo.vout]);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInSighashType(1, Transaction.SIGHASH_ALL);

    const leafHash = bip341.tapLeafHash(leaves[0]);
    const pathToBobLeaf = bip341.findScriptPath(hashTree, leafHash);
    const [script, controlBlock] = BIP341Factory(ecc).taprootSignScriptStack(
      alice.publicKey,
      leaves[0],
      hashTree.hash,
      pathToBobLeaf,
    );

    updater.addInTapLeafScript(1, {
      controlBlock,
      leafVersion: bip341.LEAF_VERSION_TAPSCRIPT,
      script,
    });

    const zkpLib = await secp256k1();
    const zkpValidator = new ZKPValidator(zkpLib);
    const zkpGenerator = new ZKPGenerator(
      zkpLib,
      ZKPGenerator.WithBlindingKeysOfInputs(bobPay.blindingKeys),
    );

    const ownedInputs = zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = zkpGenerator.blindOutputs(
      pset,
      Pset.ECCKeysGenerator(ecc),
    );

    const blinder = new PsetBlinder(
      pset,
      ownedInputs,
      zkpValidator,
      zkpGenerator,
    );

    blinder.blindLast({ outputBlindingArgs });

    const signer = new PsetSigner(pset);
    // segwit v0 input
    const preimage = pset.getInputPreimage(
      0,
      pset.inputs[0].sighashType || Transaction.SIGHASH_ALL,
    );

    const partialSig: BIP174SigningData = {
      partialSig: {
        pubkey: BOB.publicKey,
        signature: bscript.signature.encode(
          BOB.sign(preimage),
          pset.inputs[0].sighashType || Transaction.SIGHASH_ALL,
        ),
      },
    };
    signer.addSignature(0, partialSig, Pset.ECDSASigValidator(ecc));

    // taproot input
    const hashType = pset.inputs[1].sighashType || Transaction.SIGHASH_ALL;
    const sighashmsg = pset.getInputPreimage(
      1,
      hashType,
      regtest.genesisBlockHash,
      leafHash,
    );

    const sig = ecc.signSchnorr(sighashmsg, BOB.privateKey!, Buffer.alloc(32));

    const taprootData = {
      tapScriptSigs: [
        {
          signature: serializeSchnnorrSig(Buffer.from(sig), hashType),
          pubkey: BOB.publicKey.slice(1),
          leafHash,
        },
      ],
      genesisBlockHash: regtest.genesisBlockHash,
    };

    signer.addSignature(1, taprootData, Pset.SchnorrSigValidator(ecc));

    const finalizer = new PsetFinalizer(pset);
    finalizer.finalize();
    const tx = PsetExtractor.extract(pset);
    const hex = tx.toHex();

    await regtestUtils.broadcast(hex);
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
      const partialSig: BIP174SigningData = {
        partialSig: {
          pubkey: kp.publicKey,
          signature: bscript.signature.encode(kp.sign(preimage), sighashType),
        },
      };
      signer.addSignature(i, partialSig, Pset.ECDSASigValidator(ecc));
    });
  });

  if (!pset.validateAllSignatures(Pset.ECDSASigValidator(ecc))) {
    throw new Error('Failed to sign pset');
  }

  const finalizer = new PsetFinalizer(pset);
  finalizer.finalize();
  return PsetExtractor.extract(pset);
}

const serializeSchnnorrSig = (sig: Buffer, hashtype: number) =>
  Buffer.concat([
    sig,
    hashtype !== 0x00 ? Buffer.of(hashtype) : Buffer.alloc(0),
  ]);
