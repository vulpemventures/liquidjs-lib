import { describe, it } from 'mocha';
import {
  networks,
  AssetHash,
  Transaction,
  payments,
  address,
  Psbt,
  Output,
  Input,
  Creator,
  Updater,
  Blinder,
  Extractor,
  Finalizer,
  Pset,
  Signer,
  BIP371SigningData,
  BIP174SigningData,
} from '../../ts_src/index';
import { ECPair, ecc } from '../ecc';
import { broadcast, faucet, fetchTx } from './_regtest';
import { ECPairInterface } from 'ecpair';
import {
  findScriptPath,
  tapLeafHash,
  TaprootLeaf,
  toHashTree,
  BIP341Factory,
  LEAF_VERSION_TAPSCRIPT,
} from '../../ts_src/bip341';
import { compile, OPS } from '../../ts_src/script';
import { witnessStackToScriptWitness } from '../../ts_src/psbt';
import * as assert from 'assert';
import { ElementsValue } from '../../ts_src/value';
import { ZKPGenerator, ZKPValidator } from '../../ts_src/confidential';
import * as bscript from '../../ts_src/script';
import { createPayment } from './utils';

const bip341 = BIP341Factory(ecc);

const net = networks.regtest;

describe('liquidjs-lib (transaction with taproot)', () => {
  const alice = ECPair.fromWIF(
    'L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6',
  );

  const bob = ECPair.fromWIF(
    'KwoJAjrautr5EUPVxvnisVgixipMiYGKxykiV8U6e6JtAP9ZURV5',
  );

  it('should be able to compute confidential address from taproot output script', () => {
    const bobScript = compile([bob.publicKey.slice(1), OPS.OP_CHECKSIG]);

    // in this exemple, alice is the internal key (can spend via keypath spend)
    // however, the script tree allows bob to spend the coin with a simple p2pkh
    const leaves: TaprootLeaf[] = [
      {
        scriptHex: bobScript.toString('hex'),
      },
      {
        scriptHex:
          '20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac',
      },
    ];

    const hashTree = toHashTree(leaves);
    const output = bip341.taprootOutputScript(alice.publicKey, hashTree);

    const unconfidentialAddress = address.fromOutputScript(
      output,
      networks.regtest,
    );
    const confidentialAddress = address.toConfidential(
      unconfidentialAddress,
      bob.publicKey,
    );
    const fromConf = address.fromConfidential(confidentialAddress);
    assert.strictEqual(unconfidentialAddress, fromConf.unconfidentialAddress);

    assert.ok(fromConf.blindingKey.equals(bob.publicKey));
    const scriptFromConfidential = address.toOutputScript(
      confidentialAddress,
      networks.regtest,
    );
    assert.ok(scriptFromConfidential.equals(output));
  });

  it('can create (and broadcast via 3PBP) a taproot keyspend Transaction', async () => {
    const changeAddress = payments.p2pkh({
      pubkey: alice.publicKey,
      network: net,
    }).address;
    const output = bip341.taprootOutputScript(alice.publicKey);
    const faucetAddress = address.fromOutputScript(output, net); // UNCONFIDENTIAL
    const utxo = await faucet(faucetAddress);

    // amount to send
    const sendAmount = utxo.value - 10000;

    const tx = createSigned(
      alice,
      utxo.txid,
      utxo.vout,
      sendAmount,
      [output],
      [
        {
          asset: AssetHash.fromHex(utxo.asset).bytes,
          value: ElementsValue.fromNumber(utxo.value).bytes,
        },
      ],
      changeAddress!,
      Transaction.SIGHASH_SINGLE,
    );

    const hex = tx.toHex();
    await broadcast(hex, true);
  });

  it('can create (and broadcast via 3PBP) a taproot scriptspend Transaction', async () => {
    const bobScript = compile([bob.publicKey.slice(1), OPS.OP_CHECKSIG]);

    // in this exemple, alice is the internal key (can spend via keypath spend)
    // however, the script tree allows bob to spend the coin with a simple p2pkh
    const leaves: TaprootLeaf[] = [
      {
        scriptHex: bobScript.toString('hex'),
      },
      {
        scriptHex:
          '20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac',
      },
    ];

    const hashTree = toHashTree(leaves);
    const output = bip341.taprootOutputScript(alice.publicKey, hashTree);
    const faucetAddress = address.fromOutputScript(output, net); // UNCONFIDENTIAL
    const utxo = await faucet(faucetAddress);

    const sendAmount = utxo.value - 10000;
    // bob spends the coin with the script path of the leaf
    // he gets the change and send the other one to the same taproot address
    const tx = makeTransaction(
      sendAmount,
      utxo.asset,
      faucetAddress,
      utxo,
      faucetAddress,
    );

    const bobLeaf = leaves[0];
    const leafHash = tapLeafHash(bobLeaf);
    const pathToBobLeaf = findScriptPath(hashTree, leafHash);
    const taprootStack = bip341.taprootSignScriptStack(
      alice.publicKey,
      bobLeaf,
      hashTree.hash,
      pathToBobLeaf,
    );

    const inputsStack = makeStackCheckSig(
      bob,
      tx,
      0,
      [output],
      [
        {
          asset: AssetHash.fromHex(utxo.asset).bytes,
          value: ElementsValue.fromNumber(utxo.value).bytes,
        },
      ],
      Transaction.SIGHASH_NONE | Transaction.SIGHASH_ANYONECANPAY,
      leafHash,
    );

    tx.ins[0].witness = [...inputsStack, ...taprootStack];

    const hex = tx.toHex();
    await broadcast(hex, true);
  });

  it('can create (and broadcast via 3PBP) a taproot scriptspend Pset (v0)', async () => {
    const bobScript = compile([bob.publicKey.slice(1), OPS.OP_CHECKSIG]);

    // in this exemple, alice is the internal key (can spend via keypath spend)
    // however, the script tree allows bob to spend the coin with a simple p2pkh
    const leaves: TaprootLeaf[] = [
      {
        scriptHex: bobScript.toString('hex'),
      },
      {
        scriptHex:
          '20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac',
      },
    ];

    const hashTree = toHashTree(leaves);
    const output = bip341.taprootOutputScript(alice.publicKey, hashTree);
    const faucetAddress = address.fromOutputScript(output, net); // UNCONFIDENTIAL
    const utxo = await faucet(faucetAddress);

    const sendAmount = utxo.value - 10000;
    // bob spends the coin with the script path of the leaf
    // he gets the change and send the other one to the same taproot address

    const pset = new Psbt({ network: net })
      .addInput({
        hash: utxo.txid,
        index: utxo.vout,
      })
      .addOutput({
        script: address.toOutputScript(faucetAddress, net),
        asset: utxo.asset,
        value: ElementsValue.fromNumber(sendAmount).bytes,
        nonce: Buffer.of(0x00),
      })
      .addOutput({
        script: address.toOutputScript(faucetAddress, net),
        asset: utxo.asset,
        value: ElementsValue.fromNumber(utxo.value - sendAmount - FEES).bytes,
        nonce: Buffer.of(0x00),
      })
      .addOutput({
        script: Buffer.alloc(0),
        asset: utxo.asset,
        value: ElementsValue.fromNumber(FEES).bytes,
        nonce: Buffer.of(0x00),
      });

    const bobLeaf = leaves[0];
    const leafHash = tapLeafHash(bobLeaf);
    const pathToBobLeaf = findScriptPath(hashTree, leafHash);
    const taprootStack = bip341.taprootSignScriptStack(
      alice.publicKey,
      bobLeaf,
      hashTree.hash,
      pathToBobLeaf,
    );

    const inputsStack = makeStackCheckSig(
      bob,
      pset.TX,
      0,
      [output],
      [
        {
          asset: AssetHash.fromHex(utxo.asset).bytes,
          value: ElementsValue.fromNumber(utxo.value).bytes,
        },
      ],
      Transaction.SIGHASH_DEFAULT,
      leafHash,
    );

    pset.updateInput(0, {
      finalScriptWitness: witnessStackToScriptWitness([
        ...inputsStack,
        ...taprootStack,
      ]),
    });

    pset.finalizeAllInputs();
    const tx = pset.extractTransaction();
    const hex = tx.toHex();
    await broadcast(hex, true);
  });

  it.only('can create (and broadcast via 3PBP) an uconfidential taproot scriptspend Pset input with a confidential non-taproot input (v2)', async () => {
    const bobPay = createPayment('p2wpkh', undefined, undefined, true);
    const BOB = bobPay.keys[0];
    const bobScript = compile([BOB.publicKey.slice(1), OPS.OP_CHECKSIG]);

    // in this exemple, alice is the internal key (can spend via keypath spend)
    // however, the script tree allows bob to spend the coin with a simple p2pkh
    const leaves: TaprootLeaf[] = [
      {
        scriptHex: bobScript.toString('hex'),
      },
      {
        scriptHex:
          '20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac',
      },
    ];

    const hashTree = toHashTree(leaves);
    const output = bip341.taprootOutputScript(alice.publicKey, hashTree);
    const taprootAddress = address.fromOutputScript(output, net); // UNCONFIDENTIAL

    const confUtxo = await faucet(bobPay.payment.confidentialAddress!);
    const utxo = await faucet(taprootAddress);
    const txhex = await fetchTx(utxo.txid);
    const confTxHex = await fetchTx(confUtxo.txid);
    const prevoutTx = Transaction.fromHex(txhex);
    const prevoutConfTx = Transaction.fromHex(confTxHex);

    const sendAmount = 10_000;
    const change = 2_0000_0000 - sendAmount - FEES;

    // bob spends the coin with the script path of the leaf
    // he gets the change and send the other one to the same taproot address

    const lbtc = AssetHash.fromHex(net.assetHash);

    const inputs = [
      new Input(confUtxo.txid, confUtxo.vout),
      new Input(utxo.txid, utxo.vout),
    ];

    const outputs = [
      new Output(lbtc.hex, sendAmount, bobPay.payment.confidentialAddress!, 0),
      new Output(lbtc.hex, change, taprootAddress, 0),
      new Output(lbtc.hex, FEES),
    ];

    const pset = Creator.newPset({
      inputs,
      outputs,
    });

    const updater = new Updater(pset);
    updater.addInWitnessUtxo(0, prevoutConfTx.outs[confUtxo.vout]);
    updater.addInWitnessUtxo(1, prevoutTx.outs[utxo.vout]);
    updater.addInSighashType(0, Transaction.SIGHASH_ALL);
    updater.addInSighashType(1, Transaction.SIGHASH_ALL);

    const leafHash = tapLeafHash(leaves[0]);
    const pathToBobLeaf = findScriptPath(hashTree, leafHash);
    const [script, controlBlock] = bip341.taprootSignScriptStack(
      alice.publicKey,
      leaves[0],
      hashTree.hash,
      pathToBobLeaf,
    );

    updater.addInTapLeafScript(1, {
      controlBlock,
      leafVersion: LEAF_VERSION_TAPSCRIPT,
      script,
    });

    const zkpGenerator = ZKPGenerator.fromInBlindingKeys(bobPay.blindingKeys);
    const ownedInputs = await zkpGenerator.unblindInputs(pset);
    const outputBlindingArgs = await zkpGenerator.blindOutputs(
      pset,
      ZKPGenerator.ECCKeysGenerator(ecc),
    );
    const zkpValidator = new ZKPValidator();

    const blinder = new Blinder(pset, ownedInputs, zkpValidator, zkpGenerator);

    await blinder.blindLast({ outputBlindingArgs });

    const signer = new Signer(pset);
    // segwit v0 input
    const preimage = pset.getInputPreimage(
      0,
      pset.inputs[0].sighashType || Transaction.SIGHASH_ALL,
    );

    const partialSig: BIP174SigningData = {
      psig: {
        pubkey: BOB.publicKey,
        signature: bscript.signature.encode(
          BOB.sign(preimage),
          pset.inputs[0].sighashType || Transaction.SIGHASH_ALL,
        ),
      },
    };
    signer.signInput(0, partialSig, Pset.ECDSASigValidator(ecc));

    // taproot input
    const hashType = pset.inputs[1].sighashType || Transaction.SIGHASH_ALL;
    const sighashmsg = pset.getInputPreimage(
      1,
      hashType,
      net.genesisBlockHash,
      leafHash,
    );

    const sig = ecc.signSchnorr(sighashmsg, BOB.privateKey!, Buffer.alloc(32));

    const taprootData: BIP371SigningData = {
      tapScriptSigs: [
        {
          signature: serializeSchnnorrSig(Buffer.from(sig), hashType),
          pubkey: BOB.publicKey.slice(1),
          leafHash,
        },
      ],
      genesisBlockHash: net.genesisBlockHash,
    };

    signer.signInput(1, taprootData, Pset.SchnorrSigValidator(ecc));
    console.log(pset.inputs[0]);
    console.log(pset.inputs[1]);

    const finalizer = new Finalizer(pset);
    finalizer.finalize();
    const tx = Extractor.extract(pset);
    const hex = tx.toHex();

    await broadcast(hex, true);
  });
});

const FEES = 500;

function makeStackCheckSig(
  keyPair: ECPairInterface,
  transaction: Transaction,
  inputIndex: number,
  prevoutScripts: Buffer[],
  values: { asset: Buffer; value: Buffer }[],
  type: number,
  leafHash: Buffer,
): Buffer[] {
  const hash = transaction.hashForWitnessV1(
    inputIndex,
    prevoutScripts,
    values,
    type,
    net.genesisBlockHash,
    leafHash,
  );

  const sig = ecc.signSchnorr(hash, keyPair.privateKey!, Buffer.alloc(32));

  const ok = ecc.verifySchnorr(hash, keyPair.publicKey.slice(1), sig);
  if (!ok) {
    throw new Error('Signature is not valid');
  }

  return [serializeSchnnorrSig(Buffer.from(sig), type)];
}

function makeTransaction(
  amount: number,
  asset: string,
  to: string,
  utxo: { txid: string; vout: number; value: number },
  changeAddress: string,
): Transaction {
  const tx = new Transaction();
  tx.version = 2;
  // Add input
  tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout);
  // Add output
  const assetHash = AssetHash.fromHex(asset);
  tx.addOutput(
    address.toOutputScript(to),
    ElementsValue.fromNumber(amount).bytes,
    assetHash.bytes,
    Buffer.alloc(1),
  );

  // Add change output
  tx.addOutput(
    address.toOutputScript(changeAddress),
    ElementsValue.fromNumber(utxo.value - amount - FEES).bytes,
    assetHash.bytes,
    Buffer.alloc(1),
  );

  // add fee output
  tx.addOutput(
    Buffer.alloc(0),
    ElementsValue.fromNumber(FEES).bytes,
    assetHash.bytes,
    Buffer.alloc(1),
  );

  return tx;
}

// Function for creating signed tx
function createSigned(
  key: ECPairInterface,
  txid: string,
  vout: number,
  amountToSend: number,
  scriptPubkeys: Buffer[],
  values: { asset: Buffer; value: Buffer }[],
  changeAddress: string,
  hashType: number,
): Transaction {
  const changeAmount =
    values.reduce(
      (acc, { value }) => acc + ElementsValue.fromBytes(value).number,
      0,
    ) -
    amountToSend -
    FEES;

  const tx = new Transaction();
  tx.version = 2;
  // Add input
  tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);
  // Add output
  const assetHash = AssetHash.fromHex(net.assetHash);
  try {
    tx.addOutput(
      scriptPubkeys[0],
      ElementsValue.fromNumber(amountToSend).bytes,
      assetHash.bytes,
      Buffer.alloc(1),
    );
    tx.addOutput(
      address.toOutputScript(changeAddress),
      ElementsValue.fromNumber(changeAmount).bytes,
      assetHash.bytes,
      Buffer.alloc(1),
    ); // change
    tx.addOutput(
      Buffer.alloc(0),
      ElementsValue.fromNumber(500).bytes,
      assetHash.bytes,
      Buffer.alloc(1),
    ); // fees

    const sighash = tx.hashForWitnessV1(
      0, // which input
      scriptPubkeys, // scriptPubkey
      values, // All previous values of all inputs
      hashType, // sighash flag, DEFAULT is schnorr-only (DEFAULT == ALL)
      net.genesisBlockHash, // block hash
    );
    const signature = bip341.taprootSignKey(sighash, key.privateKey!);
    // witness stack for keypath spend is just the signature.
    // If sighash is not SIGHASH_DEFAULT then you must add 1 byte with sighash value
    tx.ins[0].witness = [serializeSchnnorrSig(signature, hashType)];
    return tx;
  } catch (e) {
    console.error(e);
    throw e;
  }
}

const serializeSchnnorrSig = (sig: Buffer, hashtype: number) =>
  Buffer.concat([
    sig,
    hashtype !== 0x00 ? Buffer.of(hashtype) : Buffer.alloc(0),
  ]);
