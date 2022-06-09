import { describe, it } from 'mocha';
import {
  networks,
  AssetHash,
  Transaction,
  payments,
  address,
  Psbt,
} from '../../ts_src/index';
import { ECPair, ecc } from '../ecc';
import { broadcast, faucet, fetchTx } from './_regtest';
import {
  confidentialValueToSatoshi,
  satoshiToConfidentialValue,
} from '../../ts_src/confidential';
import { ECPairInterface } from 'ecpair';
import {
  findScriptPath,
  tapLeafHash,
  TaprootLeaf,
  toHashTree,
  BIP341Factory,
} from '../../ts_src/bip341';
import { compile, OPS } from '../../ts_src/script';
import { witnessStackToScriptWitness } from '../../ts_src/psbt';
import * as assert from 'assert';

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
          asset: AssetHash.fromHex(utxo.asset, false).bytes,
          value: satoshiToConfidentialValue(utxo.value),
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
          asset: AssetHash.fromHex(utxo.asset, false).bytes,
          value: satoshiToConfidentialValue(utxo.value),
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
        value: satoshiToConfidentialValue(sendAmount),
        nonce: Buffer.of(0x00),
      })
      .addOutput({
        script: address.toOutputScript(faucetAddress, net),
        asset: utxo.asset,
        value: satoshiToConfidentialValue(utxo.value - sendAmount - FEES),
        nonce: Buffer.of(0x00),
      })
      .addOutput({
        script: Buffer.alloc(0),
        asset: utxo.asset,
        value: satoshiToConfidentialValue(FEES),
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
          asset: AssetHash.fromHex(utxo.asset, false).bytes,
          value: satoshiToConfidentialValue(utxo.value),
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

  it('can create (and broadcast via 3PBP) a confidential taproot scriptspend Pset (v0)', async () => {
    const BOB = ECPair.makeRandom({ network: net });
    const blindingKeys = ECPair.makeRandom({ network: net });

    const bobPay = payments.p2wpkh({
      pubkey: BOB.publicKey,
      blindkey: blindingKeys.publicKey,
      network: net,
    });
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
    const faucetAddress = address.fromOutputScript(output, net); // UNCONFIDENTIAL

    const confUtxo = await faucet(bobPay.confidentialAddress!);
    const utxo = await faucet(faucetAddress);
    const txhex = await fetchTx(utxo.txid);
    const confTxHex = await fetchTx(confUtxo.txid);
    const prevoutTx = Transaction.fromHex(txhex);
    const prevoutConfTx = Transaction.fromHex(confTxHex);

    const sendAmount = 1_0000_0000 - 10000;
    // bob spends the coin with the script path of the leaf
    // he gets the change and send the other one to the same taproot address

    const lbtc = AssetHash.fromHex(net.assetHash, false);

    const pset = new Psbt({ network: net })
      .addInput({
        hash: confUtxo.txid,
        index: confUtxo.vout,
        witnessUtxo: prevoutConfTx.outs[confUtxo.vout],
      })
      .addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: prevoutTx.outs[utxo.vout],
      })
      .addOutput({
        script: output,
        asset: lbtc.bytes,
        value: satoshiToConfidentialValue(sendAmount),
        nonce: Buffer.of(0x00),
      })
      .addOutput({
        script: output,
        asset: lbtc.bytes,
        value: satoshiToConfidentialValue(1_0000_0000 + 10000 - FEES),
        nonce: Buffer.of(0x00),
      })
      .addOutput({
        script: Buffer.alloc(0),
        asset: lbtc.bytes,
        value: satoshiToConfidentialValue(FEES),
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

    await pset.blindOutputsByIndex(
      Psbt.ECCKeysGenerator(ecc),
      new Map().set(0, blindingKeys.privateKey),
      new Map().set(0, blindingKeys.publicKey).set(1, blindingKeys.publicKey),
    );

    const inputsStack = makeStackCheckSig(
      BOB,
      pset.TX,
      1,
      [prevoutConfTx.outs[confUtxo.vout].script, output],
      [
        {
          asset: prevoutConfTx.outs[confUtxo.vout].asset,
          value: prevoutConfTx.outs[confUtxo.vout].value,
        },
        {
          asset: prevoutTx.outs[utxo.vout].asset,
          value: prevoutTx.outs[utxo.vout].value,
        },
      ],
      Transaction.SIGHASH_DEFAULT,
      leafHash,
    );

    pset.signInput(0, BOB);

    pset.updateInput(1, {
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
  const assetHash = AssetHash.fromHex(asset, false);
  tx.addOutput(
    address.toOutputScript(to),
    satoshiToConfidentialValue(amount),
    assetHash.bytes,
    Buffer.alloc(1),
  );

  // Add change output
  tx.addOutput(
    address.toOutputScript(changeAddress),
    satoshiToConfidentialValue(utxo.value - amount - FEES),
    assetHash.bytes,
    Buffer.alloc(1),
  );

  // add fee output
  tx.addOutput(
    Buffer.alloc(0),
    satoshiToConfidentialValue(FEES),
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
      (acc, { value }) => acc + confidentialValueToSatoshi(value),
      0,
    ) -
    amountToSend -
    FEES;

  const tx = new Transaction();
  tx.version = 2;
  // Add input
  tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);
  // Add output
  const assetHash = AssetHash.fromHex(net.assetHash, false);
  try {
    tx.addOutput(
      scriptPubkeys[0],
      satoshiToConfidentialValue(amountToSend),
      assetHash.bytes,
      Buffer.alloc(1),
    );
    tx.addOutput(
      address.toOutputScript(changeAddress),
      satoshiToConfidentialValue(changeAmount),
      assetHash.bytes,
      Buffer.alloc(1),
    ); // change
    tx.addOutput(
      Buffer.alloc(0),
      satoshiToConfidentialValue(500),
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
