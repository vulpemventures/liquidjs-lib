import { describe, it } from 'mocha';
import {
  ECPair,
  networks,
  AssetHash,
  bip341,
  Transaction,
  payments,
  address,
} from '../../ts_src';
import { broadcast, faucet } from './_regtest';
import {
  confidentialValueToSatoshi,
  satoshiToConfidentialValue,
} from '../../ts_src/confidential';
import { ECPairInterface } from 'ecpair';

const net = networks.regtest;

describe('liquidjs-lib (transaction with taproot)', () => {
  it('can create (and broadcast via 3PBP) a taproot keyspend Transaction', async () => {
    const myKey = ECPair.fromWIF(
      'L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6',
    );
    const changeAddress = payments.p2pkh({
      pubkey: myKey.publicKey,
      network: net,
    }).address;
    const output = bip341.taprootOutputScript(myKey.publicKey);
    const faucetAddress = address.fromOutputScript(output, net); // UNCONFIDENTIAL
    const utxo = await faucet(faucetAddress);

    // amount to send
    const sendAmount = utxo.value - 10000;

    const tx = createSigned(
      myKey,
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
    );

    const hex = tx.toHex();
    // console.log('Valid tx sent from:');
    // console.log(address);
    // console.log('tx hex:');
    // console.log(hex);
    // console.log(Transaction.fromHex(hex))
    await broadcast(hex, true);
  });
});

// Function for creating signed tx
function createSigned(
  key: ECPairInterface,
  txid: string,
  vout: number,
  amountToSend: number,
  scriptPubkeys: Buffer[],
  values: { asset: Buffer; value: Buffer }[],
  changeAddress: string,
): Transaction {
  const FEES = 500;
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
  console.log(assetHash.bytes, assetHash.bytes.length);
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
      Transaction.SIGHASH_DEFAULT, // sighash flag, DEFAULT is schnorr-only (DEFAULT == ALL)
      net.genesisBlockHash, // block hash
    );
    const signature = Buffer.from(bip341.taprootSignKey(sighash, key));
    // witness stack for keypath spend is just the signature.
    // If sighash is not SIGHASH_DEFAULT (ALL) then you must add 1 byte with sighash value
    tx.ins[0].witness = [signature];
    return tx;
  } catch (e) {
    console.error(e);
    throw e;
  }
}
