import * as ecc from 'tiny-secp256k1';
import { describe, it } from 'mocha';
import {
  ECPair,
  networks,
  AssetHash,
  crypto,
  Transaction,
  payments,
  address,
} from '../../ts_src';
import { broadcast, faucet } from './_regtest';
import {
  confidentialValueToSatoshi,
  satoshiToConfidentialValue,
} from '../../ts_src/confidential';

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
    const output = createKeySpendOutput(myKey.publicKey);
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

// Order of the curve (N) - 1
const N_LESS_1 = Buffer.from(
  'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
  'hex',
);
// 1 represented as 32 bytes BE
const ONE = Buffer.from(
  '0000000000000000000000000000000000000000000000000000000000000001',
  'hex',
);

// Function for creating a tweaked p2tr key-spend only address
// (This is recommended by BIP341)
function createKeySpendOutput(publicKey: Buffer): Buffer {
  // x-only pubkey (remove 1 byte y parity)
  const myXOnlyPubkey = publicKey.slice(1, 33);
  const commitHash = crypto.taggedHash('TapTweak/elements', myXOnlyPubkey);
  const tweakResult = ecc.xOnlyPointAddTweak(myXOnlyPubkey, commitHash);
  if (tweakResult === null) throw new Error('Invalid Tweak');
  const { xOnlyPubkey: tweaked } = tweakResult;
  // scriptPubkey
  return Buffer.concat([
    // witness v1, PUSH_DATA 32 bytes
    Buffer.from([0x51, 0x20]),
    // x-only tweaked pubkey
    tweaked,
  ]);
}

// Function for signing for a tweaked p2tr key-spend only address
// (Required for the above address)
interface KeyPair {
  publicKey: Buffer;
  privateKey?: Buffer;
}

function signTweaked(messageHash: Buffer, key: KeyPair): Uint8Array {
  const privateKey =
    key.publicKey[0] === 2
      ? key.privateKey
      : ecc.privateAdd(ecc.privateSub(N_LESS_1, key.privateKey!)!, ONE)!;
  const tweakHash = crypto.taggedHash(
    'TapTweak/elements',
    key.publicKey.slice(1, 33),
  );
  console.log('private key', privateKey);
  const newPrivateKey = ecc.privateAdd(privateKey!, tweakHash);
  if (newPrivateKey === null) throw new Error('Invalid Tweak');
  const signed = ecc.signSchnorr(messageHash, newPrivateKey, Buffer.alloc(32));

  const ok = ecc.verifySchnorr(
    messageHash,
    ECPair.fromPrivateKey(Buffer.from(newPrivateKey)).publicKey.slice(1),
    signed,
  );
  if (!ok) throw new Error('Invalid Signature');

  return signed;
}

// Function for creating signed tx
function createSigned(
  key: KeyPair,
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
    const signature = Buffer.from(signTweaked(sighash, key));
    // witness stack for keypath spend is just the signature.
    // If sighash is not SIGHASH_DEFAULT (ALL) then you must add 1 byte with sighash value
    tx.ins[0].witness = [signature];
    return tx;
  } catch (e) {
    console.error(e);
    throw e;
  }
}
