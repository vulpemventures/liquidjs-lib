import * as ecc from 'tiny-secp256k1';
import { describe, it } from 'mocha';
import { ECPair, networks, AssetHash, address as addr, crypto, Transaction, payments, address } from '../../ts_src';
import { broadcast, TESTNET_APIURL } from './_regtest';
import { confidentialValueToSatoshi, satoshiToConfidentialValue } from '../../ts_src/confidential';
import { TestnetGenesisBlockHash } from '../../ts_src/transaction';
const net = networks.testnet;

describe('bitcoinjs-lib (transaction with taproot)', () => {
  it('can create (and broadcast via 3PBP) a taproot keyspend Transaction', async () => {
    const myKey = ECPair.fromWIF("L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6");
    const changeAddress = payments.p2pkh({ pubkey: myKey.publicKey, network: net }).address;
    const output = createKeySpendOutput(myKey.publicKey);
    const address = addr.fromOutputScript(output, net);
    console.log(address)

    // amount from faucet
    const amount = 1_00000;
    // amount to send
    const sendAmount = amount - 10000;
    // get faucet
    // const unspent = await faucet(address);

    const tx = createSigned(
      myKey,
      "7db2eb6d3798a1064801357ea3482e44c2ed793a93c9b3af8871241ea9b9999d",
      1,
      sendAmount,
      [output],
      [{ asset: AssetHash.fromHex(net.assetHash, false).bytes, value: satoshiToConfidentialValue(amount) }],
      changeAddress!
    );

    const hex = tx.toHex();
    // console.log('Valid tx sent from:');
    // console.log(address);
    // console.log('tx hex:');
    // console.log(hex);
    // console.log(Transaction.fromHex(hex))
    const str = await broadcast(hex, true, TESTNET_APIURL);
    console.log("txid: ", str)
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
  console.log('private key', privateKey)
  const newPrivateKey = ecc.privateAdd(privateKey!, tweakHash);
  if (newPrivateKey === null) throw new Error('Invalid Tweak');
  const signed = ecc.signSchnorr(messageHash, newPrivateKey, Buffer.alloc(32));

  const ok = ecc.verifySchnorr(messageHash, ECPair.fromPrivateKey(Buffer.from(newPrivateKey)).publicKey.slice(1), signed);
  if (!ok) throw new Error('Invalid Signature');

  return signed
}

// Function for creating signed tx
function createSigned(
  key: KeyPair,
  txid: string,
  vout: number,
  amountToSend: number,
  scriptPubkeys: Buffer[],
  values: { asset: Buffer, value: Buffer }[],
  changeAddress: string,
): Transaction {
  
  const FEES = 500
  const changeAmount = values.reduce((acc, { value }) => acc + confidentialValueToSatoshi(value), 0) - amountToSend - FEES;

  const tx = new Transaction();
  tx.version = 2;
  // Add input
  tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);
  // Add output
  const assetHash = AssetHash.fromHex(net.assetHash, false)
  console.log(assetHash.bytes, assetHash.bytes.length)
  try {
    tx.addOutput(scriptPubkeys[0], satoshiToConfidentialValue(amountToSend), assetHash.bytes, Buffer.alloc(1));
    tx.addOutput(address.toOutputScript(changeAddress), satoshiToConfidentialValue(changeAmount), assetHash.bytes, Buffer.alloc(1)); // change
    tx.addOutput(Buffer.alloc(0), satoshiToConfidentialValue(500), assetHash.bytes, Buffer.alloc(1)); // fees

    const sighash = tx.hashForWitnessV1(
      0, // which input
      scriptPubkeys, // scriptPubkey
      values, // All previous values of all inputs
      Transaction.SIGHASH_DEFAULT, // sighash flag, DEFAULT is schnorr-only (DEFAULT == ALL)
      TestnetGenesisBlockHash, // block hash
    );
    const signature = Buffer.from(signTweaked(sighash, key));
    console.log(signature)
    // witness stack for keypath spend is just the signature.
    // If sighash is not SIGHASH_DEFAULT (ALL) then you must add 1 byte with sighash value
    tx.ins[0].witness = [signature];
    return tx;
  } catch (e) {
    console.error(e)
    throw e
  }
}
