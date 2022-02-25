import * as ecc from 'tiny-secp256k1';
import { describe, it } from 'mocha';
import { ECPair, networks, AssetHash, address as addr, crypto, Transaction } from '../../ts_src';
import { broadcast } from './_regtest';
import { satoshiToConfidentialValue } from '../../ts_src/confidential';
const net = networks.testnet;

describe('bitcoinjs-lib (transaction with taproot)', () => {
  it('can create (and broadcast via 3PBP) a taproot keyspend Transaction', async () => {
    const myKey = ECPair.fromWIF("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
    const output = createKeySpendOutput(myKey.publicKey);
    const address = addr.fromOutputScript(output, net);
    // console.log(address)

    // amount from faucet
    const amount = 1_0000_0000;
    // amount to send
    const sendAmount = amount - 1000;
    // get faucet
    // const unspent = await faucet(address);

    const tx = createSigned(
      myKey,
      "01ca82d3e6a9dce06a3f464ef74e90c9d3a2ff260aa76e9f309227d317a06878",
      0,
      sendAmount,
      [output],
      [{ asset: AssetHash.fromHex(net.assetHash, false).bytes, value: satoshiToConfidentialValue(amount) }],
    );

    const hex = tx.toHex();
    console.log('Valid tx sent from:');
    console.log(address);
    console.log('tx hex:');
    console.log(hex);
    throw new Error('failed');
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
  const commitHash = crypto.taggedHash('TapTweak', myXOnlyPubkey);
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
    'TapTweak',
    key.publicKey.slice(1, 33),
  );
  const newPrivateKey = ecc.privateAdd(privateKey!, tweakHash);
  if (newPrivateKey === null) throw new Error('Invalid Tweak');
  return ecc.signSchnorr(messageHash, newPrivateKey, Buffer.alloc(32));
}

// Function for creating signed tx
function createSigned(
  key: KeyPair,
  txid: string,
  vout: number,
  amountToSend: number,
  scriptPubkeys: Buffer[],
  values: { asset: Buffer, value: Buffer }[],
): Transaction {
  const tx = new Transaction();
  tx.version = 2;
  // Add input
  tx.addInput(Buffer.from(txid, 'hex').reverse(), vout);
  // Add output
  const assetHash = AssetHash.fromHex(net.assetHash, false)
  console.log(assetHash.bytes, assetHash.bytes.length)
  try {
    tx.addOutput(scriptPubkeys[0], satoshiToConfidentialValue(amountToSend), assetHash.bytes);
    const sighash = tx.hashForWitnessV1(
      0, // which input
      scriptPubkeys, // All previous outputs of all inputs
      values, // All previous values of all inputs
      Transaction.SIGHASH_DEFAULT, // sighash flag, DEFAULT is schnorr-only (DEFAULT == ALL)
    );
    const signature = Buffer.from(signTweaked(sighash, key));
    // witness stack for keypath spend is just the signature.
    // If sighash is not SIGHASH_DEFAULT (ALL) then you must add 1 byte with sighash value
    tx.ins[0].witness = [signature];
    return tx;
  } catch (e) {
    console.error(e)
    throw e
  }
}
