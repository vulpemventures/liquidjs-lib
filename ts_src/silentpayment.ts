import * as crypto from 'crypto';
import { bech32m } from 'bech32';
import { sha256 } from './crypto';

export type Outpoint = {
  txid: string;
  vout: number;
};

export interface TinySecp256k1Interface {
  privateMultiply: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  pointMultiply: (point: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
  pointAdd: (point1: Uint8Array, point2: Uint8Array) => Uint8Array | null;
  pointFromScalar: (key: Uint8Array) => Uint8Array | null;
  privateAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
  privateNegate: (key: Uint8Array) => Uint8Array;
}

export interface SilentPayment {
  makeScriptPubKey(
    inputs: Outpoint[],
    inputPrivateKey: Buffer,
    silentPaymentAddress: string,
    index?: number,
  ): Buffer;
  isMine(
    scriptPubKey: Buffer,
    inputs: Outpoint[],
    inputPublicKey: Buffer,
    scanSecretKey: Buffer,
    index?: number,
  ): boolean;
  makeSigningKey(
    inputs: Outpoint[],
    inputPublicKey: Buffer,
    spendSecretKey: Buffer,
    index?: number,
  ): Buffer;
}

export class SilentPaymentAddress {
  constructor(readonly spendPublicKey: Buffer, readonly scanPublicKey: Buffer) {
    if (spendPublicKey.length !== 33 || scanPublicKey.length !== 33) {
      throw new Error(
        'Invalid public key length, expected 33 bytes public key',
      );
    }
  }

  static decode(str: string): SilentPaymentAddress {
    const result = bech32m.decode(str, 118);
    const version = result.words.shift();
    if (version !== 0) {
      throw new Error('Unexpected version of silent payment code');
    }
    const data = bech32m.fromWords(result.words);
    const scanPubKey = Buffer.from(data.slice(0, 33));
    const spendPubKey = Buffer.from(data.slice(33));
    return new SilentPaymentAddress(spendPubKey, scanPubKey);
  }

  encode(): string {
    const data = Buffer.concat([this.scanPublicKey, this.spendPublicKey]);

    const words = bech32m.toWords(data);
    words.unshift(0);
    return bech32m.encode('sp', words, 118);
  }
}

// inject ecc dependency, returns a SilentPayment interface
export function SPFactory(ecc: TinySecp256k1Interface): SilentPayment {
  return new SilentPaymentImpl(ecc);
}

const SEGWIT_V1_SCRIPT_PREFIX = Buffer.from([0x51, 0x20]);

const G = Buffer.from(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  'hex',
);

class SilentPaymentImpl implements SilentPayment {
  constructor(private ecc: TinySecp256k1Interface) {}

  /**
   * Compute scriptPubKey used to send funds to a silent payment address
   * @param inputs list of ALL outpoints of the transaction sending to the silent payment address
   * @param inputPrivateKey private key owning the spent outpoint. Sum of all private keys if multiple inputs
   * @param silentPaymentAddress target of the scriptPubKey
   * @param index index of the silent payment address. Prevent address reuse if multiple silent addresses are in the same transaction.
   * @returns the output scriptPubKey belonging to the silent payment address
   */
  makeScriptPubKey(
    inputs: Outpoint[],
    inputPrivateKey: Buffer,
    silentPaymentAddress: string,
    index = 0,
  ): Buffer {
    const inputsHash = hashOutpoints(inputs);
    const addr = SilentPaymentAddress.decode(silentPaymentAddress);

    const sharedSecret = this.makeSharedSecret(
      inputsHash,
      addr.scanPublicKey,
      inputPrivateKey,
    );

    const outputPublicKey = this.makePublicKey(
      addr.spendPublicKey,
      index,
      sharedSecret,
    );

    return Buffer.concat([SEGWIT_V1_SCRIPT_PREFIX, outputPublicKey.slice(1)]);
  }

  /**
   * Check if a scriptPubKey belongs to a silent payment address
   * @param scriptPubKey scriptPubKey to check
   * @param inputs list of ALL outpoints of the transaction sending to the silent payment address
   * @param inputPublicKey public key owning the spent outpoint. Sum of all public keys if multiple inputs
   * @param scanSecretKey private key of the silent payment address
   * @param index index of the silent payment address.
   */
  isMine(
    scriptPubKey: Buffer,
    inputs: Outpoint[],
    inputPublicKey: Buffer,
    scanSecretKey: Buffer,
    index = 0,
  ): boolean {
    const inputsHash = hashOutpoints(inputs);

    const sharedSecret = this.makeSharedSecret(
      inputsHash,
      inputPublicKey,
      scanSecretKey,
    );

    const outputPublicKey = this.makePublicKey(
      inputPublicKey,
      index,
      sharedSecret,
    );

    console.info(
      'isMine',
      scriptPubKey.slice(SEGWIT_V1_SCRIPT_PREFIX.length).toString('hex'),
      outputPublicKey.slice(1).toString('hex'),
    );
    return (
      Buffer.compare(
        scriptPubKey.slice(SEGWIT_V1_SCRIPT_PREFIX.length),
        outputPublicKey.slice(1),
      ) === 0
    );
  }

  /**
   * Compute the secret key used to spend an output locked by a silent address script.
   * @param inputs outpoints of the transaction sending to the silent payment address
   * @param inputPublicKey public key owning the spent outpoint in the tx (may be sum of public keys)
   * @param spendSecretKey private key of the silent payment address
   * @param index index of the silent payment address in the transaction, default to 0
   * @returns 32 bytes key
   */
  makeSigningKey(
    inputs: Outpoint[],
    inputPublicKey: Buffer,
    spendSecretKey: Buffer,
    index = 0,
  ): Buffer {
    const inputsHash = hashOutpoints(inputs);
    const sharedSecret = this.makeSharedSecret(
      inputsHash,
      inputPublicKey,
      spendSecretKey,
    );

    return this.makeSecretKey(spendSecretKey, index, sharedSecret);
  }

  /**
   * ECDH shared secret used to share outpoints hash of the transactions.
   * @param secret hash of the outpoints of the transaction sending to the silent payment address
   */
  private makeSharedSecret(
    secret: Buffer,
    pubkey: Buffer,
    seckey: Buffer,
  ): Buffer {
    const ecdhSharedSecretStep = Buffer.from(
      this.ecc.privateMultiply(secret, seckey),
    );
    const ecdhSharedSecret = this.ecc.pointMultiply(
      pubkey,
      ecdhSharedSecretStep,
    );

    if (!ecdhSharedSecret) {
      throw new Error('Invalid ecdh shared secret');
    }

    return Buffer.from(ecdhSharedSecret);
  }

  /**
   * Compute the output public key of a silent payment address.
   * @param spendPubKey spend public key of the silent payment address
   * @param index index of the silent payment address.
   * @param ecdhSharedSecret ecdh shared secret identifying the transaction.
   * @returns 33 bytes public key
   */
  private makePublicKey(
    spendPubKey: Buffer,
    index: number,
    ecdhSharedSecret: Buffer,
  ): Buffer {
    const tn = sha256(Buffer.concat([ecdhSharedSecret, ser32(index)]));

    const Tn = this.ecc.pointMultiply(G, tn);
    if (!Tn) throw new Error('Invalid Tn');

    const pubkey = this.ecc.pointAdd(Tn, spendPubKey);
    if (!pubkey) throw new Error('Invalid pubkey');

    return Buffer.from(pubkey);
  }

  /**
   * Compute the secret key locking the funds sent to a silent payment address.
   * @param spendPrivKey spend private key of the silent payment address
   * @param index index of the silent payment address.
   * @param ecdhSharedSecret ecdh shared secret identifying the transaction
   * @returns 32 bytes key
   */
  private makeSecretKey(
    spendPrivKey: Buffer,
    index: number,
    ecdhSharedSecret: Buffer,
  ): Buffer {
    const tn = sha256(Buffer.concat([ecdhSharedSecret, ser32(index)]));

    let privkey = this.ecc.privateAdd(spendPrivKey, tn);
    if (!privkey) throw new Error('Invalid privkey');

    if (this.ecc.pointFromScalar(privkey)?.[0] === 0x03) {
      privkey = this.ecc.privateNegate(privkey);
    }

    return Buffer.from(privkey);
  }
}

function ser32(i: number): Buffer {
  const returnValue = Buffer.allocUnsafe(4);
  returnValue.writeUInt32BE(i);
  return returnValue;
}

/**
 * Sort outpoints and hash them
 * @param parameters list of outpoints
 */
function hashOutpoints(parameters: Outpoint[]): Buffer {
  let bufferConcat = Buffer.alloc(0);
  const outpoints: Array<Buffer> = [];
  for (const parameter of parameters) {
    outpoints.push(
      Buffer.concat([
        Buffer.from(parameter.txid, 'hex').reverse(),
        ser32(parameter.vout).reverse(),
      ]),
    );
  }
  outpoints.sort(Buffer.compare);
  for (const outpoint of outpoints) {
    bufferConcat = Buffer.concat([bufferConcat, outpoint]);
  }
  return crypto.createHash('sha256').update(bufferConcat).digest();
}
