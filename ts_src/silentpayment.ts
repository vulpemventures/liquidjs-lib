import * as crypto from 'crypto';
import { bech32m } from 'bech32';
import { bip341 } from '.';
import { sha256 } from './crypto';

export type Target = {
  silentPaymentAddress: string;
  value: number;
  asset: string;
};

export type Output = {
  scriptPubKey: string;
  value: number;
  asset: string;
};

// internal use only
type SilentPaymentGroup = {
  scanPublicKey: Buffer;
  targets: Array<{
    value: number;
    address: SilentPaymentAddress;
    asset: string;
  }>;
};

const G = Buffer.from(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  'hex',
);

export interface TinySecp256k1Interface
  extends bip341.BIP341Secp256k1Interface {
  privateMultiply: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  pointMultiply: (point: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
  pointAdd: (point1: Uint8Array, point2: Uint8Array) => Uint8Array | null;
  pointFromScalar: (key: Uint8Array) => Uint8Array | null;
  privateAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array | null;
  privateNegate: (key: Uint8Array) => Uint8Array;
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

export class SilentPayment {
  constructor(private ecc: TinySecp256k1Interface) {}

  /**
   * create the transaction outputs sending outpoints identified by *outpointHash* to the *targets*
   * @param inputsOutpointsHash hash of the input outpoints sent to the targets
   * @param sumInputsPrivKeys sum of input private keys
   * @param targets silent payment addresses receiving value/asset pair
   * @returns a list of "silent-payment" taproot outputs
   */
  pay(
    inputsOutpointsHash: Buffer,
    sumInputsPrivKeys: Buffer,
    targets: Target[],
  ): Output[] {
    const silentPaymentGroups: Array<SilentPaymentGroup> = [];
    for (const target of targets) {
      const addr = SilentPaymentAddress.decode(target.silentPaymentAddress);

      // Addresses with the same Bscan key all belong to the same recipient
      // *Liquid* also sort by asset
      const recipient = silentPaymentGroups.find(
        (group) =>
          Buffer.compare(group.scanPublicKey, addr.scanPublicKey) === 0,
      );

      const newTarget = { ...target, address: addr };

      if (recipient) {
        recipient.targets.push(newTarget);
      } else {
        silentPaymentGroups.push({
          scanPublicKey: addr.scanPublicKey,
          targets: [newTarget],
        });
      }
    }

    const outputs: Output[] = [];

    // Generating Pmn for each Bm in the group
    for (const group of silentPaymentGroups) {
      // Bscan * a * outpoint_hash
      const ecdhSharedSecretStep = Buffer.from(
        this.ecc.privateMultiply(inputsOutpointsHash, sumInputsPrivKeys),
      );
      const ecdhSharedSecret = this.ecc.pointMultiply(
        group.scanPublicKey,
        ecdhSharedSecretStep,
      );

      if (!ecdhSharedSecret) {
        throw new Error('Invalid ecdh shared secret');
      }

      let n = 0;
      for (const target of group.targets) {
        const tn = sha256(Buffer.concat([ecdhSharedSecret, ser32(n)]));

        // Let Pmn = tn·G + Bm
        const pubkey = Buffer.from(
          this.ecc.pointAdd(
            this.ecc.pointMultiply(G, tn)!,
            target.address.spendPublicKey,
          )!,
        );

        const output = {
          // Encode as a BIP341 taproot output
          scriptPubKey: Buffer.concat([
            Buffer.from([0x51, 0x20]),
            pubkey.slice(1),
          ]).toString('hex'),
          value: target.value,
          asset: target.asset,
        };
        outputs.push(output);
        n += 1;
      }
    }
    return outputs;
  }

  sumSecretKeys(outpointKeys: { key: Buffer; isTaproot?: boolean }[]): Buffer {
    const keys: Array<Buffer> = [];
    for (const { key, isTaproot } of outpointKeys) {
      // If taproot, check if the seckey results in an odd y-value and negate if so
      if (isTaproot && this.ecc.pointFromScalar(key)?.at(0) === 0x03) {
        const negated = Buffer.from(this.ecc.privateNegate(key));
        keys.push(negated);
        continue;
      }

      keys.push(key);
    }

    if (keys.length === 0) {
      throw new Error('No UTXOs with private keys found');
    }

    // summary of every item in array
    const ret = keys.reduce((acc, key) => {
      const sum = this.ecc.privateAdd(acc, key);
      if (!sum) throw new Error('Invalid private key sum');
      return Buffer.from(sum);
    });

    return ret;
  }

  // sum of public keys
  sumPublicKeys(keys: Buffer[]): Buffer {
    return keys.reduce((acc, key) => {
      const sum = this.ecc.pointAdd(acc, key);
      if (!sum) throw new Error('Invalid public key sum');
      return Buffer.from(sum);
    });
  }

  // compute the ecdh shared secret from scan private keys + public tx data (outpoints & pubkeys)
  // it may be useful to scan and spend coins owned by silent addresses.
  makeSharedSecret(
    inputsOutpointsHash: Buffer,
    inputPubKey: Buffer,
    scanSecretKey: Buffer,
  ): Buffer {
    const ecdhSharedSecretStep = Buffer.from(
      this.ecc.privateMultiply(inputsOutpointsHash, scanSecretKey),
    );
    const ecdhSharedSecret = this.ecc.pointMultiply(
      inputPubKey,
      ecdhSharedSecretStep,
    );

    if (!ecdhSharedSecret) {
      throw new Error('Invalid ecdh shared secret');
    }

    return Buffer.from(ecdhSharedSecret);
  }

  makePublicKey(
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

  makeSecretKey(
    spendPrivKey: Buffer,
    index: number,
    ecdhSharedSecret: Buffer,
  ): Buffer {
    const tn = sha256(Buffer.concat([ecdhSharedSecret, ser32(index)]));

    const privkey = this.ecc.privateAdd(spendPrivKey, tn);
    if (!privkey) throw new Error('Invalid privkey');

    return Buffer.from(privkey);
  }
}

export function ser32(i: number): Buffer {
  const returnValue = Buffer.allocUnsafe(4);
  returnValue.writeUInt32BE(i);
  return returnValue;
}

export function outpointsHash(
  parameters: { txid: string; vout: number }[],
): Buffer {
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
