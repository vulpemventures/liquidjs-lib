'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ('get' in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function (o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.outpointsHash =
  exports.ser32 =
  exports.SilentPayment =
  exports.SilentPaymentAddress =
    void 0;
const crypto = __importStar(require('crypto'));
const bech32_1 = require('bech32');
const crypto_1 = require('./crypto');
const G = Buffer.from(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  'hex',
);
class SilentPaymentAddress {
  constructor(spendPublicKey, scanPublicKey) {
    this.spendPublicKey = spendPublicKey;
    this.scanPublicKey = scanPublicKey;
    if (spendPublicKey.length !== 33 || scanPublicKey.length !== 33) {
      throw new Error(
        'Invalid public key length, expected 33 bytes public key',
      );
    }
  }
  static decode(str) {
    const result = bech32_1.bech32m.decode(str, 118);
    const version = result.words.shift();
    if (version !== 0) {
      throw new Error('Unexpected version of silent payment code');
    }
    const data = bech32_1.bech32m.fromWords(result.words);
    const scanPubKey = Buffer.from(data.slice(0, 33));
    const spendPubKey = Buffer.from(data.slice(33));
    return new SilentPaymentAddress(spendPubKey, scanPubKey);
  }
  encode() {
    const data = Buffer.concat([this.scanPublicKey, this.spendPublicKey]);
    const words = bech32_1.bech32m.toWords(data);
    words.unshift(0);
    return bech32_1.bech32m.encode('sp', words, 118);
  }
}
exports.SilentPaymentAddress = SilentPaymentAddress;
class SilentPayment {
  constructor(ecc) {
    this.ecc = ecc;
  }
  /**
   * create the transaction outputs sending outpoints identified by *outpointHash* to the *targets*
   * @param inputsOutpointsHash hash of the input outpoints sent to the targets
   * @param sumInputsPrivKeys sum of input private keys
   * @param targets silent payment addresses receiving value/asset pair
   * @returns a list of "silent-payment" taproot outputs
   */
  pay(inputsOutpointsHash, sumInputsPrivKeys, targets) {
    const silentPaymentGroups = [];
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
    const outputs = [];
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
        const tn = (0, crypto_1.sha256)(
          Buffer.concat([ecdhSharedSecret, ser32(n)]),
        );
        // Let Pmn = tn·G + Bm
        const pubkey = Buffer.from(
          this.ecc.pointAdd(
            this.ecc.pointMultiply(G, tn),
            target.address.spendPublicKey,
          ),
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
  sumSecretKeys(outpointKeys) {
    const keys = [];
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
  sumPublicKeys(keys) {
    return keys.reduce((acc, key) => {
      const sum = this.ecc.pointAdd(acc, key);
      if (!sum) throw new Error('Invalid public key sum');
      return Buffer.from(sum);
    });
  }
  // compute the ecdh shared secret from scan private keys + public tx data (outpoints & pubkeys)
  // it may be useful to scan and spend coins owned by silent addresses.
  makeSharedSecret(inputsOutpointsHash, inputPubKey, scanSecretKey) {
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
  makePublicKey(spendPubKey, index, ecdhSharedSecret) {
    const tn = (0, crypto_1.sha256)(
      Buffer.concat([ecdhSharedSecret, ser32(index)]),
    );
    const Tn = this.ecc.pointMultiply(G, tn);
    if (!Tn) throw new Error('Invalid Tn');
    const pubkey = this.ecc.pointAdd(Tn, spendPubKey);
    if (!pubkey) throw new Error('Invalid pubkey');
    return Buffer.from(pubkey);
  }
  makeSecretKey(spendPrivKey, index, ecdhSharedSecret) {
    const tn = (0, crypto_1.sha256)(
      Buffer.concat([ecdhSharedSecret, ser32(index)]),
    );
    const privkey = this.ecc.privateAdd(spendPrivKey, tn);
    if (!privkey) throw new Error('Invalid privkey');
    return Buffer.from(privkey);
  }
}
exports.SilentPayment = SilentPayment;
function ser32(i) {
  const returnValue = Buffer.allocUnsafe(4);
  returnValue.writeUInt32BE(i);
  return returnValue;
}
exports.ser32 = ser32;
function outpointsHash(parameters) {
  let bufferConcat = Buffer.alloc(0);
  const outpoints = [];
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
exports.outpointsHash = outpointsHash;
