'use strict';
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        Object.defineProperty(o, k2, {
          enumerable: true,
          get: function() {
            return m[k];
          },
        });
      }
    : function(o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function(o, v) {
        Object.defineProperty(o, 'default', { enumerable: true, value: v });
      }
    : function(o, v) {
        o['default'] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== 'default' && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
var __importDefault =
  (this && this.__importDefault) ||
  function(mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.fromWIF = exports.fromPublicKey = exports.fromPrivateKey = exports.makeRandom = void 0;
const NETWORKS = __importStar(require('./networks'));
const types = __importStar(require('./types'));
const tiny_secp256k1_1 = __importDefault(require('tiny-secp256k1'));
const randombytes_1 = __importDefault(require('randombytes'));
const wif_1 = __importDefault(require('wif'));
const typeforce = require('typeforce');
const isOptions = typeforce.maybe(
  typeforce.compile({
    compressed: types.maybe(types.Boolean),
    network: types.maybe(types.Network),
  }),
);
class ECPair {
  constructor(__D, __Q, options) {
    this.__D = __D;
    this.__Q = __Q;
    this.lowR = false;
    if (options === undefined) options = {};
    this.compressed =
      options.compressed === undefined ? true : options.compressed;
    this.network = options.network || NETWORKS.liquid;
    if (__Q !== undefined)
      this.__Q = tiny_secp256k1_1.default.pointCompress(__Q, this.compressed);
  }
  get privateKey() {
    if (!this.__D) return undefined;
    return Buffer.from(this.__D);
  }
  get publicKey() {
    if (!this.__Q) {
      if (!this.__D) throw new Error('Missing private key');
      this.__Q = tiny_secp256k1_1.default.pointFromScalar(
        this.__D,
        this.compressed,
      );
    }
    return Buffer.from(this.__Q);
  }
  toWIF() {
    if (!this.__D) throw new Error('Missing private key');
    return wif_1.default.encode(
      this.network.wif,
      Buffer.from(this.__D),
      this.compressed,
    );
  }
  sign(hash, lowR) {
    if (!this.__D) throw new Error('Missing private key');
    if (lowR === undefined) lowR = this.lowR;
    if (lowR === false) {
      return Buffer.from(tiny_secp256k1_1.default.sign(hash, this.__D));
    } else {
      let sig = tiny_secp256k1_1.default.sign(hash, this.__D);
      const extraData = Buffer.alloc(32, 0);
      let counter = 0;
      // if first try is lowR, skip the loop
      // for second try and on, add extra entropy counting up
      while (sig[0] > 0x7f) {
        counter++;
        extraData.writeUIntLE(counter, 0, 6);
        sig = tiny_secp256k1_1.default.sign(hash, this.__D, extraData);
      }
      return Buffer.from(sig);
    }
  }
  verify(hash, signature) {
    return tiny_secp256k1_1.default.verify(hash, this.publicKey, signature);
  }
}
function fromPrivateKey(buffer, options) {
  typeforce(types.Buffer256bit, buffer);
  if (!tiny_secp256k1_1.default.isPrivate(buffer))
    throw new TypeError('Private key not in range [1, n)');
  typeforce(isOptions, options);
  return new ECPair(buffer, undefined, options);
}
exports.fromPrivateKey = fromPrivateKey;
function fromPublicKey(buffer, options) {
  typeforce(tiny_secp256k1_1.default.isPoint, buffer);
  typeforce(isOptions, options);
  return new ECPair(undefined, buffer, options);
}
exports.fromPublicKey = fromPublicKey;
function fromWIF(wifString, network) {
  const decoded = wif_1.default.decode(wifString);
  const version = decoded.version;
  // list of networks?
  if (types.Array(network)) {
    network = network
      .filter(x => {
        return version === x.wif;
      })
      .pop();
    if (!network) throw new Error('Unknown network version');
    // otherwise, assume a network object (or default to liquid)
  } else {
    network = network || NETWORKS.liquid;
    if (version !== network.wif) throw new Error('Invalid network version');
  }
  return fromPrivateKey(decoded.privateKey, {
    compressed: decoded.compressed,
    network: network,
  });
}
exports.fromWIF = fromWIF;
function makeRandom(options) {
  typeforce(isOptions, options);
  if (options === undefined) options = {};
  const rng = options.rng || randombytes_1.default;
  let d;
  do {
    d = rng(32);
    typeforce(types.Buffer256bit, d);
  } while (!tiny_secp256k1_1.default.isPrivate(d));
  return fromPrivateKey(d, options);
}
exports.makeRandom = makeRandom;
