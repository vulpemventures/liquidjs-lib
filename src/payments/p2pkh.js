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
var __importDefault =
  (this && this.__importDefault) ||
  function (mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
exports.p2pkh = void 0;
const bcrypto = __importStar(require('../crypto'));
const networks_1 = require('../networks');
const bscript = __importStar(require('../script'));
const types_1 = require('../types');
const lazy = __importStar(require('./lazy'));
const bs58check_1 = __importDefault(require('bs58check'));
const OPS = bscript.OPS;
// input: {signature} {pubkey}
// output: OP_DUP OP_HASH160 {hash160(pubkey)} OP_EQUALVERIFY OP_CHECKSIG
function p2pkh(a, opts) {
  if (
    !a.address &&
    !a.hash &&
    !a.output &&
    !a.pubkey &&
    !a.input &&
    !a.confidentialAddress
  )
    throw new TypeError('Not enough data');
  opts = Object.assign({ validate: true }, opts || {});
  (0, types_1.typeforce)(
    {
      network: types_1.typeforce.maybe(types_1.typeforce.Object),
      address: types_1.typeforce.maybe(types_1.typeforce.String),
      hash: types_1.typeforce.maybe(types_1.typeforce.BufferN(20)),
      output: types_1.typeforce.maybe(types_1.typeforce.BufferN(25)),
      pubkey: types_1.typeforce.maybe(types_1.isPoint),
      signature: types_1.typeforce.maybe(bscript.isCanonicalScriptSignature),
      input: types_1.typeforce.maybe(types_1.typeforce.Buffer),
      blindkey: types_1.typeforce.maybe(types_1.isPoint),
      confidentialAddress: types_1.typeforce.maybe(types_1.typeforce.String),
    },
    a,
  );
  const _address = lazy.value(() => {
    const payload = bs58check_1.default.decode(a.address);
    const version = payload.readUInt8(0);
    const hash = payload.slice(1);
    return { version, hash };
  });
  const _chunks = lazy.value(() => {
    return bscript.decompile(a.input);
  });
  const _confidentialAddress = lazy.value(() => {
    const payload = bs58check_1.default.decode(a.confidentialAddress);
    const blindkey = payload.slice(2, 35);
    const unconfidentialAddressBuffer = Buffer.concat([
      Buffer.from([payload.readUInt8(1)]),
      payload.slice(35),
    ]);
    const unconfidentialAddress = bs58check_1.default.encode(
      unconfidentialAddressBuffer,
    );
    return { blindkey, unconfidentialAddress };
  });
  const network = a.network || networks_1.liquid;
  const o = { name: 'p2pkh', network };
  lazy.prop(o, 'address', () => {
    if (!o.hash) return;
    const payload = Buffer.allocUnsafe(21);
    payload.writeUInt8(network.pubKeyHash, 0);
    o.hash.copy(payload, 1);
    return bs58check_1.default.encode(payload);
  });
  lazy.prop(o, 'hash', () => {
    if (a.output) return a.output.slice(3, 23);
    if (a.address) return _address().hash;
    if (a.pubkey || o.pubkey) return bcrypto.hash160(a.pubkey || o.pubkey);
    if (a.confidentialAddress) {
      const address = _confidentialAddress().unconfidentialAddress;
      return bs58check_1.default.decode(address).slice(1);
    }
  });
  lazy.prop(o, 'output', () => {
    if (!o.hash) return;
    return bscript.compile([
      OPS.OP_DUP,
      OPS.OP_HASH160,
      o.hash,
      OPS.OP_EQUALVERIFY,
      OPS.OP_CHECKSIG,
    ]);
  });
  lazy.prop(o, 'pubkey', () => {
    if (!a.input) return;
    return _chunks()[1];
  });
  lazy.prop(o, 'signature', () => {
    if (!a.input) return;
    return _chunks()[0];
  });
  lazy.prop(o, 'input', () => {
    if (!a.pubkey) return;
    if (!a.signature) return;
    return bscript.compile([a.signature, a.pubkey]);
  });
  lazy.prop(o, 'witness', () => {
    if (!o.input) return;
    return [];
  });
  lazy.prop(o, 'blindkey', () => {
    if (a.confidentialAddress) return _confidentialAddress().blindkey;
    if (a.blindkey) return a.blindkey;
  });
  lazy.prop(o, 'confidentialAddress', () => {
    if (!o.address) return;
    if (!o.blindkey) return;
    const payload = bs58check_1.default.decode(o.address);
    const confidentialAddress = Buffer.concat([
      Buffer.from([network.confidentialPrefix, payload.readUInt8(0)]),
      o.blindkey,
      Buffer.from(payload.slice(1)),
    ]);
    return bs58check_1.default.encode(confidentialAddress);
  });
  // extended validation
  if (opts.validate) {
    let hash = Buffer.from([]);
    let blindkey = Buffer.from([]);
    if (a.address) {
      if (_address().version !== network.pubKeyHash)
        throw new TypeError('Invalid version or Network mismatch');
      if (_address().hash.length !== 20) throw new TypeError('Invalid address');
      hash = _address().hash;
    }
    if (a.hash) {
      if (hash.length > 0 && !hash.equals(a.hash))
        throw new TypeError('Hash mismatch');
      else hash = a.hash;
    }
    if (a.output) {
      if (
        a.output.length !== 25 ||
        a.output[0] !== OPS.OP_DUP ||
        a.output[1] !== OPS.OP_HASH160 ||
        a.output[2] !== 0x14 ||
        a.output[23] !== OPS.OP_EQUALVERIFY ||
        a.output[24] !== OPS.OP_CHECKSIG
      )
        throw new TypeError('Output is invalid');
      const hash2 = a.output.slice(3, 23);
      if (hash.length > 0 && !hash.equals(hash2))
        throw new TypeError('Hash mismatch');
      else hash = hash2;
    }
    if (a.pubkey) {
      const pkh = bcrypto.hash160(a.pubkey);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
      else hash = pkh;
    }
    if (a.input) {
      const chunks = _chunks();
      if (chunks.length !== 2) throw new TypeError('Input is invalid');
      if (!bscript.isCanonicalScriptSignature(chunks[0]))
        throw new TypeError('Input has invalid signature');
      if (!(0, types_1.isPoint)(chunks[1]))
        throw new TypeError('Input has invalid pubkey');
      if (a.signature && !a.signature.equals(chunks[0]))
        throw new TypeError('Signature mismatch');
      if (a.pubkey && !a.pubkey.equals(chunks[1]))
        throw new TypeError('Pubkey mismatch');
      const pkh = bcrypto.hash160(chunks[1]);
      if (hash.length > 0 && !hash.equals(pkh))
        throw new TypeError('Hash mismatch');
    }
    if (a.confidentialAddress) {
      if (
        a.address &&
        a.address !== _confidentialAddress().unconfidentialAddress
      )
        throw new TypeError('Address mismatch');
      if (
        blindkey.length > 0 &&
        !blindkey.equals(_confidentialAddress().blindkey)
      )
        throw new TypeError('Blindkey mismatch');
      else blindkey = _confidentialAddress().blindkey;
    }
    if (a.blindkey) {
      if (!(0, types_1.isPoint)(a.blindkey))
        throw new TypeError('Blindkey is invalid');
      if (blindkey.length > 0 && !blindkey.equals(a.blindkey))
        throw new TypeError('Blindkey mismatch');
      else blindkey = a.blindkey;
    }
  }
  return Object.assign(o, a);
}
exports.p2pkh = p2pkh;
