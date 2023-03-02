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
exports.randomBytes =
  exports.pubkeyPositionInScript =
  exports.isP2TR =
  exports.isP2SH =
  exports.isP2WSH =
  exports.isP2WPKH =
  exports.isP2PKH =
  exports.isP2PK =
  exports.isP2MS =
  exports.classifyScript =
  exports.scriptWitnessToWitnessStack =
  exports.witnessStackToScriptWitness =
  exports.hasSigs =
  exports.getPayment =
    void 0;
const randombytes = __importStar(require('randombytes'));
const __1 = require('..');
const bufferutils_1 = require('../bufferutils');
const crypto_1 = require('../crypto');
const ops_1 = require('../ops');
const bscript = __importStar(require('../script'));
function getPayment(script, scriptType, partialSig) {
  switch (scriptType) {
    case 'multisig':
      const sigs = getSortedSigs(script, partialSig);
      return __1.payments.p2ms({
        output: script,
        signatures: sigs,
      });
    case 'pubkey':
      return __1.payments.p2pk({
        output: script,
        signature: partialSig[0].signature,
      });
    case 'pubkeyhash':
      return __1.payments.p2pkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
    case 'witnesspubkeyhash':
      return __1.payments.p2wpkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
    default:
      throw new Error('unknown script');
  }
}
exports.getPayment = getPayment;
function hasSigs(neededSigs, partialSig, pubkeys) {
  if (!partialSig) return false;
  let sigs;
  if (pubkeys) {
    sigs = pubkeys
      .map((pkey) => {
        const pubkey = compressPubkey(pkey);
        return partialSig.find((pSig) => pSig.pubkey.equals(pubkey));
      })
      .filter((v) => !!v);
  } else {
    sigs = partialSig;
  }
  if (sigs.length > neededSigs) throw new Error('Too many signatures');
  return sigs.length === neededSigs;
}
exports.hasSigs = hasSigs;
function getSortedSigs(script, partialSig) {
  const p2ms = __1.payments.p2ms({ output: script });
  // for each pubkey in order of p2ms script
  return p2ms.pubkeys
    .map((pk) => {
      // filter partialSig array by pubkey being equal
      return (
        partialSig.filter((ps) => {
          return ps.pubkey.equals(pk);
        })[0] || {}
      ).signature;
      // Any pubkey without a match will return undefined
      // this last filter removes all the undefined items in the array.
    })
    .filter((v) => !!v);
}
function witnessStackToScriptWitness(witness) {
  let buffer = Buffer.allocUnsafe(0);
  function writeSlice(slice) {
    buffer = Buffer.concat([buffer, Buffer.from(slice)]);
  }
  function writeVarInt(i) {
    const currentLen = buffer.length;
    const varintLen = bufferutils_1.varuint.encodingLength(i);
    buffer = Buffer.concat([buffer, Buffer.allocUnsafe(varintLen)]);
    bufferutils_1.varuint.encode(i, buffer, currentLen);
  }
  function writeVarSlice(slice) {
    writeVarInt(slice.length);
    writeSlice(slice);
  }
  function writeVector(vector) {
    writeVarInt(vector.length);
    vector.forEach(writeVarSlice);
  }
  writeVector(witness);
  return buffer;
}
exports.witnessStackToScriptWitness = witnessStackToScriptWitness;
function scriptWitnessToWitnessStack(buffer) {
  let offset = 0;
  function readSlice(n) {
    offset += n;
    return buffer.slice(offset - n, offset);
  }
  function readVarInt() {
    const vi = bufferutils_1.varuint.decode(buffer, offset);
    offset += bufferutils_1.varuint.decode.bytes;
    return vi;
  }
  function readVarSlice() {
    return readSlice(readVarInt());
  }
  function readVector() {
    const count = readVarInt();
    const vector = [];
    for (let i = 0; i < count; i++) vector.push(readVarSlice());
    return vector;
  }
  return readVector();
}
exports.scriptWitnessToWitnessStack = scriptWitnessToWitnessStack;
function compressPubkey(pubkey) {
  if (pubkey.length === 65) {
    const parity = pubkey[64] & 1;
    const newKey = pubkey.slice(0, 33);
    newKey[0] = 2 | parity;
    return newKey;
  }
  return pubkey.slice();
}
function classifyScript(script) {
  if ((0, exports.isP2WPKH)(script)) return 'witnesspubkeyhash';
  if ((0, exports.isP2PKH)(script)) return 'pubkeyhash';
  if ((0, exports.isP2MS)(script)) return 'multisig';
  if ((0, exports.isP2PK)(script)) return 'pubkey';
  return 'nonstandard';
}
exports.classifyScript = classifyScript;
function isPaymentFactory(payment) {
  return (script) => {
    try {
      payment({ output: script });
      return true;
    } catch (err) {
      return false;
    }
  };
}
exports.isP2MS = isPaymentFactory(__1.payments.p2ms);
exports.isP2PK = isPaymentFactory(__1.payments.p2pk);
exports.isP2PKH = isPaymentFactory(__1.payments.p2pkh);
exports.isP2WPKH = isPaymentFactory(__1.payments.p2wpkh);
exports.isP2WSH = isPaymentFactory(__1.payments.p2wsh);
exports.isP2SH = isPaymentFactory(__1.payments.p2sh);
// TODO: use payment factory once in place. For now, let's check
// if the script starts with OP_1.
const isP2TR = (script) => script[0] === ops_1.OPS.OP_1;
exports.isP2TR = isP2TR;
function pubkeyPositionInScript(pubkey, script) {
  const pubkeyHash = (0, crypto_1.hash160)(pubkey);
  const pubkeyXOnly = pubkey.slice(1, 33); // slice before calling?
  const decompiled = bscript.decompile(script);
  if (decompiled === null) throw new Error('Unknown script error');
  return decompiled.findIndex((element) => {
    if (typeof element === 'number') return false;
    return (
      element.equals(pubkey) ||
      element.equals(pubkeyHash) ||
      element.equals(pubkeyXOnly)
    );
  });
}
exports.pubkeyPositionInScript = pubkeyPositionInScript;
function randomBytes(options) {
  if (options === undefined) options = {};
  const rng = options.rng || randombytes.default;
  return rng(32);
}
exports.randomBytes = randomBytes;
