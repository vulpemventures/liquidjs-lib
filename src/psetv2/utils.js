'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.isP2SH = exports.isP2WSH = exports.isP2WPKH = exports.isP2PKH = exports.isP2PK = exports.isP2MS = exports.classifyScript = exports.scriptWitnessToWitnessStack = exports.witnessStackToScriptWitness = exports.hasSigs = exports.getPayment = void 0;
const __1 = require('..');
const bufferutils_1 = require('../bufferutils');
function getPayment(script, scriptType, partialSig) {
  let payment;
  switch (scriptType) {
    case 'multisig':
      const sigs = getSortedSigs(script, partialSig);
      payment = __1.payments.p2ms({
        output: script,
        signatures: sigs,
      });
      break;
    case 'pubkey':
      payment = __1.payments.p2pk({
        output: script,
        signature: partialSig[0].signature,
      });
      break;
    case 'pubkeyhash':
      payment = __1.payments.p2pkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
      break;
    case 'witnesspubkeyhash':
      payment = __1.payments.p2wpkh({
        output: script,
        pubkey: partialSig[0].pubkey,
        signature: partialSig[0].signature,
      });
      break;
  }
  return payment;
}
exports.getPayment = getPayment;
function hasSigs(neededSigs, partialSig, pubkeys) {
  if (!partialSig) return false;
  let sigs;
  if (pubkeys) {
    sigs = pubkeys
      .map(pkey => {
        const pubkey = compressPubkey(pkey);
        return partialSig.find(pSig => pSig.pubkey.equals(pubkey));
      })
      .filter(v => !!v);
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
    .map(pk => {
      // filter partialSig array by pubkey being equal
      return (
        partialSig.filter(ps => {
          return ps.pubkey.equals(pk);
        })[0] || {}
      ).signature;
      // Any pubkey without a match will return undefined
      // this last filter removes all the undefined items in the array.
    })
    .filter(v => !!v);
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
  return script => {
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
