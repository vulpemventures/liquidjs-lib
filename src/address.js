'use strict';
var __importStar =
  (this && this.__importStar) ||
  function(mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result['default'] = mod;
    return result;
  };
Object.defineProperty(exports, '__esModule', { value: true });
const networks = __importStar(require('./networks'));
const payments = __importStar(require('./payments'));
const bscript = __importStar(require('./script'));
const types = __importStar(require('./types'));
const bech32 = require('bech32');
const blech32 = require('blech32');
const bs58check = require('bs58check');
const typeforce = require('typeforce');
function fromBase58Check(address) {
  const payload = bs58check.decode(address);
  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < 21) throw new TypeError(address + ' is too short');
  if (payload.length > 21) throw new TypeError(address + ' is too long');
  const version = payload.readUInt8(0);
  const hash = payload.slice(1);
  return { version, hash };
}
exports.fromBase58Check = fromBase58Check;
function fromBech32(address) {
  const result = bech32.decode(address);
  const data = bech32.fromWords(result.words.slice(1));
  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer.from(data),
  };
}
exports.fromBech32 = fromBech32;
function fromBlech32(address) {
  const prefix = address.substring(0, 2);
  const result = blech32.decode(prefix, address);
  const pubkey = result.words.slice(0, 33);
  const prg = result.words.slice(33);
  const data = Buffer.concat([Buffer.from([result.version, prg.length]), prg]);
  return {
    version: result.version,
    pubkey,
    data,
  };
}
exports.fromBlech32 = fromBlech32;
function fromConfidential(address) {
  const network = getNetwork(address);
  if (address.startsWith(network.blech32))
    return fromConfidentialSegwit(address, network);
  return fromConfidentialLegacy(address, network);
}
exports.fromConfidential = fromConfidential;
function toBase58Check(hash, version) {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments);
  const payload = Buffer.allocUnsafe(21);
  payload.writeUInt8(version, 0);
  hash.copy(payload, 1);
  return bs58check.encode(payload);
}
exports.toBase58Check = toBase58Check;
function toBech32(data, version, prefix) {
  const words = bech32.toWords(data);
  words.unshift(version);
  return bech32.encode(prefix, words);
}
exports.toBech32 = toBech32;
function toBlech32(data, pubkey, prefix) {
  const words = Buffer.concat([pubkey, data.slice(2)]);
  return blech32.encode(prefix, words);
}
exports.toBlech32 = toBlech32;
function toConfidential(address, blindingKey) {
  const network = getNetwork(address);
  if (address.startsWith(network.bech32))
    return toConfidentialSegwit(address, blindingKey, network);
  return toConfidentialLegacy(address, blindingKey, network);
}
exports.toConfidential = toConfidential;
function fromOutputScript(output, network) {
  // TODO: Network
  network = network || networks.liquid;
  try {
    return payments.p2pkh({ output, network }).address;
  } catch (e) {}
  try {
    return payments.p2sh({ output, network }).address;
  } catch (e) {}
  try {
    return payments.p2wpkh({ output, network }).address;
  } catch (e) {}
  try {
    return payments.p2wsh({ output, network }).address;
  } catch (e) {}
  throw new Error(bscript.toASM(output) + ' has no matching Address');
}
exports.fromOutputScript = fromOutputScript;
function toOutputScript(address, network) {
  network = network || getNetwork(address);
  let decodeBase58;
  let decodeBech32;
  let decodeConfidential;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}
  if (decodeBase58) {
    if (decodeBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodeBase58.hash }).output;
    if (decodeBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodeBase58.hash }).output;
  } else {
    try {
      decodeBech32 = fromBech32(address);
    } catch (e) {}
    if (decodeBech32) {
      if (decodeBech32.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodeBech32.version === 0) {
        if (decodeBech32.data.length === 20)
          return payments.p2wpkh({ hash: decodeBech32.data }).output;
        if (decodeBech32.data.length === 32)
          return payments.p2wsh({ hash: decodeBech32.data }).output;
      }
    } else {
      try {
        decodeConfidential = fromConfidential(address);
      } catch (e) {}
      if (decodeConfidential) {
        return toOutputScript(
          decodeConfidential.unconfidentialAddress,
          network,
        );
      }
    }
  }
  throw new Error(address + ' has no matching Script');
}
exports.toOutputScript = toOutputScript;
function getNetwork(address) {
  if (
    address.startsWith(networks.liquid.blech32) ||
    address.startsWith(networks.liquid.bech32)
  )
    return networks.liquid;
  if (
    address.startsWith(networks.regtest.blech32) ||
    address.startsWith(networks.regtest.bech32)
  )
    return networks.regtest;
  const payload = bs58check.decode(address);
  const prefix = payload.readUInt8(0);
  if (
    prefix === networks.liquid.confidentialPrefix ||
    prefix === networks.liquid.pubKeyHash ||
    prefix === networks.liquid.scriptHash
  )
    return networks.liquid;
  if (
    prefix === networks.regtest.confidentialPrefix ||
    prefix === networks.regtest.pubKeyHash ||
    prefix === networks.regtest.scriptHash
  )
    return networks.regtest;
  throw new Error(address + ' has an invalid prefix');
}
exports.getNetwork = getNetwork;
function fromConfidentialLegacy(address, network) {
  const payload = bs58check.decode(address);
  const prefix = payload.readUInt8(1);
  // Check if address has valid length and prefix
  if (prefix !== network.pubKeyHash && prefix !== network.scriptHash)
    throw new TypeError(address + 'is not valid');
  if (payload.length < 55) throw new TypeError(address + ' is too short');
  if (payload.length > 55) throw new TypeError(address + ' is too long');
  // Blinded decoded haddress has the form:
  // BLIND_PREFIX|ADDRESS_PREFIX|BLINDING_KEY|SCRIPT_HASH
  // Prefixes are 1 byte long, thus blinding key always starts at 3rd byte
  const blindingKey = payload.slice(2, 35);
  const unconfidential = payload.slice(35, payload.length);
  const versionBuf = new Uint8Array(1);
  versionBuf[0] = prefix;
  const unconfidentialAddressBuffer = Buffer.concat([
    versionBuf,
    unconfidential,
  ]);
  const unconfidentialAddress = bs58check.encode(unconfidentialAddressBuffer);
  return { blindingKey, unconfidentialAddress };
}
function fromConfidentialSegwit(address, network) {
  const result = fromBlech32(address);
  const unconfidentialAddress = fromOutputScript(result.data, network);
  return { blindingKey: result.pubkey, unconfidentialAddress };
}
function toConfidentialLegacy(address, blindingKey, network) {
  const payload = bs58check.decode(address);
  const prefix = payload.readUInt8(0);
  // Check if address has valid length and prefix
  if (
    payload.length !== 21 ||
    (prefix !== network.pubKeyHash && prefix !== network.scriptHash)
  )
    throw new TypeError(address + 'is not valid');
  // Check if blind key has valid length
  if (blindingKey.length < 33) throw new TypeError('Blinding key is too short');
  if (blindingKey.length > 33) throw new TypeError('Blinding key is too long');
  const prefixBuf = new Uint8Array(2);
  prefixBuf[0] = network.confidentialPrefix;
  prefixBuf[1] = prefix;
  const confidentialAddress = Buffer.concat([
    prefixBuf,
    blindingKey,
    Buffer.from(payload.slice(1)),
  ]);
  return bs58check.encode(confidentialAddress);
}
function toConfidentialSegwit(address, blindingKey, network) {
  const data = toOutputScript(address, network);
  return toBlech32(data, blindingKey, network.blech32);
}
