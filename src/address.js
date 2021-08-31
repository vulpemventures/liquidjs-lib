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
var __importDefault =
  (this && this.__importDefault) ||
  function(mod) {
    return mod && mod.__esModule ? mod : { default: mod };
  };
Object.defineProperty(exports, '__esModule', { value: true });
const networks = __importStar(require('./networks'));
const payments = __importStar(require('./payments'));
const bscript = __importStar(require('./script'));
const types = __importStar(require('./types'));
const blech32_1 = require('blech32');
const bech32_1 = __importDefault(require('bech32'));
const bs58check_1 = __importDefault(require('bs58check'));
const typeforce = require('typeforce');
// negative value for confidential types
var AddressType;
(function(AddressType) {
  AddressType[(AddressType['P2Pkh'] = 0)] = 'P2Pkh';
  AddressType[(AddressType['P2Sh'] = 1)] = 'P2Sh';
  AddressType[(AddressType['P2Wpkh'] = 2)] = 'P2Wpkh';
  AddressType[(AddressType['P2Wsh'] = 3)] = 'P2Wsh';
  AddressType[(AddressType['ConfidentialP2Pkh'] = 4)] = 'ConfidentialP2Pkh';
  AddressType[(AddressType['ConfidentialP2Sh'] = 5)] = 'ConfidentialP2Sh';
  AddressType[(AddressType['ConfidentialP2Wpkh'] = 6)] = 'ConfidentialP2Wpkh';
  AddressType[(AddressType['ConfidentialP2Wsh'] = 7)] = 'ConfidentialP2Wsh';
})(AddressType || (AddressType = {}));
function isConfidentialAddressType(addressType) {
  return addressType >= 4;
}
function fromBase58Check(address) {
  const payload = bs58check_1.default.decode(address);
  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < 21) throw new TypeError(address + ' is too short');
  if (payload.length > 21) throw new TypeError(address + ' is too long');
  const version = payload.readUInt8(0);
  const hash = payload.slice(1);
  return { version, hash };
}
exports.fromBase58Check = fromBase58Check;
function fromBech32(address) {
  const result = bech32_1.default.decode(address);
  const data = bech32_1.default.fromWords(result.words.slice(1));
  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer.from(data),
  };
}
exports.fromBech32 = fromBech32;
function fromBlech32(address) {
  const result = blech32_1.Blech32Address.fromString(address);
  const pubkey = Buffer.from(result.blindingPublicKey, 'hex');
  const prg = Buffer.from(result.witness, 'hex');
  const data = Buffer.concat([
    Buffer.from([result.witnessVersion, prg.length]),
    prg,
  ]);
  return {
    version: result.witnessVersion,
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
  return bs58check_1.default.encode(payload);
}
exports.toBase58Check = toBase58Check;
function toBech32(data, version, prefix) {
  const words = bech32_1.default.toWords(data);
  words.unshift(version);
  return bech32_1.default.encode(prefix, words);
}
exports.toBech32 = toBech32;
function toBlech32(data, pubkey, prefix) {
  return blech32_1.Blech32Address.from(
    data.slice(2).toString('hex'),
    pubkey.toString('hex'),
    prefix,
  ).address;
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
  let decodeBase58result;
  let decodeBech32result;
  let decodeConfidentialresult;
  try {
    decodeBase58result = fromBase58Check(address);
  } catch (e) {}
  if (decodeBase58result) {
    if (decodeBase58result.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodeBase58result.hash }).output;
    if (decodeBase58result.version === network.scriptHash)
      return payments.p2sh({ hash: decodeBase58result.hash }).output;
  } else {
    try {
      decodeBech32result = fromBech32(address);
    } catch (e) {}
    if (decodeBech32result) {
      if (decodeBech32result.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodeBech32result.version === 0) {
        if (decodeBech32result.data.length === 20)
          return payments.p2wpkh({ hash: decodeBech32result.data }).output;
        if (decodeBech32result.data.length === 32)
          return payments.p2wsh({ hash: decodeBech32result.data }).output;
      }
    } else {
      try {
        decodeConfidentialresult = fromConfidential(address);
      } catch (e) {}
      if (decodeConfidentialresult) {
        return toOutputScript(
          decodeConfidentialresult.unconfidentialAddress,
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
  const payload = bs58check_1.default.decode(address);
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
  const payload = bs58check_1.default.decode(address);
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
  const versionBuf = Buffer.alloc(1);
  versionBuf[0] = prefix;
  const unconfidentialAddressBuffer = Buffer.concat([
    versionBuf,
    unconfidential,
  ]);
  const unconfidentialAddress = bs58check_1.default.encode(
    unconfidentialAddressBuffer,
  );
  return { blindingKey, unconfidentialAddress };
}
function fromConfidentialSegwit(address, network) {
  const result = fromBlech32(address);
  const unconfidentialAddress = fromOutputScript(result.data, network);
  return { blindingKey: result.pubkey, unconfidentialAddress };
}
function toConfidentialLegacy(address, blindingKey, network) {
  const payload = bs58check_1.default.decode(address);
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
  const prefixBuf = Buffer.alloc(2);
  prefixBuf[0] = network.confidentialPrefix;
  prefixBuf[1] = prefix;
  const confidentialAddress = Buffer.concat([
    prefixBuf,
    blindingKey,
    Buffer.from(payload.slice(1)),
  ]);
  return bs58check_1.default.encode(confidentialAddress);
}
function toConfidentialSegwit(address, blindingKey, network) {
  const data = toOutputScript(address, network);
  return toBlech32(data, blindingKey, network.blech32);
}
function isBlech32(address, network) {
  return address.startsWith(network.blech32);
}
function decodeBlech32(address) {
  const blech32addr = fromBlech32(address);
  switch (blech32addr.data.length) {
    case 20:
      return AddressType.ConfidentialP2Wpkh;
    case 32:
      return AddressType.ConfidentialP2Wsh;
    default:
      throw new Error('invalid program length');
  }
}
function isBech32(address, network) {
  return address.startsWith(network.bech32);
}
function decodeBech32(address) {
  const bech32addr = fromBech32(address);
  switch (bech32addr.data.length) {
    case 20:
      return AddressType.P2Wpkh;
    case 32:
      return AddressType.P2Wsh;
    default:
      throw new Error('invalid program length');
  }
}
function UnkownPrefixError(prefix, network) {
  return new Error(
    `unknown address prefix (${prefix}), need ${network.pubKeyHash} or ${
      network.scriptHash
    }`,
  );
}
function decodeBase58(address, network) {
  const payload = bs58check_1.default.decode(address);
  // Blinded decoded haddress has the form:
  // BLIND_PREFIX|ADDRESS_PREFIX|BLINDING_KEY|SCRIPT_HASH
  // Prefixes are 1 byte long, thus blinding key always starts at 3rd byte
  const prefix = payload.readUInt8(1);
  if (payload.readUInt8(0) === network.confidentialPrefix) {
    const unconfidentialPart = payload.slice(35); // ignore the blinding key
    if (unconfidentialPart.length !== 20) {
      // ripem160 hash size
      throw new Error('decoded address is of unknown size');
    }
    switch (prefix) {
      case network.pubKeyHash:
        return AddressType.ConfidentialP2Pkh;
      case network.scriptHash:
        return AddressType.ConfidentialP2Sh;
      default:
        throw UnkownPrefixError(prefix, network);
    }
  }
  // unconf case
  const unconfidential = payload.slice(2);
  if (unconfidential.length !== 20) {
    // ripem160 hash size
    throw new Error('decoded address is of unknown size');
  }
  switch (prefix) {
    case network.pubKeyHash:
      return AddressType.P2Pkh;
    case network.scriptHash:
      return AddressType.P2Sh;
    default:
      throw UnkownPrefixError(prefix, network);
  }
}
function decodeType(address, network) {
  network = network || getNetwork(address);
  if (isBech32(address, network)) {
    return decodeBech32(address);
  }
  if (isBlech32(address, network)) {
    return decodeBlech32(address);
  }
  return decodeBase58(address, network);
}
exports.decodeType = decodeType;
/**
 * A quick check used to verify if a string could be a valid confidential address.
 * @param address address to check.
 */
function isConfidential(address) {
  const type = decodeType(address);
  return isConfidentialAddressType(type);
}
exports.isConfidential = isConfidential;
