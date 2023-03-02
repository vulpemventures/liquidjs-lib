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
exports.getScriptType =
  exports.isConfidential =
  exports.decodeType =
  exports.getNetwork =
  exports.toOutputScript =
  exports.fromOutputScript =
  exports.toConfidential =
  exports.toBlech32 =
  exports.toBech32 =
  exports.toBase58Check =
  exports.fromConfidential =
  exports.fromBlech32 =
  exports.fromBech32 =
  exports.fromBase58Check =
  exports.ScriptType =
  exports.AddressType =
    void 0;
const networks = __importStar(require('./networks'));
const payments = __importStar(require('./payments'));
const bscript = __importStar(require('./script'));
const types = __importStar(require('./types'));
const blech32_1 = require('blech32');
const bech32_1 = require('bech32');
const bs58check = __importStar(require('bs58check'));
const ops_1 = require('./ops');
const { typeforce } = types;
const FUTURE_SEGWIT_MAX_SIZE = 40;
const FUTURE_SEGWIT_MIN_SIZE = 2;
const FUTURE_SEGWIT_MAX_VERSION = 16;
const FUTURE_SEGWIT_MIN_VERSION = 1;
const FUTURE_SEGWIT_VERSION_DIFF = 0x50;
function _toFutureSegwitAddress(output, network) {
  const data = output.slice(2);
  if (
    data.length < FUTURE_SEGWIT_MIN_SIZE ||
    data.length > FUTURE_SEGWIT_MAX_SIZE
  )
    throw new TypeError('Invalid program length for segwit address');
  const version = output[0] - FUTURE_SEGWIT_VERSION_DIFF;
  if (
    version < FUTURE_SEGWIT_MIN_VERSION ||
    version > FUTURE_SEGWIT_MAX_VERSION
  )
    throw new TypeError('Invalid version for segwit address');
  if (output[1] !== data.length)
    throw new TypeError('Invalid script for segwit address');
  return toBech32(data, version, network.bech32);
}
// negative value for confidential types
var AddressType;
(function (AddressType) {
  AddressType[(AddressType['P2Pkh'] = 0)] = 'P2Pkh';
  AddressType[(AddressType['P2Sh'] = 1)] = 'P2Sh';
  AddressType[(AddressType['P2Wpkh'] = 2)] = 'P2Wpkh';
  AddressType[(AddressType['P2Wsh'] = 3)] = 'P2Wsh';
  AddressType[(AddressType['ConfidentialP2Pkh'] = 4)] = 'ConfidentialP2Pkh';
  AddressType[(AddressType['ConfidentialP2Sh'] = 5)] = 'ConfidentialP2Sh';
  AddressType[(AddressType['ConfidentialP2Wpkh'] = 6)] = 'ConfidentialP2Wpkh';
  AddressType[(AddressType['ConfidentialP2Wsh'] = 7)] = 'ConfidentialP2Wsh';
})((AddressType = exports.AddressType || (exports.AddressType = {})));
var ScriptType;
(function (ScriptType) {
  ScriptType[(ScriptType['P2Pkh'] = 0)] = 'P2Pkh';
  ScriptType[(ScriptType['P2Sh'] = 1)] = 'P2Sh';
  ScriptType[(ScriptType['P2Wpkh'] = 2)] = 'P2Wpkh';
  ScriptType[(ScriptType['P2Wsh'] = 3)] = 'P2Wsh';
  ScriptType[(ScriptType['P2Tr'] = 4)] = 'P2Tr';
})((ScriptType = exports.ScriptType || (exports.ScriptType = {})));
function isConfidentialAddressType(addressType) {
  return addressType >= 4;
}
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
  let result;
  let version;
  try {
    result = bech32_1.bech32.decode(address);
  } catch (e) {}
  if (result) {
    version = result.words[0];
    if (version !== 0) throw new TypeError(address + ' uses wrong encoding');
  } else {
    result = bech32_1.bech32m.decode(address);
    version = result.words[0];
    if (version === 0) throw new TypeError(address + ' uses wrong encoding');
  }
  const data = bech32_1.bech32.fromWords(result.words.slice(1));
  return {
    version,
    prefix: result.prefix,
    data: Buffer.from(data),
  };
}
exports.fromBech32 = fromBech32;
function fromBlech32(address) {
  let result;
  try {
    result = blech32_1.Blech32Address.fromString(address, blech32_1.BLECH32);
  } catch {
    result = blech32_1.Blech32Address.fromString(address, blech32_1.BLECH32M);
  }
  const pubkey = Buffer.from(result.blindingPublicKey, 'hex');
  const prg = Buffer.from(result.witness, 'hex');
  const data = Buffer.concat([
    Buffer.from([
      result.witnessVersion
        ? result.witnessVersion + FUTURE_SEGWIT_VERSION_DIFF
        : result.witnessVersion,
      prg.length,
    ]),
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
  return bs58check.encode(payload);
}
exports.toBase58Check = toBase58Check;
function toBech32(data, version, prefix) {
  const words = bech32_1.bech32.toWords(data);
  words.unshift(version);
  return version === 0
    ? bech32_1.bech32.encode(prefix, words)
    : bech32_1.bech32m.encode(prefix, words);
}
exports.toBech32 = toBech32;
function toBlech32(data, pubkey, prefix, witnessVersion) {
  return blech32_1.Blech32Address.from(
    data.slice(2).toString('hex'),
    pubkey.toString('hex'),
    prefix,
    witnessVersion,
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
  try {
    return _toFutureSegwitAddress(output, network);
  } catch (e) {}
  throw new Error(bscript.toASM(output) + ' has no matching Address');
}
exports.fromOutputScript = fromOutputScript;
function toOutputScript(address, network) {
  network = network || getNetwork(address);
  let decodedBase58;
  let decodedBech32;
  let decodedConfidential;
  try {
    decodedBase58 = fromBase58Check(address);
  } catch (e) {}
  if (decodedBase58) {
    if (decodedBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodedBase58.hash }).output;
    if (decodedBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodedBase58.hash }).output;
  } else {
    try {
      decodedBech32 = fromBech32(address);
    } catch (e) {}
    if (decodedBech32) {
      if (decodedBech32.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodedBech32.version === 0) {
        if (decodedBech32.data.length === 20)
          return payments.p2wpkh({ hash: decodedBech32.data }).output;
        if (decodedBech32.data.length === 32)
          return payments.p2wsh({ hash: decodedBech32.data }).output;
      } else if (
        decodedBech32.version >= FUTURE_SEGWIT_MIN_VERSION &&
        decodedBech32.version <= FUTURE_SEGWIT_MAX_VERSION &&
        decodedBech32.data.length >= FUTURE_SEGWIT_MIN_SIZE &&
        decodedBech32.data.length <= FUTURE_SEGWIT_MAX_SIZE
      ) {
        return bscript.compile([
          decodedBech32.version + FUTURE_SEGWIT_VERSION_DIFF,
          decodedBech32.data,
        ]);
      }
    } else {
      try {
        decodedConfidential = fromConfidential(address);
      } catch (e) {}
      if (decodedConfidential) {
        return toOutputScript(
          decodedConfidential.unconfidentialAddress,
          network,
        );
      }
    }
  }
  throw new Error(address + ' has no matching Script');
}
exports.toOutputScript = toOutputScript;
function isNetwork(network, address) {
  if (address.startsWith(network.blech32) || address.startsWith(network.bech32))
    return true;
  try {
    const payload = bs58check.decode(address);
    const prefix = payload.readUInt8(0);
    if (
      prefix === network.confidentialPrefix ||
      prefix === network.pubKeyHash ||
      prefix === network.scriptHash
    )
      return true;
  } catch {
    return false;
  }
  return false;
}
// determines the network of a given address
function getNetwork(address) {
  const allNetworks = [networks.liquid, networks.regtest, networks.testnet];
  for (const network of allNetworks) {
    if (isNetwork(network, address)) return network;
  }
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
  // Blinded decoded address has the form:
  // BLIND_PREFIX|ADDRESS_PREFIX|BLINDING_KEY|SCRIPT_HASH
  // Prefixes are 1 byte long, thus blinding key always starts at 3rd byte
  const blindingKey = payload.slice(2, 35);
  const scriptHash = payload.slice(35, payload.length);
  const versionBuf = Buffer.of(prefix);
  const scriptHashWithNetworkPrefix = Buffer.concat([versionBuf, scriptHash]);
  const unconfidentialAddress = bs58check.encode(scriptHashWithNetworkPrefix);
  const script = toOutputScript(unconfidentialAddress);
  return { blindingKey, unconfidentialAddress, scriptPubKey: script };
}
function fromConfidentialSegwit(address, network) {
  const result = fromBlech32(address);
  const unconfidentialAddress = fromOutputScript(result.data, network);
  return {
    blindingKey: result.pubkey,
    unconfidentialAddress,
    scriptPubKey: result.data,
  };
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
  const prefixBuf = Buffer.alloc(2);
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
  const version = fromBech32(address).version;
  return toBlech32(data, blindingKey, network.blech32, version);
}
function isBlech32(address, network) {
  return address.startsWith(network.blech32);
}
function decodeBlech32(address) {
  const blech32addr = fromBlech32(address);
  switch (blech32addr.data.length - 2) {
    case 20:
      return AddressType.ConfidentialP2Wpkh;
    case 32:
      return AddressType.ConfidentialP2Wsh;
    default:
      throw new Error(
        `invalid blech32 program length: ${blech32addr.data.length - 2}`,
      );
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
    `unknown address prefix (${prefix}), need ${network.pubKeyHash} or ${network.scriptHash}`,
  );
}
function decodeBase58(address, network) {
  const payload = bs58check.decode(address);
  // Blinded decoded haddress has the form:
  // BLIND_PREFIX|ADDRESS_PREFIX|BLINDING_KEY|SCRIPT_HASH
  // Prefixes are 1 byte long, thus blinding key always starts at 3rd byte
  if (payload.readUInt8(0) === network.confidentialPrefix) {
    const unconfidentialPart = payload.slice(35); // ignore the blinding key
    if (unconfidentialPart.length !== 20) {
      // ripem160 hash size
      throw new Error('decoded address is of unknown size');
    }
    const addrPrefix = payload.readUInt8(1);
    switch (addrPrefix) {
      case network.pubKeyHash:
        return AddressType.ConfidentialP2Pkh;
      case network.scriptHash:
        return AddressType.ConfidentialP2Sh;
      default:
        throw UnkownPrefixError(addrPrefix, network);
    }
  }
  // unconf case
  const prefix = payload.readUInt8(0);
  const unconfidential = payload.slice(1);
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
// GetScriptType returns the type of the given script (p2pkh, p2sh, etc.)
function getScriptType(script) {
  switch (script[0]) {
    case ops_1.OPS.OP_0:
      if (script.slice(2).length === 20) {
        return ScriptType.P2Wpkh;
      }
      return ScriptType.P2Wsh;
    case ops_1.OPS.OP_HASH160:
      return ScriptType.P2Sh;
    case ops_1.OPS.OP_DUP:
      return ScriptType.P2Pkh;
    case ops_1.OPS.OP_1:
      return ScriptType.P2Tr;
    default:
      throw new Error('unknow script type');
  }
}
exports.getScriptType = getScriptType;
