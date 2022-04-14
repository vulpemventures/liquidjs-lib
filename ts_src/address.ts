import { Network } from './networks';
import * as networks from './networks';
import * as payments from './payments';
import * as bscript from './script';
import * as types from './types';
import { BLECH32, Blech32Address, BLECH32M } from 'blech32';
import { bech32, bech32m } from 'bech32';
import * as bs58check from 'bs58check';
const { typeforce } = types;

export interface Base58CheckResult {
  hash: Buffer;
  version: number;
}

export interface Bech32Result {
  version: number;
  prefix: string;
  data: Buffer;
}

export interface Blech32Result {
  version: number;
  pubkey: Buffer;
  data: Buffer;
}

export interface ConfidentialResult {
  blindingKey: Buffer;
  unconfidentialAddress: string;
}

const FUTURE_SEGWIT_MAX_SIZE: number = 40;
const FUTURE_SEGWIT_MIN_SIZE: number = 2;
const FUTURE_SEGWIT_MAX_VERSION: number = 16;
const FUTURE_SEGWIT_MIN_VERSION: number = 1;
const FUTURE_SEGWIT_VERSION_DIFF: number = 0x50;
const FUTURE_SEGWIT_VERSION_WARNING: string =
  'WARNING: Sending to a future segwit version address can lead to loss of funds. ' +
  'End users MUST be warned carefully in the GUI and asked if they wish to proceed ' +
  'with caution. Wallets should verify the segwit version from the output of fromBech32, ' +
  'then decide when it is safe to use which version of segwit.';

function _toFutureSegwitAddress(output: Buffer, network: Network): string {
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

  console.warn(FUTURE_SEGWIT_VERSION_WARNING);

  return toBech32(data, version, network.bech32);
}

// negative value for confidential types
enum AddressType {
  P2Pkh = 0,
  P2Sh = 1,
  P2Wpkh = 2,
  P2Wsh = 3,
  ConfidentialP2Pkh = 4, // confidential types MUST be > 4
  ConfidentialP2Sh,
  ConfidentialP2Wpkh,
  ConfidentialP2Wsh,
}

function isConfidentialAddressType(addressType: AddressType): boolean {
  return addressType >= 4;
}

export function fromBase58Check(address: string): Base58CheckResult {
  const payload = bs58check.decode(address);

  // TODO: 4.0.0, move to "toOutputScript"
  if (payload.length < 21) throw new TypeError(address + ' is too short');
  if (payload.length > 21) throw new TypeError(address + ' is too long');

  const version = payload.readUInt8(0);
  const hash = payload.slice(1);

  return { version, hash };
}

export function fromBech32(address: string): Bech32Result {
  let result;
  let version;
  try {
    result = bech32.decode(address);
  } catch (e) {}

  if (result) {
    version = result.words[0];
    if (version !== 0) throw new TypeError(address + ' uses wrong encoding');
  } else {
    result = bech32m.decode(address);
    version = result.words[0];
    if (version === 0) throw new TypeError(address + ' uses wrong encoding');
  }

  const data = bech32.fromWords(result.words.slice(1));

  return {
    version,
    prefix: result.prefix,
    data: Buffer.from(data),
  };
}

export function fromBlech32(address: string): Blech32Result {
  let result: Blech32Address;
  try {
    result = Blech32Address.fromString(address, BLECH32);
  } catch {
    result = Blech32Address.fromString(address, BLECH32M);
  }

  const pubkey = Buffer.from(result.blindingPublicKey, 'hex');
  const prg = Buffer.from(result.witness, 'hex');
  const data = Buffer.concat([
    Buffer.from([
      result.witnessVersion
        ? result.witnessVersion + 0x50
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

export function fromConfidential(address: string): ConfidentialResult {
  const network = getNetwork(address);

  if (address.startsWith(network.blech32))
    return fromConfidentialSegwit(address, network);

  return fromConfidentialLegacy(address, network);
}

export function toBase58Check(hash: Buffer, version: number): string {
  typeforce(types.tuple(types.Hash160bit, types.UInt8), arguments);

  const payload = Buffer.allocUnsafe(21);
  payload.writeUInt8(version, 0);
  hash.copy(payload, 1);

  return bs58check.encode(payload);
}

export function toBech32(
  data: Buffer,
  version: number,
  prefix: string,
): string {
  const words = bech32.toWords(data);
  words.unshift(version);

  return version === 0
    ? bech32.encode(prefix, words)
    : bech32m.encode(prefix, words);
}

export function toBlech32(
  data: Buffer,
  pubkey: Buffer,
  prefix: string,
  witnessVersion: number,
): string {
  return Blech32Address.from(
    data.slice(2).toString('hex'),
    pubkey.toString('hex'),
    prefix,
    witnessVersion,
  ).address;
}

export function toConfidential(address: string, blindingKey: Buffer): string {
  const network = getNetwork(address);

  if (address.startsWith(network.bech32))
    return toConfidentialSegwit(address, blindingKey, network);

  return toConfidentialLegacy(address, blindingKey, network);
}

export function fromOutputScript(output: Buffer, network?: Network): string {
  // TODO: Network
  network = network || networks.liquid;

  try {
    return payments.p2pkh({ output, network }).address as string;
  } catch (e) {}
  try {
    return payments.p2sh({ output, network }).address as string;
  } catch (e) {}
  try {
    return payments.p2wpkh({ output, network }).address as string;
  } catch (e) {}
  try {
    return payments.p2wsh({ output, network }).address as string;
  } catch (e) {}
  try {
    return _toFutureSegwitAddress(output, network);
  } catch (e) {}

  throw new Error(bscript.toASM(output) + ' has no matching Address');
}

export function toOutputScript(address: string, network?: Network): Buffer {
  network = network || getNetwork(address);

  let decodedBase58: Base58CheckResult | undefined;
  let decodedBech32: Bech32Result | undefined;
  let decodedConfidential: ConfidentialResult | undefined;

  try {
    decodedBase58 = fromBase58Check(address);
  } catch (e) {}

  if (decodedBase58) {
    if (decodedBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodedBase58.hash }).output as Buffer;
    if (decodedBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodedBase58.hash }).output as Buffer;
  } else {
    try {
      decodedBech32 = fromBech32(address);
    } catch (e) {}

    if (decodedBech32) {
      if (decodedBech32.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodedBech32.version === 0) {
        if (decodedBech32.data.length === 20)
          return payments.p2wpkh({ hash: decodedBech32.data }).output as Buffer;
        if (decodedBech32.data.length === 32)
          return payments.p2wsh({ hash: decodedBech32.data }).output as Buffer;
      } else if (
        decodedBech32.version >= FUTURE_SEGWIT_MIN_VERSION &&
        decodedBech32.version <= FUTURE_SEGWIT_MAX_VERSION &&
        decodedBech32.data.length >= FUTURE_SEGWIT_MIN_SIZE &&
        decodedBech32.data.length <= FUTURE_SEGWIT_MAX_SIZE
      ) {
        console.warn(FUTURE_SEGWIT_VERSION_WARNING);

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

function isNetwork(network: Network, address: string): boolean {
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
export function getNetwork(address: string): Network {
  const allNetworks = [networks.liquid, networks.regtest, networks.testnet];

  for (const network of allNetworks) {
    if (isNetwork(network, address)) return network;
  }

  throw new Error(address + ' has an invalid prefix');
}

function fromConfidentialLegacy(
  address: string,
  network: Network,
): ConfidentialResult {
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
  const versionBuf = Buffer.alloc(1);
  versionBuf[0] = prefix;
  const unconfidentialAddressBuffer = Buffer.concat([
    versionBuf,
    unconfidential,
  ]);
  const unconfidentialAddress = bs58check.encode(unconfidentialAddressBuffer);

  return { blindingKey, unconfidentialAddress };
}

function fromConfidentialSegwit(
  address: string,
  network: Network,
): ConfidentialResult {
  const result = fromBlech32(address);
  const unconfidentialAddress = fromOutputScript(result.data, network);
  return { blindingKey: result.pubkey, unconfidentialAddress };
}

function toConfidentialLegacy(
  address: string,
  blindingKey: Buffer,
  network: Network,
): string {
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

function toConfidentialSegwit(
  address: string,
  blindingKey: Buffer,
  network: Network,
): string {
  const data = toOutputScript(address, network);
  const version = fromBech32(address).version;
  return toBlech32(data, blindingKey, network.blech32, version);
}

function isBlech32(address: string, network: Network): boolean {
  return address.startsWith(network.blech32);
}

function decodeBlech32(address: string): AddressType {
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

function isBech32(address: string, network: Network): boolean {
  return address.startsWith(network.bech32);
}

function decodeBech32(address: string): AddressType {
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

function UnkownPrefixError(prefix: number, network: Network): Error {
  return new Error(
    `unknown address prefix (${prefix}), need ${network.pubKeyHash} or ${
      network.scriptHash
    }`,
  );
}

function decodeBase58(address: string, network: Network): AddressType {
  const payload = bs58check.decode(address);

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

export function decodeType(address: string, network?: Network): AddressType {
  network = network || getNetwork(address);

  if (isBech32(address, network)) {
    return decodeBech32(address);
  }

  if (isBlech32(address, network)) {
    return decodeBlech32(address);
  }

  return decodeBase58(address, network);
}

/**
 * A quick check used to verify if a string could be a valid confidential address.
 * @param address address to check.
 */
export function isConfidential(address: string): boolean {
  const type = decodeType(address);
  return isConfidentialAddressType(type);
}
