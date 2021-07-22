import { Network } from './networks';
import * as networks from './networks';
import * as payments from './payments';
import * as bscript from './script';
import * as types from './types';

import { Blech32Address } from 'blech32';

const bech32 = require('bech32');
const bs58check = require('bs58check');
const typeforce = require('typeforce');

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
  const result = bech32.decode(address);
  const data = bech32.fromWords(result.words.slice(1));

  return {
    version: result.words[0],
    prefix: result.prefix,
    data: Buffer.from(data),
  };
}

export function fromBlech32(address: string): Blech32Result {
  const result = Blech32Address.fromString(address);
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

  return bech32.encode(prefix, words);
}

export function toBlech32(
  data: Buffer,
  pubkey: Buffer,
  prefix: string,
): string {
  return Blech32Address.from(
    data.slice(2).toString('hex'),
    pubkey.toString('hex'),
    prefix,
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

  throw new Error(bscript.toASM(output) + ' has no matching Address');
}

export function toOutputScript(address: string, network?: Network): Buffer {
  network = network || getNetwork(address);

  let decodeBase58: Base58CheckResult | undefined;
  let decodeBech32: Bech32Result | undefined;
  let decodeConfidential: ConfidentialResult | undefined;
  try {
    decodeBase58 = fromBase58Check(address);
  } catch (e) {}

  if (decodeBase58) {
    if (decodeBase58.version === network.pubKeyHash)
      return payments.p2pkh({ hash: decodeBase58.hash }).output as Buffer;
    if (decodeBase58.version === network.scriptHash)
      return payments.p2sh({ hash: decodeBase58.hash }).output as Buffer;
  } else {
    try {
      decodeBech32 = fromBech32(address);
    } catch (e) {}

    if (decodeBech32) {
      if (decodeBech32.prefix !== network.bech32)
        throw new Error(address + ' has an invalid prefix');
      if (decodeBech32.version === 0) {
        if (decodeBech32.data.length === 20)
          return payments.p2wpkh({ hash: decodeBech32.data }).output as Buffer;
        if (decodeBech32.data.length === 32)
          return payments.p2wsh({ hash: decodeBech32.data }).output as Buffer;
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

export function getNetwork(address: string): Network {
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
  return toBlech32(data, blindingKey, network.blech32);
}
