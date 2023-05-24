import { Buffer as NBuffer } from 'buffer';

export const typeforce = require('typeforce');

const ZERO32 = NBuffer.alloc(32, 0);
const EC_P = NBuffer.from(
  'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
  'hex',
);

export function isPoint(p: Buffer | number | undefined | null): boolean {
  if (!NBuffer.isBuffer(p)) return false;
  if (p.length < 33) return false;

  const t = p[0];
  const x = p.slice(1, 33);
  if (x.compare(ZERO32) === 0) return false;
  if (x.compare(EC_P) >= 0) return false;
  if ((t === 0x02 || t === 0x03) && p.length === 33) {
    return true;
  }

  const y = p.slice(33);
  if (y.compare(ZERO32) === 0) return false;
  if (y.compare(EC_P) >= 0) return false;
  if (t === 0x04 && p.length === 65) return true;
  return false;
}

const UINT31_MAX: number = Math.pow(2, 31) - 1;
export function UInt31(value: number): boolean {
  return typeforce.UInt32(value) && value <= UINT31_MAX;
}

export function BIP32Path(value: string): boolean {
  return typeforce.String(value) && !!value.match(/^(m\/)?(\d+'?\/)*\d+'?$/);
}
BIP32Path.toJSON = (): string => {
  return 'BIP32 derivation path';
};

export function Signer(obj: any): boolean {
  return (
    (typeforce.Buffer(obj.publicKey) ||
      typeof obj.getPublicKey === 'function') &&
    typeof obj.sign === 'function'
  );
}

const SATOSHI_MAX: number = 21 * 1e14;
export function Satoshi(value: number): boolean {
  return typeforce.UInt53(value) && value <= SATOSHI_MAX;
}

// external dependent types
export const ECPoint = typeforce.quacksLike('Point');

// exposed, external API
export const Network = typeforce.compile({
  messagePrefix: typeforce.oneOf(typeforce.Buffer, typeforce.String),
  bip32: {
    public: typeforce.UInt32,
    private: typeforce.UInt32,
  },
  pubKeyHash: typeforce.UInt8,
  scriptHash: typeforce.UInt8,
  wif: typeforce.UInt8,
  assetHash: typeforce.String,
  confidentialPrefix: typeforce.UInt8,
  name: typeforce.String,
});

export interface IssuanceBlindingKeys {
  assetKey?: Buffer;
  tokenKey?: Buffer;
}

export interface XOnlyPointAddTweakResult {
  parity: 1 | 0;
  xOnlyPubkey: Uint8Array;
}

export interface Tapleaf {
  output: Buffer;
  version?: number;
}

export const TAPLEAF_VERSION_MASK = 0xfe;
export function isTapleaf(o: any): o is Tapleaf {
  if (!o || !('output' in o)) return false;
  if (!NBuffer.isBuffer(o.output)) return false;
  if (o.version !== undefined)
    return (o.version & TAPLEAF_VERSION_MASK) === o.version;
  return true;
}

/**
 * Binary tree repsenting script path spends for a Taproot input.
 * Each node is either a single Tapleaf, or a pair of Tapleaf | Taptree.
 * The tree has no balancing requirements.
 */
export type Taptree = [Taptree | Tapleaf, Taptree | Tapleaf] | Tapleaf;

export function isTaptree(scriptTree: any): scriptTree is Taptree {
  if (!Array(scriptTree)) return isTapleaf(scriptTree);
  if (scriptTree.length !== 2) return false;
  return scriptTree.every((t: any) => isTaptree(t));
}

export interface TinySecp256k1Interface {
  isXOnlyPoint(p: Uint8Array): boolean;
  xOnlyPointAddTweak(
    p: Uint8Array,
    tweak: Uint8Array,
  ): XOnlyPointAddTweakResult | null;
  privateAdd(d: Uint8Array, tweak: Uint8Array): Uint8Array | null;
  privateNegate(d: Uint8Array): Uint8Array;
}

export const Buffer256bit = typeforce.BufferN(32);
export const Hash160bit = typeforce.BufferN(20);
export const Hash256bit = typeforce.BufferN(32);
export const ConfidentialCommitment = typeforce.BufferN(33);
export const AssetBufferWithFlag = typeforce.BufferN(33);
export const AssetBuffer = typeforce.BufferN(32);
export const ConfidentialValue = typeforce.BufferN(9);
export const BufferOne = typeforce.BufferN(1);
export const Number = typeforce.Number; // tslint:disable-line variable-name
export const Array = typeforce.Array;
export const Boolean = typeforce.Boolean; // tslint:disable-line variable-name
export const String = typeforce.String; // tslint:disable-line variable-name
export const Buffer = typeforce.Buffer;
export const Hex = typeforce.Hex;
export const Object = typeforce.Object;
export const maybe = typeforce.maybe;
export const tuple = typeforce.tuple;
export const UInt8 = typeforce.UInt8;
export const UInt32 = typeforce.UInt32;
export const Function = typeforce.Function;
export const BufferN = typeforce.BufferN;
export const Null = typeforce.Null;
export const oneOf = typeforce.oneOf;

export interface ConfidentialSecp256k1Interface {
  ecc: {
    privateNegate: (key: Uint8Array) => Uint8Array;
    privateAdd: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
    privateMul: (key: Uint8Array, tweak: Uint8Array) => Uint8Array;
  };
  ecdh: (pubkey: Uint8Array, scalar: Uint8Array) => Uint8Array;
  pedersen: {
    commitment(
      value: string,
      generator: Uint8Array,
      blinder: Uint8Array,
    ): Uint8Array;
    blindGeneratorBlindSum(
      values: Array<string>,
      assetBlinders: Array<Uint8Array>,
      valueBlinders: Array<Uint8Array>,
      nInputs: number,
    ): Uint8Array;
  };
  generator: {
    generate: (seed: Uint8Array) => Uint8Array;
    generateBlinded(key: Uint8Array, blinder: Uint8Array): Uint8Array;
  };
  rangeproof: {
    info(proof: Uint8Array): {
      exp: string;
      mantissa: string;
      minValue: string;
      maxValue: string;
    };
    verify(
      proof: Uint8Array,
      valueCommitment: Uint8Array,
      assetCommitment: Uint8Array,
      extraCommit?: Uint8Array,
    ): boolean;
    sign(
      value: string,
      valueCommitment: Uint8Array,
      assetCommitment: Uint8Array,
      valueBlinder: Uint8Array,
      nonce: Uint8Array,
      minValue?: string,
      base10Exp?: string,
      minBits?: string,
      message?: Uint8Array,
      extraCommit?: Uint8Array,
    ): Uint8Array;
    rewind(
      proof: Uint8Array,
      valueCommitment: Uint8Array,
      assetCommitment: Uint8Array,
      nonce: Uint8Array,
      extraCommit?: Uint8Array,
    ): {
      value: string;
      minValue: string;
      maxValue: string;
      blinder: Uint8Array;
      message: Uint8Array;
    };
  };
  surjectionproof: {
    initialize: (
      inputTags: Array<Uint8Array>,
      outputTag: Uint8Array,
      maxIterations: number,
      seed: Uint8Array,
    ) => {
      proof: Uint8Array;
      inputIndex: number;
    };
    generate: (
      proof: Uint8Array,
      inputTags: Array<Uint8Array>,
      outputTag: Uint8Array,
      inputIndex: number,
      inputBlindingKey: Uint8Array,
      outputBlindingKey: Uint8Array,
    ) => Uint8Array;
    verify: (
      proof: Uint8Array,
      inputTags: Array<Uint8Array>,
      outputTag: Uint8Array,
    ) => boolean;
  };
}
