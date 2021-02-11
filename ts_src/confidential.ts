import * as bufferutils from './bufferutils';
import * as crypto from './crypto';
import * as secp256k1 from 'secp256k1-zkp';

import { Output } from './transaction';

function nonceHash(pubkey: Buffer, privkey: Buffer): Buffer {
  return crypto.sha256(secp256k1.ecdh.ecdh(pubkey, privkey));
}

export function valueBlindingFactor(
  inValues: string[],
  outValues: string[],
  inGenerators: Buffer[],
  outGenerators: Buffer[],
  inFactors: Buffer[],
  outFactors: Buffer[],
): Buffer {
  const values = inValues.concat(outValues);
  const nInputs = inValues.length;
  const generators = inGenerators.concat(outGenerators);
  const factors = inFactors.concat(outFactors);
  return secp256k1.pedersen.blindGeneratorBlindSum(
    values,
    nInputs,
    generators,
    factors,
  );
}

export function valueCommitment(
  value: string,
  generator: Buffer,
  factor: Buffer,
): Buffer {
  const gen = secp256k1.generator.parse(generator);
  const commit = secp256k1.pedersen.commit(factor, value, gen);
  return secp256k1.pedersen.commitSerialize(commit);
}

export function assetCommitment(asset: Buffer, factor: Buffer): Buffer {
  const generator = secp256k1.generator.generateBlinded(asset, factor);
  return secp256k1.generator.serialize(generator);
}

export interface UnblindOutputResult {
  value: string;
  valueBlindingFactor: Buffer;
  asset: Buffer;
  assetBlindingFactor: Buffer;
}

export function unblindOutputWithKey(
  out: Output,
  blindingPrivKey: Buffer,
): UnblindOutputResult {
  const nonce = nonceHash(out.nonce, blindingPrivKey);
  return unblindOutputWithNonce(out, nonce);
}

export function unblindOutputWithNonce(
  out: Output,
  nonce: Buffer,
): UnblindOutputResult {
  const gen = secp256k1.generator.parse(out.asset);
  const { value, blindFactor, message } = secp256k1.rangeproof.rewind(
    out.value,
    out.rangeProof!,
    nonce,
    gen,
    out.script,
  );

  return {
    value,
    asset: message.slice(0, 32),
    valueBlindingFactor: blindFactor,
    assetBlindingFactor: message.slice(32),
  };
}

export interface RangeProofInfoResult {
  ctExp: number;
  ctBits: number;
  minValue: number;
  maxValue: number;
}

export function rangeProofInfo(proof: Buffer): RangeProofInfoResult {
  const { exp, mantissa, minValue, maxValue } = secp256k1.rangeproof.info(
    proof,
  );
  return {
    minValue: parseInt(minValue, 10),
    maxValue: parseInt(maxValue, 10),
    ctExp: exp,
    ctBits: parseInt(mantissa, 10),
  };
}

export function rangeProof(
  value: string,
  blindingPubkey: Buffer,
  ephemeralPrivkey: Buffer,
  asset: Buffer,
  assetBlindingFactor: Buffer,
  valueBlindFactor: Buffer,
  valueCommit: Buffer,
  scriptPubkey: Buffer,
  minValue?: string,
  exp?: number,
  minBits?: number,
): Buffer {
  const nonce = nonceHash(blindingPubkey, ephemeralPrivkey);
  const gen = secp256k1.generator.generateBlinded(asset, assetBlindingFactor);
  const message = Buffer.concat([asset, assetBlindingFactor]);
  const commit = secp256k1.pedersen.commitParse(valueCommit);

  const mv = minValue ? minValue : '1';
  const e = exp ? exp : 0;
  const mb = minBits ? minBits : 36;

  return secp256k1.rangeproof.sign(
    commit,
    valueBlindFactor,
    nonce,
    value,
    gen,
    mv,
    e,
    mb,
    message,
    scriptPubkey,
  );
}

export function surjectionProof(
  outputAsset: Buffer,
  outputAssetBlindingFactor: Buffer,
  inputAssets: Buffer[],
  inputAssetBlindingFactors: Buffer[],
  seed: Buffer,
): Buffer {
  const outputGenerator = secp256k1.generator.generateBlinded(
    outputAsset,
    outputAssetBlindingFactor,
  );

  const inputGenerators = inputAssets.map((v, i) =>
    secp256k1.generator.generateBlinded(v, inputAssetBlindingFactors[i]),
  );
  const nInputsToUse = inputAssets.length > 3 ? 3 : inputAssets.length;
  const maxIterations = 100;

  const init = secp256k1.surjectionproof.initialize(
    inputAssets,
    nInputsToUse,
    outputAsset,
    maxIterations,
    seed,
  );

  const proof = secp256k1.surjectionproof.generate(
    init.proof,
    inputGenerators,
    outputGenerator,
    init.inputIndex,
    inputAssetBlindingFactors[init.inputIndex],
    outputAssetBlindingFactor,
  );

  return secp256k1.surjectionproof.serialize(proof);
}

const CONFIDENTIAL_VALUE = 9; // explicit size of confidential values

export function confidentialValueToSatoshi(value: Buffer): number {
  if (!isUnconfidentialValue(value)) {
    throw new Error(
      'Value must be unconfidential, length or the prefix are not valid',
    );
  }
  const reverseValueBuffer: Buffer = Buffer.allocUnsafe(CONFIDENTIAL_VALUE - 1);
  value.slice(1, CONFIDENTIAL_VALUE).copy(reverseValueBuffer, 0);
  bufferutils.reverseBuffer(reverseValueBuffer);
  return bufferutils.readUInt64LE(reverseValueBuffer, 0);
}

export function satoshiToConfidentialValue(amount: number): Buffer {
  const unconfPrefix: Buffer = Buffer.allocUnsafe(1);
  const valueBuffer: Buffer = Buffer.allocUnsafe(CONFIDENTIAL_VALUE - 1);
  unconfPrefix.writeUInt8(1, 0);
  bufferutils.writeUInt64LE(valueBuffer, amount, 0);
  return Buffer.concat([unconfPrefix, bufferutils.reverseBuffer(valueBuffer)]);
}

export function isUnconfidentialValue(value: Buffer): boolean {
  return value.length === CONFIDENTIAL_VALUE && value.readUInt8(0) === 1;
}
