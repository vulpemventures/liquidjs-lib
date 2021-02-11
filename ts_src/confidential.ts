import * as bufferutils from './bufferutils';
import * as crypto from './crypto';

import { Output } from './transaction';
import secp256k1 from 'secp256k1-zkp';

const secp256k1Promise = secp256k1();

async function nonceHash(pubkey: Buffer, privkey: Buffer): Promise<Buffer> {
  const { ecdh } = await secp256k1Promise;
  return crypto.sha256(ecdh(pubkey, privkey));
}

export async function valueBlindingFactor(
  inValues: string[],
  outValues: string[],
  inGenerators: Buffer[],
  outGenerators: Buffer[],
  inFactors: Buffer[],
  outFactors: Buffer[],
): Promise<Buffer> {
  const { pedersen } = await secp256k1Promise;
  const values = inValues.concat(outValues);
  const nInputs = inValues.length;
  const generators = inGenerators.concat(outGenerators);
  const factors = inFactors.concat(outFactors);
  return pedersen.blindGeneratorBlindSum(values, nInputs, generators, factors);
}

export async function valueCommitment(
  value: string,
  gen: Buffer,
  factor: Buffer,
): Promise<Buffer> {
  const { generator, pedersen } = await secp256k1Promise;
  const generatorParsed = generator.parse(gen);
  const commit = pedersen.commit(factor, value, generatorParsed);
  return pedersen.commitSerialize(commit);
}

export async function assetCommitment(
  asset: Buffer,
  factor: Buffer,
): Promise<Buffer> {
  const { generator } = await secp256k1Promise;
  const gen = generator.generateBlinded(asset, factor);
  return generator.serialize(gen);
}

export interface UnblindOutputResult {
  value: string;
  valueBlindingFactor: Buffer;
  asset: Buffer;
  assetBlindingFactor: Buffer;
}

export async function unblindOutputWithKey(
  out: Output,
  blindingPrivKey: Buffer,
): Promise<UnblindOutputResult> {
  const nonce = await nonceHash(out.nonce, blindingPrivKey);
  return unblindOutputWithNonce(out, nonce);
}

export async function unblindOutputWithNonce(
  out: Output,
  nonce: Buffer,
): Promise<UnblindOutputResult> {
  const secp = await secp256k1Promise;
  const gen = secp.generator.parse(out.asset);
  const { value, blindFactor, message } = secp.rangeproof.rewind(
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

export async function rangeProofInfo(
  proof: Buffer,
): Promise<RangeProofInfoResult> {
  const { rangeproof } = await secp256k1Promise;
  const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
  return {
    minValue: parseInt(minValue, 10),
    maxValue: parseInt(maxValue, 10),
    ctExp: exp,
    ctBits: parseInt(mantissa, 10),
  };
}

export async function rangeProof(
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
): Promise<Buffer> {
  const { generator, pedersen, rangeproof } = await secp256k1Promise;

  const nonce = await nonceHash(blindingPubkey, ephemeralPrivkey);
  const gen = generator.generateBlinded(asset, assetBlindingFactor);
  const message = Buffer.concat([asset, assetBlindingFactor]);
  const commit = pedersen.commitParse(valueCommit);

  const mv = minValue ? minValue : '1';
  const e = exp ? exp : 0;
  const mb = minBits ? minBits : 36;

  return rangeproof.sign(
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

export async function surjectionProof(
  outputAsset: Buffer,
  outputAssetBlindingFactor: Buffer,
  inputAssets: Buffer[],
  inputAssetBlindingFactors: Buffer[],
  seed: Buffer,
): Promise<Buffer> {
  const { generator, surjectionproof } = await secp256k1Promise;
  const outputGenerator = generator.generateBlinded(
    outputAsset,
    outputAssetBlindingFactor,
  );

  const inputGenerators = inputAssets.map((v, i) =>
    generator.generateBlinded(v, inputAssetBlindingFactors[i]),
  );
  const nInputsToUse = inputAssets.length > 3 ? 3 : inputAssets.length;
  const maxIterations = 100;

  const init = surjectionproof.initialize(
    inputAssets,
    nInputsToUse,
    outputAsset,
    maxIterations,
    seed,
  );

  const proof = surjectionproof.generate(
    init.proof,
    inputGenerators,
    outputGenerator,
    init.inputIndex,
    inputAssetBlindingFactors[init.inputIndex],
    outputAssetBlindingFactor,
  );

  return surjectionproof.serialize(proof);
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
