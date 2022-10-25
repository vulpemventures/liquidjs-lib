import * as crypto from './crypto';
import { Output, ZERO } from './transaction';
import { ElementsValue } from './value';

export interface UnblindOutputResult {
  value: string;
  valueBlindingFactor: Buffer;
  asset: Buffer;
  assetBlindingFactor: Buffer;
}

export interface RangeProofInfoResult {
  ctExp: number;
  ctBits: number;
  minValue: number;
  maxValue: number;
}

type Ecdh = (pubkey: Buffer, scalar: Buffer) => Buffer;

interface Ec {
  prvkeyNegate: (key: Buffer) => Buffer;
  prvkeyTweakAdd: (key: Buffer, tweak: Buffer) => Buffer;
  prvkeyTweakMul: (key: Buffer, tweak: Buffer) => Buffer;
}

interface Generator {
  generate: (seed: Buffer) => Buffer;
  generateBlinded(key: Buffer, blind: Buffer): Buffer;
  parse(input: Buffer): Buffer;
  serialize(generator: Buffer): Buffer;
}

interface Pedersen {
  commit(blindFactor: Buffer, value: string, generator: Buffer): Buffer;
  commitSerialize(commitment: Buffer): Buffer;
  commitParse(input: Buffer): Buffer;
  blindSum(blinds: Array<Buffer>, nneg?: number): Buffer;
  verifySum(commits: Array<Buffer>, negativeCommits: Array<Buffer>): boolean;
  blindGeneratorBlindSum(
    values: Array<string>,
    nInputs: number,
    blindGenerators: Array<Buffer>,
    blindFactors: Array<Buffer>,
  ): Buffer;
}

interface RangeProof {
  info(proof: Buffer): {
    exp: number;
    mantissa: string;
    minValue: string;
    maxValue: string;
  };
  verify(
    commit: Buffer,
    proof: Buffer,
    generator: Buffer,
    extraCommit?: Buffer,
  ): boolean;
  sign(
    commit: Buffer,
    blind: Buffer,
    nonce: Buffer,
    value: string,
    generator: Buffer,
    minValue?: string,
    base10Exp?: number,
    minBits?: number,
    message?: Buffer,
    extraCommit?: Buffer,
  ): Buffer;
  rewind(
    commit: Buffer,
    proof: Buffer,
    nonce: Buffer,
    generator: Buffer,
    extraCommit?: Buffer,
  ): {
    value: string;
    minValue: string;
    maxValue: string;
    blindFactor: Buffer;
    message: Buffer;
  };
}

interface SurjectionProof {
  serialize: (proof: {
    nInputs: number;
    usedInputs: Buffer;
    data: Buffer;
  }) => Buffer;
  parse: (proof: Buffer) => {
    nInputs: number;
    usedInputs: Buffer;
    data: Buffer;
  };
  initialize: (
    inputTags: Array<Buffer>,
    inputTagsToUse: number,
    outputTag: Buffer,
    maxIterations: number,
    seed: Buffer,
  ) => {
    proof: { nInputs: number; usedInputs: Buffer; data: Buffer };
    inputIndex: number;
  };
  generate: (
    proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
    inputTags: Array<Buffer>,
    outputTag: Buffer,
    inputIndex: number,
    inputBlindingKey: Buffer,
    outputBlindingKey: Buffer,
  ) => { nInputs: number; usedInputs: Buffer; data: Buffer };
  verify: (
    proof: { nInputs: number; usedInputs: Buffer; data: Buffer },
    inputTags: Array<Buffer>,
    outputTag: Buffer,
  ) => boolean;
}

export interface ZKP {
  ecdh: Ecdh;
  ec: Ec;
  surjectionproof: SurjectionProof;
  rangeproof: RangeProof;
  pedersen: Pedersen;
  generator: Generator;
}

export class Confidential {
  constructor(private zkp: ZKP) {}

  nonceHash(pubkey: Buffer, privkey: Buffer): Buffer {
    return crypto.sha256(this.zkp.ecdh(pubkey, privkey));
  }

  valueBlindingFactor(
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
    return this.zkp.pedersen.blindGeneratorBlindSum(
      values,
      nInputs,
      generators,
      factors,
    );
  }

  valueCommitment(value: string, gen: Buffer, factor: Buffer): Buffer {
    const { generator, pedersen } = this.zkp;
    const generatorParsed = generator.parse(gen);
    const commit = pedersen.commit(factor, value, generatorParsed);
    return pedersen.commitSerialize(commit);
  }

  assetCommitment(asset: Buffer, factor: Buffer): Buffer {
    const { generator } = this.zkp;
    const gen = generator.generateBlinded(asset, factor);
    return generator.serialize(gen);
  }

  unblindOutputWithKey(
    out: Output,
    blindingPrivKey: Buffer,
  ): UnblindOutputResult {
    const nonce = this.nonceHash(out.nonce, blindingPrivKey);
    return this.unblindOutputWithNonce(out, nonce);
  }

  unblindOutputWithNonce(out: Output, nonce: Buffer): UnblindOutputResult {
    if (!out.rangeProof || out.rangeProof.length === 0) {
      throw new Error('Missing rangeproof to rewind');
    }
    const secp = this.zkp;
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

  rangeProofInfo(proof: Buffer): RangeProofInfoResult {
    const { rangeproof } = this.zkp;
    const { exp, mantissa, minValue, maxValue } = rangeproof.info(proof);
    return {
      minValue: parseInt(minValue, 10),
      maxValue: parseInt(maxValue, 10),
      ctExp: exp,
      ctBits: parseInt(mantissa, 10),
    };
  }

  /**
   *  nonceHash from blinding key + ephemeral key and then rangeProof computation
   */
  rangeProofWithNonceHash(
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
    const nonce = this.nonceHash(blindingPubkey, ephemeralPrivkey);
    return this.rangeProof(
      value,
      nonce,
      asset,
      assetBlindingFactor,
      valueBlindFactor,
      valueCommit,
      scriptPubkey,
      minValue,
      exp,
      minBits,
    );
  }

  rangeProofVerify(
    valueCommit: Buffer,
    assetCommit: Buffer,
    proof: Buffer,
    script?: Buffer,
  ): boolean {
    const { generator, pedersen, rangeproof } = this.zkp;
    const gen = generator.parse(assetCommit);
    const commit = pedersen.commitParse(valueCommit);
    return rangeproof.verify(commit, proof, gen, script);
  }

  /**
   *  rangeProof computation without nonceHash step.
   */
  rangeProof(
    value: string,
    nonce: Buffer,
    asset: Buffer,
    assetBlindingFactor: Buffer,
    valueBlindFactor: Buffer,
    valueCommit: Buffer,
    scriptPubkey: Buffer,
    minValue?: string,
    exp?: number,
    minBits?: number,
  ): Buffer {
    const { generator, pedersen, rangeproof } = this.zkp;

    const gen = generator.generateBlinded(asset, assetBlindingFactor);
    const message = Buffer.concat([asset, assetBlindingFactor]);
    const commit = pedersen.commitParse(valueCommit);

    const mv = value === '0' ? '0' : minValue ? minValue : '1';
    const e = exp ? exp : 0;
    const mb = minBits ? minBits : 52;

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

  surjectionProof(
    outputAsset: Buffer,
    outputAssetBlindingFactor: Buffer,
    inputAssets: Buffer[],
    inputAssetBlindingFactors: Buffer[],
    seed: Buffer,
  ): Buffer {
    const { generator, surjectionproof } = this.zkp;
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

  surjectionProofVerify(
    inAssets: Buffer[],
    inAssetBlinders: Buffer[],
    outAsset: Buffer,
    outAssetBlinder: Buffer,
    proof: Buffer,
  ): boolean {
    const { generator, surjectionproof } = this.zkp;
    const inGenerators = inAssets.map((v, i) =>
      generator.generateBlinded(v, inAssetBlinders[i]),
    );
    const outGenerator = generator.generateBlinded(outAsset, outAssetBlinder);
    const sProof = surjectionproof.parse(proof);
    return surjectionproof.verify(sProof, inGenerators, outGenerator);
  }

  blindValueProof(
    value: string,
    valueCommit: Buffer,
    assetCommit: Buffer,
    valueBlinder: Buffer,
    nonce: Buffer,
  ): Buffer {
    const { generator, pedersen, rangeproof } = this.zkp;

    const gen = generator.parse(assetCommit);
    const commit = pedersen.commitParse(valueCommit);

    return rangeproof.sign(commit, valueBlinder, nonce, value, gen, value, -1);
  }

  blindAssetProof(
    asset: Buffer,
    assetCommit: Buffer,
    assetBlinder: Buffer,
  ): Buffer {
    const { generator, surjectionproof } = this.zkp;

    const nInputsToUse = 1;
    const maxIterations = 100;

    const init = surjectionproof.initialize(
      [asset],
      nInputsToUse,
      asset,
      maxIterations,
      ZERO,
    );

    const gen = generator.generate(asset);
    const assetGen = generator.parse(assetCommit);

    const proof = surjectionproof.generate(
      init.proof,
      [gen],
      assetGen,
      init.inputIndex,
      ZERO,
      assetBlinder,
    );

    return surjectionproof.serialize(proof);
  }

  assetBlindProofVerify(
    asset: Buffer,
    assetCommit: Buffer,
    proof: Buffer,
  ): boolean {
    const { generator, surjectionproof } = this.zkp;
    const inGenerators = [generator.generate(asset)];
    const outGenerator = generator.parse(assetCommit);
    const sProof = surjectionproof.parse(proof);
    return surjectionproof.verify(sProof, inGenerators, outGenerator);
  }
}

export function confidentialValueToSatoshi(value: Buffer): number {
  return ElementsValue.fromBytes(value).number;
}

export function satoshiToConfidentialValue(amount: number): Buffer {
  return ElementsValue.fromNumber(amount).bytes;
}
